import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { ManagerApp } from './ManagerApp';
import { ManagerApiError } from './api';
import { anonymousSession, signedInApiFixture, userSession } from './test-fixtures';

async function login() {
  fireEvent.change(await screen.findByLabelText('Tên đăng nhập'), { target: { value: 'synthetic' } });
  fireEvent.change(screen.getByLabelText('Mật khẩu'), { target: { value: 'test-only-password' } });
  fireEvent.click(screen.getByRole('button', { name: 'Đăng nhập' }));
}
async function logout() {
  fireEvent.click(await screen.findByRole('button', { name: /Menu tài khoản/ }));
  fireEvent.click(screen.getByRole('button', { name: 'Đăng xuất' }));
}

describe('real Manager shell', () => {
  it('starts masked, logs in and displays only server overview counts', async () => {
    const api = signedInApiFixture('admin');
    api.session = vi.fn().mockResolvedValue(anonymousSession);
    render(<ManagerApp api={api} />);
    await login();
    expect(await screen.findByText('Thiết bị đã đăng ký')).toBeVisible();
    expect(screen.getByText('17')).toBeVisible();
    expect(api.login).toHaveBeenCalledWith({ username: 'synthetic', password: 'test-only-password' }, expect.any(AbortSignal));
    expect(screen.queryByText(/Online|98%|Chuyển vai trò|aegis\/aegis/)).not.toBeInTheDocument();
  });
  it('shows a generic login error and clears the submitted password', async () => {
    const api = signedInApiFixture('viewer');
    api.session = vi.fn().mockResolvedValue(anonymousSession);
    api.login = vi.fn().mockRejectedValue(new ManagerApiError(401));
    render(<ManagerApp api={api} />);
    await login();
    expect(await screen.findByRole('alert')).toHaveTextContent('Không thể đăng nhập');
    expect(screen.getByLabelText('Mật khẩu')).toHaveValue('');
    fireEvent.click(screen.getByRole('button', { name: 'Hiện mật khẩu' }));
    expect(screen.getByLabelText('Mật khẩu')).toHaveAttribute('type', 'text');
  });
  it('clears workspace on logout', async () => {
    const api = signedInApiFixture('admin');
    render(<ManagerApp api={api} />);
    await screen.findByText('17');
    await logout();
    expect(await screen.findByRole('heading', { name: 'Đăng nhập Manager' })).toBeVisible();
    expect(screen.queryByText('17')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Tạo tài khoản' })).not.toBeInTheDocument();
  });
  it('test_late_response_after_logout_cannot_restore_previous_workspace', async () => {
    const api = signedInApiFixture('admin');
    let finish!: (value: unknown) => void;
    api.overview = vi.fn().mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
    render(<ManagerApp api={api} />);
    await logout();
    await screen.findByRole('heading', { name: 'Đăng nhập Manager' });
    await act(async () => { finish({ registered_devices: 999, recorded_jobs: 999, recorded_releases: 999 }); });
    expect(screen.queryByText('999')).not.toBeInTheDocument();
  });
  it('keeps logout pending and failure masked, then refreshes CSRF before retry', async () => {
    const api = signedInApiFixture('admin');
    let fail!: (error: Error) => void;
    api.logout = vi.fn().mockImplementationOnce(() => new Promise((_, reject) => { fail = reject; })).mockResolvedValueOnce(undefined);
    render(<ManagerApp api={api} />);
    await screen.findByText('17');
    await logout();
    expect(screen.queryByText('17')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Đăng nhập' })).not.toBeInTheDocument();
    await act(async () => { fail(new Error('network')); });
    expect(await screen.findByRole('alert')).toHaveTextContent('Chưa thể xác nhận đăng xuất');
    expect(screen.queryByRole('button', { name: 'Đăng nhập' })).not.toBeInTheDocument();
    api.session = vi.fn().mockResolvedValue(anonymousSession);
    fireEvent.click(screen.getByRole('button', { name: 'Thử lại' }));
    await screen.findByRole('heading', { name: 'Đăng nhập Manager' });
    expect(api.session).toHaveBeenCalledTimes(2);
    expect(api.logout).toHaveBeenCalledTimes(2);
  });
  it('discards an older session read after a newer user session is accepted', async () => {
    const api = signedInApiFixture('admin');
    let finish!: (value: unknown) => void;
    api.session = vi.fn().mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }))
      .mockResolvedValueOnce({ ...userSession('viewer'), user: { ...userSession('viewer').user!, username: 'new-user', display_name: 'New user' } });
    render(<ManagerApp api={api} />);
    act(() => { window.dispatchEvent(new Event('pageshow')); });
    expect(await screen.findByRole('button', { name: 'Menu tài khoản New user' })).toBeVisible();
    await act(async () => { finish(userSession('admin')); });
    expect(screen.getByRole('button', { name: 'Menu tài khoản New user' })).toBeVisible();
    expect(screen.queryByRole('button', { name: /Tài khoản & quyền/ })).not.toBeInTheDocument();
  });
  it.each(['success', 'failure'] as const)('queues restoration during login %s and stays masked until anonymous revalidation', async (outcome) => {
    const api = signedInApiFixture('viewer');
    let validate!: (value: unknown) => void;
    api.session = vi.fn().mockResolvedValueOnce(anonymousSession)
      .mockImplementationOnce(() => new Promise((resolve) => { validate = resolve; }));
    let finish!: (value: unknown) => void;
    let fail!: (error: Error) => void;
    api.login = vi.fn().mockImplementation(() => new Promise((resolve, reject) => { finish = resolve; fail = reject; }));
    render(<ManagerApp api={api} />);
    await login();
    act(() => { window.dispatchEvent(new Event('pageshow')); });
    expect(api.session).toHaveBeenCalledTimes(1);
    await act(async () => { if (outcome === 'success') finish(userSession('viewer')); else fail(new ManagerApiError(401)); });
    expect(api.session).toHaveBeenCalledTimes(2);
    expect(screen.queryByRole('button', { name: /Menu tài khoản/ })).not.toBeInTheDocument();
    expect(api.overview).not.toHaveBeenCalled();
    await act(async () => { validate(anonymousSession); });
    expect(await screen.findByRole('heading', { name: 'Đăng nhập Manager' })).toBeVisible();
    expect(screen.queryByText('17')).not.toBeInTheDocument();
  });
  it('masks restored pages until session revalidation completes with expired cookie', async () => {
    const api = signedInApiFixture('admin');
    render(<ManagerApp api={api} />);
    await screen.findByText('17');
    let finish!: (value: unknown) => void;
    api.session = vi.fn().mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
    act(() => { window.dispatchEvent(new Event('pageshow')); });
    expect(screen.queryByText('17')).not.toBeInTheDocument();
    await act(async () => { finish(anonymousSession); });
    expect(await screen.findByRole('heading', { name: 'Đăng nhập Manager' })).toBeVisible();
  });
  it.each([401, 403])('handles protected response %s without a login loop', async (status) => {
    const api = signedInApiFixture('viewer');
    api.overview = vi.fn().mockRejectedValue(new ManagerApiError(status));
    render(<ManagerApp api={api} />);
    if (status === 401) expect(await screen.findByRole('heading', { name: 'Đăng nhập Manager' })).toBeVisible();
    else {
      expect(await screen.findByRole('alert')).toHaveTextContent('không có quyền');
      expect(screen.getByRole('button', { name: /Menu tài khoản/ })).toBeVisible();
      expect(api.session).toHaveBeenCalledTimes(1);
    }
  });
  it('keeps own account and logout available to a legacy user without view', async () => {
    const api = signedInApiFixture('viewer');
    api.session = vi.fn().mockResolvedValue({ ...userSession('viewer'), user: { ...userSession('viewer').user!, capabilities: [] } });
    render(<ManagerApp api={api} />);
    expect(await screen.findByRole('alert')).toHaveTextContent('không có quyền');
    fireEvent.click(screen.getByRole('button', { name: /Menu tài khoản/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Tài khoản của tôi' }));
    expect(await screen.findByRole('heading', { name: 'Tài khoản của tôi' })).toBeVisible();
    expect(api.overview).not.toHaveBeenCalled();
  });
  it('changes own password and clears inputs on submit and close', async () => {
    const api = signedInApiFixture('operator');
    render(<ManagerApp api={api} />);
    fireEvent.click(await screen.findByRole('button', { name: /Menu tài khoản/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Tài khoản của tôi' }));
    expect(screen.getByText('Xem dữ liệu')).toBeVisible();
    fireEvent.change(screen.getByLabelText('Mật khẩu hiện tại'), { target: { value: 'old-test-only' } });
    fireEvent.change(screen.getByLabelText('Mật khẩu mới'), { target: { value: 'new-test-only' } });
    fireEvent.click(screen.getByRole('button', { name: 'Đổi mật khẩu' }));
    await waitFor(() => expect(api.changePassword).toHaveBeenCalled());
    expect(screen.getByLabelText('Mật khẩu hiện tại')).toHaveValue('');
    expect(screen.getByLabelText('Mật khẩu mới')).toHaveValue('');
    expect(await screen.findByRole('status')).toHaveTextContent('Đã đổi mật khẩu');
    fireEvent.change(screen.getByLabelText('Mật khẩu mới'), { target: { value: 'discard-test-only' } });
    fireEvent.click(screen.getByRole('button', { name: 'Đóng tài khoản' }));
    expect(screen.queryByLabelText('Mật khẩu mới')).not.toBeInTheDocument();
  });
  it.each([
    ['logout', 'success'], ['restoration', 'success'],
    ['logout', 'failure'], ['restoration', 'failure'],
  ] as const)('serializes %s after a pending password %s even when its drawer closes', async (action, outcome) => {
    const api = signedInApiFixture('viewer');
    const events: string[] = [];
    let finishPassword!: () => void;
    let passwordSignal: AbortSignal | undefined;
    api.changePassword = vi.fn().mockImplementation((_input, signal?: AbortSignal) => {
      passwordSignal = signal;
      events.push('password-start');
      return new Promise<void>((resolve, reject) => {
        finishPassword = () => { events.push('password-end'); if (outcome === 'success') resolve(); else reject(new ManagerApiError(401)); };
      });
    });
    api.session = vi.fn().mockResolvedValueOnce(userSession('viewer')).mockImplementation(async () => {
      events.push('session'); return anonymousSession;
    });
    api.logout = vi.fn(async () => { events.push('logout'); });
    render(<ManagerApp api={api} />);
    await screen.findByText('17');
    fireEvent.click(screen.getByRole('button', { name: /Menu tài khoản/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Tài khoản của tôi' }));
    fireEvent.change(screen.getByLabelText('Mật khẩu hiện tại'), { target: { value: 'old-test-only' } });
    fireEvent.change(screen.getByLabelText('Mật khẩu mới'), { target: { value: 'new-test-only' } });
    fireEvent.click(screen.getByRole('button', { name: 'Đổi mật khẩu' }));
    fireEvent.click(screen.getByRole('button', { name: 'Đóng tài khoản' }));
    expect(passwordSignal?.aborted ?? false).toBe(false);
    if (action === 'logout') await logout();
    act(() => { window.dispatchEvent(new Event('pagehide')); window.dispatchEvent(new Event('pageshow')); });
    expect(api.logout).not.toHaveBeenCalled();
    expect(api.session).toHaveBeenCalledTimes(1);
    expect(screen.queryByText('17')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Mật khẩu mới')).not.toBeInTheDocument();
    await act(async () => { finishPassword(); });
    expect(await screen.findByRole('heading', { name: 'Đăng nhập Manager' })).toBeVisible();
    expect(events).toEqual(action === 'logout' ? ['password-start', 'password-end', 'logout', 'session'] : ['password-start', 'password-end', 'session']);
    expect(passwordSignal?.aborted ?? false).toBe(false);
  });
  it('expires absolute sessions locally and leaves future sections unavailable', async () => {
    const api = signedInApiFixture('viewer');
    api.session = vi.fn().mockResolvedValue({ ...userSession('viewer'), expires_at: Math.floor(Date.now() / 1000) - 1 });
    render(<ManagerApp api={api} />);
    expect(await screen.findByRole('heading', { name: 'Đăng nhập Manager' })).toBeVisible();
    expect(localStorage.length).toBe(0);
  });
  it('masks a running workspace at its absolute expiry deadline', async () => {
    vi.useFakeTimers();
    try {
      const api = signedInApiFixture('viewer');
      api.session = vi.fn().mockResolvedValue({ ...userSession('viewer'), expires_at: Math.floor(Date.now() / 1000) + 1 });
      render(<ManagerApp api={api} />);
      await act(async () => { await Promise.resolve(); });
      expect(screen.getByText('17')).toBeVisible();
      await act(async () => { vi.advanceTimersByTime(1100); await Promise.resolve(); });
      expect(screen.queryByText('17')).not.toBeInTheDocument();
      expect(screen.getByRole('heading', { name: 'Đăng nhập Manager' })).toBeVisible();
    } finally { vi.useRealTimers(); }
  });
  it('switches theme and exposes only capability-appropriate navigation', async () => {
    const api = signedInApiFixture('viewer');
    const { container } = render(<ManagerApp api={api} />);
    await screen.findByText('17');
    expect(screen.queryByRole('button', { name: /Tài khoản & quyền/ })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Thiết bị/ })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Chuyển giao diện sáng' }));
    expect(container.firstElementChild).toHaveAttribute('data-theme', 'light');
  });
  it('shows real zero counts without substituting sample data', async () => {
    const api = signedInApiFixture('viewer');
    api.overview = vi.fn().mockResolvedValue({ registered_devices: 0, recorded_jobs: 0, recorded_releases: 0 });
    render(<ManagerApp api={api} />);
    expect(await screen.findAllByText('0')).toHaveLength(3);
  });
  it('clears protected content and password fields before a page snapshot is restored', async () => {
    const api = signedInApiFixture('viewer');
    render(<ManagerApp api={api} />);
    await screen.findByText('17');
    fireEvent.click(screen.getByRole('button', { name: /Menu tài khoản/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Tài khoản của tôi' }));
    fireEvent.change(screen.getByLabelText('Mật khẩu mới'), { target: { value: 'snapshot-test-only' } });
    act(() => { window.dispatchEvent(new Event('pagehide')); });
    expect(screen.queryByText('17')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Mật khẩu mới')).not.toBeInTheDocument();
    act(() => { window.dispatchEvent(new Event('pageshow')); });
    expect(await screen.findByText('17')).toBeVisible();
    expect(screen.queryByLabelText('Mật khẩu mới')).not.toBeInTheDocument();
  });
});
