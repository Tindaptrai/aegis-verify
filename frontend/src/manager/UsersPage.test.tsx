import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { UsersPage } from './UsersPage';
import { ManagerApp } from './ManagerApp';
import { ManagerApiError } from './api';
import type { UserDTO, UsersDTO } from './contracts';
import { signedInApiFixture, userSession } from './test-fixtures';

function targetApi(overrides: Partial<UserDTO> = {}) {
  const api = signedInApiFixture('admin');
  const target: UserDTO = { ...userSession('viewer').user!, id: 7, username: 'synthetic-target', display_name: 'Test target', editable: true, ...overrides };
  api.listUsers = vi.fn(async (): Promise<UsersDTO> => ({ results: [target], count: 1, page: 1, page_size: 50 }));
  return { api, target };
}
async function edit() { fireEvent.click(await screen.findByRole('button', { name: 'Chỉnh sửa' })); }
async function create() {
  fireEvent.click(await screen.findByRole('button', { name: 'Tạo tài khoản' }));
  fireEvent.change(screen.getByLabelText('Tên đăng nhập'), { target: { value: 'synthetic-new' } });
  fireEvent.change(screen.getByLabelText('Tên hiển thị'), { target: { value: 'New test user' } });
  fireEvent.change(screen.getByLabelText('Mật khẩu ban đầu'), { target: { value: 'Synthetic-only-password' } });
}

describe('real account administration', () => {
  it('loads without mutations and searches with pagination on the server', async () => {
    const { api } = targetApi();
    api.listUsers = vi.fn(async ({ page = 1 }: { page?: number; q?: string } = {}): Promise<UsersDTO> => ({ results: [{ ...userSession('viewer').user!, username: `page-${page}` }], count: 60, page, page_size: 50 }));
    render(<UsersPage api={api} />);
    await screen.findByText('page-1');
    expect(api.createUser).not.toHaveBeenCalled(); expect(api.updateUser).not.toHaveBeenCalled(); expect(api.resetPassword).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Trang sau' }));
    await screen.findByText('page-2');
    expect(api.listUsers).toHaveBeenLastCalledWith({ page: 2, q: '' }, expect.any(AbortSignal));
    fireEvent.change(screen.getByLabelText('Tìm tài khoản'), { target: { value: 'test search' } });
    fireEvent.submit(screen.getByRole('search'));
    await waitFor(() => expect(api.listUsers).toHaveBeenLastCalledWith({ page: 1, q: 'test search' }, expect.any(AbortSignal)));
    expect(screen.getByLabelText('Tìm tài khoản')).toHaveAttribute('maxlength', '100');
  });

  it('creates a user with a server preset using an exact closed body and refreshes authority', async () => {
    const { api } = targetApi(); const refresh = vi.fn(async () => undefined);
    render(<UsersPage api={api} onAuthorityChanged={refresh} />);
    await create();
    fireEvent.change(screen.getByLabelText('Vai trò'), { target: { value: 'operator' } });
    fireEvent.click(screen.getByRole('button', { name: 'Lưu tài khoản' }));
    await waitFor(() => expect(api.createUser).toHaveBeenCalledWith({ username: 'synthetic-new', display_name: 'New test user', password: 'Synthetic-only-password', capabilities: ['view', 'run_jobs', 'export_evidence'], is_active: true }, expect.any(AbortSignal)));
    await waitFor(() => expect(refresh).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: 'Tạo tài khoản' }));
    expect(screen.getByLabelText('Mật khẩu ban đầu')).toHaveValue('');
  });

  it('marks modified grants Custom and keeps username immutable on edit', async () => {
    const { api } = targetApi(); render(<UsersPage api={api} />); await edit();
    expect(screen.getByLabelText('Tên đăng nhập')).toHaveAttribute('readonly');
    expect(screen.queryByLabelText('Mật khẩu ban đầu')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('checkbox', { name: /manage_devices/ }));
    expect(screen.getByLabelText('Vai trò')).toHaveValue('custom');
    fireEvent.change(screen.getByLabelText('Trạng thái'), { target: { value: 'locked' } });
    fireEvent.click(screen.getByRole('button', { name: 'Lưu tài khoản' }));
    await waitFor(() => expect(api.updateUser).toHaveBeenCalledWith(7, { display_name: 'Test target', capabilities: ['view', 'manage_devices'], is_active: false }, expect.any(AbortSignal)));
  });

  it('locks and unlocks preserving assigned grants and never guesses fields', async () => {
    const { api, target } = targetApi({ is_active: false, capabilities: ['view', 'run_jobs'], role: 'custom' });
    render(<UsersPage api={api} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Mở khóa' }));
    await waitFor(() => expect(api.updateUser).toHaveBeenCalledWith(target.id, { display_name: 'Test target', capabilities: ['view', 'run_jobs'], is_active: true }, expect.any(AbortSignal)));
  });

  it('resets a password through a separate action and clears it on failure and cancel', async () => {
    const { api } = targetApi(); api.resetPassword = vi.fn().mockRejectedValue(new ManagerApiError(400, 'invalid_password'));
    render(<UsersPage api={api} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Đặt lại mật khẩu' }));
    expect(screen.queryByLabelText('Tên đăng nhập')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Mật khẩu mới')).toHaveAttribute('type', 'password');
    expect(screen.getByLabelText('Mật khẩu mới')).toHaveValue('');
    fireEvent.change(screen.getByLabelText('Mật khẩu mới'), { target: { value: 'Replacement-synthetic' } });
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Đặt lại mật khẩu' }));
    await waitFor(() => expect(api.resetPassword).toHaveBeenCalledWith(7, { new_password: 'Replacement-synthetic' }, expect.any(AbortSignal)));
    expect(await screen.findByRole('alert')).toHaveTextContent('Mật khẩu');
    expect(screen.getByLabelText('Mật khẩu mới')).toHaveValue('');
    fireEvent.click(screen.getByRole('button', { name: 'Hủy' }));
    fireEvent.click(screen.getByRole('button', { name: 'Đặt lại mật khẩu' }));
    expect(screen.getByLabelText('Mật khẩu mới')).toHaveValue('');
    expect(api.updateUser).not.toHaveBeenCalled();
  });

  it('renders technical users read-only', async () => {
    const { api } = targetApi({ username: 'synthetic-owner', role: 'technical', editable: false });
    render(<UsersPage api={api} />);
    const row = await screen.findByRole('row', { name: /synthetic-owner/ });
    expect(within(row).queryByRole('button')).not.toBeInTheDocument();
    expect(within(row).getByText('Chỉ đọc')).toBeVisible();
  });

  it('shows inherited grants checked and locked while normal preset grants stay editable', async () => {
    const { api } = targetApi({ capabilities: ['view', 'run_jobs'], inherited_capabilities: ['run_jobs'], role: 'custom' });
    render(<UsersPage api={api} />); await edit();
    const inherited = screen.getByRole('checkbox', { name: /run_jobs/ });
    expect(inherited).toBeChecked(); expect(inherited).toBeDisabled();
    expect(screen.getByText('Kế thừa · đã khóa')).toBeVisible();
    expect(screen.getByText('Synthetic test inheritance description')).toBeVisible();
    expect(screen.getByRole('checkbox', { name: /^view/ })).not.toBeDisabled();
    fireEvent.change(screen.getByLabelText('Vai trò'), { target: { value: 'viewer' } });
    expect(inherited).toBeChecked();
    fireEvent.click(screen.getByRole('button', { name: 'Lưu tài khoản' }));
    await waitFor(() => expect(api.updateUser).toHaveBeenCalledWith(7, { display_name: 'Test target', capabilities: ['view', 'run_jobs'], is_active: true }, expect.any(AbortSignal)));
  });

  it('requires view for actions without silently granting it during editing', async () => {
    const { api } = targetApi({ capabilities: ['view', 'run_jobs'], role: 'custom' });
    render(<UsersPage api={api} />); await edit();
    fireEvent.click(screen.getByRole('checkbox', { name: /^view/ }));
    expect(screen.getByRole('checkbox', { name: /^view/ })).not.toBeChecked();
    expect(screen.getByRole('checkbox', { name: /run_jobs/ })).toBeChecked();
    expect(screen.getByRole('button', { name: 'Lưu tài khoản' })).toBeDisabled();
    expect(screen.getByText(/Các quyền thao tác yêu cầu/)).toBeVisible();
    fireEvent.click(screen.getByRole('checkbox', { name: /run_jobs/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Lưu tài khoản' }));
    await waitFor(() => expect(api.updateUser).toHaveBeenCalledWith(7, { display_name: 'Test target', capabilities: [], is_active: true }, expect.any(AbortSignal)));
  });

  it.each([
    ['username_exists', /Tên đăng nhập đã tồn tại/], ['self_lock', /tài khoản đang sử dụng/], ['last_admin', /quản trị viên cuối cùng/],
  ])('presents a fixed %s error without source values', async (code, message) => {
    const { api } = targetApi();
    if (code === 'username_exists') api.createUser = vi.fn().mockRejectedValue(new ManagerApiError(409, code));
    else api.updateUser = vi.fn().mockRejectedValue(new ManagerApiError(409, code));
    render(<UsersPage api={api} />);
    if (code === 'username_exists') await create(); else await edit();
    fireEvent.click(screen.getByRole('button', { name: 'Lưu tài khoản' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(message);
    if (code === 'username_exists') expect(screen.getByLabelText('Mật khẩu ban đầu')).toHaveValue('');
  });

  it('clears a canceled initial password and uses a fixed fallback for unknown failures', async () => {
    const { api } = targetApi(); api.createUser = vi.fn().mockRejectedValue(new Error('private source diagnostic'));
    render(<UsersPage api={api} />); await create();
    fireEvent.click(screen.getByRole('button', { name: 'Hủy' }));
    expect(api.createUser).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Tạo tài khoản' }));
    expect(screen.getByLabelText('Mật khẩu ban đầu')).toHaveValue('');
    fireEvent.change(screen.getByLabelText('Tên đăng nhập'), { target: { value: 'another-synthetic' } });
    fireEvent.change(screen.getByLabelText('Mật khẩu ban đầu'), { target: { value: 'Synthetic-only' } });
    fireEvent.click(screen.getByRole('button', { name: 'Lưu tài khoản' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Không thể lưu thay đổi');
    expect(screen.queryByText(/private source diagnostic/)).not.toBeInTheDocument();
  });

  it('offers a retry after a list failure and renders the real empty result', async () => {
    const { api } = targetApi(); api.listUsers = vi.fn().mockRejectedValueOnce(new Error('network'))
      .mockResolvedValueOnce({ results: [], count: 0, page: 1, page_size: 50 });
    render(<UsersPage api={api} />);
    expect(await screen.findByRole('alert')).toHaveTextContent('Không thể tải');
    fireEvent.click(screen.getByRole('button', { name: 'Tải lại danh sách' }));
    expect(await screen.findByText('Không tìm thấy tài khoản.')).toBeVisible();
    expect(screen.queryByText('synthetic-target')).not.toBeInTheDocument();
  });

  it('discards an older search response', async () => {
    const { api } = targetApi(); let finish!: (value: UsersDTO) => void;
    api.listUsers = vi.fn().mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }))
      .mockResolvedValueOnce({ results: [], count: 0, page: 1, page_size: 50 });
    render(<UsersPage api={api} />);
    fireEvent.change(screen.getByLabelText('Tìm tài khoản'), { target: { value: 'new search' } });
    fireEvent.submit(screen.getByRole('search'));
    await screen.findByText('Không tìm thấy tài khoản.');
    await act(async () => { finish({ results: [userSession('admin').user!], count: 1, page: 1, page_size: 50 }); });
    expect(screen.queryByText('synthetic')).not.toBeInTheDocument();
  });

  it('drops cached data and mutation controls when a write returns 403', async () => {
    const { api } = targetApi(); api.updateUser = vi.fn().mockRejectedValue(new ManagerApiError(403));
    render(<UsersPage api={api} />); await edit();
    fireEvent.click(screen.getByRole('button', { name: 'Lưu tài khoản' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('không có quyền');
    expect(screen.queryByText('synthetic-target')).not.toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Tạo tài khoản' })).not.toBeInTheDocument();
  });

  it('does not refresh authority or expose a late mutation after unmount', async () => {
    const { api, target } = targetApi(); let finish!: (value: UserDTO) => void;
    api.updateUser = vi.fn().mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
    const refresh = vi.fn(async () => undefined); const view = render(<UsersPage api={api} onAuthorityChanged={refresh} />);
    await edit(); fireEvent.click(screen.getByRole('button', { name: 'Lưu tài khoản' }));
    const signal = vi.mocked(api.updateUser).mock.calls[0]![2]!;
    view.unmount(); expect(signal.aborted).toBe(true);
    await act(async () => { finish(target); });
    expect(refresh).not.toHaveBeenCalled();
  });
});

describe('account administration authority in the real shell', () => {
  it.each(['viewer', 'operator'] as const)('%s has no account administration', async (role) => {
    const api = signedInApiFixture(role); render(<ManagerApp api={api} />);
    await screen.findByText('17');
    expect(screen.queryByRole('button', { name: 'Tài khoản & quyền' })).not.toBeInTheDocument();
    expect(api.listUsers).not.toHaveBeenCalled();
    expect(api.createUser).not.toHaveBeenCalled();
  });

  it('reloads current permissions after a write and leaves accounts if manage_users was removed', async () => {
    const { api } = targetApi(); api.session = vi.fn().mockResolvedValueOnce(userSession('admin')).mockResolvedValue(userSession('viewer'));
    render(<ManagerApp api={api} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Tài khoản & quyền' }));
    await edit(); fireEvent.click(screen.getByRole('button', { name: 'Lưu tài khoản' }));
    await waitFor(() => expect(api.session).toHaveBeenCalledTimes(2));
    await screen.findByText('17');
    expect(screen.queryByRole('button', { name: 'Tài khoản & quyền' })).not.toBeInTheDocument();
    expect(screen.queryByText('synthetic-target')).not.toBeInTheDocument();
  });

  it('preserves allowed account navigation across refresh and keeps the account API stable on shell renders', async () => {
    const { api } = targetApi(); render(<ManagerApp api={api} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Tài khoản & quyền' }));
    await screen.findByText('synthetic-target');
    fireEvent.click(screen.getByRole('button', { name: 'Chuyển giao diện sáng' }));
    fireEvent.click(screen.getByRole('button', { name: /Menu tài khoản/ }));
    expect(api.listUsers).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole('button', { name: /Menu tài khoản/ }));
    await edit(); fireEvent.click(screen.getByRole('button', { name: 'Lưu tài khoản' }));
    await waitFor(() => expect(api.session).toHaveBeenCalledTimes(2));
    expect(await screen.findByText('synthetic-target')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Tài khoản & quyền' })).toHaveAttribute('aria-current', 'page');
    expect(api.listUsers).toHaveBeenCalledTimes(2);
  });

  it.each([401, 403])('account list %s wins over visible navigation', async (status) => {
    const { api } = targetApi(); api.listUsers = vi.fn().mockRejectedValue(new ManagerApiError(status));
    render(<ManagerApp api={api} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Tài khoản & quyền' }));
    if (status === 401) {
      expect(await screen.findByRole('heading', { name: 'Đăng nhập Manager' })).toBeVisible();
      expect(screen.queryByText('17')).not.toBeInTheDocument();
    } else {
      expect(await screen.findByRole('alert')).toHaveTextContent('không có quyền');
      expect(screen.queryByRole('button', { name: 'Đăng nhập' })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Tạo tài khoản' })).not.toBeInTheDocument();
      await waitFor(() => expect(api.session).toHaveBeenCalledTimes(2));
      expect(api.listUsers).toHaveBeenCalledTimes(1);
    }
  });

  it('coalesces simultaneous permission failures into one authority read', async () => {
    const { api } = targetApi(); let finish!: (value: ReturnType<typeof userSession>) => void;
    api.session = vi.fn().mockResolvedValueOnce(userSession('admin'))
      .mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
    api.listUsers = vi.fn().mockRejectedValue(new ManagerApiError(403));
    api.permissions = vi.fn().mockRejectedValue(new ManagerApiError(403));
    render(<ManagerApp api={api} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Tài khoản & quyền' }));
    await screen.findByRole('alert');
    expect(api.session).toHaveBeenCalledTimes(2);
    await act(async () => { finish(userSession('admin')); });
    expect(screen.queryByRole('button', { name: 'Đăng nhập' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Tạo tài khoản' })).not.toBeInTheDocument();
  });

  it.each([401, 403])('ignores an old account request %s after another user is accepted', async (status) => {
    const { api } = targetApi(); let reject!: (failure: unknown) => void;
    const next = userSession('viewer'); next.user = { ...next.user!, id: 84, username: 'new-user', display_name: 'New user' };
    api.session = vi.fn().mockResolvedValueOnce(userSession('admin')).mockResolvedValue(next);
    api.listUsers = vi.fn().mockImplementation(() => new Promise((_, fail) => { reject = fail; }));
    render(<ManagerApp api={api} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Tài khoản & quyền' }));
    await waitFor(() => expect(api.listUsers).toHaveBeenCalledTimes(1));
    act(() => { window.dispatchEvent(new Event('pageshow')); });
    await screen.findByRole('button', { name: 'Menu tài khoản New user' });
    await act(async () => { reject(new ManagerApiError(status)); });
    expect(screen.getByRole('button', { name: 'Menu tài khoản New user' })).toBeVisible();
    expect(api.session).toHaveBeenCalledTimes(2);
    expect(screen.queryByRole('button', { name: 'Đăng nhập' })).not.toBeInTheDocument();
  });

  it('discards old-user list and password state after logout and another login', async () => {
    const { api, target } = targetApi(); let finish!: (value: UsersDTO) => void;
    api.listUsers = vi.fn().mockResolvedValueOnce({ results: [target], count: 1, page: 1, page_size: 50 })
      .mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }));
    api.login = vi.fn().mockResolvedValue(userSession('viewer'));
    render(<ManagerApp api={api} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Tài khoản & quyền' }));
    await create();
    fireEvent.click(screen.getByRole('button', { name: 'Hủy' }));
    fireEvent.change(screen.getByLabelText('Tìm tài khoản'), { target: { value: 'pending' } });
    fireEvent.submit(screen.getByRole('search'));
    fireEvent.click(screen.getByRole('button', { name: /Menu tài khoản/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Đăng xuất' }));
    await screen.findByRole('heading', { name: 'Đăng nhập Manager' });
    fireEvent.change(screen.getByLabelText('Tên đăng nhập'), { target: { value: 'new-user' } });
    fireEvent.change(screen.getByLabelText('Mật khẩu'), { target: { value: 'test-only' } });
    fireEvent.click(screen.getByRole('button', { name: 'Đăng nhập' }));
    await screen.findByText('17');
    await act(async () => { finish({ results: [target], count: 1, page: 1, page_size: 50 }); });
    expect(screen.queryByText('synthetic-target')).not.toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Mật khẩu ban đầu')).not.toBeInTheDocument();
  });

  it('does not refresh a new user from an old successful account mutation', async () => {
    const { api, target } = targetApi(); let finish!: (value: UserDTO) => void;
    api.updateUser = vi.fn().mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
    api.login = vi.fn().mockResolvedValue(userSession('viewer'));
    render(<ManagerApp api={api} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Tài khoản & quyền' }));
    await edit(); fireEvent.click(screen.getByRole('button', { name: 'Lưu tài khoản' }));
    fireEvent.click(screen.getByRole('button', { name: 'Hủy' }));
    fireEvent.click(screen.getByRole('button', { name: /Menu tài khoản/ })); fireEvent.click(screen.getByRole('button', { name: 'Đăng xuất' }));
    await screen.findByRole('heading', { name: 'Đăng nhập Manager' });
    fireEvent.change(screen.getByLabelText('Tên đăng nhập'), { target: { value: 'new-user' } });
    fireEvent.change(screen.getByLabelText('Mật khẩu'), { target: { value: 'synthetic-only' } });
    fireEvent.click(screen.getByRole('button', { name: 'Đăng nhập' }));
    await screen.findByText('17');
    const reads = vi.mocked(api.session).mock.calls.length;
    await act(async () => { finish(target); });
    expect(api.session).toHaveBeenCalledTimes(reads);
    expect(screen.queryByText('synthetic-target')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Tạo tài khoản' })).not.toBeInTheDocument();
  });
});
