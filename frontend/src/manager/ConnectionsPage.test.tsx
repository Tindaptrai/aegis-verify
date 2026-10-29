import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { ConnectionsPage } from './ConnectionsPage';
import { ConnectionsApiError } from './connectionsApi';
import { connectionsFixture, sourceId, syntheticSource, tested } from './connections-test-fixtures';

async function fill() {
  fireEvent.click(await screen.findByRole('button', { name: 'Thêm Wazuh' }));
  for (const [label, value] of [['Tên nguồn', 'Synthetic source'], ['Môi trường', 'synthetic'], ['HTTPS Indexer', 'https://indexer.example:9200'], ['Index đã review', 'reviewed-alerts-*'], ['Tài khoản Indexer', 'synthetic-reader'], ['Mật khẩu Indexer', 'synthetic-test-secret']]) {
    fireEvent.change(screen.getByLabelText(label!), { target: { value } });
  }
  const file = new File(['synthetic public CA'], 'public-ca.pem', { type: 'text/plain' });
  Object.defineProperty(file, 'text', { value: async () => 'synthetic public CA' });
  fireEvent.change(screen.getByLabelText('Public CA PEM'), { target: { files: [file] } });
  await screen.findByText('Public CA đã nạp trong bộ nhớ.');
  // Trust changes require the user to supply the password again.
  fireEvent.change(screen.getByLabelText('Mật khẩu Indexer'), { target: { value: 'synthetic-test-secret' } });
}
async function probe() { fireEvent.click(screen.getByRole('button', { name: 'Kiểm tra kết nối' })); await screen.findByText('Truy vấn thành công'); }
describe('Connections workspace', () => {
  it('does not request source data without manage_connections', async () => {
    const api = connectionsFixture(); render(<ConnectionsPage api={api} canManage={false} csrfToken="csrf" onAuthorityError={vi.fn()} onGuide={vi.fn()} />);
    expect(screen.queryByRole('button', { name: 'Thêm Wazuh' })).not.toBeInTheDocument(); expect(api.list).not.toHaveBeenCalled();
  });
  it('tests, confirms frozen public summary, saves and explicitly prepares candidate without activation', async () => {
    const api = connectionsFixture(); const storage = vi.spyOn(Storage.prototype, 'setItem');
    api.list = vi.fn().mockResolvedValueOnce({ results: [], count: 0, page: 1, page_size: 50, candidate_id: null })
      .mockResolvedValueOnce({ results: [syntheticSource], count: 1, page: 1, page_size: 50, candidate_id: null })
      .mockResolvedValue({ results: [{ ...syntheticSource, status: 'candidate' }], count: 1, page: 1, page_size: 50, candidate_id: sourceId });
    render(<ConnectionsPage api={api} canManage csrfToken="csrf" onAuthorityError={vi.fn()} onGuide={vi.fn()} />);
    await fill(); await probe();
    expect(screen.queryByRole('button', { name: 'Lưu nguồn' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Xác nhận snapshot' }));
    expect(screen.getByText('a'.repeat(64))).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Lưu nguồn' }));
    await screen.findByText('Nguồn mới đã lưu — máy vẫn dùng nguồn cũ.');
    expect(screen.queryByLabelText('Mật khẩu Indexer')).not.toBeInTheDocument();
    fireEvent.click(await screen.findByRole('button', { name: 'Chuẩn bị nguồn Synthetic source v1' }));
    await waitFor(() => expect(api.prepare).toHaveBeenCalledWith(sourceId, null, 'csrf', expect.any(AbortSignal)));
    expect(await screen.findByText('Đã chọn, chưa kích hoạt')).toBeVisible();
    expect(screen.getByText(/Worker: waiting_configuration/)).not.toBeVisible();
    expect(storage).not.toHaveBeenCalled(); storage.mockRestore();
  });
  it.each(['edit', 'cancel', 'csrf', 'permission', 'unmount'] as const)('a late probe cannot resurrect draft after %s', async (action) => {
    const api = connectionsFixture(); let finish!: (value: ReturnType<typeof tested>) => void;
    api.test = vi.fn(() => new Promise<ReturnType<typeof tested>>((resolve) => { finish = resolve; }));
    const props = { api, canManage: true, csrfToken: 'csrf', onAuthorityError: vi.fn(), onGuide: vi.fn() };
    const view = render(<ConnectionsPage {...props} />); await fill(); fireEvent.click(screen.getByRole('button', { name: 'Kiểm tra kết nối' }));
    if (action === 'edit') fireEvent.change(screen.getByLabelText('Tên nguồn'), { target: { value: 'Changed' } });
    if (action === 'cancel') fireEvent.click(screen.getByRole('button', { name: 'Đóng thiết lập' }));
    if (action === 'csrf') view.rerender(<ConnectionsPage {...props} csrfToken="rotated" />);
    if (action === 'permission') view.rerender(<ConnectionsPage {...props} canManage={false} />);
    if (action === 'unmount') view.unmount();
    await act(async () => { finish(tested()); });
    expect(screen.queryByText('Truy vấn thành công')).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Lưu nguồn' })).not.toBeInTheDocument();
  });
  it('editing a tested field invalidates confirmation; closing clears password', async () => {
    render(<ConnectionsPage api={connectionsFixture()} canManage csrfToken="csrf" onAuthorityError={vi.fn()} onGuide={vi.fn()} />); await fill(); await probe();
    fireEvent.change(screen.getByLabelText('HTTPS Indexer'), { target: { value: 'https://changed.example' } });
    expect(screen.getByLabelText('Mật khẩu Indexer')).toHaveValue('');
    expect(screen.queryByText('Truy vấn thành công')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Đóng thiết lập' })); fireEvent.click(screen.getByRole('button', { name: 'Thêm Wazuh' }));
    expect(screen.getByLabelText('Mật khẩu Indexer')).toHaveValue('');
  });
  it('requires a newly entered password whenever public CA changes', async () => {
    render(<ConnectionsPage api={connectionsFixture()} canManage csrfToken="csrf" onAuthorityError={vi.fn()} onGuide={vi.fn()} />); await fill();
    const file = new File(['new synthetic public CA'], 'rotated.pem'); Object.defineProperty(file, 'text', { value: async () => 'new synthetic public CA' });
    fireEvent.change(screen.getByLabelText('Public CA PEM'), { target: { files: [file] } });
    await waitFor(() => expect(screen.getByLabelText('Mật khẩu Indexer')).toHaveValue(''));
    expect(screen.getByRole('button', { name: 'Kiểm tra kết nối' })).toBeDisabled();
  });
  it('moves keyboard focus into setup and returns focus when it closes', async () => {
    render(<ConnectionsPage api={connectionsFixture()} canManage csrfToken="csrf" onAuthorityError={vi.fn()} onGuide={vi.fn()} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Thêm Wazuh' }));
    expect(screen.getByLabelText('Tên nguồn')).toHaveFocus();
    fireEvent.click(screen.getByRole('button', { name: 'Đóng thiết lập' }));
    expect(screen.getByRole('button', { name: 'Thêm Wazuh' })).toHaveFocus();
  });
  it.each(['edit', 'csrf', 'cancel', 'unmount'] as const)('does not present a late save after %s', async (action) => {
    const api = connectionsFixture(); let finish!: (value: typeof syntheticSource) => void;
    api.save = vi.fn(() => new Promise<typeof syntheticSource>((resolve) => { finish = resolve; }));
    const props = { api, canManage: true, csrfToken: 'csrf', onAuthorityError: vi.fn(), onGuide: vi.fn() };
    const view = render(<ConnectionsPage {...props} />); await fill(); await probe();
    fireEvent.click(screen.getByRole('button', { name: 'Xác nhận snapshot' })); fireEvent.click(screen.getByRole('button', { name: 'Lưu nguồn' }));
    if (action === 'edit') fireEvent.change(screen.getByLabelText('Tên nguồn'), { target: { value: 'Changed' } });
    if (action === 'csrf') view.rerender(<ConnectionsPage {...props} csrfToken="rotated" />);
    if (action === 'cancel') fireEvent.click(screen.getByRole('button', { name: 'Đóng thiết lập' }));
    if (action === 'unmount') view.unmount();
    await act(async () => { finish(syntheticSource); });
    expect(screen.queryByText('Nguồn mới đã lưu — máy vẫn dùng nguồn cũ.')).not.toBeInTheDocument();
  });
  it('keeps an idempotency key on ambiguous save failure and uses it on retry', async () => {
    const api = connectionsFixture(); api.save = vi.fn().mockRejectedValueOnce(new Error('lost reply')).mockResolvedValueOnce(syntheticSource);
    render(<ConnectionsPage api={api} canManage csrfToken="csrf" onAuthorityError={vi.fn()} onGuide={vi.fn()} />); await fill(); await probe();
    fireEvent.click(screen.getByRole('button', { name: 'Xác nhận snapshot' })); fireEvent.click(screen.getByRole('button', { name: 'Lưu nguồn' }));
    await screen.findByRole('alert'); fireEvent.click(screen.getByRole('button', { name: 'Lưu nguồn' }));
    await screen.findByText('Nguồn mới đã lưu — máy vẫn dùng nguồn cũ.');
    expect(vi.mocked(api.save).mock.calls[0]?.slice(0, 3)).toEqual(vi.mocked(api.save).mock.calls[1]?.slice(0, 3));
  });
  it('reconciles an already issued save whose committed response arrives after expiry', async () => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] });
    const api = connectionsFixture(); let finish!: (value: typeof syntheticSource) => void;
    api.save = vi.fn(() => new Promise<typeof syntheticSource>((resolve) => { finish = resolve; }));
    api.list = vi.fn().mockResolvedValueOnce({ results: [], count: 0, page: 1, page_size: 50, candidate_id: null })
      .mockResolvedValue({ results: [syntheticSource], count: 1, page: 1, page_size: 50, candidate_id: null });
    const view = render(<ConnectionsPage api={api} canManage csrfToken="csrf" onAuthorityError={vi.fn()} onGuide={vi.fn()} />);
    try {
      await fill(); await probe(); fireEvent.click(screen.getByRole('button', { name: 'Xác nhận snapshot' }));
      fireEvent.click(screen.getByRole('button', { name: 'Lưu nguồn' }));
      const issued = vi.mocked(api.save).mock.calls[0]!;
      act(() => { vi.advanceTimersByTime(301000); });
      expect(issued[3]?.aborted).toBe(false);
      await act(async () => { finish(syntheticSource); });
      expect(await screen.findByText('Nguồn mới đã lưu — máy vẫn dùng nguồn cũ.')).toBeVisible();
      expect(await screen.findByRole('heading', { name: 'Synthetic source v1' })).toBeVisible();
      expect(api.save).toHaveBeenCalledTimes(1); expect(api.list).toHaveBeenCalledTimes(2);
      expect(screen.queryByLabelText('Mật khẩu Indexer')).not.toBeInTheDocument();
    } finally { view.unmount(); vi.useRealTimers(); }
  });
  it.each(['before', 'after'] as const)('retries the original issued save pair when a response becomes ambiguous %s expiry', async (when) => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] });
    const api = connectionsFixture(); let reject!: (failure: unknown) => void;
    api.save = vi.fn().mockImplementationOnce(() => new Promise<typeof syntheticSource>((_, fail) => { reject = fail; })).mockResolvedValueOnce(syntheticSource);
    const view = render(<ConnectionsPage api={api} canManage csrfToken="csrf" onAuthorityError={vi.fn()} onGuide={vi.fn()} />);
    try {
      await fill(); await probe(); fireEvent.click(screen.getByRole('button', { name: 'Xác nhận snapshot' }));
      fireEvent.click(screen.getByRole('button', { name: 'Lưu nguồn' }));
      const issued = vi.mocked(api.save).mock.calls[0]!;
      if (when === 'before') await act(async () => { reject(new Error('synthetic lost committed response')); });
      act(() => { vi.advanceTimersByTime(301000); });
      if (when === 'after') await act(async () => { reject(new Error('synthetic lost committed response')); });
      expect(screen.getByRole('button', { name: 'Lưu nguồn' })).toBeEnabled();
      expect(screen.getByRole('button', { name: 'Kiểm tra kết nối' })).toBeDisabled();
      expect(screen.queryByText('Kiểm tra hết hạn. Cần kiểm tra lại trước khi lưu.')).not.toBeInTheDocument();
      fireEvent.click(screen.getByRole('button', { name: 'Lưu nguồn' }));
      expect(await screen.findByText('Nguồn mới đã lưu — máy vẫn dùng nguồn cũ.')).toBeVisible();
      expect(vi.mocked(api.save).mock.calls[1]?.slice(0, 3)).toEqual(issued.slice(0, 3));
      expect(api.save).toHaveBeenCalledTimes(2); expect(api.test).toHaveBeenCalledTimes(1);
    } finally { view.unmount(); vi.useRealTimers(); }
  });
  it('clears an ambiguous save only after an authoritative draft-expired replay denial', async () => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] });
    const api = connectionsFixture();
    api.save = vi.fn().mockRejectedValueOnce(new Error('synthetic lost reply')).mockRejectedValueOnce(new ConnectionsApiError(409, 'draft_expired'));
    const view = render(<ConnectionsPage api={api} canManage csrfToken="csrf" onAuthorityError={vi.fn()} onGuide={vi.fn()} />);
    try {
      await fill(); await probe(); fireEvent.click(screen.getByRole('button', { name: 'Xác nhận snapshot' }));
      await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Lưu nguồn' })); });
      const issued = vi.mocked(api.save).mock.calls[0]!;
      act(() => { vi.advanceTimersByTime(301000); });
      await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Lưu nguồn' })); });
      expect(vi.mocked(api.save).mock.calls[1]?.slice(0, 3)).toEqual(issued.slice(0, 3));
      expect(screen.getByRole('alert')).toHaveTextContent('draft_expired');
      expect(screen.queryByRole('button', { name: 'Lưu nguồn' })).not.toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Kiểm tra kết nối' })).toBeEnabled();
    } finally { view.unmount(); vi.useRealTimers(); }
  });
  it('blocks an unissued confirmed draft when its fake-clock expiry passes', async () => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] });
    const api = connectionsFixture();
    const view = render(<ConnectionsPage api={api} canManage csrfToken="csrf" onAuthorityError={vi.fn()} onGuide={vi.fn()} />);
    try {
      await fill(); await probe(); fireEvent.click(screen.getByRole('button', { name: 'Xác nhận snapshot' }));
      act(() => { vi.advanceTimersByTime(301000); });
      expect(screen.queryByRole('button', { name: 'Lưu nguồn' })).not.toBeInTheDocument();
      expect(screen.getByRole('alert')).toHaveTextContent('Kiểm tra hết hạn'); expect(api.save).not.toHaveBeenCalled();
    } finally { view.unmount(); vi.useRealTimers(); }
  });
  it('expires a tested snapshot and prevents saving it', async () => {
    const api = connectionsFixture(); api.test = vi.fn(async () => { const soon = tested(); soon.expires_at = new Date(Date.now() + 500).toISOString(); return soon; });
    render(<ConnectionsPage api={api} canManage csrfToken="csrf" onAuthorityError={vi.fn()} onGuide={vi.fn()} />); await fill(); await probe();
    await waitFor(() => expect(screen.queryByText('Truy vấn thành công')).not.toBeInTheDocument(), { timeout: 2000 });
    expect(screen.queryByRole('button', { name: 'Lưu nguồn' })).not.toBeInTheDocument(); expect(api.save).not.toHaveBeenCalled();
  });
  it('ignores a stale denial after edit instead of clearing current authority', async () => {
    const api = connectionsFixture(); const authority = vi.fn(); let reject!: (failure: unknown) => void;
    api.test = vi.fn(() => new Promise<ReturnType<typeof tested>>((_, fail) => { reject = fail; }));
    render(<ConnectionsPage api={api} canManage csrfToken="csrf" onAuthorityError={authority} onGuide={vi.fn()} />); await fill();
    fireEvent.click(screen.getByRole('button', { name: 'Kiểm tra kết nối' })); fireEvent.change(screen.getByLabelText('Tên nguồn'), { target: { value: 'Changed' } });
    await act(async () => { reject(new ConnectionsApiError(401)); });
    expect(authority).not.toHaveBeenCalled(); expect(screen.getByLabelText('Tên nguồn')).toHaveValue('Changed');
  });
  it('shows fixed-code guidance and refreshes authority on denial', async () => {
    const api = connectionsFixture(); const guide = vi.fn(); const authority = vi.fn();
    api.test = vi.fn().mockRejectedValueOnce(new ConnectionsApiError(409, 'tls_failed')).mockRejectedValueOnce(new ConnectionsApiError(403, 'permission_denied'));
    render(<ConnectionsPage api={api} canManage csrfToken="csrf" onAuthorityError={authority} onGuide={guide} />); await fill();
    fireEvent.click(screen.getByRole('button', { name: 'Kiểm tra kết nối' })); await screen.findByText(/tls_failed/);
    fireEvent.click(screen.getByRole('button', { name: 'Hướng dẫn xử lý' })); expect(guide).toHaveBeenCalledWith('ca');
    fireEvent.click(screen.getByRole('button', { name: 'Kiểm tra kết nối' })); await waitFor(() => expect(authority).toHaveBeenCalledWith(403));
    expect(screen.queryByLabelText('Mật khẩu Indexer')).not.toBeInTheDocument();
  });
  it('rejects oversized CA before reading it and never renders private keys', async () => {
    render(<ConnectionsPage api={connectionsFixture()} canManage csrfToken="csrf" onAuthorityError={vi.fn()} onGuide={vi.fn()} />); await fill();
    const file = new File(['x'.repeat(65537)], 'oversized.pem'); const read = vi.fn(); Object.defineProperty(file, 'text', { value: read });
    fireEvent.change(screen.getByLabelText('Public CA PEM'), { target: { files: [file] } });
    expect(read).not.toHaveBeenCalled(); expect(await screen.findByRole('alert')).toHaveTextContent('64 KiB');
    const key = new File(['-----BEGIN PRIVATE KEY-----secret'], 'key.pem'); Object.defineProperty(key, 'text', { value: async () => '-----BEGIN PRIVATE KEY-----secret' });
    fireEvent.change(screen.getByLabelText('Public CA PEM'), { target: { files: [key] } });
    expect(await screen.findByRole('alert')).toHaveTextContent('public CA'); expect(screen.queryByText(/BEGIN PRIVATE/)).not.toBeInTheDocument();
  });
  it('offers new version only for latest managed source; legacy remains readonly', async () => {
    const api = connectionsFixture(); api.list = vi.fn().mockResolvedValue({ results: [syntheticSource, { ...syntheticSource, id: '12345678-1234-4234-8234-123456789abd', kind: 'legacy', status: 'legacy', worker_state: 'legacy', environment_id: null }], count: 2, page: 1, page_size: 50, candidate_id: null });
    render(<ConnectionsPage api={api} canManage csrfToken="csrf" onAuthorityError={vi.fn()} onGuide={vi.fn()} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Tạo phiên bản mới Synthetic source v1' }));
    expect(screen.getByLabelText('Mật khẩu Indexer')).toHaveValue(''); expect(screen.getByLabelText('Tài khoản Indexer')).toHaveValue('');
    expect(screen.getByText(/Legacy — chỉ đọc/)).toBeVisible();
  });
});
