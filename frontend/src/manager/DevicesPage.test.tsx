import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ManagerApp } from './ManagerApp';
import { ManagerApiError, createManagerApi } from './api';
import type { DeviceDTO, DevicesDTO, PairingCodeDTO } from './types';
import { anonymousSession, signedInApiFixture, userSession } from './test-fixtures';
const id = '00000000-0000-4000-8000-000000000001', codeId = '00000000-0000-4000-8000-000000000002', secret = 'a'.repeat(64);
const device: DeviceDTO = { id, hostname: '<script>synthetic-host</script>', environment_id: 'training', wazuh_agent_id: null, connection_kind: 'paired_presence', os: 'linux', architecture: 'x64', agent_version: '0.1.0', generation: 1, status: 'offline', last_heartbeat_at: null, certificate_expires_at: '2026-11-24T00:00:00Z', execution_supported: false };
const list = (results: DeviceDTO[] = [device], page = 1, count = results.length): DevicesDTO => ({ results, page, count, page_size: 50 });
function fixture(role: 'admin' | 'viewer' = 'admin') {
  return Object.assign(signedInApiFixture(role), {
    listDevices: vi.fn(async (_query?: { page?: number; search?: string }, _signal?: AbortSignal) => list()),
    createPairingCode: vi.fn(async (_input: { environment_id: string }, _signal?: AbortSignal) => ({ id: codeId, code: secret, environment_id: 'training', expires_at: new Date(Date.now() + 600000).toISOString() })),
    revokePairingCode: vi.fn(async (_id: string, _signal?: AbortSignal) => undefined), revokeDevice: vi.fn(async (_id: string, _signal?: AbortSignal) => undefined),
  });
}
async function openDevices(api = fixture()) { render(<ManagerApp api={api} />); fireEvent.click(await screen.findByRole('button', { name: 'Máy' })); await screen.findByRole('heading', { name: 'Danh sách máy' }); return api; }
async function mint() { fireEvent.click(screen.getByRole('button', { name: 'Thêm máy' })); fireEvent.change(screen.getByLabelText('Môi trường'), { target: { value: 'training' } }); fireEvent.click(screen.getByRole('button', { name: 'Tạo mã ghép nối' })); await screen.findByText(secret); }
afterEach(() => vi.useRealTimers());
describe('Devices API wire boundary', () => {
  it('uses exact paths, search, CSRF and cancellation', async () => {
    const seen: { path: string; init: RequestInit | undefined }[] = [];
    const api = createManagerApi(async (url, init) => { seen.push({ path: String(url), init }); const path = String(url); if (path.endsWith('/auth/session')) return Response.json(anonymousSession); if (path.includes('/devices?')) return Response.json(list()); if (path.endsWith('/pairing-codes')) return Response.json({ id: codeId, code: secret, environment_id: 'training', expires_at: '2026-10-24T01:00:00Z' }, { status: 201 }); return new Response(null, { status: 204 }); });
    const controller = new AbortController(); await api.session();
    expect(await api.listDevices({ page: 2, search: 'host & vm' }, controller.signal)).toEqual(list());
    expect(await api.createPairingCode({ environment_id: 'training' }, controller.signal)).toMatchObject({ code: secret });
    await api.revokePairingCode(codeId, controller.signal); await api.revokeDevice(id, controller.signal);
    expect(seen.slice(1).map((request) => request.path)).toEqual(['/api/v1/devices?page=2&search=host+%26+vm', '/api/v1/pairing-codes', `/api/v1/pairing-codes/${codeId}/revoke`, `/api/v1/devices/${id}/revoke`]);
    expect(seen.slice(1).every(({ init }) => init?.signal === controller.signal && init.credentials === 'same-origin' && init.cache === 'no-store')).toBe(true);
    expect(seen[2]?.init).toMatchObject({ body: '{"environment_id":"training"}', headers: { 'X-CSRFToken': 'synthetic-csrf' } }); expect(seen[3]?.init).toMatchObject({ body: '{}' });
  });
  it.each([
    ['mint wrong status', 'mint', 200, { id: codeId, code: secret, environment_id: 'training', expires_at: '2026-10-24T01:00:00Z' }],
    ['mint bad secret', 'mint', 201, { id: codeId, code: 'bad', environment_id: 'training', expires_at: '2026-10-24T01:00:00Z' }],
    ['mint extra key', 'mint', 201, { id: codeId, code: secret, environment_id: 'training', expires_at: '2026-10-24T01:00:00Z', private: 'unsafe' }],
    ['invalid list', 'list', 200, { ...list(), results: [{ ...device, status: 'ready' }] }],
    ['paired execution', 'list', 200, { ...list(), results: [{ ...device, execution_supported: true }] }],
    ['array status', 'list', 200, { ...list(), results: [{ ...device, status: ['offline'] }] }],
    ['array connection kind', 'list', 200, { ...list(), results: [{ ...device, connection_kind: ['paired_presence'] }] }],
    ['invalid calendar date', 'mint', 201, { id: codeId, code: secret, environment_id: 'training', expires_at: '2026-02-30T00:00:00Z' }],
    ['revoke wrong status', 'revoke', 200, {}],
  ])('rejects %s instead of reporting success', async (_label, operation, status, body) => {
    const api = createManagerApi(async () => Response.json(body, { status: Number(status) }));
    await expect(operation === 'mint' ? api.createPairingCode({ environment_id: 'training' }) : operation === 'list' ? api.listDevices() : api.revokeDevice(id)).rejects.toThrow('Manager request failed');
  });
  it('accepts absent legacy metadata as null and renders an honest fallback', async () => {
    const legacy: DeviceDTO = { ...device, connection_kind: 'legacy_v1', status: 'unknown', hostname: null, os: null, architecture: null, agent_version: null, last_heartbeat_at: null, certificate_expires_at: null };
    const api = fixture('viewer');
    const wire = createManagerApi(async () => Response.json(list([legacy])));
    api.listDevices = vi.fn(wire.listDevices);
    await openDevices(api);
    expect(await screen.findByText('Chưa ghi nhận tên máy')).toBeVisible();
    expect(screen.getByText('Chưa xác định (legacy)')).toBeVisible();
  });
  it('recognizes fixed device_conflict without exposing arbitrary detail', async () => { const api = createManagerApi(async () => Response.json({ error: { code: 'device_conflict', detail: secret } }, { status: 409 })); await expect(api.revokeDevice(id)).rejects.toMatchObject({ status: 409, code: 'device_conflict', message: 'Manager request failed' }); });
});
describe('Devices in real Manager shell', () => {
  it('allows viewer read access and distinguishes legacy unknown from Offline', async () => {
    const api = fixture('viewer'); api.listDevices.mockResolvedValue(list([device, { ...device, id: codeId, hostname: 'legacy-host', connection_kind: 'legacy_v1', status: 'unknown' }])); await openDevices(api);
    expect(await screen.findByText('<script>synthetic-host</script>')).toBeVisible(); expect(screen.getByText('Offline')).toBeVisible(); expect(screen.getByText(/Chưa xác định.*legacy/i)).toBeVisible(); expect(screen.getByText(/Online.*không.*sẵn sàng.*kịch bản/i)).toBeVisible(); expect(screen.queryByRole('button', { name: 'Thêm máy' })).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: /Thu hồi/ })).not.toBeInTheDocument();
  });
  it('shows one-time code and trusted CA command placeholders without putting code in commands or storage', async () => {
    await openDevices(); await mint(); expect(screen.getByText(/không cần đăng nhập.*endpoint/i)).toBeVisible(); expect(screen.getByText(/CA công khai.*tin cậy/i)).toBeVisible();
    const commands = screen.getAllByText(/aegis-agent.*connect/).map((node) => node.textContent).join('\n'); expect(commands).toContain('https://<MANAGER-IP-OR-DNS>'); expect(commands).not.toContain(secret); expect(localStorage.length).toBe(0); expect(window.location.href).not.toContain(secret);
    fireEvent.click(screen.getByRole('button', { name: 'Thu hồi mã đang chờ' })); expect(await screen.findByText('Đã thu hồi mã ghép nối.')).toBeVisible(); expect(screen.queryByText(secret)).not.toBeInTheDocument();
  });
  it('requires confirmation to revoke and renders refreshed terminal server status', async () => { const api = await openDevices(); await screen.findByText('<script>synthetic-host</script>'); fireEvent.click(screen.getByRole('button', { name: 'Thu hồi máy' })); const dialog = screen.getByRole('dialog', { name: 'Thu hồi máy' }); expect(within(dialog).getByText('<script>synthetic-host</script>')).toBeVisible(); api.listDevices.mockResolvedValue(list([{ ...device, status: 'revoked' }])); fireEvent.click(within(dialog).getByRole('button', { name: 'Xác nhận thu hồi' })); expect(await screen.findByText('Đã thu hồi')).toBeVisible(); expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); });
  it.each([400, 409, 503])('shows fixed mint failure for %s', async (status) => { const api = await openDevices(); api.createPairingCode.mockRejectedValue(new ManagerApiError(status, status === 400 ? 'invalid_request' : 'private-source-value')); fireEvent.click(screen.getByRole('button', { name: 'Thêm máy' })); fireEvent.change(screen.getByLabelText('Môi trường'), { target: { value: 'training' } }); fireEvent.click(screen.getByRole('button', { name: 'Tạo mã ghép nối' })); expect(await screen.findByRole('alert')).toHaveTextContent(/Không thể|Môi trường/); expect(screen.queryByText('private-source-value')).not.toBeInTheDocument(); });
  it.each(['close', 'logout', 'navigation'] as const)('clears code on %s', async (action) => { await openDevices(); await mint(); if (action === 'close') fireEvent.click(screen.getByRole('button', { name: 'Đóng ghép nối' })); if (action === 'navigation') fireEvent.click(screen.getByRole('button', { name: 'Tổng quan' })); if (action === 'logout') { fireEvent.click(screen.getByRole('button', { name: /Menu tài khoản/ })); fireEvent.click(screen.getByRole('button', { name: 'Đăng xuất' })); } expect(screen.queryByText(secret)).not.toBeInTheDocument(); expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); });
  it.each(['navigation', 'logout'] as const)('aborts mint and ignores late success after %s', async (action) => {
    const api = await openDevices(); let resolve!: (value: PairingCodeDTO) => void; let signal: AbortSignal | undefined;
    api.createPairingCode.mockImplementation((_input, abort) => { signal = abort; return new Promise((finish) => { resolve = finish; }); });
    fireEvent.click(screen.getByRole('button', { name: 'Thêm máy' })); fireEvent.change(screen.getByLabelText('Môi trường'), { target: { value: 'training' } }); fireEvent.click(screen.getByRole('button', { name: 'Tạo mã ghép nối' }));
    if (action === 'navigation') fireEvent.click(screen.getByRole('button', { name: 'Tổng quan' })); else { fireEvent.click(screen.getByRole('button', { name: /Menu tài khoản/ })); fireEvent.click(screen.getByRole('button', { name: 'Đăng xuất' })); }
    expect(signal?.aborted).toBe(true); await act(async () => { resolve({ id: codeId, code: secret, environment_id: 'training', expires_at: new Date(Date.now() + 600000).toISOString() }); }); expect(screen.queryByText(secret)).not.toBeInTheDocument();
  });
  it('clears code at its deadline', async () => { vi.useFakeTimers(); const api = fixture(); render(<ManagerApp api={api} />); await act(async () => { await Promise.resolve(); }); fireEvent.click(screen.getByRole('button', { name: 'Máy' })); await act(async () => { await Promise.resolve(); }); fireEvent.click(screen.getByRole('button', { name: 'Thêm máy' })); fireEvent.change(screen.getByLabelText('Môi trường'), { target: { value: 'training' } }); fireEvent.click(screen.getByRole('button', { name: 'Tạo mã ghép nối' })); await act(async () => { await Promise.resolve(); }); expect(screen.getByText(secret)).toBeVisible(); await act(async () => { vi.advanceTimersByTime(600001); }); expect(screen.queryByText(secret)).not.toBeInTheDocument(); expect(screen.getByText(/Mã ghép nối đã hết hạn/)).toBeVisible(); });
  it('preserves view on manage_devices demotion but clears secrets and write controls', async () => { const api = await openDevices(); await mint(); api.session = vi.fn().mockResolvedValue(userSession('viewer')); api.revokePairingCode.mockRejectedValue(new ManagerApiError(403, 'permission_denied')); fireEvent.click(screen.getByRole('button', { name: 'Thu hồi mã đang chờ' })); await act(async () => { await Promise.resolve(); }); expect(screen.queryByText(secret)).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Thêm máy' })).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Máy' })).toHaveAttribute('aria-current', 'page'); });
  it('resets pagination on search', async () => { const api = fixture(); api.listDevices.mockImplementation(async (query) => list([{ ...device, hostname: `${query?.page}:${query?.search}` }], query?.page ?? 1, 101)); await openDevices(api); await screen.findByText('1:'); fireEvent.click(screen.getByRole('button', { name: 'Trang sau' })); await screen.findByText('2:'); fireEvent.change(screen.getByLabelText('Tìm máy'), { target: { value: 'host & vm' } }); fireEvent.submit(screen.getByRole('search')); expect(await screen.findByText('1:host & vm')).toBeVisible(); });
  it('does not overlap refresh and ignores a stale authorization failure after navigation', async () => {
    const api = await openDevices(); await screen.findByText('<script>synthetic-host</script>'); vi.useFakeTimers(); let reject!: (failure: unknown) => void; let signal: AbortSignal | undefined; let inflight = 0; let max = 0;
    api.listDevices.mockImplementation((_query, abort) => { signal = abort; inflight++; max = Math.max(max, inflight); return new Promise((_resolve, fail) => { reject = fail; }); }); fireEvent.click(screen.getByRole('button', { name: 'Làm mới' })); await act(async () => { vi.advanceTimersByTime(45000); }); expect(max).toBe(1); expect(screen.getByRole('button', { name: 'Làm mới' })).toBeDisabled(); fireEvent.click(screen.getByRole('button', { name: 'Tổng quan' })); expect(signal?.aborted).toBe(true); await act(async () => { reject(new ManagerApiError(401)); }); expect(screen.getByRole('button', { name: /Menu tài khoản/ })).toBeVisible(); expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
  it('stops refreshing after forbidden list access', async () => { const api = fixture(); api.listDevices.mockRejectedValue(new ManagerApiError(403)); await openDevices(api); expect(await screen.findByRole('alert')).toHaveTextContent(/quyền/); vi.useFakeTimers(); const before = api.listDevices.mock.calls.length; await act(async () => { vi.advanceTimersByTime(60000); }); expect(api.listDevices.mock.calls.length).toBe(before); expect(screen.getByRole('button', { name: 'Làm mới' })).toBeDisabled(); });
});

describe('Devices lifecycle boundaries', () => {
  it.each(['expired', 'revoked'] as const)('accepts legacy %s precedence without implying readiness', async (status) => {
    const wire = createManagerApi(async () => Response.json(list([{ ...device, connection_kind: 'legacy_v1', status }])));
    const api = fixture('viewer'); api.listDevices = vi.fn(wire.listDevices);
    await openDevices(api);
    expect(await screen.findByText(status === 'expired' ? 'Đã hết hạn' : 'Đã thu hồi')).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Thu hồi máy' })).not.toBeInTheDocument();
  });
  it('waits 15 seconds after settlement and never overlaps a slow periodic refresh', async () => {
    vi.useFakeTimers();
    const api = fixture('viewer');
    let finish!: (value: DevicesDTO) => void;
    let signal: AbortSignal | undefined;
    api.listDevices.mockImplementationOnce(async () => list([{ ...device, hostname: 'first-server-state' }]))
      .mockImplementationOnce((_query, abort) => { signal = abort; return new Promise((resolve) => { finish = resolve; }); })
      .mockResolvedValue(list([{ ...device, hostname: 'third-server-state' }]));
    const { unmount } = render(<ManagerApp api={api} />);
    await act(async () => { await Promise.resolve(); });
    fireEvent.click(screen.getByRole('button', { name: 'Máy' }));
    await act(async () => { await Promise.resolve(); });
    expect(screen.getByText('first-server-state')).toBeVisible();
    await act(async () => { vi.advanceTimersByTime(14999); });
    expect(screen.getByRole('button', { name: 'Làm mới' })).toBeEnabled();
    await act(async () => { vi.advanceTimersByTime(1); });
    expect(screen.getByRole('button', { name: 'Làm mới' })).toBeDisabled();
    await act(async () => { vi.advanceTimersByTime(60000); });
    expect(screen.queryByText('third-server-state')).not.toBeInTheDocument();
    await act(async () => { finish(list([{ ...device, hostname: 'second-server-state' }])); });
    expect(screen.getByText('second-server-state')).toBeVisible();
    await act(async () => { vi.advanceTimersByTime(14999); });
    expect(screen.getByText('second-server-state')).toBeVisible();
    await act(async () => { vi.advanceTimersByTime(1); });
    expect(screen.getByText('third-server-state')).toBeVisible();
    unmount(); expect(signal?.aborted).toBe(true);
  });
  it('clears code at absolute session expiry before a late pending revoke returns', async () => {
    vi.useFakeTimers();
    const api = fixture();
    api.session = vi.fn().mockResolvedValue({ ...userSession('admin'), expires_at: Math.floor(Date.now() / 1000) + 10 });
    let finish!: () => void;
    let signal: AbortSignal | undefined;
    api.revokePairingCode.mockImplementation((_id, abort) => { signal = abort; return new Promise((resolve) => { finish = () => resolve(undefined); }); });
    render(<ManagerApp api={api} />); await act(async () => { await Promise.resolve(); });
    fireEvent.click(screen.getByRole('button', { name: 'Máy' })); await act(async () => { await Promise.resolve(); });
    fireEvent.click(screen.getByRole('button', { name: 'Thêm máy' }));
    fireEvent.change(screen.getByLabelText('Môi trường'), { target: { value: 'training' } });
    fireEvent.click(screen.getByRole('button', { name: 'Tạo mã ghép nối' })); await act(async () => { await Promise.resolve(); });
    expect(screen.getByText(secret)).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Thu hồi mã đang chờ' }));
    await act(async () => { vi.advanceTimersByTime(10001); });
    expect(screen.queryByText(secret)).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Đăng nhập Manager' })).toBeVisible();
    expect(signal?.aborted).toBe(true);
    await act(async () => { finish(); });
    expect(screen.queryByText('Đã thu hồi mã ghép nối.')).not.toBeInTheDocument();
  });
  it.each(['success', 'failure'] as const)('discards old search %s after a newer search has rendered', async (outcome) => {
    const api = fixture('viewer');
    let finish!: (value: DevicesDTO) => void; let fail!: (value: unknown) => void; let signal: AbortSignal | undefined;
    api.listDevices.mockImplementationOnce((_query, abort) => { signal = abort; return new Promise((resolve, reject) => { finish = resolve; fail = reject; }); })
      .mockResolvedValue(list([{ ...device, hostname: 'new-query-host' }]));
    await openDevices(api);
    fireEvent.change(screen.getByLabelText('Tìm máy'), { target: { value: 'new-query' } }); fireEvent.submit(screen.getByRole('search'));
    expect(await screen.findByText('new-query-host')).toBeVisible(); expect(signal?.aborted).toBe(true);
    await act(async () => { if (outcome === 'success') finish(list([{ ...device, hostname: 'stale-private-host' }])); else fail(new ManagerApiError(403)); });
    expect(screen.queryByText('stale-private-host')).not.toBeInTheDocument();
    expect(screen.getByText('new-query-host')).toBeVisible(); expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
  it('clears mint on close and prevents a late code from appearing in a reopened dialog', async () => {
    const api = await openDevices(); let finish!: (value: PairingCodeDTO) => void; let signal: AbortSignal | undefined;
    api.createPairingCode.mockImplementation((_input, abort) => { signal = abort; return new Promise((resolve) => { finish = resolve; }); });
    fireEvent.click(screen.getByRole('button', { name: 'Thêm máy' })); fireEvent.change(screen.getByLabelText('Môi trường'), { target: { value: 'training' } }); fireEvent.click(screen.getByRole('button', { name: 'Tạo mã ghép nối' }));
    fireEvent.click(screen.getByRole('button', { name: 'Đóng ghép nối' })); expect(signal?.aborted).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'Thêm máy' }));
    await act(async () => { finish({ id: codeId, code: secret, environment_id: 'training', expires_at: new Date(Date.now() + 600000).toISOString() }); });
    expect(screen.queryByText(secret)).not.toBeInTheDocument(); expect(screen.getByLabelText('Môi trường')).toHaveValue('');
    expect(screen.getByRole('button', { name: 'Tạo mã ghép nối' })).toBeDisabled();
  });
  it('does not show an already expired pairing response', async () => {
    const api = await openDevices(); api.createPairingCode.mockResolvedValue({ id: codeId, code: secret, environment_id: 'training', expires_at: new Date(Date.now() - 1).toISOString() });
    fireEvent.click(screen.getByRole('button', { name: 'Thêm máy' })); fireEvent.change(screen.getByLabelText('Môi trường'), { target: { value: 'training' } }); fireEvent.click(screen.getByRole('button', { name: 'Tạo mã ghép nối' }));
    expect(await screen.findByText(/Mã ghép nối đã hết hạn/)).toBeVisible(); expect(screen.queryByText(secret)).not.toBeInTheDocument();
  });
  it.each([401, 403])('handles real HTTP %s through the guarded facade without leaking a code', async (status) => {
    let reads = 0;
    const wire = createManagerApi(async (url) => {
      const path = String(url);
      if (path.endsWith('/auth/session')) { reads++; return Response.json(status === 403 && reads > 1 ? userSession('viewer') : status === 401 && reads > 1 ? anonymousSession : userSession('admin')); }
      if (path.includes('/devices?')) return Response.json(list());
      if (path.endsWith('/overview')) return Response.json({ registered_devices: 1, recorded_jobs: 0, recorded_releases: 0 });
      return Response.json({ error: { code: status === 401 ? 'unauthenticated' : 'permission_denied', detail: secret } }, { status });
    });
    render(<ManagerApp api={wire} />); fireEvent.click(await screen.findByRole('button', { name: 'Máy' }));
    await screen.findByText('<script>synthetic-host</script>');
    fireEvent.click(screen.getByRole('button', { name: 'Thêm máy' })); fireEvent.change(screen.getByLabelText('Môi trường'), { target: { value: 'training' } }); fireEvent.click(screen.getByRole('button', { name: 'Tạo mã ghép nối' }));
    if (status === 401) expect(await screen.findByRole('heading', { name: 'Đăng nhập Manager' })).toBeVisible();
    else { await act(async () => { await Promise.resolve(); }); expect(screen.getByRole('button', { name: 'Máy' })).toHaveAttribute('aria-current', 'page'); expect(screen.queryByRole('button', { name: 'Thêm máy' })).not.toBeInTheDocument(); }
    expect(screen.queryByText(secret)).not.toBeInTheDocument(); expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
});

describe('Devices authority and confirmation safeguards', () => {
  it('leaves a rejected revoke visible for correction without reporting success', async () => {
    const api = await openDevices(); await screen.findByText('<script>synthetic-host</script>');
    api.revokeDevice.mockRejectedValue(new ManagerApiError(409, 'device_conflict'));
    fireEvent.click(screen.getByRole('button', { name: 'Thu hồi máy' }));
    fireEvent.click(screen.getByRole('button', { name: 'Xác nhận thu hồi' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Máy legacy không thể thu hồi');
    expect(screen.getByRole('dialog', { name: 'Thu hồi máy' })).toBeVisible();
    expect(screen.queryByText('Đã thu hồi máy.')).not.toBeInTheDocument();
    expect(screen.getByText('Offline')).toBeVisible();
  });
  it('clears a pending mint on authority change and ignores its late result', async () => {
    const api = fixture(); let failList!: (failure: unknown) => void; let finishMint!: (value: PairingCodeDTO) => void;
    let mintSignal: AbortSignal | undefined; let listSignal: AbortSignal | undefined;
    api.listDevices.mockImplementation((_query, signal) => { listSignal = signal; return new Promise((_resolve, reject) => { failList = reject; }); });
    api.createPairingCode.mockImplementation((_input, signal) => { mintSignal = signal; return new Promise((resolve) => { finishMint = resolve; }); });
    await openDevices(api);
    fireEvent.click(screen.getByRole('button', { name: 'Thêm máy' })); fireEvent.change(screen.getByLabelText('Môi trường'), { target: { value: 'training' } }); fireEvent.click(screen.getByRole('button', { name: 'Tạo mã ghép nối' }));
    api.session = vi.fn().mockResolvedValue(userSession('viewer')); api.listDevices.mockResolvedValue(list());
    await act(async () => { failList(new ManagerApiError(403)); });
    expect(mintSignal?.aborted).toBe(true); expect(listSignal?.aborted).toBe(true);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    await act(async () => { finishMint({ id: codeId, code: secret, environment_id: 'training', expires_at: new Date(Date.now() + 600000).toISOString() }); });
    expect(screen.queryByText(secret)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Thêm máy' })).not.toBeInTheDocument();
  });
  it('keeps the route unavailable when view is absent', async () => {
    const api = fixture(); api.session = vi.fn().mockResolvedValue({ ...userSession('admin'), user: { ...userSession('admin').user!, capabilities: ['manage_devices'] } });
    render(<ManagerApp api={api} />);
    expect(await screen.findByRole('alert')).toHaveTextContent('không có quyền xem dữ liệu');
    expect(screen.getByRole('button', { name: 'Máy' })).toBeDisabled();
    expect(screen.queryByRole('heading', { name: 'Danh sách máy' })).not.toBeInTheDocument();
  });
  it('does not disclose a code for a different environment', async () => {
    const api = await openDevices(); api.createPairingCode.mockResolvedValue({ id: codeId, code: secret, environment_id: 'unexpected', expires_at: new Date(Date.now() + 600000).toISOString() });
    fireEvent.click(screen.getByRole('button', { name: 'Thêm máy' })); fireEvent.change(screen.getByLabelText('Môi trường'), { target: { value: 'training' } }); fireEvent.click(screen.getByRole('button', { name: 'Tạo mã ghép nối' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Không thể xác nhận môi trường');
    expect(screen.queryByText(secret)).not.toBeInTheDocument();
  });
  it('keeps keyboard focus inside the dialog and clears code on Escape', async () => {
    await openDevices(); await mint();
    const dialog = screen.getByRole('dialog', { name: 'Thêm máy' }); const close = within(dialog).getByRole('button', { name: 'Đóng ghép nối' }); const revoke = within(dialog).getByRole('button', { name: 'Thu hồi mã đang chờ' });
    close.focus(); fireEvent.keyDown(document, { key: 'Tab', shiftKey: true }); expect(revoke).toHaveFocus();
    fireEvent.keyDown(document, { key: 'Tab' }); expect(close).toHaveFocus();
    fireEvent.keyDown(document, { key: 'Escape' }); expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(screen.queryByText(secret)).not.toBeInTheDocument();
  });
});
