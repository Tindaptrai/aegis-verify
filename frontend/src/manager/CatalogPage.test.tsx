import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { ManagerApp } from './ManagerApp';
import { createManagerApi, ManagerApiError } from './api';
import { signedInApiFixture, userSession } from './test-fixtures';
import { catalogDetail, catalogHash, catalogId, catalogList } from './catalog-test-fixtures';

function fixture(role: 'admin' | 'viewer' = 'admin') {
  return { ...signedInApiFixture(role),
    listCatalog: vi.fn(async () => catalogList), catalogPackage: vi.fn(async () => catalogDetail),
    catalogFile: vi.fn(async (_id: string, path: string) => ({ path, text: '<img src=x onerror="alert(1)"><script>unsafe()</script>' })),
    importCatalog: vi.fn(async () => catalogDetail),
    publishCatalog: vi.fn(async () => ({ ...catalogDetail, status: 'published' as const, published_at: '2026-10-25T01:00:00Z', published_by: 'synthetic' })),
    unpublishCatalog: vi.fn(async () => ({ ...catalogDetail, status: 'unpublished' as const })),
  };
}
async function openCatalog() { fireEvent.click(await screen.findByRole('button', { name: 'Kịch bản' })); await screen.findByRole('heading', { name: 'Kịch bản' }); }
async function openDetail() { fireEvent.click(await screen.findByRole('button', { name: 'Xem gói' })); return screen.findByRole('dialog', { name: 'Chi tiết gói' }); }

describe('real Catalog navigation and review', () => {
  it('loads real rows, filters/searches from page one, paginates and never offers execution', async () => {
    const api = fixture(); api.listCatalog.mockResolvedValue({ ...catalogList, count: 51 });
    render(<ManagerApp api={api} />); await openCatalog();
    expect(await screen.findByText('Synthetic catalog scenario')).toBeVisible();
    expect(screen.getByText('SCN-900')).toBeVisible(); expect(screen.getByText(catalogHash)).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Trang sau' }));
    await waitFor(() => expect(api.listCatalog).toHaveBeenLastCalledWith({ page: 2, q: '', status: '' }, expect.any(AbortSignal)));
    fireEvent.change(screen.getByLabelText('Trạng thái gói'), { target: { value: 'published' } });
    await waitFor(() => expect(api.listCatalog).toHaveBeenLastCalledWith({ page: 1, q: '', status: 'published' }, expect.any(AbortSignal)));
    fireEvent.change(screen.getByLabelText('Tìm kịch bản'), { target: { value: 'SCN-900' } }); fireEvent.click(screen.getByRole('button', { name: 'Tìm kiếm' }));
    await waitFor(() => expect(api.listCatalog).toHaveBeenLastCalledWith({ page: 1, q: 'SCN-900', status: 'published' }, expect.any(AbortSignal)));
    expect(screen.queryByRole('button', { name: /Run|Chạy/ })).not.toBeInTheDocument();
  });
  it('shows honest empty and retryable errors with no sample rows', async () => {
    const api = fixture(); api.listCatalog.mockRejectedValueOnce(new Error('private diagnostic')).mockResolvedValue({ ...catalogList, results: [], count: 0 });
    render(<ManagerApp api={api} />); await openCatalog();
    expect(await screen.findByRole('alert')).toHaveTextContent('Không thể tải');
    expect(screen.queryByText('private diagnostic')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Làm mới' }));
    expect(await screen.findByText('Không tìm thấy gói kịch bản.')).toBeVisible();
    expect(screen.queryByText('SCN-900')).not.toBeInTheDocument();
  });
  it('hides import and publication from viewers while allowing private review as escaped text', async () => {
    const api = fixture('viewer'); const { container } = render(<ManagerApp api={api} />); await openCatalog();
    expect(screen.queryByRole('button', { name: 'Nhập ZIP' })).not.toBeInTheDocument();
    const dialog = await openDetail();
    expect(within(dialog).getByText(catalogHash)).toBeVisible();
    fireEvent.click(within(dialog).getByRole('button', { name: 'README.md' }));
    expect(await within(dialog).findByText('<img src=x onerror="alert(1)"><script>unsafe()</script>')).toBeVisible();
    expect(container.querySelector('script')).toBeNull(); expect(container.querySelector('img[src="x"]')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Xuất bản' })).not.toBeInTheDocument();
    expect(within(dialog).getByText(/không xác nhận.*an toàn/i)).toBeVisible();
  });
  it('imports a selected ZIP, reviews returned draft and reports bounded validation failure', async () => {
    const api = fixture(); api.importCatalog.mockRejectedValueOnce(new ManagerApiError(400, 'invalid_package'));
    render(<ManagerApp api={api} />); await openCatalog(); fireEvent.click(screen.getByRole('button', { name: 'Nhập ZIP' }));
    const file = new File(['synthetic'], 'test.zip', { type: 'application/zip' });
    fireEvent.change(screen.getByLabelText('Gói ZIP'), { target: { files: [file] } }); fireEvent.click(screen.getByRole('button', { name: 'Kiểm tra và nhập' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('không hợp lệ');
    fireEvent.click(screen.getByRole('button', { name: 'Kiểm tra và nhập' }));
    expect(await screen.findByRole('dialog', { name: 'Chi tiết gói' })).toBeVisible();
    expect(api.importCatalog).toHaveBeenCalledWith(file, expect.any(AbortSignal));
  });
  it('requires the exact full hash to confirm publication and preserves history on unpublish', async () => {
    const api = fixture(); render(<ManagerApp api={api} />); await openCatalog(); const dialog = await openDetail();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Xuất bản' }));
    expect(within(dialog).getByText(/SCN-900.*0.1.0/)).toBeVisible();
    const confirm = within(dialog).getByRole('button', { name: 'Xác nhận xuất bản' }); expect(confirm).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText('Nhập SHA-256 để xác nhận'), { target: { value: ` ${catalogHash}` } }); expect(confirm).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText('Nhập SHA-256 để xác nhận'), { target: { value: catalogHash } }); fireEvent.click(confirm);
    await waitFor(() => expect(api.publishCatalog).toHaveBeenCalledWith(catalogId, catalogHash, expect.any(AbortSignal)));
    fireEvent.click(await within(dialog).findByRole('button', { name: 'Ngừng xuất bản' }));
    expect(within(dialog).getByText(/giữ lại lịch sử/i)).toBeVisible();
    fireEvent.change(within(dialog).getByLabelText('Nhập SHA-256 để xác nhận'), { target: { value: catalogHash } }); fireEvent.click(within(dialog).getByRole('button', { name: 'Xác nhận ngừng xuất bản' }));
    await waitFor(() => expect(api.unpublishCatalog).toHaveBeenCalledWith(catalogId, catalogHash, expect.any(AbortSignal)));
  });
  it('refreshes fresh 403 grants and removes denied import/publication actions', async () => {
    const api = fixture(); api.importCatalog.mockRejectedValueOnce(new ManagerApiError(403));
    api.session = vi.fn().mockResolvedValueOnce(userSession('admin')).mockResolvedValue(userSession('viewer'));
    render(<ManagerApp api={api} />); await openCatalog(); fireEvent.click(screen.getByRole('button', { name: 'Nhập ZIP' }));
    fireEvent.change(screen.getByLabelText('Gói ZIP'), { target: { files: [new File([''], 'a.zip')] } }); fireEvent.click(screen.getByRole('button', { name: 'Kiểm tra và nhập' }));
    await waitFor(() => expect(api.session).toHaveBeenCalledTimes(2));
    expect(screen.queryByRole('button', { name: 'Nhập ZIP' })).not.toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
  it('ignores stale list results after filters change', async () => {
    const api = fixture(); let finish!: (value: typeof catalogList) => void;
    api.listCatalog.mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; })).mockResolvedValue({ ...catalogList, results: [], count: 0 });
    render(<ManagerApp api={api} />); await openCatalog();
    fireEvent.change(screen.getByLabelText('Trạng thái gói'), { target: { value: 'published' } });
    await screen.findByText('Không tìm thấy gói kịch bản.');
    await act(async () => finish(catalogList));
    expect(screen.queryByText('Synthetic catalog scenario')).not.toBeInTheDocument();
  });
  it('displays the fixed validation report without retaining uploaded diagnostics', async () => {
    const api = fixture();
    const wire = createManagerApi(vi.fn<typeof fetch>().mockResolvedValue(Response.json({ error: { code: 'invalid_metadata' }, validation: { valid: false, codes: ['invalid_metadata', 'profile_mismatch'] } }, { status: 400 })));
    api.importCatalog = vi.fn().mockImplementation((file, signal) => wire.importCatalog(file, signal));
    render(<ManagerApp api={api} />); await openCatalog(); fireEvent.click(screen.getByRole('button', { name: 'Nhập ZIP' }));
    fireEvent.change(screen.getByLabelText('Gói ZIP'), { target: { files: [new File([''], 'a.zip')] } }); fireEvent.click(screen.getByRole('button', { name: 'Kiểm tra và nhập' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('profile_mismatch');
  });
  it('keeps an import locked until settlement after the drawer closes and ignores its late result', async () => {
    const api = fixture(); let finish!: (value: typeof catalogDetail) => void;
    api.importCatalog.mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }));
    render(<ManagerApp api={api} />); await openCatalog(); fireEvent.click(screen.getByRole('button', { name: 'Nhập ZIP' }));
    fireEvent.change(screen.getByLabelText('Gói ZIP'), { target: { files: [new File([''], 'a.zip')] } }); fireEvent.click(screen.getByRole('button', { name: 'Kiểm tra và nhập' }));
    fireEvent.click(screen.getByRole('button', { name: 'Kiểm tra và nhập' })); expect(api.importCatalog).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole('button', { name: 'Đóng gói' }));
    expect(screen.getByRole('button', { name: 'Nhập ZIP' })).toBeDisabled();
    await act(async () => finish(catalogDetail));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Nhập ZIP' })).toBeEnabled();
  });
  it.each([401, 403])('handles real HTTP %s through the catalog facade with fresh authority', async (status) => {
    let sessions = 0;
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async (url) => {
      const path = String(url);
      if (path.endsWith('/auth/session')) { sessions++; return Response.json(sessions > 1 ? status === 401 ? { ...userSession('viewer'), authenticated: false, user: null } : userSession('viewer') : userSession('admin')); }
      if (path.endsWith('/overview')) return Response.json({ registered_devices: 0, recorded_jobs: 0, recorded_releases: 0 });
      return Response.json({ error: { code: status === 401 ? 'unauthenticated' : 'permission_denied' } }, { status });
    });
    render(<ManagerApp api={createManagerApi(fetcher)} />); await openCatalog();
    if (status === 401) expect(await screen.findByRole('heading', { name: 'Đăng nhập Manager' })).toBeVisible();
    else { await waitFor(() => expect(sessions).toBe(2)); expect(screen.queryByRole('button', { name: 'Nhập ZIP' })).not.toBeInTheDocument(); }
  });
  it.each(['success', 'forbidden'] as const)('ignores late private detail %s after a newer workspace is restored', async (outcome) => {
    const api = fixture(); let finish!: (value: typeof catalogDetail) => void; let fail!: (error: Error) => void;
    api.catalogPackage.mockImplementationOnce(() => new Promise((resolve, reject) => { finish = resolve; fail = reject; }));
    render(<ManagerApp api={api} />); await openCatalog(); await openDetail();
    act(() => { window.dispatchEvent(new Event('pageshow')); }); await screen.findByText('17');
    await act(async () => { if (outcome === 'success') finish(catalogDetail); else fail(new ManagerApiError(403)); });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(api.session).toHaveBeenCalledTimes(2);
  });
  it('aborts stale private file reads after another inventory selection', async () => {
    const api = fixture(); let finish!: (value: { path: string; text: string }) => void;
    api.catalogFile.mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; })).mockResolvedValue({ path: 'payload/demo.ps1', text: 'current script' });
    render(<ManagerApp api={api} />); await openCatalog(); const dialog = await openDetail();
    fireEvent.click(within(dialog).getByRole('button', { name: 'README.md' }));
    fireEvent.click(within(dialog).getByRole('button', { name: 'payload/demo.ps1' }));
    expect(await within(dialog).findByText('current script')).toBeVisible();
    await act(async () => finish({ path: 'README.md', text: 'stale private readme' }));
    expect(screen.queryByText('stale private readme')).not.toBeInTheDocument();
  });
});
