import { act, fireEvent, render, screen, within, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { ExecutionPage } from './ExecutionPage';
import { ExecutionJobStatus } from './ExecutionJobStatus';
import { ManagerApp } from './ManagerApp';
import { ManagerApiError } from './api';
import { executionFixture, device, readiness, provider, preview, job, targetId, hash } from './execution-test-fixtures';
import { blockingLabels } from './executionTypes';
import reportFixture from '../../../tests/fixtures/dashboard/after-detected.json';
import { CatalogPage } from './CatalogPage';
import { userSession } from './test-fixtures';

async function openPreview() { fireEvent.click(await screen.findByRole('radio')); fireEvent.click(screen.getByRole('button', { name: 'Xem trước' })); return screen.findByRole('dialog', { name: 'Xem trước tác vụ' }); }
describe('single Windows execution approval', () => {
  it('separates Online and Ready and chooses exactly one native Windows radio', async () => {
    const api = executionFixture(); api.listDevices = vi.fn(async () => ({ results: [device, { ...device, id: '22222222-2222-4222-8222-222222222222', hostname: 'Synthetic second' }, { ...device, id: '33333333-3333-4333-8333-333333333333', hostname: 'Synthetic Linux', os: 'linux' as const }], count: 3, page: 1, page_size: 50 as const }));
    render(<ExecutionPage api={api} canRun canManage />);
    const radios = await screen.findAllByRole('radio'); expect(radios).toHaveLength(3); expect(radios[2]!).toBeDisabled();
    fireEvent.click(radios[0]!); fireEvent.click(radios[1]!); expect(radios.filter((radio) => (radio as HTMLInputElement).checked)).toHaveLength(1);
    expect(screen.getAllByText('Online')).toHaveLength(3); expect(screen.getAllByText('Sẵn sàng')).toHaveLength(2);
  });
  it.each(Object.entries(blockingLabels))('renders blocker %s and disables preview', async (code, label) => {
    const api = executionFixture(); api.executionDevice = vi.fn(async () => ({ ...readiness, ready: false, blocking_codes: [code as keyof typeof blockingLabels] }));
    render(<ExecutionPage api={api} canRun canManage={false} />); expect(await screen.findByText(label)).toBeVisible(); expect(screen.getByRole('radio')).toBeDisabled(); expect(screen.getByRole('button', { name: 'Xem trước' })).toBeDisabled(); expect(screen.queryByText('Thiết lập thực thi')).not.toBeInTheDocument();
  });
  it('matches provider to exact bound release and digest, never the first release', async () => {
    const api = executionFixture(); api.executionProviders = vi.fn(async () => ({ providers: [{ ...provider, release_sha256: 'b'.repeat(64), allow_rehearsal: true }, provider] }));
    render(<ExecutionPage api={api} canRun canManage />); fireEvent.click(await screen.findByRole('radio')); expect(screen.queryByRole('option', { name: 'Rehearsal' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Xem trước' })).toBeEnabled();
  });
  it('shows frozen scope/windows/pins and keeps approval key on retry and double click', async () => {
    const api = executionFixture(); api.approveExecution = vi.fn().mockRejectedValueOnce(new Error('network')).mockResolvedValueOnce(job);
    render(<ExecutionPage api={api} canRun canManage />); const dialog = await openPreview();
    expect(dialog).toHaveTextContent('training'); expect(dialog).toHaveTextContent('300'); expect(dialog).toHaveTextContent('bounded_process_tree'); expect(dialog).toHaveTextContent('unknown'); expect(dialog).toHaveTextContent('9007199254740993');
    fireEvent.click(within(dialog).getByText('Chi tiết kỹ thuật')); expect(dialog).toHaveTextContent(hash);
    fireEvent.click(within(dialog).getByRole('button', { name: 'Xác nhận và chạy' })); await screen.findByRole('alert');
    const confirm = screen.getByRole('button', { name: 'Xác nhận và chạy' }); fireEvent.click(confirm); fireEvent.click(confirm);
    await screen.findByRole('heading', { name: 'Trạng thái tác vụ' }); expect(api.approveExecution).toHaveBeenCalledTimes(2); expect(vi.mocked(api.approveExecution).mock.calls[0]![0]).toEqual(vi.mocked(api.approveExecution).mock.calls[1]![0]);
    expect(vi.mocked(api.approveExecution).mock.calls[0]![0]).toEqual({ preview_id: targetId, preview_sha256: hash, idempotency_key: expect.any(String) });
  });
  it('requires a fresh preview after conflict and invalidates preview when parameters change', async () => {
    const api = executionFixture(); api.approveExecution = vi.fn().mockRejectedValue(new ManagerApiError(409, 'preview_conflict'));
    render(<ExecutionPage api={api} canRun canManage />); await openPreview(); fireEvent.click(screen.getByRole('button', { name: 'Xác nhận và chạy' })); await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(screen.getByRole('alert')).toHaveTextContent('xem trước mới'); fireEvent.click(screen.getByRole('button', { name: 'Xem trước' })); await screen.findByRole('dialog');
    fireEvent.change(screen.getByLabelText('Nhãn lượt chạy'), { target: { value: 'C' } }); expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
  it('keeps successful receipt separate from pending collection and unevaluated result', () => {
    render(<ExecutionJobStatus job={job} />); expect(screen.getByText('Thành công')).toBeVisible(); expect(screen.getByText('Đang chờ')).toBeVisible(); expect(screen.getByText('Chưa đánh giá')).toBeVisible(); expect(screen.queryByText('Detected')).not.toBeInTheDocument(); expect(screen.queryByRole('progressbar')).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: /Stop|Dừng|Hủy/ })).not.toBeInTheDocument();
  });
  it('aborts pending preview on unmount and ignores late success', async () => {
    const api = executionFixture(); let finish!: (value: typeof preview) => void; api.previewExecution = vi.fn().mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
    const view = render(<ExecutionPage api={api} canRun canManage />); fireEvent.click(await screen.findByRole('radio')); fireEvent.click(screen.getByRole('button', { name: 'Xem trước' })); view.unmount();
    expect(vi.mocked(api.previewExecution).mock.calls[0]![1]?.aborted).toBe(true); await act(async () => finish(preview)); expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
  it('shell opens real tasks but logout removes preview and late work', async () => {
    const api = executionFixture(); render(<ManagerApp api={api} />); fireEvent.click(await screen.findByRole('button', { name: 'Tác vụ' })); await openPreview();
    fireEvent.click(screen.getByRole('button', { name: /Menu tài khoản/ })); fireEvent.click(screen.getByRole('button', { name: 'Đăng xuất' })); await screen.findByRole('heading', { name: 'Đăng nhập Manager' }); expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
  it('Catalog shows reviewed release provenance separately from imported ZIPs', async () => {
    const api = executionFixture(); render(<CatalogPage api={api} canImport canPublish />);
    const reviewed = await screen.findByRole('region', { name: 'Adapter đã review' }); expect(reviewed).toHaveTextContent('RunnerRelease #9007199254740993');
    expect(within(reviewed).queryByRole('link')).not.toBeInTheDocument(); expect(screen.getByRole('region', { name: 'Danh mục kịch bản' })).not.toHaveTextContent('RunnerRelease');
  });
  it('offers binding setup to manage_devices without requiring connection management', async () => {
    const api = executionFixture(); const session = userSession('operator'); session.user!.capabilities = ['view', 'manage_devices']; api.session = vi.fn(async () => session);
    render(<ManagerApp api={api} />); fireEvent.click(await screen.findByRole('button', { name: 'Tác vụ' })); fireEvent.click(await screen.findByRole('button', { name: 'Thiết lập thực thi' }));
    const dialog = screen.getByRole('dialog'); fireEvent.change(within(dialog).getByLabelText('Installation profile SHA-256 đã review'), { target: { value: hash } }); fireEvent.change(within(dialog).getByLabelText('Connection revision đã review'), { target: { value: '2' } }); fireEvent.click(within(dialog).getByRole('button', { name: 'Lưu binding đã review' }));
    await waitFor(() => expect(api.setExecutionBinding).toHaveBeenCalledWith(targetId, expect.objectContaining({ runner_release_id: '9007199254740993', expected_revision: 1, wazuh_connection_revision: 2 }), expect.any(AbortSignal)));
  });
  it('loading error retries into empty inventory without synthetic targets', async () => {
    const api = executionFixture(); api.listDevices = vi.fn().mockRejectedValueOnce(new Error('private')).mockResolvedValue({ results: [], count: 0, page: 1, page_size: 50 as const }); render(<ExecutionPage api={api} canRun canManage={false} />);
    expect(screen.getByRole('status')).toHaveTextContent('Đang tải'); await screen.findByRole('alert'); fireEvent.click(screen.getByRole('button', { name: 'Tải lại readiness' })); expect(await screen.findByText('Không có máy trong phạm vi này.')).toBeVisible(); expect(screen.queryByRole('radio')).not.toBeInTheDocument();
  });
  it('restores keyboard focus after Escape closes the preview drawer', async () => {
    const api = executionFixture(); render(<ExecutionPage api={api} canRun canManage />); fireEvent.click(await screen.findByRole('radio')); const trigger = screen.getByRole('button', { name: 'Xem trước' }); trigger.focus(); fireEvent.click(trigger); const dialog = await screen.findByRole('dialog'); expect(dialog).toHaveFocus(); fireEvent.keyDown(document, { key: 'Tab' }); expect(within(dialog).getByRole('button', { name: 'Đóng cửa sổ' })).toHaveFocus(); fireEvent.keyDown(document, { key: 'Escape' }); expect(trigger).toHaveFocus();
  });
  it('keeps Inconclusive canonical report and actual evidence IDs available', () => {
    const report = structuredClone(reportFixture); report.evaluation.final_status = 'Inconclusive';
    render(<ExecutionJobStatus job={{ ...job, collection_state: 'evaluated', evaluation_state: 'evaluated', report }} />);
    expect(screen.getByText('Inconclusive')).toBeVisible(); expect(screen.getByRole('link', { name: 'Xem report và evidence' })).toHaveAttribute('href', `#execution-report-${targetId}`);
    expect(screen.getAllByText(/unknown/).length).toBeGreaterThan(0); fireEvent.click(screen.getByRole('tab', { name: /Timeline/ })); fireEvent.click(screen.getByLabelText('Hiện ID đầy đủ')); expect(screen.getAllByText(report.evaluation.evidence_index[0]!.event_id).length).toBeGreaterThan(0);
  });
  it('blocks approval at under 30s remaining without silently extending server windows', async () => {
    const api = executionFixture(); const expires = new Date(Date.now() + 29000).toISOString().replace(/\.\d{3}Z$/, 'Z'); api.previewExecution = vi.fn(async () => ({ ...preview, expires_at: expires, summary: { ...preview.summary, expires_at: expires } }));
    render(<ExecutionPage api={api} canRun canManage />); const dialog = await openPreview(); expect(within(dialog).getByRole('button', { name: 'Xác nhận và chạy' })).toBeDisabled(); expect(api.approveExecution).not.toHaveBeenCalled();
  });
  it('authority refresh removes preview and aborts pending approval even if it resolves late', async () => {
    const api = executionFixture(); let finish!: (value: typeof job) => void; api.approveExecution = vi.fn().mockImplementation(() => new Promise((resolve) => { finish = resolve; })); render(<ManagerApp api={api} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Tác vụ' })); await openPreview(); fireEvent.click(screen.getByRole('button', { name: 'Xác nhận và chạy' }));
    api.session = vi.fn(async () => userSession('viewer')); act(() => window.dispatchEvent(new Event('pageshow'))); await screen.findByText('17');
    expect(vi.mocked(api.approveExecution).mock.calls[0]![1]?.aborted).toBe(true); await act(async () => finish(job)); expect(screen.queryByRole('heading', { name: 'Trạng thái tác vụ' })).not.toBeInTheDocument(); expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
  it('rejects an approval result that changes the frozen parameters', async () => {
    const api = executionFixture(); api.approveExecution = vi.fn(async () => ({ ...job, summary: { ...job.summary, parameters: { ...job.summary.parameters, run_label: 'B' as const } } })); render(<ExecutionPage api={api} canRun canManage />); await openPreview(); fireEvent.click(screen.getByRole('button', { name: 'Xác nhận và chạy' }));
    await screen.findByRole('alert'); expect(screen.queryByRole('heading', { name: 'Trạng thái tác vụ' })).not.toBeInTheDocument();
  });
  it('permits reviewed Rehearsal and derives C behavioral revision without client windows', async () => {
    const api = executionFixture(); api.executionProviders = vi.fn(async () => ({ providers: [{ ...provider, allow_rehearsal: true }] })); api.previewExecution = vi.fn(async (input) => ({ ...preview, summary: { ...preview.summary, parameters: { ...preview.summary.parameters, run_label: input.run_label, rule_revision: input.rule_revision } } }));
    render(<ExecutionPage api={api} canRun canManage />); fireEvent.click(await screen.findByRole('radio')); expect(screen.getByRole('option', { name: 'Rehearsal' })).toBeInTheDocument(); fireEvent.change(screen.getByLabelText('Nhãn lượt chạy'), { target: { value: 'C' } }); fireEvent.click(screen.getByRole('button', { name: 'Xem trước' })); await screen.findByRole('dialog');
    expect(api.previewExecution).toHaveBeenCalledWith({ device_id: targetId, provider_id: provider.provider_id, binding_revision: 1, run_label: 'C', rule_revision: 'behavioral' }, expect.any(AbortSignal));
  });
  it('new preview receives a new idempotency key after the old drawer closes', async () => {
    const api = executionFixture(); api.approveExecution = vi.fn().mockRejectedValue(new Error('network')); render(<ExecutionPage api={api} canRun canManage />); await openPreview(); fireEvent.click(screen.getByRole('button', { name: 'Xác nhận và chạy' })); await screen.findByRole('alert'); fireEvent.keyDown(document, { key: 'Escape' });
    fireEvent.click(screen.getByRole('button', { name: 'Xem trước' })); await screen.findByRole('dialog'); fireEvent.click(screen.getByRole('button', { name: 'Xác nhận và chạy' })); await screen.findByRole('alert'); const calls = vi.mocked(api.approveExecution).mock.calls; expect(calls[0]![0].idempotency_key).not.toBe(calls[1]![0].idempotency_key);
  });
  it('invalid canonical report stays unavailable without changing the evaluated stage', () => {
    render(<ExecutionJobStatus job={{ ...job, evaluation_state: 'evaluated', collection_state: 'evaluated', report: { private: 'untrusted' } }} />); expect(screen.getByText('Đã đánh giá')).toBeVisible(); expect(screen.queryByRole('link')).not.toBeInTheDocument(); expect(screen.queryByText('untrusted')).not.toBeInTheDocument();
  });
  it('a GET poll begun before cancel cannot restore the old queued state', async () => {
    vi.useFakeTimers();
    try {
      const api = executionFixture(); api.approveExecution = vi.fn(async () => ({ ...job, execution_state: 'queued' as const })); let finish!: (value: typeof job) => void; api.executionJob = vi.fn().mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
      await act(async () => { render(<ExecutionPage api={api} canRun canManage />); });
      await act(async () => { fireEvent.click(screen.getByRole('radio')); }); await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Xem trước' })); }); await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Xác nhận và chạy' })); });
      await act(async () => { await vi.advanceTimersByTimeAsync(5000); }); expect(api.executionJob).toHaveBeenCalledWith(targetId, expect.any(AbortSignal));
      await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Hủy trước khi bắt đầu' })); }); expect(screen.getByText('Đã hủy trước khi bắt đầu')).toBeVisible();
      await act(async () => finish({ ...job, execution_state: 'queued' })); expect(screen.getByText('Đã hủy trước khi bắt đầu')).toBeVisible();
    } finally { vi.useRealTimers(); }
  });
  it('a successful receipt with pending collection does not offer another approval', async () => {
    const api = executionFixture(); render(<ExecutionPage api={api} canRun canManage />); await openPreview(); fireEvent.click(screen.getByRole('button', { name: 'Xác nhận và chạy' })); await screen.findByRole('heading', { name: 'Trạng thái tác vụ' }); expect(screen.getByRole('button', { name: 'Xem trước' })).toBeDisabled();
  });
});
