import { useEffect, useRef, useState } from 'react';
import { ManagerApiError, type ManagerApi } from './api';
import type { DeviceV2DTO, DevicesV2DTO } from './types';
import { blockingLabels, type ProviderDTO, type ExecutionDeviceDTO, type PreviewDTO, type JobDTO, type RunLabel, type ApproveInput, type BindingInput } from './executionTypes';
import { ExecutionPreview } from './ExecutionPreview';
import { ExecutionBindingEditor } from './ExecutionBindingEditor';
import { ExecutionJobStatus } from './ExecutionJobStatus';
import { deviceStatusLabels } from './DeviceInventory';

// Compare the complete public frozen summary, independent of JSON key order.
function summaryIdentity(value: unknown): string {
  const ordered = (v: unknown): unknown => v && typeof v === 'object' && !Array.isArray(v)
    ? Object.entries(v).sort(([a], [b]) => a.localeCompare(b)).map(([key, child]) => [key, ordered(child)]) : v;
  return JSON.stringify(ordered(value));
}

function message(failure: unknown) {
  if (failure instanceof ManagerApiError) {
    if (failure.status === 401) return 'Phiên đã kết thúc. Vui lòng đăng nhập lại.';
    if (failure.status === 403) return 'Bạn không có quyền thực hiện thao tác này.';
    if (failure.status === 409) return 'Snapshot hoặc trạng thái đã thay đổi. Cần xem trước mới.';
    if (failure.status === 503) return 'Thực thi chưa khả dụng. Kiểm tra readiness và worker.';
    if (failure.code === 'invalid_request') return 'Yêu cầu không hợp lệ. Kiểm tra các giá trị đã review.';
  }
  return 'Không thể hoàn tất yêu cầu. Vui lòng thử lại.';
}
export function boundProvider(providers: ProviderDTO[], meta: ExecutionDeviceDTO | undefined) { return meta ? providers.find((p) => p.provider_id === meta.provider_id && p.release_id === meta.release_id && p.release_sha256 === meta.release_sha256) : undefined; }
export function ExecutionPage({ api, canRun, canManage }: { api: ManagerApi; canRun: boolean; canManage: boolean }) {
  const [inventory, setInventory] = useState<DevicesV2DTO | null>(null); const [providers, setProviders] = useState<ProviderDTO[]>([]); const [metadata, setMetadata] = useState<Record<string, ExecutionDeviceDTO>>({});
  const [page, setPage] = useState(1); const [revision, setRevision] = useState(0); const [loading, setLoading] = useState(true); const [error, setError] = useState(''); const [denied, setDenied] = useState(false);
  const [selected, setSelected] = useState(''); const [label, setLabel] = useState<RunLabel>('A'); const [preview, setPreview] = useState<PreviewDTO | null>(null); const [approvalKey, setApprovalKey] = useState('');
  const [editing, setEditing] = useState<ExecutionDeviceDTO | null>(null); const [job, setJob] = useState<JobDTO | null>(null); const [busy, setBusy] = useState(false); const [now, setNow] = useState(Date.now());
  const [pollRevision, setPollRevision] = useState(0); const jobRead = useRef<AbortController | null>(null);
  const mounted = useRef(false); const mutation = useRef<AbortController | null>(null); const reads = useRef<AbortController | null>(null); const deniedRef = useRef(false);
  const approvalPending = useRef<AbortController | null>(null);
  function invalidatePreview() { mutation.current?.abort(); mutation.current = null; approvalPending.current = null; setBusy(false); setPreview(null); setApprovalKey(''); setEditing(null); }
  function fail(failure: unknown) {
    if (failure instanceof ManagerApiError && [401, 403].includes(failure.status)) { deniedRef.current = true; setDenied(true); reads.current?.abort(); invalidatePreview(); setInventory(null); setMetadata({}); setJob(null); }
    setError(message(failure));
  }
  useEffect(() => { mounted.current = true; const timer = window.setInterval(() => setNow(Date.now()), 1000); return () => { mounted.current = false; mutation.current?.abort(); reads.current?.abort(); window.clearInterval(timer); }; }, []);
  useEffect(() => { invalidatePreview(); }, [canRun, canManage]);
  useEffect(() => {
    const controller = new AbortController(); reads.current = controller; let timer: number | undefined;
    const current = () => mounted.current && !controller.signal.aborted && !deniedRef.current;
    async function load() {
      if (!current()) return; setLoading(true);
      try {
        const [devices, available] = await Promise.all([api.listDevices({ page, scope: 'managed' }, controller.signal), api.executionProviders(controller.signal)]);
        const facts = await Promise.allSettled(devices.results.map((device) => api.executionDevice(device.id, controller.signal)));
        if (!current()) return;
        const next: Record<string, ExecutionDeviceDTO> = {}; let partial = false;
        facts.forEach((fact, i) => { if (fact.status === 'fulfilled' && fact.value.device_id === devices.results[i]?.id) next[fact.value.device_id] = fact.value; else { partial = true; if (fact.status === 'rejected' && fact.reason instanceof ManagerApiError && [401, 403].includes(fact.reason.status)) throw fact.reason; } });
        setInventory(devices); setProviders(available.providers); setMetadata(next); if (partial) setError('Một số readiness chưa khả dụng. Máy đó không thể chọn.');
      } catch (failure) { if (current()) { setInventory(null); setMetadata({}); fail(failure); } }
      finally { if (current()) { setLoading(false); timer = window.setTimeout(() => void load(), 15000); } }
    }
    setInventory(null); setMetadata({}); void load(); return () => { controller.abort(); window.clearTimeout(timer); };
  }, [api, page, revision]);
  const target = inventory?.results.find((d) => d.id === selected); const meta = metadata[selected]; const provider = boundProvider(providers, meta);
  function eligible(device: DeviceV2DTO) { const fact = metadata[device.id]; return device.connection_kind === 'paired_presence' && device.os === 'windows' && device.archived_at === null && fact?.ready === true && fact.capability === 'installed_supported' && fact.blocking_codes.length === 0 && fact.binding_id !== null && fact.binding_revision !== null && fact.wazuh_connection_id !== null && fact.wazuh_agent_id !== null && fact.checked_at !== null && fact.readiness_expires_at !== null && Date.parse(fact.readiness_expires_at) > now && !!boundProvider(providers, fact); }
  const jobHoldsAdmission = job !== null && !['evaluated', 'empty', 'reconciled'].includes(job.collection_state);
  const allowed = !jobHoldsAdmission && !!target && eligible(target) && !!provider && (label !== 'Rehearsal' || provider.allow_rehearsal);
  useEffect(() => {
    // Admission itself makes readiness busy. Keep the matching approval response
    // alive; explicit target/config/authority changes still call invalidatePreview.
    if (!preview || approvalPending.current) return;
    const s = preview.summary;
    if (!allowed || s.device_id !== selected || s.binding_revision !== meta?.binding_revision || s.release_id !== meta?.release_id || s.release_sha256 !== meta?.release_sha256 || s.wazuh_connection_id !== meta?.wazuh_connection_id || s.wazuh_agent_id !== meta?.wazuh_agent_id || s.parameters.run_label !== label) invalidatePreview();
  }, [allowed, selected, meta, label, preview, busy]);
  async function write<T>(action: (signal: AbortSignal) => Promise<T>, success: (result: T) => void, kind: 'approval' | 'other' = 'other') {
    if (!mounted.current || deniedRef.current || mutation.current) return;
    const controller = new AbortController(); mutation.current = controller; setBusy(true); setError('');
    if (kind === 'approval') approvalPending.current = controller;
    const current = () => mounted.current && !controller.signal.aborted && mutation.current === controller;
    try { const result = await action(controller.signal); if (current()) success(result); }
    catch (failure) { if (current()) { if (failure instanceof ManagerApiError && failure.status === 409) { setPreview(null); setApprovalKey(''); setEditing(null); } fail(failure); } }
    finally { if (approvalPending.current === controller) approvalPending.current = null; if (current()) { mutation.current = null; setBusy(false); } }
  }
  function requestPreview() {
    if (!allowed || !canRun || !target || !meta?.binding_revision || !provider) return;
    const input = { device_id: target.id, provider_id: provider.provider_id, binding_revision: meta.binding_revision, run_label: label, rule_revision: label === 'C' ? 'behavioral' as const : 'baseline' as const };
    void write((signal) => api.previewExecution(input, signal), (result) => {
      const s = result.summary;
      if (s.device_id !== target.id || s.environment_id !== target.environment_id || s.binding_id !== meta.binding_id || s.binding_revision !== meta.binding_revision || s.release_id !== provider.release_id || s.release_sha256 !== provider.release_sha256 || s.provider_id !== provider.provider_id || s.parameters.run_label !== label || s.parameters.rule_revision !== input.rule_revision || s.wazuh_connection_id !== meta.wazuh_connection_id || s.wazuh_agent_id !== meta.wazuh_agent_id || s.timeout_seconds !== provider.timeout_seconds) { setError('Snapshot không khớp lựa chọn. Cần xem trước mới.'); return; }
      setPreview(result); setApprovalKey(crypto.randomUUID());
    });
  }
  function approve(input: ApproveInput) { if (!preview || !canRun || !allowed || Date.parse(preview.expires_at) - Date.now() < 30000) return; void write((signal) => api.approveExecution(input, signal), (result) => { if (summaryIdentity(result.summary) !== summaryIdentity(preview.summary)) { setError('Không thể xác nhận tác vụ. Cần kiểm tra trạng thái server.'); return; } setJob(result); setPreview(null); setApprovalKey(''); }, 'approval'); }
  useEffect(() => {
    if (!job || denied) return; const controller = new AbortController(); jobRead.current = controller; let timer: number | undefined; const jobId = job.job_id; const frozenSummary = summaryIdentity(job.summary);
    async function poll() { try { const result = await api.executionJob(jobId, controller.signal); if (!controller.signal.aborted) { if (result.job_id !== jobId || summaryIdentity(result.summary) !== frozenSummary) throw new Error('Unexpected job'); setJob(result); } } catch (failure) { if (!controller.signal.aborted) fail(failure); } finally { if (!controller.signal.aborted && !deniedRef.current) timer = window.setTimeout(() => void poll(), 5000); } }
    timer = window.setTimeout(() => void poll(), 5000); return () => { controller.abort(); window.clearTimeout(timer); };
  }, [api, job?.job_id, denied, pollRevision]);
  function saveBinding(input: BindingInput) { if (!canManage || !editing) return; void write((signal) => api.setExecutionBinding(editing.device_id, input, signal), (result) => { if (result.device_id !== editing.device_id) { setError('Không thể xác nhận binding. Tải lại trước khi tiếp tục.'); return; } setEditing(null); setSelected(''); setRevision((r) => r + 1); }); }
  return <>
    <div className="page-heading"><p className="eyebrow">THỰC THI ĐÃ REVIEW</p><h1>Tác vụ</h1><p>Một máy Windows, một tác vụ đang hoạt động. Online chỉ xác nhận liên hệ; readiness do server xác nhận riêng.</p></div>
    {error && !preview && !editing && <p role="alert" className="manager-alert">{error}</p>}{loading && <p role="status">Đang tải máy và readiness…</p>}
    <section className="panel panel-body execution-selection"><h2>Máy đích</h2><button disabled={loading || denied || busy} onClick={() => { invalidatePreview(); setError(''); setRevision((r) => r + 1); }}>Tải lại readiness</button>
      {inventory?.results.length === 0 && <p>Không có máy trong phạm vi này.</p>}{inventory?.results.map((d) => { const fact = metadata[d.id]; const supported = d.os === 'windows' && d.connection_kind === 'paired_presence'; return <article key={d.id} className="execution-target"><label><input type="radio" name="execution-target" checked={selected === d.id} disabled={!eligible(d) || !canRun || denied} onChange={() => { invalidatePreview(); setSelected(d.id); }} />{d.hostname ?? d.id}</label><span>{deviceStatusLabels[d.status]}</span><span>{!supported ? 'Không hỗ trợ thực thi · Linux/legacy chỉ hiện diện' : fact?.ready && eligible(d) ? 'Sẵn sàng' : fact?.capability === 'upgrade_required' ? 'Agent cần nâng cấp' : 'Chưa sẵn sàng'}</span>{fact?.blocking_codes.map((code) => <p key={code}>{blockingLabels[code]}</p>)}{!fact && <p>Chưa có readiness được xác minh.</p>}{fact && !boundProvider(providers, fact) && <p>Chưa có release đã review khớp binding.</p>}{fact?.checked_at && <small>Kiểm tra: {fact.checked_at} · Hết hạn: {fact.readiness_expires_at ?? 'Chưa ghi nhận'}</small>}{canManage && supported && fact && !denied && <button disabled={busy} onClick={() => { invalidatePreview(); setError(''); setEditing(fact); }}>Thiết lập thực thi</button>}</article>; })}
      {inventory && <div className="device-actions"><button disabled={page <= 1 || busy || denied} onClick={() => { invalidatePreview(); setSelected(''); setPage((p) => p - 1); }}>Trang trước</button><span>Trang {page} · {inventory.count} máy</span><button disabled={page * inventory.page_size >= inventory.count || busy || denied} onClick={() => { invalidatePreview(); setSelected(''); setPage((p) => p + 1); }}>Trang sau</button></div>}
    </section>
    <section className="panel panel-body execution-parameters"><h2>Kịch bản đã review</h2>{provider ? <><p>{provider.scenario_id} · {provider.provider_id}</p><p>RunnerRelease #{provider.release_id} · {provider.runner_id} {provider.runner_version}</p><p>Timeout đã review: {provider.timeout_seconds} giây · mặc định 300 giây</p></> : <p>Chọn máy có binding khớp RunnerRelease đã review. Catalog ZIP không cấp khả năng thực thi.</p>}<label htmlFor="execution-label">Nhãn lượt chạy</label><select id="execution-label" value={label} disabled={!canRun || denied} onChange={(e) => { invalidatePreview(); setLabel(e.target.value as RunLabel); }}>{['A', 'B', 'C', ...(provider?.allow_rehearsal ? ['Rehearsal'] : [])].map((value) => <option key={value}>{value}</option>)}</select><p>Rule revision: {label === 'C' ? 'behavioral' : 'baseline'} · A/B dùng baseline, C dùng behavioral. Không cài rule từ giao diện này.</p><button className="primary" disabled={!allowed || !canRun || busy || denied} onClick={requestPreview}>Xem trước</button>{!canRun && <p>Cần quyền Chạy tác vụ để phê duyệt.</p>}</section>
    {preview && canRun && !denied && <ExecutionPreview preview={preview} targetName={target?.hostname ?? preview.summary.device_id} idempotencyKey={approvalKey} now={now} busy={busy} error={error} onApprove={approve} onClose={invalidatePreview} />}
    {editing && canManage && !denied && <ExecutionBindingEditor device={editing} providers={providers} busy={busy} error={error} onSave={saveBinding} onClose={invalidatePreview} />}
    {job && !denied && <ExecutionJobStatus job={job} busy={busy} onCancel={canRun ? () => void write((signal) => api.cancelExecution(job.job_id, signal), (result) => { if (result.job_id !== job.job_id || summaryIdentity(result.summary) !== summaryIdentity(job.summary)) { setError('Không thể xác nhận trạng thái hủy.'); return; } jobRead.current?.abort(); setPollRevision((r) => r + 1); setJob(result); }) : undefined} />}
  </>;
}
