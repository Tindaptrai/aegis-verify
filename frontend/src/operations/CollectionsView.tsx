import { useEffect, useRef, useState } from 'react';
import { errorMessage, type OperationsClient } from './api';
import { utc, type Bootstrap, type CollectionRequest, type Job } from './contracts';

export function CollectionsView({ client, config, initialJobId = null, onJob = () => {} }: {
  client: OperationsClient; config: Bootstrap; initialJobId?: string | null; onJob?: (id: string) => void;
}) {
  const [agent, setAgent] = useState(config.agent_ids[0] ?? '');
  const [start, setStart] = useState(() => new Date(Date.now() - 900000).toISOString());
  const [end, setEnd] = useState(() => new Date().toISOString());
  const [adaptive, setAdaptive] = useState(true);
  const [pending, setPending] = useState<CollectionRequest | null>(null);
  const [job, setJob] = useState<Job | null>(null);
  const [jobId, setJobId] = useState(initialJobId);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [blocked, setBlocked] = useState(false);
  const [busy, setBusy] = useState(false);
  const mutation = useRef<AbortController | null>(null);
  const confirmButton = useRef<HTMLButtonElement>(null);
  useEffect(() => () => { mutation.current?.abort(); }, []);
  useEffect(() => { if (pending) confirmButton.current?.focus(); }, [pending]);
  useEffect(() => {
    const controller = new AbortController();
    void client.collections(controller.signal).then(data => {
      if (controller.signal.aborted) return;
      // Detail/submission responses may have completed while the initial list was in flight.
      setJobs(current => [...current, ...data.jobs.filter(item => !current.some(j => j.id === item.id))]);
      setBlocked(data.error_code !== null);
      if (data.error_code) setError(errorMessage(new Error(data.error_code)));
    }).catch(e => { if (!controller.signal.aborted) setError(errorMessage(e)); });
    return () => controller.abort();
  }, [client]);
  useEffect(() => {
    if (!jobId) return;
    const controller = new AbortController(); let timer: number | undefined;
    async function poll() {
      try {
        const next = await client.collection(jobId!, controller.signal);
        if (controller.signal.aborted) return;
        setJob(next); setJobs(items => [next, ...items.filter(j => j.id !== next.id)]);
        if (next.state === 'running') timer = window.setTimeout(poll, 2000);
      } catch (e) { if (!controller.signal.aborted) setError(errorMessage(e)); }
    }
    void poll();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [client, jobId]);
  function review() {
    setError(null);
    if (!config.agent_ids.includes(agent) || !utc(start) || !utc(end) || Date.parse(start) >= Date.parse(end) ||
        Date.parse(end) > Date.now() || Date.parse(end) - Date.parse(start) > 86400000) {
      setError('Chọn agent và khoảng UTC hợp lệ: bắt đầu trước kết thúc, tối đa 24 giờ, không ở tương lai.'); return;
    }
    setPending({ agent_id: agent, start, end, adaptive, request_id: crypto.randomUUID() });
  }
  async function submit() {
    if (!pending || mutation.current) return;
    const controller = new AbortController(); mutation.current = controller; setBusy(true); setError(null);
    try {
      const next = await client.submitCollection(pending, controller.signal);
      if (!controller.signal.aborted) {
        setJob(next); setPending(null); setJobs(items => [next, ...items.filter(j => j.id !== next.id)]);
        onJob(next.id);
        setJobId(next.id);
      }
    } catch (e) { if (!controller.signal.aborted) { setPending(null); setError(errorMessage(e)); } }
    finally { mutation.current = null; if (!controller.signal.aborted) setBusy(false); }
  }
  const running = busy || job?.state === 'running' || jobs.some(j => j.state === 'running');
  return <section className="operations-page" aria-labelledby="collections-title">
    <header className="operations-header"><div><p className="eyebrow">OPERATIONS · {config.environment_id}</p><h1 id="collections-title">Collections</h1>
      <p>Thu thập evidence lịch sử. Không chạy scenario và không tự đánh giá detection.</p></div><span className="operations-chip">1 job / lần · không hàng đợi</span></header>
    {error && <p role="alert" className="operations-warning">{error}</p>}
    {!config.capabilities.collection && <p role="status">Collection chưa được cấu hình hoặc lưu trữ đang bị khóa.</p>}
    <div className="operations-grid"><form className="operations-card" onSubmit={e => { e.preventDefault(); review(); }}>
      <h2>Thu thập mới</h2><fieldset disabled={!config.capabilities.collection || blocked || running || pending !== null}>
        <label>Agent<select value={agent} onChange={e => setAgent(e.target.value)}>{config.agent_ids.map(id => <option key={id}>{id}</option>)}</select></label>
        <label>Bắt đầu (UTC)<input value={start} onChange={e => setStart(e.target.value)} spellCheck={false} /></label>
        <label>Kết thúc (UTC)<input value={end} onChange={e => setEnd(e.target.value)} spellCheck={false} /></label>
        <p className="operations-meta">ISO 8601 với Z hoặc +00:00. Tối đa 24 giờ.</p>
        <label className="operations-checkbox"><input type="checkbox" checked={adaptive} onChange={e => setAdaptive(e.target.checked)} />Adaptive — chia nhỏ cửa sổ khi cần</label>
        <button className="button" type="submit">Xem lại yêu cầu</button></fieldset>
      <p className="operations-meta">Agent không active vẫn có thể có dữ liệu lịch sử. Trạng thái máy không quyết định kết quả thu thập.</p>
    </form><div className="operations-card" aria-live="polite"><h2>Job đang xem</h2>{job ? <>
      <p className="operations-chip">{job.state}</p><p>Agent <strong>{job.agent_id}</strong></p><p className="operations-meta">{job.start} → {job.end}</p>
      <p className="operations-meta">Job ID: {job.id}</p>
      {job.state === 'running' && <p role="status">Đang thu thập… Giữ backend chạy; rời trang không hủy job.</p>}
      {job.result && <><h3>{job.result.record_count} bản ghi · truy vấn hoàn tất</h3><p>Collection assurance: unknown. Chưa phải kết luận bảo mật.</p>
        {job.result.cleanup_failed && <p className="operations-warning">Dọn phiên truy vấn chưa thành công; cần operator kiểm tra.</p>}</>}
      {job.error_code && <p role="alert">{errorMessage(new Error(job.error_code))}</p>}
    </> : <p>Chọn một job hoặc tạo yêu cầu mới. Không có tác vụ nào tự chạy khi mở trang.</p>}</div></div>
    {pending && <section className="operations-confirm" role="dialog" aria-modal="false" aria-labelledby="confirm-title" onKeyDown={e => { if (e.key === 'Escape' && !busy) setPending(null); }}>
      <h2 id="confirm-title">Xác nhận phạm vi thu thập</h2><p>Agent {pending.agent_id} · {config.environment_id}</p><p>{pending.start} → {pending.end}</p>
      <p>Adaptive: {pending.adaptive ? 'bật' : 'tắt'}. Chỉ đọc dữ liệu nguồn; ghi bundle vào thư mục riêng tại backend.</p>
      <button ref={confirmButton} className="button" onClick={() => void submit()} disabled={busy}>Xác nhận thu thập</button>{' '}
      <button className="button" onClick={() => setPending(null)} disabled={busy}>Quay lại</button></section>}
    <section className="operations-card"><h2>Lịch sử job</h2>{jobs.length === 0 ? <p>Chưa có job.</p> : <ul className="operations-jobs">{jobs.map(j => <li key={j.id}>
      <button onClick={() => { if (job?.id === j.id) return; setError(null); setJob(null); setJobId(j.id); onJob(j.id); }}>{j.agent_id} · {j.created_at} · {j.state}</button></li>)}</ul>}</section>
  </section>;
}
