import { useEffect, useRef, useState } from 'react';
import { errorMessage, type OperationsClient } from './api';
import type { Bootstrap, Snapshot } from './contracts';

const statusName = (value: string | null) => ({ active: 'Active', disconnected: 'Disconnected', pending: 'Pending',
  never_connected: 'Never connected' }[value ?? ''] ?? `Không nhận diện (${value ?? 'null'})`);

export function AgentsView({ client, config }: { client: OperationsClient; config: Bootstrap }) {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [tick, setTick] = useState(0);
  const [now, setNow] = useState(Date.now());
  const mutation = useRef<AbortController | null>(null);
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 2000);
    return () => { clearInterval(timer); mutation.current?.abort(); };
  }, []);
  useEffect(() => {
    const controller = new AbortController(); let timer: number | undefined;
    async function load() {
      try {
        const next = await client.agents(controller.signal);
        if (controller.signal.aborted) return;
        setSnapshot(next);
        if (next.refreshing) timer = window.setTimeout(load, 2000);
      } catch (e) { if (!controller.signal.aborted) setError(errorMessage(e)); }
    }
    void load();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [client, tick]);
  async function refresh() {
    if (mutation.current) return;
    const controller = new AbortController(); mutation.current = controller; setBusy(true); setError(null);
    try {
      const next = await client.refreshAgents(controller.signal);
      if (!controller.signal.aborted) { setSnapshot(next); setTick(n => n + 1); }
    } catch (e) { if (!controller.signal.aborted) setError(errorMessage(e)); }
    finally { mutation.current = null; if (!controller.signal.aborted) setBusy(false); }
  }
  const stale = snapshot?.state === 'stale' || (snapshot?.fetched_at != null && now - Date.parse(snapshot.fetched_at) > 60000);
  return <section className="operations-page" aria-labelledby="agents-title">
    <header className="operations-header"><div><p className="eyebrow">OPERATIONS · {config.environment_id}</p>
      <h1 id="agents-title">Agents</h1><p>Trạng thái agent theo Wazuh — không phải ping máy hay xác minh máy an toàn.</p></div>
      <button className="button" onClick={() => void refresh()} disabled={!config.capabilities.inventory || busy || snapshot?.refreshing}>Làm mới từ Wazuh</button></header>
    {error && <p role="alert" className="operations-warning">{error}</p>}
    {!config.capabilities.inventory && <p role="status">Server API chưa được cấu hình.</p>}
    {snapshot?.refreshing && <p role="status">Đang lấy snapshot…</p>}
    {stale && <p className="operations-warning">Dữ liệu cũ — cần làm mới để đối chiếu trạng thái hiện tại.</p>}
    {snapshot?.error_code && <p role="alert">{errorMessage(new Error(snapshot.error_code))}</p>}
    {snapshot?.state === 'unavailable' && <p>Chưa có snapshot thành công. Bấm làm mới để truy vấn nguồn.</p>}
    {!snapshot && !error && <p role="status">Đang đọc inventory đã lưu…</p>}
    <p className="operations-meta">Lấy dữ liệu (UTC): {snapshot?.fetched_at ?? '—'} · {snapshot?.agents.length ?? 0} agent trong snapshot</p>
    <div className="operations-table-wrap"><table className="operations-table"><thead><tr><th>Agent</th><th>Máy / OS</th><th>Trạng thái nguồn</th><th>Keepalive nguồn</th></tr></thead>
      <tbody>{snapshot?.agents.map(a => <tr key={a.agent_id}><td><strong>{a.agent_id}</strong></td><td>{a.name ?? '—'}<small>{[a.os_name, a.os_version].filter(Boolean).join(' ') || 'OS chưa có dữ liệu'}</small></td>
        <td><span className={`operations-chip ${a.source_status === 'active' && !stale ? 'is-active' : ''}`}>{statusName(a.source_status)}</span></td><td>{a.last_keepalive ?? '—'}</td></tr>)}</tbody></table></div>
    <p className="operations-meta">Snapshot nhiều trang không đồng thời tuyệt đối. Lỗi refresh không đồng nghĩa máy bị ngắt kết nối.</p>
  </section>;
}
