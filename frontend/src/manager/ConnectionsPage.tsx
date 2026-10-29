import { useEffect, useRef, useState } from 'react';
import { ConnectionsApiError, type ConnectionsApi, type ConnectionErrorCode } from './connectionsApi';
import { validInput, type ConnectionList, type ConnectionSource, type ConnectionTest, type WazuhInput } from './connectionsTypes';
import type { GuideStep } from './IntegrationGuides';
import './connections.css';

const emptyInput = (): WazuhInput => ({ name: '', environment_id: '', endpoint: '', index: '', username: '', password: '', ca_pem: '', source_id: null, expected_version: null });
const labels = { policy: 'Policy', tls: 'TLS chain & SAN', authentication: 'Xác thực', query: 'Truy vấn giới hạn' } as const;
const fields = [['name', 'Tên nguồn', 80], ['environment_id', 'Môi trường', 64], ['endpoint', 'HTTPS Indexer', 2048], ['index', 'Index đã review', 128], ['username', 'Tài khoản Indexer', 128], ['password', 'Mật khẩu Indexer', 1024]] as const;
const summaryLabels: Record<string, string> = { name: 'Tên nguồn', environment_id: 'Môi trường', endpoint: 'HTTPS Indexer', index: 'Index đã review', ca_sha256: 'CA SHA-256' };
const diagnosticHelp: Partial<Record<ConnectionErrorCode, string>> = {
  policy_denied: 'Quản trị viên cần kiểm tra đích và index trong policy.', connection_unavailable: 'Kiểm tra đường mạng từ Manager tới Indexer.',
  invalid_ca: 'Chọn public CA PEM hợp lệ, còn hạn.', tls_failed: 'Kiểm tra public CA, chuỗi chứng thư và SAN khớp URL.',
  authentication_failed: 'Kiểm tra tài khoản kỹ thuật Indexer và mật khẩu.', query_denied: 'Quản trị viên cần review quyền đọc index và role mapping.',
  query_failed: 'Quản trị viên cần kiểm tra cấu hình truy vấn nguồn.', draft_expired: 'Snapshot hết hạn. Cần kiểm tra lại.',
  draft_conflict: 'Snapshot đã thay đổi. Cần kiểm tra lại.', source_conflict: 'Tải lại phiên bản nguồn rồi review lại.', candidate_conflict: 'Tải lại candidate hiện tại rồi review lại.',
  storage_unavailable: 'Quản trị viên cần kiểm tra Manager Linux và private storage.', rate_limited: 'Chờ rồi thử lại.', invalid_request: 'Kiểm tra các trường bắt buộc và giới hạn đầu vào.',
  permission_denied: 'Cần xác minh lại quyền và phiên.', unauthenticated: 'Phiên đã kết thúc. Cần đăng nhập lại.',
};
export function guideForCode(code?: ConnectionErrorCode): GuideStep {
  if (code === 'invalid_ca' || code === 'tls_failed') return 'ca';
  if (code === 'authentication_failed' || code === 'query_denied') return 'account';
  return 'troubleshooting';
}
export function ConnectionsPage({ api, canManage, csrfToken, onAuthorityError, onGuide }: {
  api: ConnectionsApi; canManage: boolean; csrfToken: string; onAuthorityError: (status: number) => void; onGuide: (step: GuideStep) => void;
}) {
  const [inventory, setInventory] = useState<ConnectionList | null>(null); const [page, setPage] = useState(1); const [reload, setReload] = useState(0);
  const [open, setOpen] = useState(false); const [input, setInput] = useState<WazuhInput>(emptyInput); const [step, setStep] = useState<1 | 2 | 3>(1);
  const [draft, setDraft] = useState<ConnectionTest | null>(null); const [key, setKey] = useState(''); const [busy, setBusy] = useState(false);
  const [saveIssued, setSaveIssued] = useState(false);
  const [error, setError] = useState(''); const [errorCode, setErrorCode] = useState<ConnectionErrorCode>(); const [saved, setSaved] = useState(false); const [denied, setDenied] = useState(false); const [now, setNow] = useState(Date.now());
  const mounted = useRef(false); const epoch = useRef(0); const active = useRef<AbortController | null>(null); const reads = useRef<AbortController | null>(null); const caRead = useRef(0);
  const authority = `${canManage}:${csrfToken}`; const currentAuthority = useRef(authority); currentAuthority.current = authority;
  const deniedRef = useRef(false);
  const addButton = useRef<HTMLButtonElement | null>(null); const nameInput = useRef<HTMLInputElement | null>(null);
  function invalidate() { epoch.current++; caRead.current++; active.current?.abort(); active.current = null; setDraft(null); setKey(''); setSaveIssued(false); setBusy(false); setStep(1); }
  function close() { invalidate(); setOpen(false); setInput(emptyInput()); setError(''); setErrorCode(undefined); addButton.current?.focus(); }
  function fail(failure: unknown) {
    const code = failure instanceof ConnectionsApiError ? failure.code : undefined;
    setErrorCode(code); setError(code ? `Không thể hoàn tất: ${code}. ${diagnosticHelp[code] ?? ''}` : 'Không thể hoàn tất yêu cầu. Thử lại hoặc xem hướng dẫn.');
    if (failure instanceof ConnectionsApiError && [401, 403].includes(failure.status)) {
      invalidate(); setInput(emptyInput()); setOpen(false); setInventory(null); reads.current?.abort(); deniedRef.current = true; setDenied(true); onAuthorityError(failure.status);
    } else if (code && ['draft_expired', 'draft_conflict', 'source_conflict', 'candidate_conflict'].includes(code)) {
      invalidate(); setReload((n) => n + 1);
    }
  }
  useEffect(() => {
    mounted.current = true; const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => { mounted.current = false; epoch.current++; caRead.current++; active.current?.abort(); reads.current?.abort(); window.clearInterval(timer); };
  }, []);
  useEffect(() => { if (open) nameInput.current?.focus(); }, [open]);
  useEffect(() => {
    close(); setInventory(null); setSaved(false); deniedRef.current = false; setDenied(false);
  // Reset private memory when authority changes even if the shell keeps this component mounted.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authority, api]);
  useEffect(() => {
    if (!canManage || deniedRef.current) return;
    const controller = new AbortController(); reads.current = controller; const issuedAuthority = authority;
    const current = () => mounted.current && !controller.signal.aborted && currentAuthority.current === issuedAuthority && !deniedRef.current;
    void api.list(page, controller.signal).then((result) => { if (current()) setInventory(result); }).catch((failure: unknown) => { if (current()) fail(failure); });
    return () => controller.abort();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api, authority, page, reload]);
  // An issued save can already be committed remotely. Expiry must not abort its
  // response or discard the original pair needed for an idempotent replay.
  useEffect(() => { if (draft && !saveIssued && Date.parse(draft.expires_at) <= now) { invalidate(); setError('Kiểm tra hết hạn. Cần kiểm tra lại trước khi lưu.'); } }, [draft, now, saveIssued]);
  function edit(field: keyof WazuhInput, value: string) {
    invalidate(); setError(''); setErrorCode(undefined); setSaved(false);
    setInput((previous) => ({ ...previous, ...(field === 'endpoint' ? { password: '' } : {}), [field]: value }));
  }
  function start(source?: ConnectionSource) {
    close(); setSaved(false);
    setInput(source ? { ...emptyInput(), name: source.name, environment_id: source.environment_id ?? '', endpoint: source.endpoint ?? '', index: source.index ?? '', source_id: source.source_id, expected_version: source.version } : emptyInput()); setOpen(true);
  }
  async function loadCA(file?: File) {
    invalidate(); const read = caRead.current; const issuedAuthority = authority;
    setInput((previous) => ({ ...previous, ca_pem: '', password: '' })); setError(''); setErrorCode(undefined);
    if (!file) return;
    if (file.size > 65536) { setError('Public CA tối đa 64 KiB.'); return; }
    try {
      const pem = await file.text();
      if (!mounted.current || read !== caRead.current || issuedAuthority !== currentAuthority.current || deniedRef.current) return;
      if (!pem.trim() || new TextEncoder().encode(pem).length > 65536 || /-----BEGIN (?:[A-Z ]*PRIVATE KEY|[A-Z ]*PUBLIC KEY)-----/.test(pem)) { setError('Chỉ upload public CA PEM, không chứa key; tối đa 64 KiB.'); return; }
      setInput((previous) => ({ ...previous, ca_pem: pem }));
    } catch { if (mounted.current && read === caRead.current && issuedAuthority === currentAuthority.current) setError('Không thể đọc public CA.'); }
  }
  async function write<T>(action: (signal: AbortSignal) => Promise<T>, success: (value: T) => void) {
    if (!canManage || deniedRef.current || active.current) return;
    const controller = new AbortController(); active.current = controller; const issuedEpoch = epoch.current; const issuedAuthority = authority;
    setBusy(true); setError(''); setErrorCode(undefined);
    const current = () => mounted.current && !controller.signal.aborted && active.current === controller && issuedEpoch === epoch.current && issuedAuthority === currentAuthority.current && !deniedRef.current;
    try { const result = await action(controller.signal); if (current()) success(result); }
    catch (failure) { if (current()) fail(failure); }
    finally { if (current()) { active.current = null; setBusy(false); } }
  }
  function test() {
    if (saveIssued) return;
    if (!validInput(input)) { setError('Kiểm tra HTTPS origin, môi trường, index và các trường bắt buộc.'); return; }
    setStep(2); setDraft(null); setKey('');
    void write((signal) => api.test(input, csrfToken, signal), (result) => {
      // Bind public snapshot to the exact submitted values as well as request epoch.
      const s = result.summary;
      if (s.name !== input.name || s.environment_id !== input.environment_id || s.endpoint !== input.endpoint || s.index !== input.index || s.source_id !== input.source_id || s.version !== (input.expected_version ?? 0) + 1 || Date.parse(result.expires_at) <= Date.now()) {
        invalidate(); setError('Snapshot không khớp hoặc hết hạn. Kiểm tra lại.'); return;
      }
      setDraft(result); setKey(crypto.randomUUID()); setNow(Date.now());
    });
  }
  function save() {
    if (!draft || (!saveIssued && Date.parse(draft.expires_at) <= Date.now()) || step !== 3) return;
    void write((signal) => { setSaveIssued(true); return api.save(draft.draft_id, key, csrfToken, signal); }, () => { close(); setSaved(true); setReload((n) => n + 1); });
  }
  function prepare(source: ConnectionSource) {
    if (!inventory) return;
    void write((signal) => api.prepare(source.id, inventory.candidate_id, csrfToken, signal), () => setReload((n) => n + 1));
  }
  function renderField([field, label, max]: typeof fields[number]) {
    return <label key={field}>{label}<input ref={field === 'name' ? nameInput : undefined} type={field === 'password' ? 'password' : 'text'} autoComplete={field === 'password' ? 'new-password' : 'off'} value={input[field]} maxLength={max} onChange={(event) => edit(field, event.target.value)} /></label>;
  }
  return <div className="connections-page"><div className="page-heading"><p className="eyebrow">KẾT NỐI · WAZUH 4.14.4 TỰ QUẢN LÝ</p><h1>Kết nối</h1><p>Lưu nguồn kết nối; máy vẫn dùng nguồn hiện tại cho đến khi bạn duyệt chuyển đổi.</p></div>
    <div className="connection-actions"><button onClick={() => onGuide('overview')}>Hướng dẫn tích hợp</button>{canManage && !denied && <button ref={addButton} className="primary" onClick={() => start()}>Thêm Wazuh</button>}</div>
    {error && <div className="manager-alert" role="alert">{error}<button onClick={() => onGuide(guideForCode(errorCode))}>Hướng dẫn xử lý</button></div>}
    {!canManage || denied ? <p>Cần quyền quản lý kết nối để xem dữ liệu nguồn và thiết lập.</p> : <>
      {saved && <p role="status">Nguồn mới đã lưu — máy vẫn dùng nguồn cũ.</p>}
      {open && <section className="panel panel-body connection-wizard" aria-label="Thiết lập Wazuh" aria-busy={busy}>
        <div className="connection-actions"><h2>Thiết lập Wazuh 4.14.4</h2><button onClick={close}>Đóng thiết lập</button></div>
        <ol className="connection-steps" aria-label="Tiến trình thiết lập">{['Thông tin kết nối', 'Kiểm tra', 'Xác nhận và lưu'].map((title, i) => <li key={title} aria-current={step === i + 1 ? 'step' : undefined}>{i + 1}. {title}</li>)}</ol>
        <p>Hướng dẫn dành cho Wazuh 4.14.4 tự quản lý. Indexer khác Dashboard và Server API; hãy xác nhận phiên bản với người quản trị.</p>
        <p>Chọn CA trước khi nhập mật khẩu. Đổi HTTPS endpoint hoặc CA sẽ xóa mật khẩu và yêu cầu nhập lại.</p>
        <div className="connection-fields">{fields.slice(0, 4).map(renderField)}
          <label>Public CA PEM<input type="file" accept=".pem,.crt,text/plain,application/x-pem-file" onChange={(event) => { void loadCA(event.target.files?.[0]); event.target.value = ''; }} /></label>
          {fields.slice(4).map(renderField)}
        </div><p>{input.ca_pem ? 'Public CA đã nạp trong bộ nhớ.' : 'Chọn public CA, tối đa 64 KiB. Không upload private key.'}</p>
        <div className="connection-actions"><button onClick={() => onGuide('account')}>Cách tạo tài khoản đọc</button><button onClick={() => onGuide('ca')}>Cách lấy public CA</button><button disabled={busy || saveIssued || !validInput(input)} onClick={test}>Kiểm tra kết nối</button></div>
        {busy && step === 2 && <p role="status">Đang kiểm tra policy, TLS, xác thực và truy vấn…</p>}
        {draft && <><h3>Truy vấn thành công</h3><ul>{Object.entries(labels).map(([check, label]) => <li key={check}>{label}: Đạt</li>)}</ul><p>Chỉ chứng minh thao tác đã test được phép; không chứng minh tài khoản không có quyền ghi. Snapshot hết hạn: {draft.expires_at}.</p>
          {step === 2 ? <button className="primary" onClick={() => setStep(3)}>Xác nhận snapshot</button> : <><dl className="connection-summary">{Object.entries(draft.summary).filter(([field]) => !['source_id', 'version'].includes(field)).map(([field, value]) => <div key={field}><dt>{summaryLabels[field]}</dt><dd>{value}</dd></div>)}<div><dt>Thời điểm kiểm tra</dt><dd>{draft.tested_at}</dd></div></dl><p>Lưu không chuyển máy, không cấp quyền chạy, không tự bật admission.</p>{saveIssued && <p role="status">Yêu cầu lưu đã gửi. Nếu chưa nhận được xác nhận, bấm Lưu nguồn để kiểm tra lại cùng yêu cầu; không cần kiểm tra kết nối mới.</p>}<button className="primary" disabled={busy || (!saveIssued && Date.parse(draft.expires_at) <= now)} onClick={save}>Lưu nguồn</button></>}
        </>}
      </section>}
      <section aria-label="Nguồn đã lưu" className="connection-sources">{!inventory ? <p>Đang tải nguồn…</p> : inventory.results.length === 0 ? <p>Chưa có nguồn đã lưu.</p> : inventory.results.map((source) => <article className="panel panel-body" key={source.id}><h2>{source.name} <small>v{source.version}</small></h2>
        {source.kind === 'legacy' ? <p>Legacy — chỉ đọc; giữ đường kết nối hiện có. Môi trường: {source.environment_id ?? 'Chưa xác định'}.</p> : <><p>{source.endpoint} · {source.environment_id} · {source.index}</p><p>{source.status === 'candidate' ? 'Đã chọn, chưa kích hoạt' : 'Đã lưu, chưa gắn máy'}</p><p>Đang chờ cấu hình. Chưa sẵn sàng thực thi.</p><details><summary>Chi tiết kỹ thuật</summary><p>Worker: waiting_configuration · Chưa có healthy lease.</p></details><p>Kiểm tra query: {source.tested_at} · CA SHA-256: <span className="connection-digest">{source.ca_sha256}</span></p><div className="connection-actions"><button disabled={busy || inventory.results.some((other) => other.source_id === source.source_id && other.version > source.version)} aria-label={`Tạo phiên bản mới ${source.name} v${source.version}`} onClick={() => start(source)}>Tạo phiên bản mới</button><button disabled={busy || source.status === 'candidate' || !source.tested_at || Date.parse(source.tested_at) + 300000 <= now} aria-label={`Chuẩn bị nguồn ${source.name} v${source.version}`} onClick={() => prepare(source)}>Chuẩn bị nguồn</button></div></>}
      </article>)}</section>
      <div className="connection-actions"><button disabled={busy || page <= 1} onClick={() => { setInventory(null); setPage((p) => p - 1); }}>Trang trước</button><span>Trang {page}</span><button disabled={busy || !inventory || page * 50 >= inventory.count} onClick={() => { setInventory(null); setPage((p) => p + 1); }}>Trang sau</button><button disabled={busy} onClick={() => setReload((n) => n + 1)}>Tải lại nguồn</button></div>
    </>}
  </div>;
}
