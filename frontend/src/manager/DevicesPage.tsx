import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { ManagerApiError, type ManagerApi } from './api';
import { validEnvironment, type DeviceDTO, type DevicesDTO, type PairingCodeDTO } from './types';

function failureMessage(failure: unknown) {
  if (failure instanceof ManagerApiError) {
    if (failure.status === 401) return 'Phiên đã kết thúc. Vui lòng đăng nhập lại.';
    if (failure.status === 403) return 'Bạn không có quyền thực hiện thao tác này.';
    if (failure.code === 'device_conflict') return 'Máy legacy không thể thu hồi qua thao tác ghép nối này.';
    if (failure.code === 'invalid_request') return 'Môi trường hoặc tài nguyên không còn hợp lệ. Kiểm tra và thử lại.';
  }
  return 'Không thể hoàn tất yêu cầu. Vui lòng thử lại.';
}
function date(value: string | null) { return value === null ? 'Chưa ghi nhận' : new Date(value).toLocaleString('vi-VN'); }
const statusLabels = { online: 'Online', offline: 'Offline', expired: 'Đã hết hạn', revoked: 'Đã thu hồi', unknown: 'Chưa xác định (legacy)' };
function DeviceDialog({ title, closeLabel, onClose, children }: { title: string; closeLabel: string; onClose: () => void; children: ReactNode }) {
  const dialog = useRef<HTMLElement>(null);
  const close = useRef(onClose); close.current = onClose;
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    dialog.current?.focus();
    function keyboard(event: KeyboardEvent) {
      if (event.key === 'Escape') close.current();
      if (event.key !== 'Tab') return;
      const nodes = dialog.current?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled)');
      const first = nodes?.[0], last = nodes?.[nodes.length - 1];
      if (event.shiftKey && (document.activeElement === first || document.activeElement === dialog.current)) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && (document.activeElement === last || document.activeElement === dialog.current)) { event.preventDefault(); first?.focus(); }
    }
    document.addEventListener('keydown', keyboard);
    return () => { document.removeEventListener('keydown', keyboard); if (previous?.isConnected) previous.focus(); };
  }, []);
  return <div className="drawer-backdrop" onClick={onClose}><section className="account-drawer device-dialog" role="dialog" aria-modal="true" aria-label={title} tabIndex={-1} ref={dialog} onClick={(event) => event.stopPropagation()}><header><h2>{title}</h2><button aria-label={closeLabel} onClick={onClose}>×</button></header>{children}</section></div>;
}

export function DevicesPage({ api, canManage }: { api: ManagerApi; canManage: boolean }) {
  const [data, setData] = useState<DevicesDTO | null>(null);
  const [query, setQuery] = useState({ page: 1, search: '' });
  const [search, setSearch] = useState('');
  const [revision, setRevision] = useState(0);
  const [loading, setLoading] = useState(true);
  const [denied, setDenied] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [dialog, setDialog] = useState<'pair' | DeviceDTO | null>(null);
  const [environment, setEnvironment] = useState('');
  const [pairing, setPairing] = useState<PairingCodeDTO | null>(null);
  const [minted, setMinted] = useState(false);
  const [dialogNotice, setDialogNotice] = useState('');
  const [formError, setFormError] = useState('');
  const [busy, setBusy] = useState(false);
  const mounted = useRef(false);
  const mutation = useRef<AbortController | null>(null);
  const deniedRef = useRef(false);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; mutation.current?.abort(); };
  }, []);
  function closeDialog() {
    mutation.current?.abort(); mutation.current = null;
    setPairing(null); setDialog(null); setEnvironment(''); setFormError(''); setBusy(false); setMinted(false); setDialogNotice('');
  }
  function rejectAuthority(failure: unknown) {
    if (!(failure instanceof ManagerApiError) || ![401, 403].includes(failure.status)) return false;
    deniedRef.current = true; setDenied(true); setData(null); closeDialog(); setError(failureMessage(failure));
    return true;
  }
  useEffect(() => {
    const controller = new AbortController(); let timer: number | undefined;
    const current = () => mounted.current && !controller.signal.aborted;
    async function load() {
      if (!current() || deniedRef.current) return;
      setLoading(true); setError('');
      try {
        const result = await api.listDevices(query, controller.signal);
        if (current()) setData(result);
      } catch (failure) {
        if (!current()) return;
        setData(null);
        if (!rejectAuthority(failure)) setError('Không thể tải danh sách máy. Vui lòng thử lại.');
      } finally {
        if (current()) {
          setLoading(false);
          if (!deniedRef.current) timer = window.setTimeout(() => void load(), 15000);
        }
      }
    }
    setData(null); void load();
    return () => { controller.abort(); window.clearTimeout(timer); };
  }, [api, query, revision]);
  useEffect(() => {
    if (!pairing) return;
    const timer = window.setTimeout(() => {
      // Abort an outstanding revoke as well: a late response cannot restore code.
      mutation.current?.abort(); mutation.current = null; setBusy(false); setPairing(null); setFormError('');
      setDialogNotice('Mã ghép nối đã hết hạn. Đóng cửa sổ và tạo mã mới nếu cần.');
    }, Math.max(0, Date.parse(pairing.expires_at) - Date.now()));
    return () => window.clearTimeout(timer);
  }, [pairing]);
  async function write<T>(action: (signal: AbortSignal) => Promise<T>, success: (value: T) => void) {
    if (!mounted.current || !canManage || deniedRef.current || mutation.current) return;
    const controller = new AbortController(); mutation.current = controller;
    const current = () => mounted.current && !controller.signal.aborted && mutation.current === controller;
    setBusy(true); setFormError(''); setNotice('');
    try { const result = await action(controller.signal); if (current()) success(result); }
    catch (failure) { if (current() && !rejectAuthority(failure)) setFormError(failureMessage(failure)); }
    finally { if (current()) { mutation.current = null; setBusy(false); } }
  }
  function create(event: FormEvent) {
    event.preventDefault(); if (!validEnvironment(environment) || minted) return;
    void write((signal) => api.createPairingCode({ environment_id: environment }, signal), (result) => {
      setMinted(true);
      if (Date.parse(result.expires_at) <= Date.now()) setDialogNotice('Mã ghép nối đã hết hạn. Đóng cửa sổ và tạo mã mới nếu cần.');
      else if (result.environment_id !== environment) setFormError('Không thể xác nhận môi trường ghép nối. Đóng cửa sổ và thử lại.');
      else setPairing(result);
    });
  }
  function openPair() { setEnvironment(''); setPairing(null); setMinted(false); setDialogNotice(''); setFormError(''); setDialog('pair'); }
  function searchDevices(event: FormEvent) { event.preventDefault(); if (!deniedRef.current) setQuery({ page: 1, search: search.slice(0, 100) }); }
  return <>
    <div className="page-heading users-heading"><div><p className="eyebrow">KẾT NỐI</p><h1>Máy</h1><p>Máy đã đăng ký và lần liên hệ được Manager ghi nhận.</p></div>{canManage && !denied && <button className="primary" onClick={openPair} disabled={busy}>Thêm máy</button>}</div>
    <p className="panel panel-body presence-help">Online chỉ xác nhận liên hệ gần đây, không xác nhận máy sẵn sàng chạy kịch bản. Máy ghép nối chỉ hỗ trợ hiện diện.</p>
    <section className="panel users-panel" aria-label="Danh sách máy"><header className="users-panel-header"><h2>Danh sách máy {data && <span className="count-tag">{data.count}</span>}</h2><div className="device-tools"><form role="search" onSubmit={searchDevices}><label className="visually-hidden" htmlFor="device-search">Tìm máy</label><input id="device-search" type="search" maxLength={100} placeholder="Tìm máy…" value={search} disabled={denied} onChange={(event) => setSearch(event.target.value)} /><button disabled={denied}>Tìm kiếm</button></form><button disabled={loading || denied} onClick={() => setRevision((value) => value + 1)}>Làm mới</button></div></header>
      <p className="users-feedback">Tự làm mới sau mỗi 15 giây khi yêu cầu trước đã hoàn tất.</p>
      {error && <p className="manager-alert users-feedback" role="alert">{error}</p>}{notice && <p className="users-feedback" role="status">{notice}</p>}
      {loading && <p className="users-feedback" role="status">Đang tải máy…</p>}
      {data && <>{data.results.length === 0 ? <p className="users-feedback">Không tìm thấy máy.</p> : <div className="users-table-scroll"><table className="users-table devices-table"><thead><tr><th>Máy / hệ điều hành</th><th>Môi trường</th><th>Trạng thái</th><th>Liên hệ cuối</th><th>Hết hạn chứng thư</th>{canManage && !denied && <th>Thao tác</th>}</tr></thead><tbody>{data.results.map((device) => <tr key={device.id}><td><strong>{device.hostname ?? 'Chưa ghi nhận tên máy'}</strong><small>{device.os === null ? 'Chưa ghi nhận OS' : device.os === 'windows' ? 'Windows' : 'Linux'} · {device.architecture ?? '—'}</small><small>{device.id}</small></td><td>{device.environment_id}</td><td><span className={`user-state ${device.status === 'online' ? 'active' : ''}`}>{statusLabels[device.status]}</span></td><td>{date(device.last_heartbeat_at)}</td><td>{date(device.certificate_expires_at)}</td>{canManage && !denied && <td>{device.connection_kind === 'paired_presence' && device.status !== 'revoked' ? <button disabled={busy} onClick={() => { setFormError(''); setDialog(device); }}>Thu hồi máy</button> : <span>{device.connection_kind === 'legacy_v1' ? 'Legacy · chỉ đọc' : '—'}</span>}</td>}</tr>)}</tbody></table></div>}
        <footer className="users-pagination"><span>Trang {data.page} · {data.count} máy</span><div><button disabled={loading || denied || data.page <= 1} onClick={() => setQuery({ ...query, page: data.page - 1 })}>Trang trước</button><button disabled={loading || denied || data.page * data.page_size >= data.count} onClick={() => setQuery({ ...query, page: data.page + 1 })}>Trang sau</button></div></footer></>}
    </section>
    {dialog && canManage && !denied && <DeviceDialog title={dialog === 'pair' ? 'Thêm máy' : 'Thu hồi máy'} closeLabel={dialog === 'pair' ? 'Đóng ghép nối' : 'Đóng thu hồi'} onClose={closeDialog}><div className="drawer-body">
      {formError && <p className="manager-alert" role="alert">{formError}</p>}
      {dialog === 'pair' ? <><p>Không cần đăng nhập tài khoản web trên endpoint. Nhập mã tại lời nhắc ẩn của agent.</p><p>Chỉ sử dụng HTTPS với CA công khai được chủ hệ thống phân phối qua kênh tin cậy. Địa chỉ IP phải khớp IP SAN của chứng thư máy chủ.</p>
        {!minted && <form onSubmit={create}><label htmlFor="pair-environment">Môi trường</label><input id="pair-environment" autoComplete="off" maxLength={64} required pattern="[A-Za-z0-9][A-Za-z0-9._-]{0,63}" disabled={busy} value={environment} onChange={(event) => setEnvironment(event.target.value)} /><p className="field-help">1–64 ký tự: chữ, số, dấu chấm, gạch dưới hoặc gạch ngang; bắt đầu bằng chữ hoặc số.</p><button className="primary" disabled={busy || !validEnvironment(environment)}>Tạo mã ghép nối</button></form>}
        {pairing && <><h3>Mã ghép nối một lần</h3><code className="pairing-secret">{pairing.code}</code><p>Hạn sử dụng: <time dateTime={pairing.expires_at}>{date(pairing.expires_at)}</time>. Mã chỉ hiển thị trong cửa sổ này và chỉ dùng một lần.</p><button disabled={busy} onClick={() => void write((signal) => api.revokePairingCode(pairing.id, signal), () => { setPairing(null); setDialogNotice('Đã thu hồi mã ghép nối.'); })}>Thu hồi mã đang chờ</button></>}
        {dialogNotice && <p role="status">{dialogNotice}</p>}
        <h3>Lệnh mẫu sau khi cài agent</h3><p>Thay các placeholder bằng địa chỉ Manager và đường dẫn tuyệt đối đã được phê duyệt. Lệnh connect hỏi mã qua lời nhắc ẩn.</p><h4>Windows</h4><pre><code>{'aegis-agent.exe connect --manager "https://<MANAGER-IP-OR-DNS>" --server-ca "<ABSOLUTE-PUBLIC-SERVER-CA.pem>" --state-dir "<ABSOLUTE-STATE-DIRECTORY>"'}</code></pre><h4>Linux</h4><pre><code>{'aegis-agent connect --manager "https://<MANAGER-IP-OR-DNS>" --server-ca "<ABSOLUTE-PUBLIC-SERVER-CA.pem>" --state-dir "<ABSOLUTE-STATE-DIRECTORY>"'}</code></pre><p>Đóng cửa sổ xóa mã khỏi giao diện, không tự thu hồi mã trên Manager. Dùng “Thu hồi mã đang chờ” trước khi đóng nếu cần hủy.</p>
      </> : <><p>Thu hồi danh tính của máy sau sẽ ngăn agent liên hệ bằng chứng thư hiện tại.</p><strong>{dialog.hostname}</strong><p>{dialog.id}</p><button className="primary" disabled={busy} onClick={() => void write((signal) => api.revokeDevice(dialog.id, signal), () => { closeDialog(); setNotice('Đã thu hồi máy.'); setRevision((value) => value + 1); })}>Xác nhận thu hồi</button></>}
    </div></DeviceDialog>}
  </>;
}
