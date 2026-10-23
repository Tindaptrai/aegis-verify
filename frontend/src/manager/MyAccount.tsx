import { useEffect, useRef, useState, type FormEvent } from 'react';
import type { ManagerApi } from './api';
import { ManagerApiError } from './api';
import type { Capability, UserDTO } from './contracts';
import { roleLabels } from './AccountMenu';

// Display labels from the approved product vocabulary; grants come only from
// the server session. The management editor uses its permissions metadata API.
const capabilityLabels: Record<Capability, string> = {
  view: 'Xem dữ liệu', run_jobs: 'Chạy tác vụ', import_scenarios: 'Nhập kịch bản',
  publish_scenarios: 'Xuất bản kịch bản', manage_devices: 'Quản lý thiết bị',
  manage_connections: 'Quản lý kết nối', export_evidence: 'Xuất bằng chứng', manage_users: 'Quản lý tài khoản',
};

export function MyAccount({ user, api, onClose, onUnauthorized }: { user: UserDTO; api: ManagerApi; onClose: () => void; onUnauthorized: () => void }) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const controller = useRef<AbortController | null>(null);
  const dialog = useRef<HTMLElement>(null);
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    dialog.current?.focus();
    function keyboard(event: KeyboardEvent) {
      if (event.key === 'Escape') onClose();
      if (event.key !== 'Tab') return;
      const nodes = dialog.current?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled)');
      const first = nodes?.[0]; const last = nodes?.[nodes.length - 1];
      if (event.shiftKey && (document.activeElement === first || document.activeElement === dialog.current)) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
    }
    document.addEventListener('keydown', keyboard);
    return () => { controller.current?.abort(); document.removeEventListener('keydown', keyboard); previous?.focus(); };
  }, [onClose]);
  async function submit(event: FormEvent) {
    event.preventDefault();
    const input = { current_password: currentPassword, new_password: newPassword };
    setCurrentPassword(''); setNewPassword(''); setBusy(true); setError(''); setMessage('');
    const request = new AbortController(); controller.current = request;
    try { await api.changePassword(input, request.signal); if (!request.signal.aborted) setMessage('Đã đổi mật khẩu.'); }
    catch (failure) {
      if (request.signal.aborted) return;
      if (failure instanceof ManagerApiError && failure.status === 401) onUnauthorized();
      else setError('Không thể đổi mật khẩu. Kiểm tra mật khẩu hiện tại và yêu cầu mật khẩu mới.');
    } finally { if (!request.signal.aborted) setBusy(false); }
  }
  return <div className="drawer-backdrop" onClick={onClose}><section className="account-drawer" role="dialog" aria-modal="true" aria-labelledby="my-account-title" tabIndex={-1} ref={dialog} onClick={(event) => event.stopPropagation()}>
    <header><h2 id="my-account-title">Tài khoản của tôi</h2><button aria-label="Đóng tài khoản" onClick={onClose}>×</button></header>
    <div className="drawer-body"><h3>{user.display_name || user.username}</h3><p>{user.username} · {roleLabels[user.role]}</p><h3>Quyền được cấp</h3>
      {user.capabilities.length ? <ul className="capability-list">{user.capabilities.map((key) => <li key={key}><span>{capabilityLabels[key]}</span><code>{key}</code></li>)}</ul> : <p>Chưa được cấp quyền sản phẩm.</p>}
      <form onSubmit={submit}><h3>Đổi mật khẩu</h3>{error && <p className="manager-alert" role="alert">{error}</p>}{message && <p role="status">{message}</p>}
        <label htmlFor="current-password">Mật khẩu hiện tại</label><input id="current-password" type="password" autoComplete="current-password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} required disabled={busy} />
        <label htmlFor="new-password">Mật khẩu mới</label><input id="new-password" type="password" autoComplete="new-password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} required disabled={busy} />
        <button className="primary" disabled={busy}>Đổi mật khẩu</button>
      </form></div></section></div>;
}
