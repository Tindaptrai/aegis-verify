import { useEffect, useRef, useState, type FormEvent } from 'react';
import type { CreateUserInput, PermissionsDTO, UpdateUserInput, UserDTO } from './contracts';
import { PermissionEditor } from './PermissionEditor';

export function UserEditor({ user, resetPassword = false, metadata, busy, error, onCreate, onUpdate, onReset, onClose }: {
  user?: UserDTO; resetPassword?: boolean; metadata: PermissionsDTO; busy: boolean; error: string;
  onCreate: (input: CreateUserInput) => Promise<void>; onUpdate: (input: UpdateUserInput) => Promise<void>;
  onReset: (input: { new_password: string }) => Promise<void>; onClose: () => void;
}) {
  const [username, setUsername] = useState(user?.username ?? '');
  const [displayName, setDisplayName] = useState(user?.display_name ?? '');
  const [password, setPassword] = useState('');
  const [capabilities, setCapabilities] = useState(user?.capabilities ?? metadata.presets.viewer);
  const [active, setActive] = useState(user?.is_active ?? true);
  const dialog = useRef<HTMLElement>(null);
  const close = useRef(onClose); close.current = onClose;
  const invalidGrants = !capabilities.includes('view') && capabilities.length > 0;
  const title = resetPassword ? 'Đặt lại mật khẩu' : user ? 'Chỉnh sửa tài khoản' : 'Tạo tài khoản';
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    dialog.current?.focus();
    function keyboard(event: KeyboardEvent) {
      if (event.key === 'Escape') close.current();
      if (event.key !== 'Tab') return;
      const nodes = dialog.current?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), select:not(:disabled)');
      const first = nodes?.[0]; const last = nodes?.[nodes.length - 1];
      if (event.shiftKey && (document.activeElement === first || document.activeElement === dialog.current)) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
    }
    document.addEventListener('keydown', keyboard);
    return () => { document.removeEventListener('keydown', keyboard); previous?.focus(); };
  }, []);
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy || (!resetPassword && invalidGrants)) return;
    const submittedPassword = password; setPassword('');
    if (resetPassword) await onReset({ new_password: submittedPassword });
    else if (user) await onUpdate({ display_name: displayName, capabilities: [...capabilities], is_active: active });
    else await onCreate({ username, display_name: displayName, password: submittedPassword, capabilities: [...capabilities], is_active: active });
  }
  return <div className="drawer-backdrop" onClick={onClose}><section className="account-drawer user-editor" role="dialog" aria-modal="true" aria-labelledby="user-editor-title" tabIndex={-1} ref={dialog} onClick={(event) => event.stopPropagation()}>
    <header><h2 id="user-editor-title">{title}</h2><button aria-label="Đóng trình sửa tài khoản" onClick={onClose}>×</button></header>
    <form onSubmit={(event) => void submit(event)}>
      <div className="drawer-body">{error && <p className="manager-alert" role="alert">{error}</p>}
        {resetPassword ? <><p>Đặt mật khẩu mới cho <strong>{user?.username}</strong>.</p><label htmlFor="reset-password">Mật khẩu mới</label><input id="reset-password" type="password" autoComplete="new-password" required value={password} disabled={busy} onChange={(event) => setPassword(event.target.value)} /></> : <>
          <label htmlFor="edit-username">Tên đăng nhập</label><input id="edit-username" value={username} readOnly={!!user} maxLength={150} required disabled={busy} autoComplete="off" onChange={(event) => setUsername(event.target.value)} />
          {user && <p className="field-help">Tên đăng nhập không thể thay đổi.</p>}
          <label htmlFor="edit-display-name">Tên hiển thị</label><input id="edit-display-name" value={displayName} maxLength={150} disabled={busy} onChange={(event) => setDisplayName(event.target.value)} />
          {!user && <><label htmlFor="initial-password">Mật khẩu ban đầu</label><input id="initial-password" type="password" autoComplete="new-password" required value={password} disabled={busy} onChange={(event) => setPassword(event.target.value)} /></>}
          <label htmlFor="edit-user-state">Trạng thái</label><select id="edit-user-state" value={active ? 'active' : 'locked'} disabled={busy} onChange={(event) => setActive(event.target.value === 'active')}><option value="active">Hoạt động</option><option value="locked">Đã khóa</option></select>
          <PermissionEditor metadata={metadata} capabilities={capabilities} inherited={user?.inherited_capabilities ?? []} onChange={setCapabilities} disabled={busy} />
          {invalidGrants && <p className="manager-alert" role="alert">Các quyền thao tác yêu cầu quyền xem dữ liệu. Chọn quyền xem hoặc bỏ các quyền thao tác.</p>}
        </>}
      </div><footer className="drawer-footer"><button type="button" onClick={onClose}>Hủy</button><button className="primary" disabled={busy || (!resetPassword && invalidGrants)}>{busy ? 'Đang lưu…' : resetPassword ? 'Đặt lại mật khẩu' : 'Lưu tài khoản'}</button></footer>
    </form>
  </section></div>;
}
