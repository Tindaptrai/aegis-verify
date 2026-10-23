import { useEffect, useRef, useState } from 'react';
import type { UserDTO } from './contracts';

export const roleLabels: Record<UserDTO['role'], string> = { admin: 'Quản trị viên', operator: 'Vận hành', viewer: 'Chỉ xem', custom: 'Tùy chỉnh', technical: 'Tài khoản kỹ thuật' };
export function AccountMenu({ user, onAccount, onLogout }: { user: UserDTO; onAccount: () => void; onLogout: () => void }) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    function close(event: PointerEvent) { if (!root.current?.contains(event.target as Node)) setOpen(false); }
    function escape(event: KeyboardEvent) { if (event.key === 'Escape') { setOpen(false); trigger.current?.focus(); } }
    document.addEventListener('pointerdown', close); document.addEventListener('keydown', escape);
    return () => { document.removeEventListener('pointerdown', close); document.removeEventListener('keydown', escape); };
  }, []);
  return <div className="account-menu" ref={root}><button ref={trigger} className="account-trigger" aria-label={`Menu tài khoản ${user.display_name || user.username}`} aria-expanded={open} onClick={() => setOpen(!open)}>
    <span className="initial">{(user.display_name || user.username).slice(0, 1).toUpperCase()}</span><span className="account-name">{user.display_name || user.username}</span>
  </button>{open && <div className="account-popover"><div className="account-summary"><strong>{user.display_name || user.username}</strong><p>{user.username} · {roleLabels[user.role]}</p></div>
    <button onClick={() => { setOpen(false); onAccount(); }}>Tài khoản của tôi</button><button onClick={() => { setOpen(false); onLogout(); }}>Đăng xuất</button>
  </div>}</div>;
}
