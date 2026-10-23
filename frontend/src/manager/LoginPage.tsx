import { useState, type FormEvent } from 'react';
import logo from '../../../packaging/windows/demo-launcher/assets/aegis-demo-logo.png';

export function LoginPage({ onLogin, busy, error }: { onLogin: (input: { username: string; password: string }) => void; busy: boolean; error: string }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [visible, setVisible] = useState(false);
  function submit(event: FormEvent) {
    event.preventDefault();
    const input = { username, password };
    setPassword(''); setVisible(false);
    onLogin(input);
  }
  return <main className="manager-login"><section className="login-story">
    <div className="manager-brand"><img src={logo} alt="" /><div><strong>AEGIS</strong><small>VERIFY · MANAGER</small></div></div>
    <div className="story-copy"><p className="eyebrow">KHÔNG GIAN QUẢN LÝ</p><h1>Kiểm chứng năng lực.<br />Củng cố niềm tin.</h1><p>Quản lý tài khoản và theo dõi dữ liệu kiểm thử trong một không gian làm việc có kiểm soát.</p></div>
  </section><section className="panel login-card"><h2>Đăng nhập Manager</h2><p>Sử dụng tài khoản được cấp để tiếp tục.</p>
    {error && <p role="alert" className="manager-alert">{error}</p>}
    <form onSubmit={submit}><label htmlFor="manager-username">Tên đăng nhập</label><input id="manager-username" autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} required disabled={busy} maxLength={150} />
      <label htmlFor="manager-password">Mật khẩu</label><div className="password-field"><input id="manager-password" type={visible ? 'text' : 'password'} autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required disabled={busy} /><button type="button" aria-label={visible ? 'Ẩn mật khẩu' : 'Hiện mật khẩu'} onClick={() => setVisible(!visible)}>{visible ? 'Ẩn' : 'Hiện'}</button></div>
      <button className="primary login-submit" disabled={busy}>{busy ? 'Đang đăng nhập…' : 'Đăng nhập'}</button>
    </form></section></main>;
}
