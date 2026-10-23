import { useCallback, useEffect, useRef, useState } from 'react';
import type { ManagerApi } from './api';
import { ManagerApiError } from './api';
import type { OverviewDTO, SessionDTO } from './contracts';
import { LoginPage } from './LoginPage';
import { AccountMenu } from './AccountMenu';
import { MyAccount } from './MyAccount';
import logo from '../../../packaging/windows/demo-launcher/assets/aegis-demo-logo.png';

const anonymous: SessionDTO = { authenticated: false, csrf_token: '', user: null, expires_at: null };
export function ManagerApp({ api }: { api: ManagerApi }) {
  const [session, setSession] = useState<SessionDTO | null>(null);
  const [overview, setOverview] = useState<OverviewDTO | null>(null);
  const [overviewError, setOverviewError] = useState('');
  const [loginError, setLoginError] = useState('');
  const [sessionError, setSessionError] = useState('');
  const [authBusy, setAuthBusy] = useState(false);
  const [accountOpen, setAccountOpen] = useState(false);
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const generation = useRef(0);
  const active = useRef<AbortController | null>(null);
  const writingAuth = useRef(false);
  const logoutFailed = useRef(false);

  const clear = useCallback(() => {
    generation.current += 1; active.current?.abort();
    const controller = new AbortController(); active.current = controller;
    setOverview(null); setOverviewError(''); setAccountOpen(false);
    return { controller, generation: generation.current };
  }, []);
  const isCurrent = (request: { controller: AbortController; generation: number }) => request.generation === generation.current && !request.controller.signal.aborted;

  const revalidate = useCallback(async (forceAnonymous = false) => {
    if (writingAuth.current || logoutFailed.current) return;
    const request = clear(); api.invalidate(); setSession(null); setSessionError('');
    try {
      const result = await api.session(request.controller.signal);
      if (!isCurrent(request)) return;
      const expired = result.expires_at !== null && result.expires_at * 1000 <= Date.now();
      setSession(forceAnonymous || expired ? { ...anonymous, csrf_token: result.csrf_token } : result);
    } catch {
      if (isCurrent(request)) setSessionError('Không thể xác minh phiên. Vui lòng thử lại.');
    }
  }, [api, clear]);

  useEffect(() => {
    void revalidate();
    function restored() { void revalidate(); }
    function hidden() {
      if (writingAuth.current) return;
      clear(); api.invalidate(); setSession(null);
    }
    window.addEventListener('pageshow', restored); window.addEventListener('pagehide', hidden);
    return () => { generation.current += 1; active.current?.abort(); api.invalidate(); window.removeEventListener('pageshow', restored); window.removeEventListener('pagehide', hidden); };
  }, [api, clear, revalidate]);

  const unauthorized = useCallback(() => { void revalidate(true); }, [revalidate]);
  useEffect(() => {
    if (!session?.authenticated || session.expires_at === null) return;
    const timer = window.setTimeout(unauthorized, Math.max(0, session.expires_at * 1000 - Date.now()));
    return () => window.clearTimeout(timer);
  }, [session, unauthorized]);

  useEffect(() => {
    if (!session?.authenticated || !session.user?.capabilities.includes('view')) return;
    const current = generation.current;
    const controller = new AbortController();
    void api.overview(controller.signal).then((result) => {
      if (current === generation.current && !controller.signal.aborted) setOverview(result);
    }).catch((failure: unknown) => {
      if (current !== generation.current || controller.signal.aborted) return;
      if (failure instanceof ManagerApiError && failure.status === 401) unauthorized();
      else setOverviewError(failure instanceof ManagerApiError && failure.status === 403 ? 'Bạn không có quyền xem dữ liệu này.' : 'Không thể tải tổng quan. Thử xác minh lại phiên.');
    });
    return () => controller.abort();
  }, [api, session, unauthorized]);

  async function login(input: { username: string; password: string }) {
    if (writingAuth.current || logoutFailed.current) return;
    writingAuth.current = true; const request = clear(); setAuthBusy(true); setLoginError('');
    try {
      const result = await api.login(input, request.controller.signal);
      if (isCurrent(request)) setSession(result);
    } catch {
      if (isCurrent(request)) setLoginError('Không thể đăng nhập. Kiểm tra thông tin và thử lại.');
    } finally { writingAuth.current = false; if (isCurrent(request)) setAuthBusy(false); }
  }

  async function logout() {
    if (writingAuth.current) return;
    writingAuth.current = true; const request = clear(); setSession(null); setSessionError('');
    try {
      // A failed logout may already have reached Django. Refresh CSRF while
      // keeping the workspace masked before trying the write again.
      if (logoutFailed.current) await api.session(request.controller.signal);
      if (!isCurrent(request)) return;
      await api.logout(request.controller.signal);
      if (!isCurrent(request)) return;
      const result = await api.session(request.controller.signal);
      if (isCurrent(request)) { logoutFailed.current = false; setSession({ ...anonymous, csrf_token: result.csrf_token }); }
    } catch {
      if (isCurrent(request)) { logoutFailed.current = true; setSessionError('Chưa thể xác nhận đăng xuất. Vui lòng thử lại.'); }
    } finally { writingAuth.current = false; }
  }
  const closeAccount = useCallback(() => setAccountOpen(false), []);
  const user = session?.authenticated ? session.user : null;
  return <div className="manager-app" data-theme={theme}>
    {!session ? <main className="session-pending" aria-busy={!sessionError}>{sessionError ? <><p role="alert">{sessionError}</p><button onClick={() => { if (logoutFailed.current) void logout(); else void revalidate(); }}>Thử lại</button></> : <p>Đang xác minh phiên…</p>}</main> : !user ? <LoginPage onLogin={(input) => void login(input)} busy={authBusy} error={loginError} /> : <>
      <aside className="manager-sidebar"><div className="manager-brand"><img src={logo} alt="" /><div><strong>AEGIS</strong><small>VERIFY · MANAGER</small></div></div>
        <p className="eyebrow nav-label">KHÔNG GIAN LÀM VIỆC</p><nav aria-label="Điều hướng Manager"><button className="selected" aria-current="page">Tổng quan</button>
          <button disabled title="Chưa khả dụng">Thiết bị <small>Chưa khả dụng</small></button><button disabled title="Chưa khả dụng">Kịch bản <small>Chưa khả dụng</small></button><button disabled title="Chưa khả dụng">Tác vụ <small>Chưa khả dụng</small></button><button disabled title="Chưa khả dụng">Kết nối <small>Chưa khả dụng</small></button>
          {user.capabilities.includes('view') && user.capabilities.includes('manage_users') && <button disabled title="Chưa khả dụng">Tài khoản &amp; quyền <small>Chưa khả dụng</small></button>}
        </nav></aside>
      <div className="manager-workspace"><header className="manager-header"><div className="header-identity"><div className="manager-brand"><img src={logo} alt="AEGIS" /><div><strong>AEGIS</strong><small>MANAGER</small></div></div><span className="breadcrumb">Không gian làm việc / Tổng quan</span></div>
        <div className="header-actions"><button className="theme-toggle" aria-label={`Chuyển giao diện ${theme === 'dark' ? 'sáng' : 'tối'}`} onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>{theme === 'dark' ? '☀' : '☾'}</button><AccountMenu user={user} onAccount={() => setAccountOpen(true)} onLogout={() => void logout()} /></div>
      </header><main className="manager-content"><div className="page-heading"><p className="eyebrow">MANAGER</p><h1>Tổng quan</h1><p>Dữ liệu đã ghi nhận trong hệ thống quản lý.</p></div>
        {!user.capabilities.includes('view') ? <p className="manager-alert" role="alert">Bạn không có quyền xem dữ liệu. Liên hệ quản trị viên để được cấp quyền.</p> : overviewError ? <section className="panel panel-body"><p className="manager-alert" role="alert">{overviewError}</p><button onClick={() => void revalidate()}>Xác minh lại phiên</button></section> : !overview ? <p>Đang tải tổng quan…</p> : <section className="overview-counts" aria-label="Số liệu đã ghi nhận">
          <article className="panel"><p>Thiết bị đã đăng ký</p><strong>{overview.registered_devices}</strong><small>Số đăng ký trong cơ sở dữ liệu</small></article><article className="panel"><p>Tác vụ đã ghi nhận</p><strong>{overview.recorded_jobs}</strong><small>Số tác vụ trong cơ sở dữ liệu</small></article><article className="panel"><p>Phiên bản đã ghi nhận</p><strong>{overview.recorded_releases}</strong><small>Số phiên bản trong cơ sở dữ liệu</small></article>
        </section>}
      </main></div>{accountOpen && <MyAccount key={user.id} user={user} api={api} onClose={closeAccount} onUnauthorized={unauthorized} />}
    </>}
  </div>;
}
