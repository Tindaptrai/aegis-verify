import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ManagerApi } from './api';
import { ManagerApiError } from './api';
import type { OverviewDTO, SessionDTO } from './contracts';
import { LoginPage } from './LoginPage';
import { AccountMenu } from './AccountMenu';
import { MyAccount } from './MyAccount';
import { UsersPage } from './UsersPage';
import { DevicesPage } from './DevicesPage';
import { CatalogPage } from './CatalogPage';
import { ExecutionPage } from './ExecutionPage';
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
  const [page, setPage] = useState<'overview' | 'users' | 'devices' | 'catalog' | 'execution'>('overview');
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const generation = useRef(0);
  const active = useRef<AbortController | null>(null);
  const writingAuth = useRef(false);
  const logoutFailed = useRef(false);
  const mounted = useRef(true);
  const pendingRevalidation = useRef<{ forceAnonymous: boolean } | null>(null);
  const pendingLogout = useRef(false);
  const authorityRefresh = useRef<{ generation: number; promise: Promise<void> } | null>(null);
  const sessionUserId = useRef<number | null>(null);
  sessionUserId.current = session?.authenticated ? session.user?.id ?? null : null;

  const clear = useCallback(() => {
    generation.current += 1; active.current?.abort();
    const controller = new AbortController(); active.current = controller;
    setOverview(null); setOverviewError(''); setAccountOpen(false); setPage('overview');
    return { controller, generation: generation.current };
  }, []);
  const isCurrent = (request: { controller: AbortController; generation: number }) => request.generation === generation.current && !request.controller.signal.aborted;

  const revalidate = useCallback(async (forceAnonymous = false) => {
    if (writingAuth.current) {
      pendingRevalidation.current = { forceAnonymous: forceAnonymous || !!pendingRevalidation.current?.forceAnonymous };
      setSession(null); setOverview(null); setAccountOpen(false);
      return;
    }
    if (logoutFailed.current) return;
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
    mounted.current = true;
    void revalidate();
    function restored() { void revalidate(); }
    function hidden() {
      if (writingAuth.current) { void revalidate(); return; }
      clear(); api.invalidate(); setSession(null);
    }
    window.addEventListener('pageshow', restored); window.addEventListener('pagehide', hidden);
    return () => { mounted.current = false; generation.current += 1; active.current?.abort(); api.invalidate(); window.removeEventListener('pageshow', restored); window.removeEventListener('pagehide', hidden); };
  }, [api, clear, revalidate]);

  const unauthorized = useCallback(() => { void revalidate(true); }, [revalidate]);
  // Refresh grants without remounting an allowed account page. Coalesce the
  // list/metadata failure paths so their session reads cannot supersede CSRF.
  const refreshAuthority = useCallback((): Promise<void> => {
    if (writingAuth.current) return revalidate();
    if (authorityRefresh.current?.generation === generation.current) return authorityRefresh.current.promise;
    const request = { generation: generation.current, controller: active.current ?? new AbortController() };
    const promise = (async () => {
      try {
        const result = await api.session(request.controller.signal);
        if (!mounted.current || !isCurrent(request)) return;
        if (!result.authenticated || !result.user || (result.expires_at !== null && result.expires_at * 1000 <= Date.now())) {
          clear(); setSession({ ...anonymous, csrf_token: result.csrf_token }); return;
        }
        if (result.user.id !== sessionUserId.current) clear();
        setPage((current) => !result.user!.capabilities.includes('view') || (current === 'users' && !result.user!.capabilities.includes('manage_users')) ? 'overview' : current);
        setSession(result);
      } catch (failure) {
        if (!mounted.current || !isCurrent(request)) return;
        if (failure instanceof ManagerApiError && failure.status === 401) unauthorized();
        else await revalidate();
      }
    })();
    authorityRefresh.current = { generation: request.generation, promise };
    void promise.finally(() => { if (authorityRefresh.current?.promise === promise) authorityRefresh.current = null; });
    return promise;
  }, [api, clear, revalidate, unauthorized]);
  const accountsApi = useMemo<ManagerApi>(() => {
    // Keep this facade stable across shell renders and bound every settlement
    // to the workspace that issued it, including late authorization failures.
    async function guarded<T>(action: () => Promise<T>, signal?: AbortSignal) {
      const current = generation.current;
      try {
        const result = await action();
        if (!mounted.current || current !== generation.current || signal?.aborted) throw new DOMException('Request superseded', 'AbortError');
        return result;
      }
      catch (failure) {
        if (mounted.current && current === generation.current && !signal?.aborted && failure instanceof ManagerApiError) {
          if (failure.status === 401) unauthorized();
          else if (failure.status === 403) void refreshAuthority();
        }
        throw failure;
      }
    }
    return { ...api,
      executionProviders: (signal) => guarded(() => api.executionProviders(signal), signal),
      executionDevice: (id, signal) => guarded(() => api.executionDevice(id, signal), signal),
      setExecutionBinding: (id, input, signal) => guarded(() => api.setExecutionBinding(id, input, signal), signal),
      previewExecution: (input, signal) => guarded(() => api.previewExecution(input, signal), signal),
      approveExecution: (input, signal) => guarded(() => api.approveExecution(input, signal), signal),
      currentExecutionJob: (signal) => guarded(() => api.currentExecutionJob(signal), signal),
      executionJob: (id, signal) => guarded(() => api.executionJob(id, signal), signal),
      cancelExecution: (id, signal) => guarded(() => api.cancelExecution(id, signal), signal),
      listCatalog: (query, signal) => guarded(() => api.listCatalog(query, signal), signal),
      catalogPackage: (id, signal) => guarded(() => api.catalogPackage(id, signal), signal),
      catalogFile: (id, path, signal) => guarded(() => api.catalogFile(id, path, signal), signal),
      importCatalog: (file, signal) => guarded(() => api.importCatalog(file, signal), signal),
      publishCatalog: (id, hash, signal) => guarded(() => api.publishCatalog(id, hash, signal), signal),
      unpublishCatalog: (id, hash, signal) => guarded(() => api.unpublishCatalog(id, hash, signal), signal),
      device: (id, signal) => guarded(() => api.device(id, signal), signal),
      deviceHistory: (id, page, signal) => guarded(() => api.deviceHistory(id, page, signal), signal),
      archiveDevice: (id, signal) => guarded(() => api.archiveDevice(id, signal), signal),
      listDevices: (query, signal) => guarded(() => api.listDevices(query, signal), signal),
      createPairingCode: (input, signal) => guarded(() => api.createPairingCode(input, signal), signal),
      revokePairingCode: (id, signal) => guarded(() => api.revokePairingCode(id, signal), signal),
      revokeDevice: (id, signal) => guarded(() => api.revokeDevice(id, signal), signal),
      listUsers: (query, signal) => guarded(() => api.listUsers(query, signal), signal),
      permissions: (signal) => guarded(() => api.permissions(signal), signal),
      createUser: (input, signal) => guarded(() => api.createUser(input, signal), signal),
      updateUser: (id, input, signal) => guarded(() => api.updateUser(id, input, signal), signal),
      resetPassword: (id, input, signal) => guarded(() => api.resetPassword(id, input, signal), signal),
    };
  }, [api, refreshAuthority, unauthorized]);
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

  function settleAuthWrite(forceAnonymous = false) {
    writingAuth.current = false;
    if (!mounted.current) return;
    if (pendingLogout.current) {
      pendingLogout.current = false;
      pendingRevalidation.current = null;
      void logout();
    } else if (pendingRevalidation.current) {
      const pending = pendingRevalidation.current;
      pendingRevalidation.current = null;
      void revalidate(forceAnonymous || pending.forceAnonymous);
    }
  }

  async function login(input: { username: string; password: string }) {
    if (writingAuth.current || logoutFailed.current) return;
    writingAuth.current = true; const request = clear(); setAuthBusy(true); setLoginError('');
    try {
      const result = await api.login(input, request.controller.signal);
      if (isCurrent(request) && !pendingRevalidation.current && !pendingLogout.current) setSession(result);
    } catch {
      if (isCurrent(request)) setLoginError('Không thể đăng nhập. Kiểm tra thông tin và thử lại.');
    } finally {
      if (isCurrent(request)) setAuthBusy(false);
      settleAuthWrite();
    }
  }

  async function logout() {
    if (writingAuth.current) {
      pendingLogout.current = true;
      setSession(null); setOverview(null); setAccountOpen(false);
      return;
    }
    writingAuth.current = true; const request = clear(); setSession(null); setSessionError('');
    try {
      // A failed logout may already have reached Django. Refresh CSRF while
      // keeping the workspace masked before trying the write again.
      if (logoutFailed.current) await api.session(request.controller.signal);
      if (!isCurrent(request)) return;
      await api.logout(request.controller.signal);
      if (!isCurrent(request)) return;
      // This fresh read fulfils restoration requests queued before the logout
      // settled; later restoration events are drained after this read settles.
      pendingRevalidation.current = null;
      const result = await api.session(request.controller.signal);
      if (isCurrent(request)) { logoutFailed.current = false; setSession({ ...anonymous, csrf_token: result.csrf_token }); }
    } catch {
      if (isCurrent(request)) { logoutFailed.current = true; setSessionError('Chưa thể xác nhận đăng xuất. Vui lòng thử lại.'); }
    } finally { settleAuthWrite(true); }
  }

  async function changePassword(input: { current_password: string; new_password: string }) {
    if (writingAuth.current) throw new ManagerApiError(409);
    writingAuth.current = true;
    try {
      // The root retains ownership until settlement. Closing the drawer must
      // not abort a mutation that may already have renewed Django's cookie.
      await api.changePassword(input);
    } catch (failure) {
      if (mounted.current && failure instanceof ManagerApiError && failure.status === 401) unauthorized();
      throw failure;
    } finally { settleAuthWrite(); }
  }
  const closeAccount = useCallback(() => setAccountOpen(false), []);
  const user = session?.authenticated ? session.user : null;
  const canManageUsers = !!user?.capabilities.includes('view') && !!user?.capabilities.includes('manage_users');
  const canView = !!user?.capabilities.includes('view');
  const canManageDevices = canView && !!user?.capabilities.includes('manage_devices');
  const showingDevices = page === 'devices' && canView;
  const showingCatalog = page === 'catalog' && canView;
  const showingExecution = page === 'execution' && canView;
  const canRun = canView && !!user?.capabilities.includes('run_jobs');
  const canImport = canView && !!user?.capabilities.includes('import_scenarios');
  const canPublish = canView && !!user?.capabilities.includes('publish_scenarios');
  const deviceAuthority = user ? `${user.id}:${[...user.capabilities].sort().join(',')}` : '';
  const showingUsers = page === 'users' && canManageUsers;
  return <div className="manager-app" data-theme={theme}>
    {!session ? <main className="session-pending" aria-busy={!sessionError}>{sessionError ? <><p role="alert">{sessionError}</p><button onClick={() => { if (logoutFailed.current) void logout(); else void revalidate(); }}>Thử lại</button></> : <p>Đang xác minh phiên…</p>}</main> : !user ? <LoginPage onLogin={(input) => void login(input)} busy={authBusy} error={loginError} /> : <>
      <aside className="manager-sidebar"><div className="manager-brand"><img src={logo} alt="" /><div><strong>AEGIS</strong><small>VERIFY · MANAGER</small></div></div>
        <p className="eyebrow nav-label">KHÔNG GIAN LÀM VIỆC</p><nav aria-label="Điều hướng Manager"><button className={!showingUsers && !showingDevices && !showingCatalog && !showingExecution ? 'selected' : ''} aria-current={!showingUsers && !showingDevices && !showingCatalog && !showingExecution ? 'page' : undefined} onClick={() => setPage('overview')}>Tổng quan</button>
          <button disabled={!canView} className={showingDevices ? 'selected' : ''} aria-current={showingDevices ? 'page' : undefined} onClick={() => setPage('devices')}>Máy</button><button disabled={!canView} className={showingCatalog ? 'selected' : ''} aria-current={showingCatalog ? 'page' : undefined} onClick={() => setPage('catalog')}>Kịch bản</button><button disabled={!canView} className={showingExecution ? 'selected' : ''} aria-current={showingExecution ? 'page' : undefined} onClick={() => setPage('execution')}>Tác vụ</button><button disabled title="Chưa khả dụng">Kết nối <small>Chưa khả dụng</small></button>
          {canManageUsers && <button className={showingUsers ? 'selected' : ''} aria-current={showingUsers ? 'page' : undefined} onClick={() => setPage('users')}>Tài khoản &amp; quyền</button>}
        </nav></aside>
      <div className="manager-workspace"><header className="manager-header"><div className="header-identity"><div className="manager-brand"><img src={logo} alt="AEGIS" /><div><strong>AEGIS</strong><small>MANAGER</small></div></div><span className="breadcrumb">Không gian làm việc / {showingUsers ? 'Tài khoản & quyền' : showingDevices ? 'Máy' : showingCatalog ? 'Kịch bản' : showingExecution ? 'Tác vụ' : 'Tổng quan'}</span></div>
        <div className="header-actions"><button className="theme-toggle" aria-label={`Chuyển giao diện ${theme === 'dark' ? 'sáng' : 'tối'}`} onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>{theme === 'dark' ? '☀' : '☾'}</button><AccountMenu user={user} onAccount={() => setAccountOpen(true)} onLogout={() => void logout()} /></div>
      </header><main className="manager-content">{showingUsers ? <UsersPage key={user.id} api={accountsApi} onAuthorityChanged={refreshAuthority} /> : showingDevices ? <DevicesPage key={deviceAuthority} api={accountsApi} canManage={canManageDevices} onExecution={() => setPage('execution')} /> : showingExecution ? <ExecutionPage key={deviceAuthority} api={accountsApi} canRun={canRun} canManage={canManageDevices} /> : showingCatalog ? <CatalogPage key={deviceAuthority} api={accountsApi} canImport={canImport} canPublish={canPublish} onExecution={() => setPage('execution')} /> : <><div className="page-heading"><p className="eyebrow">MANAGER</p><h1>Tổng quan</h1><p>Dữ liệu đã ghi nhận trong hệ thống quản lý.</p></div>
        {!user.capabilities.includes('view') ? <p className="manager-alert" role="alert">Bạn không có quyền xem dữ liệu. Liên hệ quản trị viên để được cấp quyền.</p> : overviewError ? <section className="panel panel-body"><p className="manager-alert" role="alert">{overviewError}</p><button onClick={() => void revalidate()}>Xác minh lại phiên</button></section> : !overview ? <p>Đang tải tổng quan…</p> : <section className="overview-counts" aria-label="Số liệu đã ghi nhận">
          <article className="panel"><p>Thiết bị đã đăng ký</p><strong>{overview.registered_devices}</strong><small>Số đăng ký trong cơ sở dữ liệu</small></article><article className="panel"><p>Tác vụ đã ghi nhận</p><strong>{overview.recorded_jobs}</strong><small>Số tác vụ trong cơ sở dữ liệu</small></article><article className="panel"><p>Phiên bản đã ghi nhận</p><strong>{overview.recorded_releases}</strong><small>Số phiên bản trong cơ sở dữ liệu</small></article>
        </section>}</>}
      </main></div>{accountOpen && <MyAccount key={user.id} user={user} onChangePassword={changePassword} onClose={closeAccount} />}
    </>}
  </div>;
}
