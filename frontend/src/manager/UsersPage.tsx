import { useEffect, useRef, useState, type FormEvent } from 'react';
import { ManagerApiError, type ManagerApi } from './api';
import type { PermissionsDTO, UserDTO, UsersDTO } from './contracts';
import { roleLabels } from './AccountMenu';
import { UserEditor } from './UserEditor';

type Editor = { kind: 'create' } | { kind: 'edit' | 'reset'; user: UserDTO };
function failureMessage(failure: unknown) {
  if (!(failure instanceof ManagerApiError)) return 'Không thể lưu thay đổi. Vui lòng thử lại.';
  switch (failure.code) {
    case 'username_exists': return 'Tên đăng nhập đã tồn tại. Chọn tên khác.';
    case 'self_lock': return 'Không thể khóa tài khoản đang sử dụng.';
    case 'last_admin': return 'Không thể loại bỏ quản trị viên cuối cùng đang hoạt động.';
    case 'invalid_password': return 'Mật khẩu chưa đáp ứng yêu cầu. Chọn mật khẩu khác.';
    case 'invalid_username': return 'Tên đăng nhập không hợp lệ.';
    case 'invalid_display_name': return 'Tên hiển thị không hợp lệ.';
    case 'view_required': return 'Các quyền thao tác yêu cầu quyền xem dữ liệu.';
    case 'inherited_capabilities_required': return 'Quyền kế thừa đã thay đổi. Tải lại danh sách trước khi chỉnh sửa.';
    case 'user_not_found': return 'Tài khoản không còn khả dụng. Tải lại danh sách.';
    default: return 'Không thể lưu thay đổi. Kiểm tra thông tin và thử lại.';
  }
}

export function UsersPage({ api, onAuthorityChanged }: { api: ManagerApi; onAuthorityChanged?: () => Promise<void> }) {
  const [data, setData] = useState<UsersDTO | null>(null);
  const [metadata, setMetadata] = useState<PermissionsDTO | null>(null);
  const [query, setQuery] = useState({ page: 1, q: '' });
  const [search, setSearch] = useState('');
  const [revision, setRevision] = useState(0);
  const [loading, setLoading] = useState(true);
  const [denied, setDenied] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [editor, setEditor] = useState<Editor | null>(null);
  const [formError, setFormError] = useState('');
  const [busy, setBusy] = useState(false);
  const mounted = useRef(false);
  const identity = useRef(0);
  const listGeneration = useRef(0);
  const mutation = useRef<AbortController | null>(null);
  const authorityChanged = useRef(onAuthorityChanged); authorityChanged.current = onAuthorityChanged;
  const deniedRef = useRef(false);

  function rejectAuthority(failure: unknown) {
    if (!(failure instanceof ManagerApiError) || (failure.status !== 401 && failure.status !== 403)) return false;
    deniedRef.current = true; setDenied(true); setData(null); setMetadata(null); setEditor(null); setFormError(''); setNotice(''); setLoading(false);
    setError(failure.status === 401 ? 'Phiên đã kết thúc. Vui lòng đăng nhập lại.' : 'Bạn không có quyền quản lý tài khoản.');
    return true;
  }
  useEffect(() => {
    mounted.current = true; identity.current += 1; deniedRef.current = false;
    setEditor(null); setData(null); setMetadata(null); setDenied(false); setBusy(false);
    return () => { mounted.current = false; identity.current += 1; listGeneration.current += 1; mutation.current?.abort(); mutation.current = null; };
  }, [api]);

  useEffect(() => {
    const controller = new AbortController(); const generation = ++listGeneration.current;
    setData(null); setMetadata(null); setError(''); setLoading(true);
    const current = () => mounted.current && generation === listGeneration.current && !controller.signal.aborted;
    void Promise.all([api.listUsers(query, controller.signal), api.permissions(controller.signal)]).then(([users, permissions]) => {
      if (!current()) return;
      setData(users); setMetadata(permissions);
    }).catch((failure: unknown) => {
      if (!current()) return;
      if (!rejectAuthority(failure)) setError('Không thể tải danh sách tài khoản. Vui lòng thử lại.');
    }).finally(() => { if (current()) setLoading(false); });
    return () => controller.abort();
  }, [api, query, revision]);

  async function write(action: (signal: AbortSignal) => Promise<unknown>, inEditor = false) {
    if (!mounted.current || deniedRef.current || mutation.current) return;
    const controller = new AbortController(); mutation.current = controller;
    const owner = identity.current;
    const current = () => mounted.current && owner === identity.current && !controller.signal.aborted;
    setBusy(true); setError(''); setFormError(''); setNotice('');
    try {
      await action(controller.signal);
      if (!current()) return;
      setEditor(null); setData(null); setLoading(true);
      await authorityChanged.current?.();
      if (!current()) return;
      setNotice('Đã lưu thay đổi tài khoản.'); setRevision((value) => value + 1);
    } catch (failure) {
      if (!current()) return;
      if (!rejectAuthority(failure)) {
        if (inEditor) setFormError(failureMessage(failure)); else setError(failureMessage(failure));
      }
    } finally {
      if (current()) { mutation.current = null; setBusy(false); }
    }
  }
  function open(value: Editor) { if (busy || deniedRef.current) return; setFormError(''); setEditor(value); }
  function searchUsers(event: FormEvent) { event.preventDefault(); if (!deniedRef.current && !busy) setQuery({ page: 1, q: search.slice(0, 100) }); }

  return <>
    <div className="page-heading users-heading"><div><p className="eyebrow">QUẢN TRỊ</p><h1>Tài khoản &amp; quyền</h1><p>Quản lý tài khoản và quyền truy cập sản phẩm.</p></div>
      {!denied && <button className="primary" disabled={!metadata || busy} onClick={() => open({ kind: 'create' })}>Tạo tài khoản</button>}
    </div>
    <section className="panel users-panel" aria-label="Danh sách tài khoản">
      <header className="users-panel-header"><h2>Danh sách tài khoản {data && <span className="count-tag">{data.count}</span>}</h2>
        <form role="search" onSubmit={searchUsers}><label className="visually-hidden" htmlFor="user-search">Tìm tài khoản</label><input id="user-search" type="search" placeholder="Tìm tài khoản…" maxLength={100} value={search} disabled={denied || busy} onChange={(event) => setSearch(event.target.value)} /><button disabled={denied || busy}>Tìm kiếm</button></form>
      </header>
      {error && <div className="users-feedback"><p className="manager-alert" role="alert">{error}</p>{!denied && <button onClick={() => setRevision((value) => value + 1)} disabled={busy}>Tải lại danh sách</button>}</div>}
      {notice && <p className="users-feedback" role="status">{notice}</p>}
      {loading ? <p className="users-feedback" role="status">Đang tải tài khoản…</p> : data && <>
        {data.results.length === 0 ? <p className="users-feedback">Không tìm thấy tài khoản.</p> : <div className="users-table-scroll"><table className="users-table"><thead><tr><th>Tài khoản</th><th>Vai trò</th><th>Quyền</th><th>Trạng thái</th><th>Thao tác</th></tr></thead>
          <tbody>{data.results.map((user) => <tr key={user.id}>
            <td><div className="user-identity"><span className="initial">{user.username.slice(0, 1).toUpperCase()}</span><span><strong>{user.username}</strong><small>{user.display_name || '—'}</small></span></div></td>
            <td><span className="role-tag">{roleLabels[user.role]}</span></td><td>{user.capabilities.length} quyền</td><td><span className={`user-state ${user.is_active ? 'active' : ''}`}>{user.is_active ? 'Hoạt động' : 'Đã khóa'}</span></td>
            <td>{user.editable && user.role !== 'technical' ? <div className="user-actions"><button disabled={busy} onClick={() => open({ kind: 'edit', user })}>Chỉnh sửa</button><button disabled={busy} onClick={() => void write((signal) => api.updateUser(user.id, { display_name: user.display_name, capabilities: [...user.capabilities], is_active: !user.is_active }, signal))}>{user.is_active ? 'Khóa' : 'Mở khóa'}</button><button disabled={busy} onClick={() => open({ kind: 'reset', user })}>Đặt lại mật khẩu</button></div> : <span>Chỉ đọc</span>}</td>
          </tr>)}</tbody></table></div>}
        <footer className="users-pagination"><span>Trang {data.page} · {data.count} tài khoản</span><div><button disabled={data.page <= 1 || busy} onClick={() => setQuery({ ...query, page: data.page - 1 })}>Trang trước</button><button disabled={data.page * data.page_size >= data.count || busy} onClick={() => setQuery({ ...query, page: data.page + 1 })}>Trang sau</button></div></footer>
      </>}
    </section>
    {metadata && !denied && <section className="role-summaries" aria-label="Vai trò có sẵn">{(['admin', 'operator', 'viewer'] as const).map((key) => <article key={key} className="panel"><h3>{roleLabels[key]}</h3><p>{metadata.presets[key].map((capability) => metadata.capabilities.find((item) => item.key === capability)?.label).filter(Boolean).join(' · ')}</p></article>)}</section>}
    {editor && metadata && !denied && <UserEditor key={editor.kind === 'create' ? 'create' : `${editor.kind}-${editor.user.id}`} user={editor.kind === 'create' ? undefined : editor.user} resetPassword={editor.kind === 'reset'} metadata={metadata} busy={busy} error={formError}
      onCreate={(input) => write((signal) => api.createUser(input, signal), true)}
      onUpdate={(input) => editor.kind === 'edit' ? write((signal) => api.updateUser(editor.user.id, input, signal), true) : Promise.resolve()}
      onReset={(input) => editor.kind === 'reset' ? write((signal) => api.resetPassword(editor.user.id, input, signal), true) : Promise.resolve()}
      onClose={() => { setEditor(null); setFormError(''); }} />}
  </>;
}
