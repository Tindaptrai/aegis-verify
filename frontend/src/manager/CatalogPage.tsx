import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { ManagerApiError, type ManagerApi } from './api';
import { catalogValidationCodes, type CatalogListDTO, type CatalogPackageDTO, type CatalogStatus } from './catalogTypes';
import './catalog.css';

const statusLabels = { draft: 'Bản nháp', published: 'Đã xuất bản', unpublished: 'Đã ngừng xuất bản' };
const auditLabels = { imported: 'Nhập gói', published: 'Xuất bản', unpublished: 'Ngừng xuất bản' };
const assessment = 'Xuất bản chỉ xác nhận đã duyệt để đưa vào danh mục; không xác nhận mã an toàn, khả năng phát hiện hay sẵn sàng thực thi. Gói chưa hỗ trợ thực thi.';
function failureMessage(failure: unknown) {
  if (failure instanceof ManagerApiError) {
    if (failure.status === 401) return 'Phiên đã kết thúc. Vui lòng đăng nhập lại.';
    if (failure.status === 403) return 'Bạn không có quyền thực hiện thao tác này.';
    if (failure.status === 413) return 'Gói ZIP vượt giới hạn 20 MiB.';
    if (failure.code === 'version_conflict') return 'Phiên bản này đã có nội dung khác. Tạo phiên bản mới để nhập.';
    if (failure.code === 'content_conflict') return 'Nội dung hoặc SHA-256 không còn khớp. Đóng chi tiết và tải lại trước khi duyệt.';
    if (failure.code === 'package_not_found') return 'Không tìm thấy gói. Làm mới danh sách và thử lại.';
    if (failure.code === 'storage_unavailable') return 'Kho gói riêng tư chưa khả dụng. Vui lòng thử lại sau.';
    if (failure.code === 'invalid_package' || catalogValidationCodes.some((code) => code === failure.code) || failure.validationCodes.length > 0) {
      const codes = failure.validationCodes.length > 0 ? failure.validationCodes : failure.code !== 'invalid_package' && failure.code ? [failure.code] : [];
      return `Gói ZIP không hợp lệ. Kiểm tra định dạng, inventory và fingerprint trước khi nhập lại.${codes.length > 0 ? ` Mã: ${codes.join(', ')}.` : ''}`;
    }
    if (failure.code === 'invalid_request') return 'Yêu cầu không hợp lệ. Kiểm tra và thử lại.';
  }
  return 'Không thể hoàn tất yêu cầu. Vui lòng thử lại.';
}
function date(value: string | null) { return value === null ? 'Chưa ghi nhận' : new Date(value).toLocaleString('vi-VN'); }
function CatalogDialog({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  const element = useRef<HTMLElement>(null);
  const close = useRef(onClose); close.current = onClose;
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    element.current?.focus();
    function keyboard(event: KeyboardEvent) {
      if (event.key === 'Escape') close.current();
      if (event.key !== 'Tab') return;
      const nodes = element.current?.querySelectorAll<HTMLElement>('button:not(:disabled),input:not(:disabled),select:not(:disabled)');
      const first = nodes?.[0], last = nodes?.[nodes.length - 1];
      if (event.shiftKey && (document.activeElement === first || document.activeElement === element.current)) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && (document.activeElement === last || document.activeElement === element.current)) { event.preventDefault(); first?.focus(); }
    }
    document.addEventListener('keydown', keyboard);
    return () => { document.removeEventListener('keydown', keyboard); if (previous?.isConnected) previous.focus(); };
  }, []);
  return <div className="drawer-backdrop" onClick={onClose}><section className="account-drawer catalog-drawer" role="dialog" aria-modal="true" aria-label={title} ref={element} tabIndex={-1} onClick={(event) => event.stopPropagation()}><header><h2>{title}</h2><button onClick={onClose} aria-label="Đóng gói">×</button></header><div className="drawer-body">{children}</div></section></div>;
}
type Write = (action: (signal: AbortSignal) => Promise<CatalogPackageDTO>, success: (result: CatalogPackageDTO) => void, allowed: boolean) => Promise<void>;
function CatalogImport({ busy, onImport }: { busy: boolean; onImport: (file: File) => void }) {
  const [file, setFile] = useState<File | null>(null);
  const oversized = !!file && file.size > 20 * 1024 * 1024;
  return <form onSubmit={(event) => { event.preventDefault(); if (file && !oversized && !busy) onImport(file); }}><p>ZIP tối đa 20 MiB, không có thư mục bọc. Gói hợp lệ được lưu riêng tư dưới dạng bản nháp bất biến.</p><label htmlFor="catalog-zip">Gói ZIP</label><input id="catalog-zip" type="file" accept=".zip,application/zip" disabled={busy} onChange={(event) => setFile(event.target.files?.[0] ?? null)} />{oversized && <p role="alert" className="manager-alert">Gói ZIP vượt giới hạn 20 MiB.</p>}<button className="primary" disabled={busy || !file || oversized}>Kiểm tra và nhập</button><p className="field-help">Gói cần package.json, scenario.yaml, profile.json, README.md và payload PowerShell. Nhập gói không chạy nội dung.</p></form>;
}
function CatalogReview({ api, id, initial, canPublish, busy, write, onAuthorityFailure }: { api: ManagerApi; id: string; initial?: CatalogPackageDTO; canPublish: boolean; busy: boolean; write: Write; onAuthorityFailure: (failure: unknown) => boolean }) {
  const [detail, setDetail] = useState<CatalogPackageDTO | null>(initial ?? null);
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);
  const [path, setPath] = useState<string | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [previewError, setPreviewError] = useState('');
  const [previewRevision, setPreviewRevision] = useState(0);
  const [confirmation, setConfirmation] = useState<'publish' | 'unpublish' | null>(null);
  const [hash, setHash] = useState('');
  useEffect(() => {
    if (initial && revision === 0) return;
    const controller = new AbortController(); setDetail(null); setError('');
    void api.catalogPackage(id, controller.signal).then((result) => {
      if (controller.signal.aborted) return;
      if (result.id !== id) throw new Error('Unexpected package');
      setDetail(result);
    }).catch((failure: unknown) => { if (!controller.signal.aborted && !onAuthorityFailure(failure)) setError(failureMessage(failure)); });
    return () => controller.abort();
  }, [api, id, initial, revision, onAuthorityFailure]);
  useEffect(() => {
    setPreview(null); setPreviewError('');
    if (path === null) return;
    const controller = new AbortController();
    void api.catalogFile(id, path, controller.signal).then((result) => {
      if (controller.signal.aborted) return;
      if (result.path !== path) throw new Error('Unexpected file');
      setPreview(result.text);
    }).catch((failure: unknown) => { if (!controller.signal.aborted && !onAuthorityFailure(failure)) setPreviewError(failureMessage(failure)); });
    return () => controller.abort();
  }, [api, id, path, previewRevision, onAuthorityFailure]);
  if (error) return <><p className="manager-alert" role="alert">{error}</p><button onClick={() => setRevision((value) => value + 1)}>Tải lại chi tiết</button></>;
  if (!detail) return <p role="status">Đang tải chi tiết gói…</p>;
  function publish(event: FormEvent) {
    event.preventDefault(); if (!detail || !confirmation || hash !== detail.sha256 || !canPublish || busy) return;
    const action = confirmation;
    void write((signal) => action === 'publish' ? api.publishCatalog(detail.id, detail.sha256, signal) : api.unpublishCatalog(detail.id, detail.sha256, signal), (result) => {
      if (result.id !== detail.id || result.sha256 !== detail.sha256 || result.status !== (action === 'publish' ? 'published' : 'unpublished')) { setError('Không thể xác nhận trạng thái gói. Tải lại chi tiết trước khi thử lại.'); return; }
      setDetail(result); setConfirmation(null); setHash('');
    }, canPublish);
  }
  return <>
    <h3>{detail.name}</h3><p>{detail.scenario_id} · {detail.version}</p><span className={`user-state ${detail.status === 'published' ? 'active' : ''}`}>{statusLabels[detail.status]}</span>
    <dl className="catalog-metadata"><dt>Nền tảng / runner</dt><dd>{detail.platform} / {detail.runner}</dd><dt>Giới hạn thời gian</dt><dd>{detail.timeout_seconds} giây</dd><dt>Nhập bởi</dt><dd>{detail.created_by ?? 'Chưa ghi nhận'} · {date(detail.created_at)}</dd><dt>Xuất bản gần nhất</dt><dd>{detail.published_by ?? 'Chưa ghi nhận'} · {date(detail.published_at)}</dd><dt>SHA-256 ZIP</dt><dd><code className="catalog-hash">{detail.sha256}</code></dd></dl>
    <p className="presence-help">Đã kiểm tra cấu trúc, inventory và fingerprint. {assessment}</p>
    <h3>Inventory riêng tư</h3><ul className="catalog-files">{detail.files.map((file) => <li key={file.path}><button aria-pressed={path === file.path} disabled={busy} onClick={() => setPath(file.path)}>{file.path}</button><small>{file.size} byte · <code className="catalog-hash">{file.sha256}</code></small></li>)}</ul>
    {path && <section className="catalog-preview" aria-label="Nội dung tệp"><h3>{path}</h3>{previewError ? <><p role="alert" className="manager-alert">{previewError}</p><button disabled={busy} onClick={() => setPreviewRevision((value) => value + 1)}>Tải lại nội dung</button></> : preview === null ? <p role="status">Đang tải nội dung…</p> : <pre><code>{preview}</code></pre>}</section>}
    <h3>Lịch sử gần nhất · tối đa 100 mục</h3>{detail.audit.length === 0 ? <p>Chưa ghi nhận lịch sử.</p> : <ol className="catalog-audit">{detail.audit.map((entry, index) => <li key={index}>{auditLabels[entry.action]} · {entry.actor ?? 'Chưa ghi nhận'} · {date(entry.at)}</li>)}</ol>}
    {canPublish && (confirmation ? <form className="catalog-confirm" onSubmit={publish}><h3>{confirmation === 'publish' ? 'Duyệt xuất bản' : 'Duyệt ngừng xuất bản'}</h3><p>{confirmation === 'publish' ? 'Xác nhận phiên bản và SHA-256 chính xác ở trên trước khi đưa gói vào danh mục.' : 'Ngừng cung cấp gói cho công việc sau này; giữ lại lịch sử và nội dung gói.'}</p><label htmlFor="catalog-confirm-hash">Nhập SHA-256 để xác nhận</label><input id="catalog-confirm-hash" autoComplete="off" spellCheck={false} value={hash} disabled={busy} onChange={(event) => setHash(event.target.value)} /><div className="device-actions"><button type="button" disabled={busy} onClick={() => { setConfirmation(null); setHash(''); }}>Hủy</button><button className="primary" disabled={busy || hash !== detail.sha256}>{confirmation === 'publish' ? 'Xác nhận xuất bản' : 'Xác nhận ngừng xuất bản'}</button></div></form> : <button disabled={busy} onClick={() => { setHash(''); setConfirmation(detail.status === 'published' ? 'unpublish' : 'publish'); }}>{detail.status === 'published' ? 'Ngừng xuất bản' : 'Xuất bản'}</button>)}
  </>;
}

export function CatalogPage({ api, canImport, canPublish }: { api: ManagerApi; canImport: boolean; canPublish: boolean }) {
  const [data, setData] = useState<CatalogListDTO | null>(null);
  const [query, setQuery] = useState<{ page: number; q: string; status: CatalogStatus | '' }>({ page: 1, q: '', status: '' });
  const [search, setSearch] = useState('');
  const [revision, setRevision] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [formError, setFormError] = useState('');
  const [denied, setDenied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [dialog, setDialog] = useState<{ kind: 'import' } | { kind: 'review'; id: string; initial?: CatalogPackageDTO } | null>(null);
  const mounted = useRef(false);
  const mutation = useRef<AbortController | null>(null);
  const deniedRef = useRef(false);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; mutation.current?.abort(); }; }, []);
  function closeDialog() { mutation.current?.abort(); setDialog(null); setFormError(''); }
  // Stable reference keeps active private reads alive across ordinary renders.
  const rejectAuthority = useRef((failure: unknown) => {
    if (!(failure instanceof ManagerApiError) || ![401, 403].includes(failure.status)) return false;
    deniedRef.current = true; setDenied(true); setData(null); closeDialog(); setError(failureMessage(failure)); return true;
  }).current;
  useEffect(() => {
    const controller = new AbortController(); setData(null); setLoading(true); setError('');
    if (deniedRef.current) { setLoading(false); return () => controller.abort(); }
    void api.listCatalog(query, controller.signal).then((result) => { if (!controller.signal.aborted) setData(result); })
      .catch((failure: unknown) => { if (!controller.signal.aborted && !rejectAuthority(failure)) setError('Không thể tải danh mục kịch bản. Vui lòng thử lại.'); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [api, query, revision, rejectAuthority]);
  async function write(action: (signal: AbortSignal) => Promise<CatalogPackageDTO>, success: (result: CatalogPackageDTO) => void, allowed: boolean) {
    if (!mounted.current || !allowed || deniedRef.current || mutation.current) return;
    const controller = new AbortController(); mutation.current = controller;
    const current = () => mounted.current && !controller.signal.aborted && mutation.current === controller;
    setBusy(true); setFormError('');
    try { const result = await action(controller.signal); if (current()) { success(result); setRevision((value) => value + 1); } }
    catch (failure) { if (current() && !rejectAuthority(failure)) setFormError(failureMessage(failure)); }
    finally { if (mutation.current === controller) { mutation.current = null; if (mounted.current) setBusy(false); } }
  }
  function changeQuery(next: typeof query) { closeDialog(); setQuery(next); }
  return <>
    <div className="page-heading users-heading"><div><p className="eyebrow">DANH MỤC</p><h1>Kịch bản</h1><p>Gói có phiên bản, nội dung riêng tư và lịch sử duyệt.</p></div>{canImport && !denied && <button className="primary" disabled={busy} onClick={() => { setFormError(''); setDialog({ kind: 'import' }); }}>Nhập ZIP</button>}</div>
    <p className="panel panel-body presence-help">{assessment}</p>
    <section className="panel users-panel" aria-label="Danh mục kịch bản"><header className="users-panel-header catalog-panel-header"><h2>Danh mục {data && <span className="count-tag">{data.count}</span>}</h2><div className="catalog-tools"><form className="catalog-search" role="search" onSubmit={(event) => { event.preventDefault(); changeQuery({ ...query, page: 1, q: search.slice(0, 100) }); }}><label className="visually-hidden" htmlFor="catalog-search">Tìm kịch bản</label><input id="catalog-search" type="search" placeholder="Tên hoặc mã kịch bản…" maxLength={100} value={search} disabled={denied} onChange={(event) => setSearch(event.target.value)} /><button disabled={denied}>Tìm kiếm</button></form><div className="catalog-filter"><label htmlFor="catalog-status">Trạng thái gói</label><select id="catalog-status" value={query.status} disabled={denied} onChange={(event) => changeQuery({ ...query, page: 1, status: event.target.value as CatalogStatus | '' })}><option value="">Tất cả</option><option value="draft">Bản nháp</option><option value="published">Đã xuất bản</option><option value="unpublished">Đã ngừng xuất bản</option></select></div><button disabled={loading || denied} onClick={() => { closeDialog(); setRevision((value) => value + 1); }}>Làm mới</button></div></header>
      {error && <p role="alert" className="manager-alert users-feedback">{error}</p>}{loading && <p role="status" className="users-feedback">Đang tải danh mục…</p>}
      {data && <>{data.results.length === 0 ? <p className="users-feedback">Không tìm thấy gói kịch bản.</p> : <div className="users-table-scroll"><table className="users-table catalog-table"><thead><tr><th>Kịch bản</th><th>Phiên bản / nền tảng</th><th>Trạng thái</th><th>SHA-256 ZIP</th><th>Thao tác</th></tr></thead><tbody>{data.results.map((item) => <tr key={item.id}><td><strong>{item.name}</strong><small>{item.scenario_id}</small></td><td><span className="catalog-version">{item.version}</span><small>{item.platform}</small></td><td><span className={`user-state ${item.status === 'published' ? 'active' : ''}`}>{statusLabels[item.status]}</span></td><td><code className="catalog-hash">{item.sha256}</code></td><td><button disabled={busy} onClick={() => { closeDialog(); setDialog({ kind: 'review', id: item.id }); }}>Xem gói</button></td></tr>)}</tbody></table></div>}<footer className="users-pagination"><span>Trang {data.page} · {data.count} gói</span><div><button disabled={loading || denied || data.page <= 1} onClick={() => changeQuery({ ...query, page: data.page - 1 })}>Trang trước</button><button disabled={loading || denied || data.page * data.page_size >= data.count} onClick={() => changeQuery({ ...query, page: data.page + 1 })}>Trang sau</button></div></footer></>}
    </section>
    {dialog && !denied && <CatalogDialog title={dialog.kind === 'import' ? 'Nhập gói ZIP' : 'Chi tiết gói'} onClose={closeDialog}>{formError && <p role="alert" className="manager-alert">{formError}</p>}{dialog.kind === 'import' ? canImport && <CatalogImport busy={busy} onImport={(file) => void write((signal) => api.importCatalog(file, signal), (result) => setDialog({ kind: 'review', id: result.id, initial: result }), canImport)} /> : <CatalogReview key={dialog.id} api={api} id={dialog.id} initial={dialog.initial} canPublish={canPublish} busy={busy} write={write} onAuthorityFailure={rejectAuthority} />}</CatalogDialog>}
  </>;
}
