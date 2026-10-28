import { useEffect, useState } from 'react';
import { ManagerApiError, type ManagerApi } from './api';
import type { ProviderDTO } from './executionTypes';

export function ReviewedProviders({ api, onExecution }: { api: ManagerApi; onExecution?: () => void }) {
  const [providers, setProviders] = useState<ProviderDTO[] | null>(null); const [error, setError] = useState(''); const [revision, setRevision] = useState(0); const [denied, setDenied] = useState(false);
  useEffect(() => { const controller = new AbortController(); setProviders(null); setError('');
    void api.executionProviders(controller.signal).then((result) => { if (!controller.signal.aborted) setProviders(result.providers); }).catch((failure) => { if (!controller.signal.aborted) { const forbidden = failure instanceof ManagerApiError && [401, 403].includes(failure.status); setDenied(forbidden); setError(forbidden ? 'Bạn không có quyền xem adapter.' : 'Không thể tải adapter đã review.'); } });
    return () => controller.abort();
  }, [api, revision]);
  return <section className="panel panel-body reviewed-providers" aria-label="Adapter đã review"><h2>Adapter đã review</h2><p>Nguồn RunnerRelease được review riêng. Xuất bản ZIP Catalog không tạo provider hoặc cấp quyền Run.</p>{error ? <><p role="alert">{error}</p>{!denied && <button onClick={() => setRevision((r) => r + 1)}>Tải lại adapter</button>}</> : providers === null ? <p role="status">Đang tải adapter…</p> : providers.length === 0 ? <p>Chưa có adapter đã review.</p> : <ul>{providers.map((p) => <li key={`${p.provider_id}:${p.release_id}:${p.release_sha256}`}><strong>{p.scenario_id} · {p.provider_id}</strong><p>RunnerRelease #{p.release_id} · {p.runner_id} {p.runner_version}</p><details><summary>Chi tiết release</summary><code>{p.release_sha256}</code><p>Timeout {p.timeout_seconds} giây · Rehearsal {p.allow_rehearsal ? 'được review' : 'chưa được cho phép'}</p></details></li>)}</ul>}{onExecution && !denied && <button onClick={onExecution}>Mở tác vụ và readiness</button>}</section>;
}
