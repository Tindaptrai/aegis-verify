import { useEffect, useState } from 'react';
import type { AnyReport, ApiClient, LoadState } from '../api';
import { ErrorPanel, Notice, Skeleton } from '../components/Feedback';
import { RunView, type RunTab } from '../components/RunView';
import { StatusBadge } from '../components/StatusBadge';
import { MISSING, shortId, text } from '../format';
import type { OverviewClient } from './api';
import type { RunSummary, ScenarioDetail } from './contracts';
import { MISMATCH_TEXT, RUN_STATE_TEXT, when } from './labels';

export interface ScenarioDetailPageProps {
  client: OverviewClient;
  api: ApiClient;
  id: string;
  onBack: () => void;
  onOpenReport: (name: string) => void;
}

export function ScenarioDetailPage({ client, api, id, onBack, onOpenReport }: ScenarioDetailPageProps) {
  const [detail, setDetail] = useState<LoadState<ScenarioDetail>>({ status: 'loading' });
  const [tick, setTick] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setDetail({ status: 'loading' });
    void client.scenario(id).then((value) => { if (!cancelled) setDetail(value); });
    return () => { cancelled = true; };
  }, [client, id, tick]);

  const header = (status: string | null, subtitle: string | null) => (
    <header className="page-header">
      <div className="page-heading">
        <p className="eyebrow">Kịch bản</p>
        <h1>{detail.status === 'ready' ? `${id} · ${detail.value.scenario.name}` : id}</h1>
        {subtitle ? <p className="page-sub">{subtitle}</p> : null}
      </div>
      <div className="page-actions">
        {status !== null ? <StatusBadge value={status} /> : null}
        <button type="button" className="btn ghost" onClick={onBack}>← Tổng quan</button>
        <button type="button" className="btn" onClick={() => setTick((value) => value + 1)}>Tải lại</button>
      </div>
    </header>
  );

  if (detail.status === 'loading') return <>{header(null, null)}<Skeleton lines={6} label={`Đang tải ${id}`} /></>;
  if (detail.status !== 'ready') {
    return (
      <>
        {header(null, null)}
        <ErrorPanel title="Không đọc được chi tiết kịch bản" message="Backend không trả chi tiết hợp lệ cho kịch bản này."
          details={detail.reason} onRetry={() => setTick((value) => value + 1)} />
      </>
    );
  }
  const data = detail.value;
  const manifest = data.scenario;
  const latestStatus = data.run_state === 'run' && data.latest_run !== null ? data.latest_run.final_status : null;
  return (
    <>
      {header(latestStatus, `v${manifest.version} · ${manifest.status} · ${manifest.file}`)}
      {data.run_state !== 'run' ? (
        <Notice tone={data.run_state === 'stale_only' ? 'warn' : 'info'} title={RUN_STATE_TEXT[data.run_state] ?? data.run_state}>
          <p>
            {data.run_state === 'stale_only'
              ? 'Chỉ có lượt chạy của manifest cũ (version hoặc nội dung khác). Chúng nằm trong lịch sử nhưng không phải kết quả của manifest hiện tại.'
              : 'Chưa có report nào cho manifest này. Không có kết luận detection.'}
          </p>
        </Notice>
      ) : null}
      <section className="detail-grid" aria-label="Metadata kịch bản">
        <div className="detail-card">
          <h2 className="section-title">Mục tiêu kiểm thử</h2>
          <p>{manifest.description}</p>
          <dl className="detail-meta">
            <div><dt>Kết quả kỳ vọng</dt><dd>{manifest.expected_outcome}</dd></div>
            <div><dt>Nguồn kỳ vọng</dt><dd>{manifest.expected_sources.join(', ')}</dd></div>
            <div><dt>Tags</dt><dd>{manifest.tags === null ? MISSING : manifest.tags.join(', ')}</dd></div>
            <div><dt>An toàn</dt><dd>
              {manifest.safety.destructive ? 'Có phá huỷ' : 'Không phá huỷ'} · {manifest.safety.authorization_required
                ? 'Cần phê duyệt' : 'Không cần phê duyệt'} · {manifest.safety.notes}
            </dd></div>
            <div><dt>Fingerprint</dt><dd className="mono" title={manifest.fingerprint}>{shortId(manifest.fingerprint)}</dd></div>
          </dl>
        </div>
        <div className="detail-card">
          <h2 className="section-title">Assertion trong manifest</h2>
          <ul className="assertion-list">
            {manifest.assertions.map((item) => (
              <li key={item.id}><span className="mono">{item.id}</span> <span className="chip-static">{item.source}</span> {item.description}</li>
            ))}
          </ul>
        </div>
      </section>
      <RunHistory runs={data.runs} onOpenReport={onOpenReport} />
      {data.comparisons.length > 0 ? (
        <section className="detail-card" aria-label="So sánh trước sau">
          <h2 className="section-title">So sánh trước / sau ({data.comparisons.length})</h2>
          <ul className="history-list">
            {data.comparisons.map((item) => (
              <li key={item.name}>
                <StatusBadge value={item.comparison_status} size="sm" />
                <span className="mono">{text(item.before_run_id)} → {text(item.after_run_id)}</span>
                <button type="button" className="btn sm" onClick={() => onOpenReport(item.name)}>Mở {item.name}</button>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
      {data.report_errors.length > 0 ? (
        <Notice tone="error" title={`Report không đọc được trong thư mục (${data.report_errors.length})`}>
          <p>Không gán được cho kịch bản nào vì không đọc được nội dung.</p>
          <ul>{data.report_errors.map((item) => <li key={item.name}><code>{item.name}</code>: {item.code}</li>)}</ul>
        </Notice>
      ) : null}
      {data.run_state === 'run' && data.latest_run !== null
        ? <LatestRun api={api} run={data.latest_run} />
        : null}
    </>
  );
}

function RunHistory({ runs, onOpenReport }: { runs: RunSummary[]; onOpenReport: (name: string) => void }) {
  return (
    <section className="detail-card" aria-label="Lịch sử lượt chạy">
      <h2 className="section-title">Lịch sử lượt chạy ({runs.length})</h2>
      {runs.length === 0 ? <p className="kpi-note">Chưa có lượt chạy nào.</p> : (
        <div className="table-wrap">
          <table className="table scenario-table">
            <thead>
              <tr>
                <th scope="col">Report</th>
                <th scope="col">Run ID</th>
                <th scope="col">Kết quả</th>
                <th scope="col">Cửa sổ chạy (context)</th>
                <th scope="col">Thời gian file</th>
                <th scope="col">Manifest</th>
                <th scope="col">Assertion đạt</th>
                <th scope="col">Evidence</th>
                <th scope="col"><span className="visually-hidden">Hành động</span></th>
              </tr>
            </thead>
            <tbody>
              {runs.map((run) => (
                <tr key={run.name} className={run.manifest_match === false ? 'is-not-run' : undefined}>
                  <td className="mono">{run.name}</td>
                  <td className="mono">{text(run.run_id)}</td>
                  <td><StatusBadge value={run.final_status} size="sm" /></td>
                  <td className="mono">{text(when(run.window_start))} → {text(when(run.window_end))}</td>
                  <td className="mono">{text(when(run.file_modified))}</td>
                  <td>{run.manifest_match === false ? `Khác: ${MISMATCH_TEXT[run.mismatch ?? ''] ?? text(run.mismatch)}` : 'Khớp'}</td>
                  <td className="cell-num">{text(run.assertions.satisfied)} / {text(run.assertions.total)}</td>
                  <td className="cell-num">{text(run.evidence_referenced)}</td>
                  <td><button type="button" className="btn sm" onClick={() => onOpenReport(run.name)}>Mở report</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function LatestRun({ api, run }: { api: ApiClient; run: RunSummary }) {
  const [report, setReport] = useState<LoadState<AnyReport>>({ status: 'loading' });
  const [tab, setTab] = useState<RunTab>('assertions');
  useEffect(() => {
    let cancelled = false;
    setReport({ status: 'loading' });
    void api.report(run.name).then((value) => { if (!cancelled) setReport(value); });
    return () => { cancelled = true; };
  }, [api, run.name]);
  return (
    <section className="latest-run" aria-label="Lượt chạy gần nhất">
      <h2 className="section-title">Lượt chạy gần nhất: <span className="mono">{text(run.run_id)}</span></h2>
      <p className="kpi-note">Kết quả, assertion và evidence ID dưới đây là nguyên văn report <code>{run.name}</code>.</p>
      {report.status === 'loading' ? <Skeleton lines={4} label={`Đang tải ${run.name}`} /> : null}
      {report.status === 'malformed' || report.status === 'backend-error' ? (
        <ErrorPanel title="Không đọc được report của lượt gần nhất" message="Report không tải được hoặc sai contract." details={report.reason} />
      ) : null}
      {report.status === 'ready' && report.value.kind === 'evaluation'
        ? <RunView report={report.value.report} tab={tab} onTab={setTab} /> : null}
    </section>
  );
}
