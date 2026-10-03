import { useCallback, useEffect, useMemo, useState } from 'react';
import type { LoadState } from '../api';
import { FINAL_STATUSES } from '../contracts';
import { EmptyState, ErrorPanel, Notice, Skeleton } from '../components/Feedback';
import { StatusBadge } from '../components/StatusBadge';
import { Icon } from '../components/Icon';
import { MISSING, text } from '../format';
import type { OverviewClient } from './api';
import type { ScenarioIndex, ScenarioRow, SystemComponent, SystemStatus } from './contracts';
import { COMPONENT_TEXT, RUN_STATE_TEXT, reasonText, sourceText, when } from './labels';
import { OpsBadge } from './OpsBadge';
import { DEFAULT_QUERY, selectRows, type ResultFilter, type RowQuery, type SortKey } from './select';

export interface OverviewPageProps {
  client: OverviewClient;
  onOpenScenario: (id: string) => void;
  onOpenReport: (name: string) => void;
}

export function OverviewPage({ client, onOpenScenario, onOpenReport }: OverviewPageProps) {
  const [index, setIndex] = useState<LoadState<ScenarioIndex>>({ status: 'loading' });
  const [status, setStatus] = useState<LoadState<SystemStatus>>({ status: 'loading' });
  const [tick, setTick] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setIndex({ status: 'loading' });
    setStatus({ status: 'loading' });
    void client.scenarios().then((value) => { if (!cancelled) setIndex(value); });
    void client.systemStatus().then((value) => { if (!cancelled) setStatus(value); });
    return () => { cancelled = true; };
  }, [client, tick]);

  const refresh = useCallback(() => setTick((value) => value + 1), []);

  return (
    <div className="overview-page">
      <header className="page-header">
        <div className="page-heading">
          <p className="eyebrow">AEGIS Verify</p>
          <h1>Tổng quan</h1>
          <p className="page-sub">
            {status.status === 'ready' ? `Trạng thái tạo lúc ${when(status.value.generated_at)}` : 'Trạng thái chưa tải được'}
            {' · '}
            {index.status === 'ready'
              ? `Report mới nhất (thời gian file): ${text(when(index.value.last_report_modified))}`
              : 'Danh sách kịch bản chưa tải được'}
          </p>
        </div>
        <div className="page-actions">
          <button type="button" className="btn" onClick={refresh}><Icon name="refresh" />Tải lại</button>
        </div>
      </header>
      <OverallBanner status={status} />
      <KpiRow index={index} />
      <ScenarioSection index={index} onOpenScenario={onOpenScenario} onOpenReport={onOpenReport} onRetry={refresh} />
      <SystemStatusGrid status={status} />
    </div>
  );
}

function OverallBanner({ status }: { status: LoadState<SystemStatus> }) {
  const overall = status.status === 'ready' ? status.value.overall : null;
  return (
    <section className="overall" aria-label="Trạng thái tổng">
      <div className="overall-head">
        <span className="overall-title">Trạng thái dữ liệu và vận hành</span>
        {status.status === 'loading' ? <span className="badge neutral md">Đang tải</span>
          : overall !== null ? <OpsBadge status={overall.status} /> : <OpsBadge status="unknown" />}
      </div>
      <p className="overall-note">
        Cho biết AEGIS có đủ dữ liệu để trình bày kết quả hay không. Đây không phải mức an toàn của môi trường được giám
        sát; kết luận detection nằm ở từng kịch bản, kèm evidence ID.
      </p>
      {status.status !== 'loading' && status.status !== 'ready' ? (
        <p className="overall-reasons">Không lấy được trạng thái từ backend, nên hiển thị Unknown: {status.reason}</p>
      ) : null}
      {overall !== null && overall.reasons.length > 0 ? (
        <ul className="overall-reasons" aria-label="Lý do">
          {overall.reasons.map((item) => (
            <li key={item.component}>
              <strong>{COMPONENT_TEXT[item.component]?.title ?? item.component}</strong>
              {': '}
              <OpsBadge status={item.status} size="sm" /> {text(reasonText(item.reason))}
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}

function KpiRow({ index }: { index: LoadState<ScenarioIndex> }) {
  if (index.status === 'loading') return <Skeleton lines={2} label="Đang tải chỉ số" />;
  const ready = index.status === 'ready' && index.value.registry.configured && index.value.registry.error === null;
  const value = (read: (data: ScenarioIndex) => number) => (ready && index.status === 'ready' ? String(read(index.value)) : MISSING);
  const by = (key: string) => (data: ScenarioIndex) => data.kpi.by_status[key] ?? 0;
  const items: [string, string, string?][] = [
    ['Tổng kịch bản', value((d) => d.kpi.total)],
    ['Đã chạy', value((d) => d.kpi.run)],
    ['Chưa chạy', value((d) => d.kpi.not_run)],
    ['Detected', value(by('Detected')), 'ok'],
    ['Prevented', value(by('Prevented')), 'ok'],
    ['False negative', value(by('False negative')), 'bad'],
    ['Missing telemetry', value(by('Missing telemetry')), 'warn'],
    ['Inconclusive / Unknown', value((d) => by('Inconclusive')(d) + by('Other')(d)), 'warn'],
  ];
  return (
    <section aria-label="Chỉ số kịch bản">
      <dl className="kpi-row">
        {items.map(([label, shown, tone]) => (
          <div key={label} className={`kpi${tone && shown !== '0' && shown !== MISSING ? ` ${tone}` : ''}`}>
            <dt>{label}</dt>
            <dd>{shown}</dd>
          </div>
        ))}
      </dl>
      <p className="kpi-note">Đếm theo kết quả gần nhất của mỗi kịch bản (manifest hiện tại), không đếm theo số report.</p>
    </section>
  );
}

function SystemStatusGrid({ status }: { status: LoadState<SystemStatus> }) {
  return (
    <section className="system-status" aria-labelledby="system-status-title">
      <h2 id="system-status-title" className="section-title">System status</h2>
      {status.status === 'loading' ? <Skeleton lines={3} label="Đang tải trạng thái hệ thống" /> : null}
      {status.status === 'malformed' || status.status === 'backend-error' ? (
        <ErrorPanel title="Không đọc được trạng thái hệ thống" message="Mọi thành phần được coi là Unknown cho tới khi tải lại được."
          details={status.reason} />
      ) : null}
      {status.status === 'ready' ? (
        <div className="status-grid">
          {status.value.components.map((component) => <ComponentCard key={component.id} component={component} />)}
        </div>
      ) : null}
    </section>
  );
}

function seenInReports(component: SystemComponent): string | null {
  const seen = component.details['seen_in_reports'];
  if (typeof seen !== 'object' || seen === null) return null;
  const { report, parsed } = seen as { report?: unknown; parsed?: unknown };
  if (typeof report !== 'string' || typeof parsed !== 'number') return null;
  return `${parsed} bản ghi trong ${report}`;
}

function ComponentCard({ component }: { component: SystemComponent }) {
  const copy = COMPONENT_TEXT[component.id];
  const seen = seenInReports(component);
  return (
    <article className="status-card" aria-label={copy?.title ?? component.name}>
      <div className="status-card-head">
        <h3>{copy?.title ?? component.name}</h3>
        <OpsBadge status={component.status} size="sm" />
      </div>
      <p className="status-card-desc">{copy?.description ?? component.summary}</p>
      <dl className="status-card-meta">
        <div><dt>Lý do</dt><dd>{text(reasonText(component.reason))}</dd></div>
        <div><dt>Hoạt động gần nhất</dt><dd>{text(when(component.last_activity))}</dd></div>
        <div><dt>Nguồn</dt><dd>{sourceText(component.source)}</dd></div>
        {seen !== null ? <div><dt>Thấy trong report</dt><dd>{seen} (không phải trạng thái connector)</dd></div> : null}
      </dl>
    </article>
  );
}

const RESULT_OPTIONS: { value: ResultFilter; label: string }[] = [
  { value: 'all', label: 'Mọi kết quả' },
  ...FINAL_STATUSES.map((status) => ({ value: status as ResultFilter, label: status })),
  { value: 'other', label: 'Kết quả khác / Unknown' },
  { value: 'not_run', label: 'Chưa chạy' },
];

const SORT_OPTIONS: { value: SortKey; label: string }[] = [
  { value: 'attention', label: 'Mức cần chú ý' },
  { value: 'id', label: 'ID' },
  { value: 'run_time', label: 'Thời gian chạy' },
];

function ScenarioSection({ index, onOpenScenario, onOpenReport, onRetry }: {
  index: LoadState<ScenarioIndex>;
  onOpenScenario: (id: string) => void;
  onOpenReport: (name: string) => void;
  onRetry: () => void;
}) {
  const [query, setQuery] = useState<RowQuery>(DEFAULT_QUERY);
  const rows = useMemo(() => (index.status === 'ready' ? selectRows(index.value.scenarios, query) : []), [index, query]);
  const manifestStatuses = useMemo(
    () => (index.status === 'ready' ? [...new Set(index.value.scenarios.map((row) => row.status))].sort() : []),
    [index],
  );
  if (index.status === 'loading') {
    return <section aria-label="Tất cả kịch bản"><Skeleton lines={5} label="Đang tải kịch bản" /></section>;
  }
  if (index.status !== 'ready') {
    return (
      <section aria-label="Tất cả kịch bản">
        <ErrorPanel title="Không đọc được danh sách kịch bản" message="Backend không trả danh sách kịch bản hợp lệ."
          details={index.reason} onRetry={onRetry} />
      </section>
    );
  }
  const data = index.value;
  return (
    <section className="scenarios" aria-labelledby="scenarios-title">
      <h2 id="scenarios-title" className="section-title">Tất cả kịch bản</h2>
      {!data.registry.configured ? (
        <Notice tone="warn" title="Scenario registry: Not configured">
          <p>Dashboard đang chạy không có <code>--scenarios</code>, nên không biết có những kịch bản nào. Chạy lại với
            {' '}<code>aegis dashboard --reports &lt;dir&gt; --scenarios scenarios</code>. Report hiện có được liệt kê ở dưới.</p>
        </Notice>
      ) : null}
      {data.registry.error !== null ? (
        <Notice tone="error" title="Không đọc được thư mục manifest">
          <p>Mã lỗi: <code>{data.registry.error}</code></p>
        </Notice>
      ) : null}
      {data.registry.errors.length > 0 ? (
        <Notice tone="warn" title={`Manifest không dùng được (${data.registry.errors.length})`}>
          <ul>{data.registry.errors.map((item) => <li key={`${item.file}:${item.code}`}><code>{item.file}</code>: {item.code}</li>)}</ul>
        </Notice>
      ) : null}
      {data.report_errors.length > 0 ? (
        <Notice tone="error" title={`Report không đọc được (${data.report_errors.length})`}>
          <p>Các file này không được tính vào kết quả của kịch bản nào.</p>
          <ul>{data.report_errors.map((item) => <li key={item.name}><code>{item.name}</code>: {item.code}{item.field ? ` (${item.field})` : ''}</li>)}</ul>
        </Notice>
      ) : null}
      {data.registry.configured ? (
        <>
          <div className="scenario-filters" role="search">
            <label>
              <span>Tìm</span>
              <input type="search" value={query.query} placeholder="ID, tên hoặc profile"
                aria-label="Tìm kịch bản theo ID, tên hoặc profile"
                onChange={(event) => setQuery({ ...query, query: event.target.value })} />
            </label>
            <label>
              <span>Trạng thái manifest</span>
              <select value={query.manifestStatus} onChange={(event) => setQuery({ ...query, manifestStatus: event.target.value })}>
                <option value="all">Mọi trạng thái</option>
                {manifestStatuses.map((value) => <option key={value} value={value}>{value}</option>)}
              </select>
            </label>
            <label>
              <span>Kết quả</span>
              <select value={query.result} onChange={(event) => setQuery({ ...query, result: event.target.value as ResultFilter })}>
                {RESULT_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
              </select>
            </label>
            <label>
              <span>Sắp xếp</span>
              <select value={query.sort} onChange={(event) => setQuery({ ...query, sort: event.target.value as SortKey })}>
                {SORT_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
              </select>
            </label>
          </div>
          {data.scenarios.length === 0 ? (
            <EmptyState title="Chưa có manifest nào"><p>Thư mục --scenarios không có manifest hợp lệ.</p></EmptyState>
          ) : rows.length === 0 ? (
            <EmptyState title="Không có kịch bản khớp bộ lọc" />
          ) : (
            <ScenarioTable rows={rows} onOpenScenario={onOpenScenario} />
          )}
        </>
      ) : null}
      {data.unregistered.length > 0 ? (
        <div className="unregistered" aria-label="Report không có manifest">
          <h3>Report không có manifest ({data.unregistered.reduce((sum, group) => sum + group.reports.length, 0)})</h3>
          <p className="kpi-note">Không tính vào KPI. Mở report để xem kết quả nguyên văn.</p>
          <ul>
            {data.unregistered.map((group) => (
              <li key={group.scenario_id ?? 'none'}>
                <strong className="mono">{group.scenario_id ?? 'Không có scenario ID'}</strong>
                {group.reports.map((name) => (
                  <button key={name} type="button" className="chip" onClick={() => onOpenReport(name)}>{name}</button>
                ))}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}

function assuranceText(row: ScenarioRow): string {
  const tally = row.latest_run?.collection_assurance ?? {};
  const parts = Object.entries(tally).map(([key, value]) => `${key} ×${value}`);
  return parts.length === 0 ? MISSING : parts.join(', ');
}

function ScenarioTable({ rows, onOpenScenario }: { rows: ScenarioRow[]; onOpenScenario: (id: string) => void }) {
  return (
    <div className="table-wrap">
      <table className="table scenario-table">
        <caption className="visually-hidden">Mọi kịch bản trong registry, kể cả kịch bản chưa chạy</caption>
        <thead>
          <tr>
            <th scope="col">ID</th>
            <th scope="col">Tên</th>
            <th scope="col">Version</th>
            <th scope="col">Manifest</th>
            <th scope="col">Kết quả gần nhất</th>
            <th scope="col">Assertion đạt</th>
            <th scope="col">Evidence</th>
            <th scope="col">Collection assurance</th>
            <th scope="col">Lúc chạy (cửa sổ context)</th>
            <th scope="col"><span className="visually-hidden">Hành động</span></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const latest = row.latest_run;
            return (
              <tr key={row.id} className={row.run_state === 'run' ? undefined : 'is-not-run'}>
                <td className="mono">{row.id}</td>
                <td>{row.name}</td>
                <td className="mono">{row.version}</td>
                <td>{row.status}</td>
                <td>
                  {latest !== null && row.run_state === 'run'
                    ? <StatusBadge value={latest.final_status} size="sm" />
                    : <span className="badge neutral sm">{RUN_STATE_TEXT[row.run_state]}</span>}
                  {row.stale_run_count > 0 ? <small className="row-note">{row.stale_run_count} lượt của manifest cũ</small> : null}
                </td>
                <td className="cell-num">
                  {latest === null ? MISSING : `${text(latest.assertions.satisfied)} / ${text(latest.assertions.total)}`}
                </td>
                <td className="cell-num">{latest === null ? MISSING : text(latest.evidence_referenced)}</td>
                <td>{latest === null ? MISSING : assuranceText(row)}</td>
                <td className="mono">{latest === null ? MISSING : text(when(latest.window_end))}</td>
                <td>
                  <button type="button" className="btn sm" aria-label={`Chi tiết ${row.id}`} onClick={() => onOpenScenario(row.id)}>
                    Chi tiết
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
