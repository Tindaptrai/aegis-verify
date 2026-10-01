import { useCallback, useEffect, useState } from 'react';
import type { AnyReport, ApiClient, LoadState } from './api';
import type { ReportIndex } from './contracts';
import { ComparisonView } from './components/ComparisonView';
import { EmptyState, ErrorPanel, Skeleton } from './components/Feedback';
import { RunView, type RunTab } from './components/RunView';
import { orderEntries, Sidebar } from './components/Sidebar';
import { StatusBadge } from './components/StatusBadge';
import { text } from './format';
import { readRoute, writeRoute } from './route';
import { createOperationsClient, type OperationsClient } from './operations/api';
import type { Bootstrap } from './operations/contracts';
import { AgentsView } from './operations/AgentsView';
import { CollectionsView } from './operations/CollectionsView';
import { createOverviewClient, type OverviewClient } from './overview/api';
import { OverviewPage } from './overview/OverviewPage';
import { ScenarioDetailPage } from './overview/ScenarioDetailPage';

export interface AppProps {
  api: ApiClient;
  operationsClient?: OperationsClient;
  overviewClient?: OverviewClient;
}

function initialTab(value: string | null): RunTab {
  return value === 'timeline' ? 'timeline' : 'assertions';
}

export function App({ api, operationsClient, overviewClient }: AppProps) {
  const [operations] = useState(() => operationsClient ?? createOperationsClient());
  const [overview] = useState(() => overviewClient ?? createOverviewClient());
  const [capabilities, setCapabilities] = useState<Bootstrap | null>(null);
  const [page, setPage] = useState(() => readRoute().page ?? 'overview');
  const [scenario, setScenario] = useState<string | null>(() => readRoute().scenario ?? null);
  const [jobId, setJobId] = useState(() => readRoute().job ?? null);
  const [index, setIndex] = useState<LoadState<ReportIndex>>({ status: 'loading' });
  const [selected, setSelected] = useState<string | null>(() => readRoute().report);
  const [tab, setTab] = useState<RunTab>(() => initialTab(readRoute().tab));
  const [report, setReport] = useState<LoadState<AnyReport> | null>(null);
  const [query, setQuery] = useState('');
  const [reportTick, setReportTick] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    void operations.bootstrap(controller.signal).then(data => {
      if (!controller.signal.aborted) setCapabilities(data);
    }).catch(() => {
      if (controller.signal.aborted) return;
      setCapabilities(null);
      // Only the capability-gated pages fall back; the overview and reports stay put.
      setPage((current) => (current === 'agents' || current === 'collections' ? 'reports' : current));
    });
    return () => controller.abort();
  }, [operations]);

  // A pasted link or back/forward changes only the hash; follow it instead of
  // leaving the screen out of step with the address bar.
  useEffect(() => {
    const follow = () => {
      const route = readRoute();
      setPage(route.page ?? 'overview');
      setScenario(route.scenario ?? null);
      if (route.report !== null) setSelected(route.report);
      if (route.tab !== null) setTab(initialTab(route.tab));
    };
    window.addEventListener('hashchange', follow);
    return () => window.removeEventListener('hashchange', follow);
  }, []);

  const loadIndex = useCallback(() => {
    setIndex({ status: 'loading' });
    void api.index().then(setIndex);
  }, [api]);

  useEffect(() => {
    loadIndex();
  }, [loadIndex]);

  // Keep the selection meaningful: a stale name is dropped, and with nothing
  // chosen the first readable report opens so the page is useful at once.
  useEffect(() => {
    if (index.status !== 'ready') return;
    const ordered = orderEntries(index.value.reports);
    if (selected !== null && ordered.some((entry) => entry.name === selected)) return;
    const first = ordered.find((entry) => entry.error === null && entry.kind !== null) ?? null;
    setSelected(first === null ? null : first.name);
  }, [index, selected]);

  useEffect(() => {
    writeRoute({ report: selected, tab: selected === null ? null : tab, page, job: jobId, scenario });
  }, [selected, tab, page, jobId, scenario]);

  useEffect(() => {
    if (selected === null || page !== 'reports') {
      setReport(null);
      return;
    }
    let cancelled = false;
    setReport({ status: 'loading' });
    void api.report(selected).then((state) => {
      if (!cancelled) setReport(state);
    });
    return () => {
      cancelled = true;
    };
  }, [api, selected, reportTick, page]);

  const refresh = () => {
    loadIndex();
    setReportTick((value) => value + 1);
  };

  const openReport = (name: string) => {
    setSelected(name);
    setTab('assertions');
    setPage('reports');
  };
  const pages = capabilities ? (['overview', 'reports', 'collections', 'agents'] as const) : (['overview', 'reports'] as const);

  return (
    <div className="app">
      <Sidebar state={index} selected={selected} query={query} onQuery={setQuery}
        onSelect={name => { setSelected(name); setPage('reports'); }} onRetry={loadIndex}
        operationsNav={<nav className="operations-nav" aria-label="Workspace">
          {pages.map(item => <button key={item} aria-current={page === item ? 'page' : undefined}
            onClick={() => { setPage(item); if (item === 'overview') setScenario(null); }}>
            {({ overview: 'Tổng quan', reports: 'Reports', collections: 'Collections', agents: 'Agents' })[item]}</button>)}
        </nav>} />
      <main className="main">
        {page === 'overview' ? (scenario !== null
          ? <ScenarioDetailPage client={overview} api={api} id={scenario} onBack={() => setScenario(null)} onOpenReport={openReport} />
          : <OverviewPage client={overview} onOpenScenario={setScenario} onOpenReport={openReport} />) :
          capabilities && page === 'agents' ? <AgentsView client={operations} config={capabilities} /> :
          capabilities && page === 'collections' ? <CollectionsView client={operations} config={capabilities} initialJobId={jobId} onJob={setJobId} /> : <Content
          index={index}
          selected={selected}
          report={report}
          tab={tab}
          onTab={setTab}
          onRefresh={refresh}
          onRetryReport={() => setReportTick((value) => value + 1)}
        />}
      </main>
    </div>
  );
}

function Content({
  index,
  selected,
  report,
  tab,
  onTab,
  onRefresh,
  onRetryReport,
}: {
  index: LoadState<ReportIndex>;
  selected: string | null;
  report: LoadState<AnyReport> | null;
  tab: RunTab;
  onTab: (tab: RunTab) => void;
  onRefresh: () => void;
  onRetryReport: () => void;
}) {
  if (index.status === 'loading') {
    return (
      <>
        <Header title="Đang tải" subtitle={null} status={null} onRefresh={onRefresh} />
        <Skeleton lines={5} label="Đang tải report" />
      </>
    );
  }
  if (index.status !== 'ready') {
    return (
      <>
        <Header title="Không kết nối được backend" subtitle={null} status={null} onRefresh={onRefresh} />
        <EmptyState title="Dashboard cần server report">
          <p>
            Chạy <code>aegis dashboard --reports &lt;thư mục&gt; --static frontend/dist</code> rồi bấm Tải lại. Chi tiết lỗi ở cột
            trái.
          </p>
        </EmptyState>
      </>
    );
  }
  if (selected === null) {
    return (
      <>
        <Header title="Chưa có report" subtitle={null} status={null} onRefresh={onRefresh} />
        <EmptyState title="Chưa có report nào để hiển thị">
          <p>
            Tạo report bằng <code>aegis validate --format json</code> hoặc <code>aegis compare --format json</code>, lưu vào thư
            mục <code>--reports</code> rồi bấm Tải lại.
          </p>
        </EmptyState>
      </>
    );
  }
  if (report === null || report.status === 'loading') {
    return (
      <>
        <Header title={selected} subtitle="Đang tải report…" status={null} onRefresh={onRefresh} />
        <Skeleton lines={6} label={`Đang tải ${selected}`} />
      </>
    );
  }
  if (report.status === 'backend-error') {
    return (
      <>
        <Header title={selected} subtitle="Backend lỗi" status={null} onRefresh={onRefresh} />
        <ErrorPanel
          title="Không đọc được report từ backend"
          message="Server không phản hồi hoặc trả lỗi. Kiểm tra server đang chạy rồi thử lại."
          details={report.reason}
          onRetry={onRetryReport}
        />
      </>
    );
  }
  if (report.status === 'malformed') {
    return (
      <>
        <Header title={selected} subtitle="Report không đúng contract" status={null} onRefresh={onRefresh} />
        <ErrorPanel
          title="Report không đúng contract, không hiển thị một phần"
          message="File không phải report evaluation/comparison hợp lệ. Tạo lại bằng `aegis validate` hoặc `aegis compare --format json`."
          details={report.reason}
          onRetry={onRetryReport}
        />
      </>
    );
  }
  if (report.value.kind === 'evaluation') {
    const { scenario, evaluation } = report.value.report;
    return (
      <>
        <Header
          eyebrow="Run"
          title={evaluation.run_id}
          mono
          subtitle={`${scenario.id} — ${text(scenario.name)} · v${scenario.version} · ${selected}`}
          status={evaluation.final_status}
          onRefresh={onRefresh}
        />
        <RunView report={report.value.report} tab={tab} onTab={onTab} />
      </>
    );
  }
  const { scenario, before, after, comparison } = report.value.report;
  return (
    <>
      <Header
        eyebrow="Comparison"
        title={`${scenario.id} · ${text(scenario.name)}`}
        subtitle={`${before.run_id} → ${after.run_id} · v${scenario.version} · ${selected}`}
        status={comparison.status}
        onRefresh={onRefresh}
      />
      <ComparisonView report={report.value.report} />
    </>
  );
}

function Header({
  eyebrow,
  title,
  mono = false,
  subtitle,
  status,
  onRefresh,
}: {
  eyebrow?: string;
  title: string;
  mono?: boolean;
  subtitle: string | null;
  status: string | null;
  onRefresh: () => void;
}) {
  return (
    <header className="page-header">
      <div className="page-heading">
        {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
        <h1 className={mono ? 'mono' : undefined}>{title}</h1>
        {subtitle ? <p className="page-sub">{subtitle}</p> : null}
      </div>
      <div className="page-actions">
        {status !== null ? <StatusBadge value={status} /> : null}
        <button type="button" className="btn" onClick={onRefresh}>
          Tải lại
        </button>
      </div>
    </header>
  );
}
