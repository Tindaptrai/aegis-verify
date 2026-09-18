import { useCallback, useEffect, useState } from 'react';
import type { AnyReport, ApiClient, LoadState } from './api';
import type { IndexEntry, ReportIndex } from './contracts';
import { ComparisonView } from './components/ComparisonView';
import { RunView } from './components/RunView';
import { StateNotice } from './components/StateNotice';
import { StatusBadge } from './components/StatusBadge';

export interface AppProps {
  api: ApiClient;
}

export function App({ api }: AppProps) {
  const [index, setIndex] = useState<LoadState<ReportIndex>>({ status: 'loading' });
  const [selected, setSelected] = useState<string | null>(null);
  const [report, setReport] = useState<LoadState<AnyReport> | null>(null);

  const loadIndex = useCallback(() => {
    setIndex({ status: 'loading' });
    void api.index().then(setIndex);
  }, [api]);

  useEffect(() => {
    loadIndex();
  }, [loadIndex]);

  useEffect(() => {
    if (selected === null) {
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
  }, [api, selected]);

  return (
    <div className="layout">
      <aside className="sidebar" aria-label="Danh sách report">
        <header className="brand">
          <h1>AEGIS Verify</h1>
          <p>Kết quả validation offline, chỉ đọc. Mọi giá trị hiển thị nguyên như backend trả.</p>
          <button type="button" onClick={loadIndex} className="link">
            Tải lại danh sách
          </button>
        </header>
        <IndexPanel state={index} selected={selected} onSelect={setSelected} />
      </aside>
      <main className="content">
        {selected === null ? (
          <StateNotice tone="neutral" title="Chưa chọn report">
            Chọn một report ở cột trái. Report `evaluation` hiện một run; report `comparison` hiện trước/sau.
          </StateNotice>
        ) : (
          <ReportPanel name={selected} state={report} />
        )}
      </main>
    </div>
  );
}

function IndexPanel({
  state,
  selected,
  onSelect,
}: {
  state: LoadState<ReportIndex>;
  selected: string | null;
  onSelect: (name: string) => void;
}) {
  if (state.status === 'loading') return <StateNotice tone="neutral" title="Đang tải danh sách report…" />;
  if (state.status === 'backend-error') {
    return (
      <StateNotice tone="error" title="Không lấy được danh sách từ backend">
        {state.reason} Chạy <code>aegis dashboard --reports &lt;thư mục&gt;</code> rồi tải lại.
      </StateNotice>
    );
  }
  if (state.status === 'malformed') {
    return (
      <StateNotice tone="warning" title="Danh sách report không đúng contract">
        {state.reason}
      </StateNotice>
    );
  }
  if (state.value.reports.length === 0) {
    return (
      <StateNotice tone="neutral" title="Thư mục report trống">
        Không có file <code>*.json</code> nào. Tạo report bằng <code>aegis validate --format json</code> hoặc{' '}
        <code>aegis compare --format json</code>.
      </StateNotice>
    );
  }
  return (
    <ul className="report-list">
      {state.value.reports.map((entry) => (
        <li key={entry.name}>
          <button
            type="button"
            className={`report-item${selected === entry.name ? ' selected' : ''}`}
            aria-current={selected === entry.name ? 'true' : undefined}
            onClick={() => onSelect(entry.name)}
          >
            <span className="report-name">{entry.name}</span>
            <IndexSummary entry={entry} />
          </button>
        </li>
      ))}
    </ul>
  );
}

function IndexSummary({ entry }: { entry: IndexEntry }) {
  if (entry.error !== null) {
    return (
      <span className="report-meta bad">
        malformed · {entry.error.code}
        {entry.error.field ? ` (${entry.error.field})` : ''}
      </span>
    );
  }
  if (entry.kind === 'evaluation') {
    return (
      <span className="report-meta">
        run · {entry.scenario_id ?? 'scenario?'} · {entry.run_id ?? 'run_id: null'} ·{' '}
        <StatusBadge value={entry.final_status} />
      </span>
    );
  }
  if (entry.kind === 'comparison') {
    return (
      <span className="report-meta">
        comparison · {entry.scenario_id ?? 'scenario?'} · <StatusBadge value={entry.comparison_status} />
      </span>
    );
  }
  return <span className="report-meta">kind: null</span>;
}

function ReportPanel({ name, state }: { name: string; state: LoadState<AnyReport> | null }) {
  if (state === null || state.status === 'loading') {
    return <StateNotice tone="neutral" title={`Đang tải ${name}…`} />;
  }
  if (state.status === 'backend-error') {
    return (
      <StateNotice tone="error" title={`Backend lỗi khi đọc ${name}`}>
        {state.reason}
      </StateNotice>
    );
  }
  if (state.status === 'malformed') {
    return (
      <StateNotice tone="warning" title={`${name} không đúng contract report`}>
        {state.reason} Dashboard không hiển thị một phần report để tránh kết luận sai.
      </StateNotice>
    );
  }
  if (state.value.kind === 'evaluation') return <RunView name={name} report={state.value.report} />;
  return <ComparisonView name={name} report={state.value.report} />;
}
