import type { LoadState } from '../api';
import type { IndexEntry, ReportIndex } from '../contracts';
import { text } from '../format';
import { EmptyState, ErrorPanel, Notice, Skeleton } from './Feedback';
import { StatusBadge } from './StatusBadge';
import type { ReactNode } from 'react';

export function orderEntries(entries: IndexEntry[]): IndexEntry[] {
  const runs = entries.filter((entry) => entry.error === null && entry.kind === 'evaluation');
  const comparisons = entries.filter((entry) => entry.error === null && entry.kind === 'comparison');
  const unreadable = entries.filter((entry) => entry.error !== null || entry.kind === null);
  return [...runs, ...comparisons, ...unreadable];
}

export function matchesQuery(entry: IndexEntry, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (needle === '') return true;
  const haystack = [
    entry.name,
    entry.scenario_id,
    entry.scenario_version,
    entry.run_id,
    entry.final_status,
    entry.comparison_status,
    entry.error?.code ?? null,
  ];
  return haystack.some((value) => value !== null && value.toLowerCase().includes(needle));
}

export function Sidebar({
  state,
  selected,
  query,
  onQuery,
  onSelect,
  onRetry,
  operationsNav,
}: {
  state: LoadState<ReportIndex>;
  selected: string | null;
  query: string;
  onQuery: (value: string) => void;
  onSelect: (name: string) => void;
  onRetry: () => void;
  operationsNav?: ReactNode;
}) {
  return (
    <aside className="sidebar" aria-label="Danh sách report">
      <div className="brand">
        <span className="brand-mark" aria-hidden="true" />
        <div>
          <p className="brand-name">AEGIS Verify</p>
          <p className="brand-sub">Results dashboard · chỉ đọc</p>
        </div>
      </div>
      {operationsNav}
      <label className="search">
        <span className="visually-hidden">Tìm report</span>
        <input
          type="search"
          value={query}
          onChange={(event) => onQuery(event.target.value)}
          placeholder="Tìm run, scenario, trạng thái, file"
          autoComplete="off"
          disabled={state.status !== 'ready'}
        />
      </label>
      <nav className="nav">
        <SidebarBody state={state} selected={selected} query={query} onSelect={onSelect} onRetry={onRetry} />
      </nav>
    </aside>
  );
}

function SidebarBody({
  state,
  selected,
  query,
  onSelect,
  onRetry,
}: {
  state: LoadState<ReportIndex>;
  selected: string | null;
  query: string;
  onSelect: (name: string) => void;
  onRetry: () => void;
}) {
  if (state.status === 'loading') return <Skeleton lines={6} label="Đang tải danh sách report" />;
  if (state.status === 'backend-error') {
    return (
      <ErrorPanel
        title="Không lấy được danh sách report"
        message="Backend không phản hồi. Kiểm tra server `aegis dashboard --reports <thư mục>` rồi thử lại."
        details={state.reason}
        onRetry={onRetry}
      />
    );
  }
  if (state.status === 'malformed') {
    return (
      <ErrorPanel
        title="Danh sách report không đúng contract"
        message="Backend trả dữ liệu không đúng dạng `report_index`; không hiển thị để tránh sai lệch."
        details={state.reason}
        onRetry={onRetry}
      />
    );
  }
  const ordered = orderEntries(state.value.reports);
  if (ordered.length === 0) {
    return (
      <EmptyState title="Chưa có report">
        <p>
          Thư mục `--reports` không có file <code>*.json</code>.
        </p>
      </EmptyState>
    );
  }
  const visible = ordered.filter((entry) => matchesQuery(entry, query));
  if (visible.length === 0) {
    return (
      <Notice tone="info" title="Không có report khớp từ khóa">
        <p>Xóa hoặc đổi từ khóa tìm kiếm.</p>
      </Notice>
    );
  }
  const groups: Array<{ id: string; title: string; entries: IndexEntry[] }> = [
    { id: 'runs', title: 'Runs', entries: visible.filter((e) => e.error === null && e.kind === 'evaluation') },
    { id: 'comparisons', title: 'Comparisons', entries: visible.filter((e) => e.error === null && e.kind === 'comparison') },
    { id: 'unreadable', title: 'Không đọc được', entries: visible.filter((e) => e.error !== null || e.kind === null) },
  ];
  return (
    <>
      {groups
        .filter((group) => group.entries.length > 0)
        .map((group) => (
          <section key={group.id} className="nav-group" aria-labelledby={`group-${group.id}`}>
            <h2 id={`group-${group.id}`} className="nav-group-title">
              {group.title} <span className="nav-count">{group.entries.length}</span>
            </h2>
            <ul className="nav-list">
              {group.entries.map((entry) => (
                <li key={entry.name}>
                  <NavItem entry={entry} selected={selected === entry.name} onSelect={onSelect} />
                </li>
              ))}
            </ul>
          </section>
        ))}
    </>
  );
}

function NavItem({ entry, selected, onSelect }: { entry: IndexEntry; selected: boolean; onSelect: (name: string) => void }) {
  const unreadable = entry.error !== null || entry.kind === null;
  const primary =
    entry.kind === 'evaluation' ? text(entry.run_id) : entry.kind === 'comparison' ? text(entry.scenario_id) : entry.name;
  const secondary =
    entry.kind === 'evaluation'
      ? `${text(entry.scenario_id)} ${entry.scenario_version ?? ''}`.trim()
      : entry.kind === 'comparison'
        ? 'So sánh trước / sau'
        : `${entry.error?.code ?? 'kind: null'}${entry.error?.field ? ` (${entry.error.field})` : ''}`;
  const status = entry.kind === 'evaluation' ? entry.final_status : entry.kind === 'comparison' ? entry.comparison_status : null;
  return (
    <button
      type="button"
      className={`nav-item${selected ? ' selected' : ''}${unreadable ? ' unreadable' : ''}`}
      aria-current={selected ? 'page' : undefined}
      aria-label={`${primary} — ${entry.name}`}
      onClick={() => onSelect(entry.name)}
    >
      <span className="nav-primary">
        <span className={entry.kind === 'evaluation' ? 'mono' : ''}>{primary}</span>
        {unreadable ? <span className="badge bad sm">lỗi</span> : <StatusBadge value={status} size="sm" />}
      </span>
      <span className="nav-secondary">{secondary}</span>
      {entry.kind !== null && entry.error === null ? <span className="nav-file">{entry.name}</span> : null}
    </button>
  );
}
