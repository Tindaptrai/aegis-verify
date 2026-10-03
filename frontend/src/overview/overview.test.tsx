import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from '../App';
import type { AnyReport, ApiClient, LoadState } from '../api';
import { parseEvaluationReport } from '../contracts';
import { MISSING } from '../format';
import type { OverviewClient } from './api';
import {
  parseScenarioDetail, parseScenarioIndex, parseSystemStatus,
  type ScenarioDetail, type ScenarioIndex, type ScenarioRow, type SystemStatus,
} from './contracts';
import { OverviewPage } from './OverviewPage';
import { ScenarioDetailPage } from './ScenarioDetailPage';
import { attentionRank, DEFAULT_QUERY, resultKey, selectRows } from './select';
import indexFixture from '../../../tests/fixtures/dashboard/overview/scenario-index.json';
import indexNotConfigured from '../../../tests/fixtures/dashboard/overview/scenario-index-not-configured.json';
import detail002 from '../../../tests/fixtures/dashboard/overview/scenario-detail-SCN-002.json';
import detail001 from '../../../tests/fixtures/dashboard/overview/scenario-detail-SCN-001.json';
import statusFixture from '../../../tests/fixtures/dashboard/overview/system-status.json';
import statusNotConfigured from '../../../tests/fixtures/dashboard/overview/system-status-not-configured.json';
import afterFixture from '../../../tests/fixtures/dashboard/after-detected.json';

const clone = <T,>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

function ready<T>(parsed: { ok: true; value: T } | { ok: false; reason: string }): LoadState<T> {
  if (!parsed.ok) throw new Error(parsed.reason);
  return { status: 'ready', value: parsed.value };
}

const indexState = (body: unknown = indexFixture) => ready<ScenarioIndex>(parseScenarioIndex(body));
const statusState = (body: unknown = statusFixture) => ready<SystemStatus>(parseSystemStatus(body));
const detailState = (body: unknown) => ready<ScenarioDetail>(parseScenarioDetail(body));

function client(overrides: Partial<{ index: LoadState<ScenarioIndex>; status: LoadState<SystemStatus>;
  detail: Record<string, LoadState<ScenarioDetail>> }> = {}): OverviewClient & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    scenarios: async () => { calls.push('scenarios'); return overrides.index ?? indexState(); },
    systemStatus: async () => { calls.push('status'); return overrides.status ?? statusState(); },
    scenario: async (id: string) => {
      calls.push(`scenario:${id}`);
      return overrides.detail?.[id] ?? { status: 'backend-error', reason: 'HTTP 404 (scenario_not_found)' };
    },
  };
}

function reportApi(): ApiClient & { requested: string[] } {
  const requested: string[] = [];
  const parsed = parseEvaluationReport(afterFixture);
  if (!parsed.ok) throw new Error(parsed.reason);
  return {
    requested,
    index: async () => ({ status: 'ready', value: { kind: 'report_index', reports: ['scn002-block.json', 'scn002-control.json']
      .map((name) => ({ name, kind: 'evaluation' as const, scenario_id: 'SCN-002', scenario_version: '0.1.0', run_id: name,
        final_status: 'Prevented', comparison_status: null, error: null })) } }),
    report: async (name: string): Promise<LoadState<AnyReport>> => {
      requested.push(name);
      return { status: 'ready', value: { kind: 'evaluation', report: parsed.value } };
    },
  };
}

const table = () => screen.getByRole('table');
const rowIds = () => within(table()).getAllByRole('row').slice(1).map((row) => within(row).getAllByRole('cell')[0]?.textContent);

beforeEach(() => {
  window.history.replaceState(null, '', '/');
});

describe('overview contracts', () => {
  it('reads every checked-in backend fixture', () => {
    expect(parseScenarioIndex(indexFixture).ok).toBe(true);
    expect(parseScenarioIndex(indexNotConfigured).ok).toBe(true);
    expect(parseScenarioDetail(detail002).ok).toBe(true);
    expect(parseScenarioDetail(detail001).ok).toBe(true);
    expect(parseSystemStatus(statusFixture).ok).toBe(true);
    expect(parseSystemStatus(statusNotConfigured).ok).toBe(true);
  });

  it('rejects off-contract bodies instead of showing part of them', () => {
    const negative = clone(indexFixture) as { kpi: { total: number } };
    negative.kpi.total = -1;
    expect(parseScenarioIndex(negative)).toMatchObject({ ok: false });
    const state = clone(indexFixture) as { scenarios: { run_state: string }[] };
    state.scenarios[0]!.run_state = 'maybe';
    expect(parseScenarioIndex(state)).toMatchObject({ ok: false });
    expect(parseSystemStatus({ ...statusFixture, kind: 'report_index' })).toMatchObject({ ok: false });
    expect(parseScenarioDetail({ ...detail002, runs: 'none' })).toMatchObject({ ok: false });
  });

  it('keeps nulls as nulls', () => {
    const body = clone(indexFixture) as { scenarios: { id: string; latest_run: Record<string, unknown> | null }[] };
    const row = body.scenarios.find((item) => item.id === 'SCN-003')!;
    row.latest_run!['window_end'] = null;
    row.latest_run!['evidence_referenced'] = null;
    const parsed = parseScenarioIndex(body);
    if (!parsed.ok) throw new Error(parsed.reason);
    const latest = parsed.value.scenarios.find((item) => item.id === 'SCN-003')!.latest_run!;
    expect(latest.window_end).toBeNull();
    expect(latest.evidence_referenced).toBeNull();
  });
});

describe('row selection', () => {
  const rows = (indexState() as { status: 'ready'; value: ScenarioIndex }).value.scenarios;
  const withStatus = (row: ScenarioRow, status: string | null): ScenarioRow =>
    ({ ...row, latest_run: { ...row.latest_run!, final_status: status } });

  it('orders by the approved attention ranking', () => {
    const scn002 = rows.find((row) => row.id === 'SCN-002')!;
    const fn = { ...withStatus(scn002, 'False negative'), id: 'SCN-010' };
    const mt = { ...withStatus(scn002, 'Missing telemetry'), id: 'SCN-011' };
    const odd = { ...withStatus(scn002, 'Something new'), id: 'SCN-012' };
    const ordered = selectRows([...rows, fn, mt, odd], DEFAULT_QUERY).map((row) => row.id);
    expect(ordered).toEqual(['SCN-010', 'SCN-011', 'SCN-012', 'SCN-001', 'SCN-002', 'SCN-003']);
    expect(resultKey(odd)).toBe('other');
    expect(attentionRank({ ...scn002, run_state: 'stale_only', latest_run: null })).toBe(attentionRank(rows[0]!));
  });

  it('searches by ID, name or profile and filters by result and manifest status', () => {
    expect(selectRows(rows, { ...DEFAULT_QUERY, query: 'deception' }).map((row) => row.id)).toEqual(['SCN-003']);
    expect(selectRows(rows, { ...DEFAULT_QUERY, query: 'scn002-udp' }).map((row) => row.id)).toEqual(['SCN-002']);
    expect(selectRows(rows, { ...DEFAULT_QUERY, result: 'not_run' }).map((row) => row.id)).toEqual(['SCN-001']);
    expect(selectRows(rows, { ...DEFAULT_QUERY, result: 'Prevented' }).map((row) => row.id)).toEqual(['SCN-002']);
    expect(selectRows(rows, { ...DEFAULT_QUERY, manifestStatus: 'ready' })).toEqual([]);
  });

  it('sorts by run time with unrun scenarios last and by ID', () => {
    expect(selectRows(rows, { ...DEFAULT_QUERY, sort: 'run_time' }).map((row) => row.id)).toEqual(['SCN-003', 'SCN-002', 'SCN-001']);
    expect(selectRows(rows, { ...DEFAULT_QUERY, sort: 'id' }).map((row) => row.id)).toEqual(['SCN-001', 'SCN-002', 'SCN-003']);
  });
});

describe('Overview page', () => {
  it('shows KPIs, every scenario including the unrun one, and the latest backend result', async () => {
    render(<OverviewPage client={client()} onOpenScenario={vi.fn()} onOpenReport={vi.fn()} />);
    const kpis = await screen.findByRole('region', { name: 'Chỉ số kịch bản' });
    const kpi = (label: string) => within(kpis).getByText(label).nextElementSibling?.textContent;
    expect(kpi('Tổng kịch bản')).toBe('3');
    expect(kpi('Đã chạy')).toBe('2');
    expect(kpi('Chưa chạy')).toBe('1');
    expect(kpi('Detected')).toBe('1');
    expect(kpi('Prevented')).toBe('1');
    expect(kpi('False negative')).toBe('0');
    expect(rowIds()).toEqual(['SCN-001', 'SCN-002', 'SCN-003']);
    const unrun = within(table()).getAllByRole('row').find((row) => row.textContent?.includes('SCN-001'))!;
    expect(unrun).toHaveClass('is-not-run');
    expect(within(unrun).getByText('Chưa chạy')).toBeInTheDocument();
    const scn002 = within(table()).getAllByRole('row').find((row) => row.textContent?.includes('SCN-002'))!;
    expect(within(scn002).getByText('Prevented')).toBeInTheDocument();
    expect(within(scn002).getByText('4 / 4')).toBeInTheDocument();
    expect(within(scn002).getByText('unknown ×4')).toBeInTheDocument();
  });

  it('shows the overall status with reasons and never presents it as security posture', async () => {
    render(<OverviewPage client={client()} onOpenScenario={vi.fn()} onOpenReport={vi.fn()} />);
    const banner = await screen.findByRole('region', { name: 'Trạng thái tổng' });
    const head = banner.querySelector('.overall-head') as HTMLElement;
    expect(await within(head).findByText('Degraded')).toBeInTheDocument();
    expect(banner).toHaveTextContent('không phải mức an toàn');
    expect(within(banner).getByRole('list', { name: 'Lý do' })).toHaveTextContent('Có report không đọc được');
    expect(within(banner).getByRole('list', { name: 'Lý do' })).toHaveTextContent('Có report không có manifest');
  });

  it('shows component status with its source and does not claim connector health', async () => {
    render(<OverviewPage client={client()} onOpenScenario={vi.fn()} onOpenReport={vi.fn()} />);
    const cowrie = await screen.findByRole('article', { name: 'Cowrie connector' });
    expect(within(cowrie).getByText('Not configured')).toBeInTheDocument();
    expect(cowrie).toHaveTextContent('không có nguồn dữ liệu live');
    expect(cowrie).toHaveTextContent('2 bản ghi trong scn003.json (không phải trạng thái connector)');
    const engine = screen.getByRole('article', { name: 'Validation engine' });
    expect(within(engine).getByText('Unknown')).toBeInTheDocument();
    const storage = screen.getByRole('article', { name: 'Report storage' });
    expect(within(storage).getByText('Degraded')).toBeInTheDocument();
    expect(storage).toHaveTextContent('2026-09-21 14:13:27 UTC');
  });

  it('lists unreadable reports and reports without a manifest instead of hiding them', async () => {
    const onOpenReport = vi.fn();
    render(<OverviewPage client={client()} onOpenScenario={vi.fn()} onOpenReport={onOpenReport} />);
    expect(await screen.findByText('Report không đọc được (1)')).toBeInTheDocument();
    expect(screen.getByText('malformed-truncated.json')).toBeInTheDocument();
    const orphan = screen.getByLabelText('Report không có manifest');
    expect(orphan).toHaveTextContent('SCN-999');
    fireEvent.click(within(orphan).getByRole('button', { name: 'after-detected.json' }));
    expect(onOpenReport).toHaveBeenCalledWith('after-detected.json');
  });

  it('searches, filters, sorts and opens a scenario', async () => {
    const onOpenScenario = vi.fn();
    render(<OverviewPage client={client()} onOpenScenario={onOpenScenario} onOpenReport={vi.fn()} />);
    const search = await screen.findByRole('searchbox', { name: 'Tìm kịch bản theo ID, tên hoặc profile' });
    fireEvent.change(search, { target: { value: 'exfil' } });
    expect(rowIds()).toEqual(['SCN-002']);
    fireEvent.change(search, { target: { value: '' } });
    fireEvent.change(screen.getByLabelText('Kết quả'), { target: { value: 'not_run' } });
    expect(rowIds()).toEqual(['SCN-001']);
    fireEvent.change(screen.getByLabelText('Kết quả'), { target: { value: 'all' } });
    fireEvent.change(screen.getByLabelText('Sắp xếp'), { target: { value: 'run_time' } });
    expect(rowIds()).toEqual(['SCN-003', 'SCN-002', 'SCN-001']);
    fireEvent.change(screen.getByLabelText('Kết quả'), { target: { value: 'False negative' } });
    expect(screen.getByText('Không có kịch bản khớp bộ lọc')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Kết quả'), { target: { value: 'all' } });
    fireEvent.click(screen.getByRole('button', { name: 'Chi tiết SCN-002' }));
    expect(onOpenScenario).toHaveBeenCalledWith('SCN-002');
  });

  it('renders missing values as no data and keeps unknown statuses verbatim', async () => {
    const body = clone(indexFixture) as { scenarios: { id: string; latest_run: Record<string, unknown> | null }[] };
    const row = body.scenarios.find((item) => item.id === 'SCN-003')!;
    row.latest_run!['window_end'] = null;
    row.latest_run!['evidence_referenced'] = null;
    const status = clone(statusFixture) as { components: { id: string; status: string }[] };
    status.components.find((item) => item.id === 'validation_engine')!.status = 'warming_up';
    render(<OverviewPage client={client({ index: indexState(body), status: statusState(status) })}
      onOpenScenario={vi.fn()} onOpenReport={vi.fn()} />);
    const scn003 = (await screen.findAllByRole('row')).find((item) => item.textContent?.includes('SCN-003'))!;
    const cells = within(scn003).getAllByRole('cell');
    expect(cells[6]).toHaveTextContent(MISSING);
    expect(cells[8]).toHaveTextContent(MISSING);
    expect(within(screen.getByRole('article', { name: 'Validation engine' })).getByText('warming_up')).toBeInTheDocument();
  });

  it('shows Not configured and no-data KPIs when the dashboard runs without manifests', async () => {
    render(<OverviewPage client={client({ index: indexState(indexNotConfigured), status: statusState(statusNotConfigured) })}
      onOpenScenario={vi.fn()} onOpenReport={vi.fn()} />);
    expect(await screen.findByText('Scenario registry: Not configured')).toBeInTheDocument();
    const kpis = screen.getByRole('region', { name: 'Chỉ số kịch bản' });
    expect(within(kpis).getByText('Tổng kịch bản').nextElementSibling).toHaveTextContent(MISSING);
    expect(within(kpis).getByText('Detected').nextElementSibling).toHaveTextContent(MISSING);
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
    const banner = screen.getByRole('region', { name: 'Trạng thái tổng' });
    expect(await within(banner).findByText('Not configured')).toBeInTheDocument();
  });

  it('shows Unknown and errors, not health, when the backend fails', async () => {
    const failing = client({
      index: { status: 'backend-error', reason: 'Không kết nối được backend (/api/scenarios).' },
      status: { status: 'malformed', reason: 'status.kind: expected "system_status"' },
    });
    render(<OverviewPage client={failing} onOpenScenario={vi.fn()} onOpenReport={vi.fn()} />);
    const banner = await screen.findByRole('region', { name: 'Trạng thái tổng' });
    expect(await within(banner).findByText('Unknown')).toBeInTheDocument();
    expect(banner).toHaveTextContent('status.kind: expected "system_status"');
    expect(await screen.findByText('Không đọc được danh sách kịch bản')).toBeInTheDocument();
    expect(screen.getByText('Không đọc được trạng thái hệ thống')).toBeInTheDocument();
    expect(screen.queryByText('Healthy')).not.toBeInTheDocument();
  });
});

describe('Scenario detail', () => {
  it('shows manifest metadata, run history, comparisons and the latest run from its report', async () => {
    const api = reportApi();
    const onOpenReport = vi.fn();
    render(<ScenarioDetailPage client={client({ detail: { 'SCN-002': detailState(detail002) } })} api={api} id="SCN-002"
      onBack={vi.fn()} onOpenReport={onOpenReport} />);
    expect(await screen.findByRole('heading', { name: 'SCN-002 · Attempted Exfiltration' })).toBeInTheDocument();
    const metadata = screen.getByRole('region', { name: 'Metadata kịch bản' });
    expect(metadata).toHaveTextContent('prevented');
    expect(metadata).toHaveTextContent('SCN-002-A04');
    const history = screen.getByRole('region', { name: 'Lịch sử lượt chạy' });
    const rows = within(history).getAllByRole('row').slice(1);
    expect(rows.map((row) => within(row).getAllByRole('cell')[0]?.textContent)).toEqual(['scn002-block.json', 'scn002-control.json']);
    expect(rows[0]).toHaveTextContent('Khớp');
    fireEvent.click(within(rows[1]!).getByRole('button', { name: 'Mở report' }));
    expect(onOpenReport).toHaveBeenCalledWith('scn002-control.json');
    expect(screen.getByRole('region', { name: 'So sánh trước sau' })).toHaveTextContent('scn002-compare.json');
    await waitFor(() => expect(api.requested).toEqual(['scn002-block.json']));
    const latest = screen.getByRole('region', { name: 'Lượt chạy gần nhất' });
    expect(await within(latest).findByRole('tab', { name: /Assertions/ })).toBeInTheDocument();
  });

  it('says a never-run scenario has no detection conclusion and loads no report', async () => {
    const api = reportApi();
    render(<ScenarioDetailPage client={client({ detail: { 'SCN-001': detailState(detail001) } })} api={api} id="SCN-001"
      onBack={vi.fn()} onOpenReport={vi.fn()} />);
    expect(await screen.findByText('Không có kết luận detection.', { exact: false })).toBeInTheDocument();
    expect(screen.getByText('Chưa có lượt chạy nào.')).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Lượt chạy gần nhất' })).not.toBeInTheDocument();
    expect(api.requested).toEqual([]);
  });

  it('keeps runs of a changed manifest as history without a current result', async () => {
    const stale = clone(detail002) as { run_state: string; latest_run: unknown; runs: Record<string, unknown>[] };
    stale.run_state = 'stale_only';
    stale.latest_run = null;
    stale.runs = stale.runs.map((run) => ({ ...run, manifest_match: false, mismatch: 'version' }));
    const api = reportApi();
    render(<ScenarioDetailPage client={client({ detail: { 'SCN-002': detailState(stale) } })} api={api} id="SCN-002"
      onBack={vi.fn()} onOpenReport={vi.fn()} />);
    expect(await screen.findByText('Chỉ có lượt của manifest cũ')).toBeInTheDocument();
    expect(screen.getAllByText('Khác: version manifest khác')).toHaveLength(2);
    expect(screen.queryByRole('region', { name: 'Lượt chạy gần nhất' })).not.toBeInTheDocument();
    expect(api.requested).toEqual([]);
  });

  it('shows an error for an unknown scenario and retries', async () => {
    const failing = client();
    render(<ScenarioDetailPage client={failing} api={reportApi()} id="SCN-404" onBack={vi.fn()} onOpenReport={vi.fn()} />);
    expect(await screen.findByText('Không đọc được chi tiết kịch bản')).toBeInTheDocument();
    expect(screen.getByText(/scenario_not_found/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Thử lại' }));
    await waitFor(() => expect(failing.calls.filter((call) => call === 'scenario:SCN-404')).toHaveLength(2));
  });
});

describe('App navigation', () => {
  it('marks a report as current only while the report page is open', async () => {
    render(<App api={reportApi()} overviewClient={client()}
      operationsClient={{ bootstrap: async () => { throw new Error('off'); } } as never} />);
    const library = screen.getByRole('complementary', { name: 'Danh sách report' });
    const report = await within(library).findByRole('button', { name: /scn002-block.json — scn002-block.json/ });
    expect(report).not.toHaveAttribute('aria-current');
    fireEvent.click(report);
    await waitFor(() => expect(report).toHaveAttribute('aria-current', 'page'));
    fireEvent.click(within(library).getByRole('button', { name: 'Tổng quan' }));
    await screen.findByRole('heading', { name: 'Tổng quan' });
    expect(report).not.toHaveAttribute('aria-current');
  });

  it('lands on the overview, opens a scenario, goes back and opens a report', async () => {
    const api = reportApi();
    render(<App api={api} overviewClient={client({ detail: { 'SCN-002': detailState(detail002) } })}
      operationsClient={{ bootstrap: async () => { throw new Error('off'); } } as never} />);
    expect(await screen.findByRole('heading', { name: 'Tổng quan' })).toBeInTheDocument();
    fireEvent.click(await screen.findByRole('button', { name: 'Chi tiết SCN-002' }));
    expect(await screen.findByRole('heading', { name: 'SCN-002 · Attempted Exfiltration' })).toBeInTheDocument();
    await waitFor(() => expect(window.location.hash).toBe('#scenario=SCN-002'));
    fireEvent.click(screen.getByRole('button', { name: '← Tổng quan' }));
    expect(await screen.findByRole('heading', { name: 'Tổng quan' })).toBeInTheDocument();
    await waitFor(() => expect(window.location.hash).toBe(''));
    fireEvent.click(await screen.findByRole('button', { name: 'Chi tiết SCN-002' }));
    const history = await screen.findByRole('region', { name: 'Lịch sử lượt chạy' });
    fireEvent.click(within(history).getAllByRole('button', { name: 'Mở report' })[0]!);
    await waitFor(() => expect(window.location.hash).toBe('#report=scn002-block.json&tab=assertions'));
  });

  it('follows a hash change made while the app is open', async () => {
    render(<App api={reportApi()} overviewClient={client({ detail: { 'SCN-002': detailState(detail002) } })}
      operationsClient={{ bootstrap: async () => { throw new Error('off'); } } as never} />);
    expect(await screen.findByRole('heading', { name: 'Tổng quan' })).toBeInTheDocument();
    window.history.pushState(null, '', '/#scenario=SCN-002');
    window.dispatchEvent(new HashChangeEvent('hashchange'));
    expect(await screen.findByRole('heading', { name: 'SCN-002 · Attempted Exfiltration' })).toBeInTheDocument();
  });

  it('opens a scenario straight from a shared link', async () => {
    window.history.replaceState(null, '', '/#scenario=SCN-002');
    render(<App api={reportApi()} overviewClient={client({ detail: { 'SCN-002': detailState(detail002) } })}
      operationsClient={{ bootstrap: async () => { throw new Error('off'); } } as never} />);
    expect(await screen.findByRole('heading', { name: 'SCN-002 · Attempted Exfiltration' })).toBeInTheDocument();
  });
});
