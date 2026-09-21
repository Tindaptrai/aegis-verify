import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { createApiClient } from './api';
import afterFixture from '../../tests/fixtures/dashboard/after-detected.json';
import beforeFixture from '../../tests/fixtures/dashboard/before-false-negative.json';
import comparisonFixture from '../../tests/fixtures/dashboard/comparison-regression-passed.json';

type Route = { status: number; body?: unknown; text?: string } | 'network-error';

function fakeFetch(routes: Record<string, Route | Route[]>) {
  const calls: Record<string, number> = {};
  const impl = async (input: string): Promise<Response> => {
    calls[input] = (calls[input] ?? 0) + 1;
    const configured = routes[input];
    const route = Array.isArray(configured) ? configured[Math.min(calls[input] - 1, configured.length - 1)] : configured;
    if (route === undefined) return new Response('{"kind":"error","error":{"code":"not_found"}}', { status: 404 });
    if (route === 'network-error') throw new TypeError('Failed to fetch');
    const text = route.text ?? JSON.stringify(route.body ?? null);
    return new Response(text, { status: route.status, headers: { 'Content-Type': 'application/json' } });
  };
  return { impl, calls };
}

const index = (reports: unknown[]) => ({ status: 200, body: { kind: 'report_index', version: '0.1.0', reports } });

const entries = [
  { name: 'after-detected.json', kind: 'evaluation', scenario_id: 'SCN-999', scenario_version: '0.1.0',
    run_id: 'synthetic-run-after-fix', final_status: 'Detected', comparison_status: null, error: null },
  { name: 'before-false-negative.json', kind: 'evaluation', scenario_id: 'SCN-999', scenario_version: '0.1.0',
    run_id: 'synthetic-run-before-gap', final_status: 'False negative', comparison_status: null, error: null },
  { name: 'comparison-regression-passed.json', kind: 'comparison', scenario_id: 'SCN-999', scenario_version: '0.1.0',
    run_id: null, final_status: null, comparison_status: 'Regression Passed', error: null },
  { name: 'malformed-truncated.json', kind: null, scenario_id: null, scenario_version: null, run_id: null,
    final_status: null, comparison_status: null, error: { code: 'invalid_json', stage: 'inputs', field: null } },
];

const allReports: Record<string, Route> = {
  '/api/reports': index(entries),
  '/api/reports/after-detected.json': { status: 200, body: afterFixture },
  '/api/reports/before-false-negative.json': { status: 200, body: beforeFixture },
  '/api/reports/comparison-regression-passed.json': { status: 200, body: comparisonFixture },
  '/api/reports/malformed-truncated.json': {
    status: 422,
    body: { kind: 'error', error: { code: 'invalid_json', stage: 'inputs', field: null, hint: 'x' } },
  },
};

function renderApp(routes: Record<string, Route | Route[]>) {
  const fetcher = fakeFetch(routes);
  render(<App api={createApiClient(fetcher.impl)} />);
  return fetcher;
}

const sidebar = () => screen.getByRole('complementary', { name: 'Danh sách report' });
const main = () => screen.getByRole('main');

beforeEach(() => {
  window.history.replaceState(null, '', '/');
});

describe('App states', () => {
  it('shows skeletons while loading, then a structured empty state', async () => {
    renderApp({ '/api/reports': index([]) });
    expect(within(sidebar()).getByRole('status', { name: 'Đang tải danh sách report' })).toBeInTheDocument();
    expect(within(main()).getByRole('status', { name: 'Đang tải report' })).toBeInTheDocument();
    expect(await within(sidebar()).findByText('Chưa có report')).toBeInTheDocument();
    expect(within(main()).getByText('Chưa có report nào để hiển thị')).toBeInTheDocument();
    expect(within(main()).getByRole('button', { name: 'Tải lại' })).toBeInTheDocument();
  });

  it('shows a backend error with retry and technical details, and retry recovers', async () => {
    const fetcher = renderApp({ '/api/reports': ['network-error', index([])] });
    const alert = await within(sidebar()).findByRole('alert');
    expect(alert).toHaveTextContent('Không lấy được danh sách report');
    expect(within(alert).getByText('Chi tiết kỹ thuật')).toBeInTheDocument();
    expect(within(alert).getByText(/Không kết nối được backend/)).toBeInTheDocument();
    fireEvent.click(within(alert).getByRole('button', { name: 'Thử lại' }));
    expect(await within(sidebar()).findByText('Chưa có report')).toBeInTheDocument();
    expect(fetcher.calls['/api/reports']).toBe(2);
  });

  it('shows a backend error for HTTP 500 without inventing a list', async () => {
    renderApp({ '/api/reports': { status: 500, body: { kind: 'error', error: { code: 'internal_error' } } } });
    const alert = await within(sidebar()).findByRole('alert');
    expect(within(alert).getByText(/HTTP 500/)).toBeInTheDocument();
    expect(within(sidebar()).queryByRole('list')).not.toBeInTheDocument();
  });

  it('shows a malformed state when the index is off-contract', async () => {
    renderApp({ '/api/reports': { status: 200, body: { kind: 'something-else' } } });
    expect(await within(sidebar()).findByText('Danh sách report không đúng contract')).toBeInTheDocument();
  });
});

describe('Sidebar', () => {
  it('groups runs, comparisons and unreadable files, with run ID as primary text', async () => {
    renderApp(allReports);
    const nav = sidebar();
    expect(await within(nav).findByRole('heading', { name: /Runs 2/ })).toBeInTheDocument();
    expect(within(nav).getByRole('heading', { name: /Comparisons 1/ })).toBeInTheDocument();
    expect(within(nav).getByRole('heading', { name: /Không đọc được 1/ })).toBeInTheDocument();
    const item = within(nav).getByRole('button', { name: 'synthetic-run-before-gap — before-false-negative.json' });
    expect(item).toHaveTextContent('SCN-999 0.1.0');
    expect(item).toHaveTextContent('False negative');
    const broken = within(nav).getByRole('button', { name: 'malformed-truncated.json — malformed-truncated.json' });
    expect(broken).toHaveTextContent('invalid_json');
  });

  it('auto-selects the first readable run and marks it selected', async () => {
    renderApp(allReports);
    const item = await within(sidebar()).findByRole('button', { name: 'synthetic-run-after-fix — after-detected.json' });
    await waitFor(() => expect(item).toHaveAttribute('aria-current', 'page'));
    expect(await within(main()).findByRole('heading', { level: 1, name: 'synthetic-run-after-fix' })).toBeInTheDocument();
    expect(window.location.hash).toContain('report=after-detected.json');
  });

  it('opens the report named in the URL hash', async () => {
    window.history.replaceState(null, '', '/#report=comparison-regression-passed.json');
    renderApp(allReports);
    expect(await within(main()).findByRole('heading', { level: 1, name: /SCN-999/ })).toBeInTheDocument();
    expect(within(main()).getByText('synthetic-run-before-gap → synthetic-run-after-fix', { exact: false })).toBeInTheDocument();
  });

  it('filters the list with the search box', async () => {
    renderApp(allReports);
    const nav = sidebar();
    await within(nav).findByRole('heading', { name: /Runs 2/ });
    fireEvent.change(within(nav).getByRole('searchbox', { name: 'Tìm report' }), { target: { value: 'before' } });
    expect(within(nav).getAllByRole('button', { name: /—/ })).toHaveLength(1);
    expect(within(nav).getByRole('heading', { name: /Runs 1/ })).toBeInTheDocument();
    fireEvent.change(within(nav).getByRole('searchbox', { name: 'Tìm report' }), { target: { value: 'nothing-here' } });
    expect(within(nav).getByText('Không có report khớp từ khóa')).toBeInTheDocument();
  });
});

describe('Run view', () => {
  it('renders a prototype-named assertion without crashing or inventing a description', async () => {
    const report = structuredClone(afterFixture);
    report.evaluation.assertions[0]!.assertion_id = '__proto__';
    renderApp({ ...allReports, '/api/reports/after-detected.json': { status: 200, body: report } });
    expect(await within(main()).findByText('__proto__')).toBeInTheDocument();
  });

  it('rejects negative counts before showing charts', async () => {
    const report = structuredClone(afterFixture);
    report.evaluation.counts.false_negative = -1;
    renderApp({ ...allReports, '/api/reports/after-detected.json': { status: 200, body: report } });
    expect(await within(main()).findByRole('alert')).toHaveTextContent('Report không đúng contract');
  });
  it('shows header, overview numbers, assertion descriptions and expandable details', async () => {
    renderApp(allReports);
    const content = main();
    await within(content).findByRole('heading', { level: 1, name: 'synthetic-run-after-fix' });
    expect(within(content).getByText(/SCN-999 — Synthetic dashboard example · v0\.1\.0 · after-detected\.json/)).toBeInTheDocument();
    const overview = within(content).getByRole('region', { name: 'Tổng quan' });
    expect(within(overview).getByText('Detected')).toBeInTheDocument();
    expect(within(overview).getByText('/ 2 satisfied')).toBeInTheDocument();
    expect(within(overview).getByText('false_negative 0 · missing_telemetry 0 · inconclusive 0')).toBeInTheDocument();
    expect(within(overview).getByText('parsed 2 · skipped 0 · referenced 2')).toBeInTheDocument();
    expect(within(content).getByText('Scenario status: draft')).toBeInTheDocument();
    expect(within(content).getByText('Collection assurance: unknown cho mọi assertion')).toBeInTheDocument();

    const rows = within(content).getAllByRole('row').slice(1);
    expect(rows).toHaveLength(2);
    expect(rows[1]).toHaveTextContent('SCN-999-A02');
    expect(rows[1]).toHaveTextContent('Distinct correlated synthetic alert exists.');
    expect(rows[1]).toHaveTextContent('satisfied');
    fireEvent.click(within(rows[1]!).getByRole('button', { name: 'Chi tiết' }));
    expect(within(content).getByText('witness_found')).toBeInTheDocument();
    expect(within(content).getByText(/target wazuh:evidence-v1:.* ← anchor wazuh:evidence-v1:/)).toBeInTheDocument();
  });

  it('keeps timeline order and renders null fields as no-data, and links evidence to the timeline', async () => {
    renderApp(allReports);
    const content = main();
    await within(content).findByRole('heading', { level: 1, name: 'synthetic-run-after-fix' });
    fireEvent.click(within(content).getByRole('tab', { name: /Timeline/ }));
    const list = within(content).getByRole('list', { name: 'Evidence timeline theo thứ tự thời gian' });
    const items = within(list).getAllByRole('listitem');
    expect(items).toHaveLength(2);
    expect(items[0]).toHaveTextContent('2026-01-01T00:00:01Z');
    expect(items[1]).toHaveTextContent('2026-01-01T00:00:02Z');
    expect(within(items[0]!).getAllByText('Không có dữ liệu').length).toBeGreaterThan(0);
    expect(items[0]).toHaveTextContent('900001');

    fireEvent.click(within(content).getByRole('tab', { name: /Assertions/ }));
    const chips = within(content).getAllByRole('button', { name: /wazuh:evidence/ });
    fireEvent.click(chips[0]!);
    expect(within(content).getByRole('tab', { name: /Timeline/ })).toHaveAttribute('aria-selected', 'true');
    const highlighted = within(content).getByRole('list', { name: 'Evidence timeline theo thứ tự thời gian' })
      .querySelector('li.highlight');
    expect(highlighted).not.toBeNull();
  });

  it('shows the caller-attested notice for a false negative run', async () => {
    window.history.replaceState(null, '', '/#report=before-false-negative.json');
    renderApp(allReports);
    const content = main();
    await within(content).findByRole('heading', { level: 1, name: 'synthetic-run-before-gap' });
    expect(within(content).getByText(/caller-attested\)$/)).toBeInTheDocument();
    expect(within(content).getByText(/synthetic-only\/collection-attestation/)).toBeInTheDocument();
    expect(within(content).getByText('false_negative')).toBeInTheDocument();
  });

  it('shows the configured source label apart from the observed host, and falls back to the ref', async () => {
    renderApp(allReports);
    const content = main();
    await within(content).findByRole('heading', { level: 1, name: 'synthetic-run-after-fix' });
    fireEvent.click(within(content).getByRole('tab', { name: /Timeline/ }));
    const items = within(content).getAllByRole('listitem');

    const labelled = items.find((item) => item.textContent?.includes('Synthetic endpoint'))!;
    expect(labelled).toBeDefined();
    expect(labelled).toHaveTextContent('Nguồn');
    expect(labelled).toHaveTextContent('Synthetic endpoint (cấu hình)');
    // The observed hostname keeps its own field and is marked as observed.
    expect(labelled).toHaveTextContent('Host (quan sát)');
    expect(labelled).toHaveTextContent('synthetic-host');

    const unlabelled = items.find((item) => item.textContent?.includes('synthetic-alert#record=1'))!;
    expect(unlabelled).toBeDefined();
    expect(unlabelled).toHaveTextContent('synthetic-alert (source ref)');
    expect(unlabelled).not.toHaveTextContent('Synthetic endpoint');
  });

  it('marks bytes the manifest declares as an extract, and stays quiet for a native record', async () => {
    const timeline = afterFixture.timeline as { events: Record<string, unknown>[] };
    const report = {
      ...afterFixture,
      timeline: {
        ...timeline,
        events: timeline.events.map((event, index) =>
          index === 0 ? { ...event, source_derived: true } : event,
        ),
      },
    };
    renderApp({ ...allReports, '/api/reports/after-detected.json': { status: 200, body: report } });
    const content = main();
    await within(content).findByRole('heading', { level: 1, name: 'synthetic-run-after-fix' });
    fireEvent.click(within(content).getByRole('tab', { name: /Timeline/ }));
    const items = within(content).getAllByRole('listitem');
    const derived = items.find((item) => item.textContent?.includes('Synthetic endpoint'))!;
    expect(derived).toHaveTextContent('bản trích');
    const native = items.find((item) => item.textContent?.includes('synthetic-alert#record=1'))!;
    expect(native).not.toHaveTextContent('bản trích');
  });

  it('says the byte source is unknown when an older report is silent about it', async () => {
    const timeline = afterFixture.timeline as { events: Record<string, unknown>[] };
    const legacy = {
      ...afterFixture,
      timeline: {
        ...timeline,
        events: timeline.events.map(({ source_derived: _flag, ...rest }) => rest),
      },
    };
    renderApp({ ...allReports, '/api/reports/after-detected.json': { status: 200, body: legacy } });
    const content = main();
    await within(content).findByRole('heading', { level: 1, name: 'synthetic-run-after-fix' });
    fireEvent.click(within(content).getByRole('tab', { name: /Timeline/ }));
    expect(within(content).getAllByText(/nguồn bytes: không có dữ liệu/).length).toBe(2);
  });

  it('explains a report without a timeline instead of ordering by guesswork', async () => {
    const { timeline: _omitted, ...legacy } = afterFixture;
    renderApp({ ...allReports, '/api/reports/after-detected.json': { status: 200, body: legacy } });
    const content = main();
    await within(content).findByRole('heading', { level: 1, name: 'synthetic-run-after-fix' });
    fireEvent.click(within(content).getByRole('tab', { name: /Timeline/ }));
    expect(within(content).getByText('Report này không có mục timeline')).toBeInTheDocument();
    expect(within(content).getByRole('list', { name: 'Evidence index, không theo thời gian' })).toBeInTheDocument();
  });

  it('shows the malformed state for a 422 report with technical details and retry', async () => {
    window.history.replaceState(null, '', '/#report=malformed-truncated.json');
    renderApp(allReports);
    const alert = await within(main()).findByRole('alert');
    expect(alert).toHaveTextContent('Report không đúng contract, không hiển thị một phần');
    expect(within(alert).getByText(/invalid_json/)).toBeInTheDocument();
    expect(within(alert).getByRole('button', { name: 'Thử lại' })).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Tổng quan' })).not.toBeInTheDocument();
  });

  it('shows the malformed state for a 200 body that is off-contract', async () => {
    renderApp({ ...allReports, '/api/reports/after-detected.json': { status: 200, body: { kind: 'evaluation', evaluation: { run_id: 1 } } } });
    expect(await within(main()).findByRole('alert')).toHaveTextContent('Report không đúng contract');
  });

  it('shows a backend error when the report request fails and retry re-fetches', async () => {
    const fetcher = renderApp({
      ...allReports,
      '/api/reports/after-detected.json': ['network-error', { status: 200, body: afterFixture }],
    });
    const alert = await within(main()).findByRole('alert');
    expect(alert).toHaveTextContent('Không đọc được report từ backend');
    fireEvent.click(within(alert).getByRole('button', { name: 'Thử lại' }));
    expect(await within(main()).findByRole('heading', { level: 1, name: 'synthetic-run-after-fix' })).toBeInTheDocument();
    expect(fetcher.calls['/api/reports/after-detected.json']).toBe(2);
  });

  it('refresh reloads both the index and the open report', async () => {
    const fetcher = renderApp(allReports);
    await within(main()).findByRole('heading', { level: 1, name: 'synthetic-run-after-fix' });
    fireEvent.click(within(main()).getByRole('button', { name: 'Tải lại' }));
    await waitFor(() => expect(fetcher.calls['/api/reports']).toBe(2));
    await waitFor(() => expect(fetcher.calls['/api/reports/after-detected.json']).toBe(2));
  });
});

describe('Comparison view', () => {
  it('uses a neutral before label even when the earlier run was detected', async () => {
    const report = structuredClone(comparisonFixture);
    report.before.final_status = 'Detected';
    window.history.replaceState(null, '', '/#report=comparison-regression-passed.json');
    renderApp({ ...allReports, '/api/reports/comparison-regression-passed.json': { status: 200, body: report } });
    const sides = await within(main()).findByRole('region', { name: 'Trước và sau' });
    expect(within(sides).getByText('Trước', { exact: true })).toBeInTheDocument();
    expect(within(sides).queryByText('Trước · gap', { exact: true })).not.toBeInTheDocument();
  });
  it('renders before/after side by side, backend counts and per-assertion transitions', async () => {
    window.history.replaceState(null, '', '/#report=comparison-regression-passed.json');
    renderApp(allReports);
    const content = main();
    await within(content).findByRole('heading', { level: 1, name: /SCN-999/ });
    const sides = within(content).getByRole('region', { name: 'Trước và sau' });
    expect(within(sides).getByText('synthetic-run-before-gap')).toBeInTheDocument();
    expect(within(sides).getByText('False negative')).toBeInTheDocument();
    expect(within(sides).getByText('synthetic-run-after-fix')).toBeInTheDocument();
    expect(within(sides).getByText('Detected')).toBeInTheDocument();
    const summary = within(content).getByRole('region', { name: 'Tóm tắt so sánh' });
    expect(within(summary).getByText('Regression Passed')).toBeInTheDocument();
    expect(within(summary).getByText('improvement').nextElementSibling).toHaveTextContent('1');
    expect(within(summary).getByText('regression').nextElementSibling).toHaveTextContent('0');
    expect(within(summary).getByText('unchanged_pass').nextElementSibling).toHaveTextContent('1');
    const rows = within(content).getAllByRole('row').slice(1);
    expect(rows[1]).toHaveTextContent('SCN-999-A02');
    expect(rows[1]).toHaveTextContent('false_negative');
    expect(rows[1]).toHaveTextContent('improvement');
    expect(rows[1]).toHaveTextContent('satisfied');
    fireEvent.click(within(rows[1]!).getByRole('button', { name: 'Xem ID' }));
    expect(within(rows[1]!).getByText('thêm')).toBeInTheDocument();
  });
});

describe('Route sync', () => {
  it('writes the selected report and tab into the hash', async () => {
    renderApp(allReports);
    const content = main();
    await within(content).findByRole('heading', { level: 1, name: 'synthetic-run-after-fix' });
    fireEvent.click(within(content).getByRole('tab', { name: /Timeline/ }));
    await waitFor(() => expect(window.location.hash).toBe('#report=after-detected.json&tab=timeline'));
    vi.restoreAllMocks();
  });
});
