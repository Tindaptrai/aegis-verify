import { render, screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { App } from './App';
import { createApiClient } from './api';
import afterFixture from '../../tests/fixtures/dashboard/after-detected.json';
import beforeFixture from '../../tests/fixtures/dashboard/before-false-negative.json';
import comparisonFixture from '../../tests/fixtures/dashboard/comparison-regression-passed.json';

type Route = { status: number; body?: unknown; text?: string } | 'network-error';

function fakeFetch(routes: Record<string, Route>) {
  return async (input: string): Promise<Response> => {
    const route = routes[input];
    if (route === undefined) return new Response('{"kind":"error","error":{"code":"not_found"}}', { status: 404 });
    if (route === 'network-error') throw new TypeError('Failed to fetch');
    const text = route.text ?? JSON.stringify(route.body ?? null);
    return new Response(text, { status: route.status, headers: { 'Content-Type': 'application/json' } });
  };
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

function renderApp(routes: Record<string, Route>) {
  render(<App api={createApiClient(fakeFetch(routes))} />);
}

describe('App states', () => {
  it('shows a loading state, then an empty state when the directory has no reports', async () => {
    renderApp({ '/api/reports': index([]) });
    expect(screen.getByText(/Đang tải danh sách report/)).toBeInTheDocument();
    expect(await screen.findByText(/Thư mục report trống/)).toBeInTheDocument();
  });

  it('shows a backend error when the index request fails', async () => {
    renderApp({ '/api/reports': 'network-error' });
    expect(await screen.findByRole('alert')).toHaveTextContent(/Không lấy được danh sách từ backend/);
  });

  it('shows a backend error for a 500 without inventing a list', async () => {
    renderApp({ '/api/reports': { status: 500, body: { kind: 'error', error: { code: 'internal_error' } } } });
    expect(await screen.findByRole('alert')).toHaveTextContent(/HTTP 500/);
    expect(screen.queryByRole('list')).not.toBeInTheDocument();
  });

  it('shows a malformed state when the index is not the contract', async () => {
    renderApp({ '/api/reports': { status: 200, body: { kind: 'something-else' } } });
    expect(await screen.findByText(/Danh sách report không đúng contract/)).toBeInTheDocument();
  });

  it('lists reports with their backend summaries and marks malformed files', async () => {
    renderApp({ '/api/reports': index(entries) });
    const list = await screen.findByRole('list');
    expect(within(list).getAllByRole('listitem')).toHaveLength(4);
    expect(within(list).getByText('after-detected.json')).toBeInTheDocument();
    expect(within(list).getByText(/malformed · invalid_json/)).toBeInTheDocument();
    expect(within(list).getByText('Regression Passed')).toBeInTheDocument();
  });
});

describe('Run view', () => {
  it('renders scenario, run ID, final result, classification, evidence count, assertions and an ordered timeline', async () => {
    renderApp({
      '/api/reports': index(entries),
      '/api/reports/after-detected.json': { status: 200, body: afterFixture },
    });
    (await screen.findByText('after-detected.json')).click();
    const article = await screen.findByRole('article', { name: /synthetic-run-after-fix/ });
    expect(within(article).getByText(/SCN-999 v0\.1\.0/)).toBeInTheDocument();
    expect(within(article).getByText('synthetic-run-after-fix')).toBeInTheDocument();
    expect(within(article).getByText('Detected')).toBeInTheDocument();
    expect(within(article).getByText(/satisfied 2 · missing_telemetry 0 · false_negative 0 · inconclusive 0/)).toBeInTheDocument();
    expect(within(article).getByText(/2 evidence được tham chiếu · parsed 2 · skipped 0/)).toBeInTheDocument();

    const rows = within(article).getAllByRole('row').slice(1);
    expect(rows).toHaveLength(2);
    expect(rows[1]).toHaveTextContent('SCN-999-A02');
    expect(rows[1]).toHaveTextContent('witness_found');
    const detection = afterFixture.evaluation.assertions[1]!;
    expect(within(rows[1]!).getAllByRole('link')).toHaveLength(detection.evidence_ids.length);

    const timeline = within(article).getByRole('list', { name: /Evidence timeline theo thứ tự thời gian/ });
    const items = within(timeline).getAllByRole('listitem');
    expect(items.map((item) => item.textContent)).toEqual(
      afterFixture.timeline.events.map((event) => expect.stringContaining(event.timestamp)),
    );
    expect(items[0]).toHaveTextContent('2026-01-01T00:00:01Z');
    expect(items[1]).toHaveTextContent('2026-01-01T00:00:02Z');
    expect(items[0]).toHaveTextContent('signature: null');
  });

  it('keeps a false negative and unknown/attested assurance as the backend stated them', async () => {
    renderApp({
      '/api/reports': index(entries),
      '/api/reports/before-false-negative.json': { status: 200, body: beforeFixture },
    });
    (await screen.findByText('before-false-negative.json')).click();
    const article = await screen.findByRole('article', { name: /synthetic-run-before-gap/ });
    expect(within(article).getAllByText('False negative').length).toBeGreaterThan(0);
    expect(within(article).getByText('false_negative')).toBeInTheDocument();
    expect(within(article).getByText('expected_detection_absent')).toBeInTheDocument();
    expect(within(article).getByText(/caller-attested/)).toBeInTheDocument();
  });

  it('explains a report without a timeline instead of ordering by guesswork', async () => {
    const { timeline: _omitted, ...legacy } = afterFixture;
    renderApp({
      '/api/reports': index(entries),
      '/api/reports/after-detected.json': { status: 200, body: legacy },
    });
    (await screen.findByText('after-detected.json')).click();
    expect(await screen.findByText(/Report này không có mục timeline/)).toBeInTheDocument();
    expect(screen.getAllByText(/thời điểm: không có trong report/)).toHaveLength(2);
  });

  it('shows the malformed state for a report the backend rejected with 422', async () => {
    renderApp({
      '/api/reports': index(entries),
      '/api/reports/malformed-truncated.json': {
        status: 422,
        body: { kind: 'error', error: { code: 'invalid_json', stage: 'inputs', field: null, hint: 'x' } },
      },
    });
    (await screen.findByText('malformed-truncated.json')).click();
    expect(await screen.findByText(/không đúng contract report/)).toBeInTheDocument();
    expect(screen.getByText(/invalid_json/, { selector: 'p' })).toBeInTheDocument();
    expect(screen.queryByRole('article')).not.toBeInTheDocument();
  });

  it('shows the malformed state for a 200 body that is not the contract', async () => {
    renderApp({
      '/api/reports': index(entries),
      '/api/reports/after-detected.json': { status: 200, body: { kind: 'evaluation', evaluation: { run_id: 1 } } },
    });
    (await screen.findByText('after-detected.json')).click();
    expect(await screen.findByText(/không đúng contract report/)).toBeInTheDocument();
  });

  it('shows a backend error when the report request fails', async () => {
    renderApp({ '/api/reports': index(entries), '/api/reports/after-detected.json': 'network-error' });
    (await screen.findByText('after-detected.json')).click();
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(/Backend lỗi khi đọc/));
  });
});

describe('Comparison view', () => {
  it('renders before/after runs, comparison status and per-assertion transitions', async () => {
    renderApp({
      '/api/reports': index(entries),
      '/api/reports/comparison-regression-passed.json': { status: 200, body: comparisonFixture },
    });
    (await screen.findByText('comparison-regression-passed.json')).click();
    const article = await screen.findByRole('article', { name: /synthetic-run-before-gap → synthetic-run-after-fix/ });
    expect(within(article).getByText('synthetic-run-before-gap')).toBeInTheDocument();
    expect(within(article).getByText('synthetic-run-after-fix')).toBeInTheDocument();
    expect(within(article).getAllByText('Regression Passed').length).toBeGreaterThan(0);
    expect(within(article).getByText(/unchanged_pass 1 · unchanged_fail 0 · improvement 1 · regression 0/)).toBeInTheDocument();
    const rows = within(article).getAllByRole('row').slice(1);
    expect(rows[1]).toHaveTextContent('SCN-999-A02');
    expect(rows[1]).toHaveTextContent('improvement');
    expect(rows[1]).toHaveTextContent('false_negative');
    expect(rows[1]).toHaveTextContent('satisfied');
  });
});
