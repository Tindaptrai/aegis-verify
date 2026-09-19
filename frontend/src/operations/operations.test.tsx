import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { createOperationsClient } from './api';
import { parseJob, utc } from './contracts';
import { AgentsView } from './AgentsView';
import { CollectionsView } from './CollectionsView';
import { App } from '../App';
import { readRoute, routeHash } from '../route';

const id = '00000000-0000-4000-8000-000000000001';
const boot = { environment_id: 'fixture', agent_ids: ['012'], session_token: 'synthetic-session',
  capabilities: { collection: true, inventory: true }, error_code: null };
const job = { id, request_id: id, agent_id: '012', start: '2026-01-01T00:00:00Z', end: '2026-01-01T00:01:00Z',
  adaptive: true, state: 'completed', created_at: '2026-01-01T00:02:00Z', finished_at: '2026-01-01T00:03:00Z',
  result: { record_count: 0, query_complete: true, collection_assurance: 'unknown', cleanup_failed: true }, error_code: null };
const snapshot = { state: 'stale', refreshing: false, fetched_at: '2026-01-01T00:00:00Z', error_code: null,
  agents: [{ environment_id: 'fixture', agent_id: '012', name: null, os_name: null, os_version: null,
    source_status: 'future_status', last_keepalive: null, fetched_at: '2026-01-01T00:00:00Z' }] };

function fixture(overrides: Record<string, unknown> = {}) {
  const calls: Array<{ path: string; init?: RequestInit }> = [];
  const routes: Record<string, unknown> = { bootstrap: boot, agents: snapshot, collections: { jobs: [], error_code: null },
    [`collections/${id}`]: job, ...overrides };
  const client = createOperationsClient(async (url, init) => {
    const path = url.replace('/api/operations/', '');
    calls.push({ path, init });
    if (init?.method === 'POST' && path === 'collections') return Response.json(job);
    const value = routes[path];
    return value instanceof Response ? value : Response.json(value);
  });
  return { client, calls, routes };
}

afterEach(() => { vi.useRealTimers(); });

it('keeps report-only usable when bootstrap is unavailable', async () => {
  const f = fixture({ bootstrap: new Response('{}', { status: 404 }) });
  render(<App api={{ index: async () => ({ status: 'ready', value: { kind: 'report_index', version: '0.1.0', reports: [] } }),
    report: async () => ({ status: 'backend-error', reason: 'unused' }) }} operationsClient={f.client} />);
  expect(await screen.findByText('Chưa có report nào để hiển thị')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Collections' })).not.toBeInTheDocument();
});

it('opens capability-gated operations pages while preserving report selection', async () => {
  window.history.replaceState(null, '', '/');
  const f = fixture();
  render(<App api={{ index: async () => ({ status: 'ready', value: { kind: 'report_index', version: '0.1.0', reports: [] } }),
    report: async () => ({ status: 'backend-error', reason: 'unused' }) }} operationsClient={f.client} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Agents' }));
  expect(await screen.findByRole('heading', { name: 'Agents' })).toBeInTheDocument();
  expect(readRoute().page).toBe('agents');
  fireEvent.click(screen.getByRole('button', { name: 'Collections' }));
  expect(await screen.findByLabelText('Bắt đầu (UTC)')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Reports' }));
  expect(await screen.findByText('Chưa có report nào để hiển thị')).toBeInTheDocument();
});

it('routes only known pages and valid job ids', () => {
  expect(readRoute('#page=collections&job=invalid').job).toBeNull();
  expect(readRoute('#page=malicious').page).toBe('reports');
  expect(routeHash({ report: null, tab: null, page: 'collections', job: id })).toBe(`#page=collections&job=${id}`);
});

it('rejects a late bootstrap body after a newer server session', async () => {
  let resolveBody!: (value: string) => void;
  let count = 0;
  const client = createOperationsClient(async () => {
    count++;
    if (count === 1) return { ok: true, status: 200, text: () => new Promise<string>(resolve => { resolveBody = resolve; }) } as Response;
    return Response.json({ ...boot, session_token: 'new-session' });
  });
  const first = client.bootstrap();
  const rejected = expect(first).rejects.toThrow('session_expired');
  await Promise.resolve();
  await client.bootstrap();
  resolveBody(JSON.stringify(boot));
  await rejected;
});

it('rejects forged verdicts and incomplete successful jobs', () => {
  expect(parseJob({ ...job, state: 'Detected' }).ok).toBe(false);
  expect(parseJob({ ...job, result: { ...job.result, query_complete: false } }).ok).toBe(false);
  expect(parseJob(job).ok).toBe(true);
});

it('rejects impossible calendar dates even when Date.parse normalizes them', () => {
  expect(utc('2026-02-30T00:00:00Z')).toBe(false);
  expect(utc('2026-01-01T24:00:00Z')).toBe(false);
  expect(utc('2026-02-28T00:00:00.1234567+00:00')).toBe(true);
});

it('keeps token in request headers and never retries after session expiry', async () => {
  const f = fixture({ collections: Response.json({ error: { code: 'private secret' } }, { status: 403 }) });
  await f.client.bootstrap();
  await expect(f.client.collections()).rejects.toThrow('session_expired');
  expect(f.calls.map(c => c.path)).toEqual(['bootstrap', 'collections']);
  expect(new Headers(f.calls[1]!.init?.headers).get('X-Aegis-Session')).toBe('synthetic-session');
  expect(localStorage.length).toBe(0);
});

it('shows unknown source status and stale snapshot without initiating refresh', async () => {
  const f = fixture(); const config = await f.client.bootstrap();
  render(<AgentsView client={f.client} config={config} />);
  expect(await screen.findByText(/Không nhận diện.*future_status/)).toBeInTheDocument();
  expect(screen.getByText(/Dữ liệu cũ/)).toBeInTheDocument();
  expect(f.calls.filter(c => c.init?.method === 'POST')).toHaveLength(0);
});

it('rejects invalid window before submitting any collection', async () => {
  const f = fixture(); const config = await f.client.bootstrap();
  render(<CollectionsView client={f.client} config={config} />);
  fireEvent.change(screen.getByLabelText('Bắt đầu (UTC)'), { target: { value: 'invalid' } });
  fireEvent.click(screen.getByRole('button', { name: 'Xem lại yêu cầu' }));
  expect(await screen.findByRole('alert')).toHaveTextContent(/UTC/);
  expect(f.calls.filter(c => c.init?.method === 'POST')).toHaveLength(0);
});

it('requires confirmation, submits once and displays empty success with cleanup warning', async () => {
  const f = fixture(); const config = await f.client.bootstrap();
  render(<CollectionsView client={f.client} config={config} />);
  fireEvent.change(screen.getByLabelText('Bắt đầu (UTC)'), { target: { value: job.start } });
  fireEvent.change(screen.getByLabelText('Kết thúc (UTC)'), { target: { value: job.end } });
  fireEvent.click(screen.getByRole('button', { name: 'Xem lại yêu cầu' }));
  expect(screen.getByRole('dialog')).toHaveTextContent('012');
  expect(f.calls.filter(c => c.init?.method === 'POST')).toHaveLength(0);
  const confirm = screen.getByRole('button', { name: 'Xác nhận thu thập' });
  fireEvent.click(confirm); fireEvent.click(confirm);
  expect(await screen.findByText(/0 bản ghi/)).toBeInTheDocument();
  expect(screen.getByText(/Dọn phiên truy vấn chưa thành công/)).toBeInTheDocument();
  const submissions = f.calls.filter(c => c.init?.method === 'POST');
  expect(submissions).toHaveLength(1);
  expect(JSON.parse(String(submissions[0]!.init?.body))).toMatchObject({ agent_id: '012', start: job.start, end: job.end, adaptive: true });
  expect(screen.queryByText('False negative')).not.toBeInTheDocument();
});

it('polls running jobs no faster than two seconds and stops after terminal response', async () => {
  vi.useFakeTimers();
  const running = { ...job, state: 'running', result: null, finished_at: null };
  const f = fixture({ [`collections/${id}`]: running }); const config = await f.client.bootstrap();
  render(<CollectionsView client={f.client} config={config} initialJobId={id} />);
  await act(async () => { await vi.advanceTimersByTimeAsync(0); });
  expect(f.calls.filter(c => c.path === `collections/${id}`)).toHaveLength(1);
  await act(async () => { await vi.advanceTimersByTimeAsync(1999); });
  expect(f.calls.filter(c => c.path === `collections/${id}`)).toHaveLength(1);
  f.routes[`collections/${id}`] = job;
  await act(async () => { await vi.advanceTimersByTimeAsync(1); });
  expect(screen.getByText(/0 bản ghi/)).toBeInTheDocument();
  await act(async () => { await vi.advanceTimersByTimeAsync(10000); });
  expect(f.calls.filter(c => c.path === `collections/${id}`)).toHaveLength(2);
});

it('aborts read requests on unmount', async () => {
  const f = fixture(); const config = await f.client.bootstrap();
  const view = render(<AgentsView client={f.client} config={config} />);
  await waitFor(() => expect(f.calls.some(c => c.path === 'agents')).toBe(true));
  view.unmount();
  expect(f.calls.find(c => c.path === 'agents')?.init?.signal?.aborted).toBe(true);
});

it('keeps the selected completed job visible when selected again', async () => {
  const f = fixture({ collections: { jobs: [job], error_code: null } }); const config = await f.client.bootstrap();
  render(<CollectionsView client={f.client} config={config} initialJobId={id} />);
  await screen.findByText(/0 bản ghi/);
  fireEvent.click(screen.getByRole('button', { name: /012.*2026-01-01T00:02:00Z.*completed/ }));
  expect(screen.getByText(/0 bản ghi/)).toBeInTheDocument();
});

it('moves completed submissions into the URL selection too', async () => {
  const f = fixture(); const config = await f.client.bootstrap(); const onJob = vi.fn();
  render(<CollectionsView client={f.client} config={config} onJob={onJob} />);
  fireEvent.change(screen.getByLabelText('Bắt đầu (UTC)'), { target: { value: job.start } });
  fireEvent.change(screen.getByLabelText('Kết thúc (UTC)'), { target: { value: job.end } });
  fireEvent.click(screen.getByRole('button', { name: 'Xem lại yêu cầu' }));
  expect(screen.getByRole('button', { name: 'Xác nhận thu thập' })).toHaveFocus();
  fireEvent.click(screen.getByRole('button', { name: 'Xác nhận thu thập' }));
  await screen.findByText(/0 bản ghi/);
  expect(onJob).toHaveBeenCalledWith(id);
});

it('rejects inventory from a different environment', async () => {
  const f = fixture({ agents: { ...snapshot, agents: [{ ...snapshot.agents[0], environment_id: 'other' }] } });
  await f.client.bootstrap();
  await expect(f.client.agents()).rejects.toThrow('invalid_response');
});

it('does not show late inventory after leaving the page or replay its mutation', async () => {
  let resolveLate!: (value: Response) => void;
  const calls: string[] = [];
  const client = createOperationsClient(async url => {
    calls.push(url);
    if (url.endsWith('bootstrap')) return Response.json(boot);
    return new Promise<Response>(resolve => { resolveLate = resolve; });
  });
  const config = await client.bootstrap();
  const view = render(<AgentsView client={client} config={config} />);
  view.unmount();
  await act(async () => { resolveLate(Response.json(snapshot)); });
  expect(screen.queryByText(/future_status/)).not.toBeInTheDocument();
  expect(calls).toEqual(['/api/operations/bootstrap', '/api/operations/agents']);
});

it('stops job polling on navigation', async () => {
  vi.useFakeTimers();
  const f = fixture({ [`collections/${id}`]: { ...job, state: 'running', result: null, finished_at: null } });
  const config = await f.client.bootstrap();
  const view = render(<CollectionsView client={f.client} config={config} initialJobId={id} />);
  await act(async () => { await vi.advanceTimersByTimeAsync(0); });
  view.unmount();
  await act(async () => { await vi.advanceTimersByTimeAsync(10000); });
  expect(f.calls.filter(c => c.path === `collections/${id}`)).toHaveLength(1);
  expect(f.calls.find(c => c.path === `collections/${id}`)?.init?.signal?.aborted).toBe(true);
});

it('does not let a delayed job list replace newer terminal detail and lock admission', async () => {
  let resolveList!: (value: Response) => void;
  const client = createOperationsClient(async url => {
    if (url.endsWith('bootstrap')) return Response.json(boot);
    if (url.endsWith('/collections')) return new Promise<Response>(resolve => { resolveList = resolve; });
    return Response.json(job);
  });
  const config = await client.bootstrap();
  render(<CollectionsView client={client} config={config} initialJobId={id} />);
  await screen.findByText(/0 bản ghi/);
  await act(async () => { resolveList(Response.json({ jobs: [{ ...job, state: 'running', result: null, finished_at: null }], error_code: null })); });
  expect(screen.getByRole('button', { name: 'Xem lại yêu cầu' })).not.toBeDisabled();
  expect(screen.getByRole('button', { name: /012.*2026-01-01T00:02:00Z.*completed/ })).toBeInTheDocument();
});

it('can reselect an older job after a submission returns completed', async () => {
  const secondId = '00000000-0000-4000-8000-000000000002';
  const second = { ...job, id: secondId, created_at: '2026-01-01T00:04:00Z', result: { ...job.result, record_count: 9 } };
  const client = createOperationsClient(async (url, init) => {
    if (url.endsWith('bootstrap')) return Response.json(boot);
    if (init?.method === 'POST' || url.endsWith(secondId)) return Response.json(second);
    if (url.endsWith('/collections')) return Response.json({ jobs: [job], error_code: null });
    return Response.json(job);
  });
  const config = await client.bootstrap();
  render(<CollectionsView client={client} config={config} initialJobId={id} />);
  await screen.findByText(/0 bản ghi/);
  fireEvent.change(screen.getByLabelText('Bắt đầu (UTC)'), { target: { value: job.start } });
  fireEvent.change(screen.getByLabelText('Kết thúc (UTC)'), { target: { value: job.end } });
  fireEvent.click(screen.getByRole('button', { name: 'Xem lại yêu cầu' }));
  fireEvent.click(screen.getByRole('button', { name: 'Xác nhận thu thập' }));
  await screen.findByText(/9 bản ghi/);
  fireEvent.click(screen.getByRole('button', { name: /012.*2026-01-01T00:02:00Z.*completed/ }));
  expect(await screen.findByText(/0 bản ghi/)).toBeInTheDocument();
});
