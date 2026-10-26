import { describe, expect, it, vi } from 'vitest';
import { createManagerApi } from './api';
import { provider, readiness, preview, job, targetId, hash, release } from './execution-test-fixtures';

const raw = (value: unknown, status = 200) => new Response(JSON.stringify(value).replaceAll(`"${release}"`, release), { status });
describe('authenticated execution API', () => {
  it('current-job framing preserves the existing maximum job depth and byte bounds', async () => {
    let nested: unknown = []; for (let i = 0; i < 9; i++) nested = [nested];
    const value = { ...job, report: { nested } };
    expect((await createManagerApi(vi.fn<typeof fetch>().mockResolvedValue(raw(value))).executionJob(targetId)).report).toEqual({ nested });
    expect((await createManagerApi(vi.fn<typeof fetch>().mockResolvedValue(raw({ job: value }))).currentExecutionJob()).job?.report).toEqual({ nested });
    await expect(createManagerApi(vi.fn<typeof fetch>().mockResolvedValue(raw({ job: { ...job, report: { nested: [nested] } } }))).currentExecutionJob()).rejects.toMatchObject({ name: 'ManagerApiError' });
    const base = JSON.stringify({ ...job, report: { padding: '' } }).replaceAll(`"${release}"`, release);
    const large = base.replace('"padding":""', `"padding":"${'x'.repeat(4 * 1024 * 1024 - new TextEncoder().encode(base).length)}"`);
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(new Response(`{"job":${large}}`)).mockResolvedValueOnce(new Response(`{"job":${large} }`));
    const api = createManagerApi(fetcher); expect((await api.currentExecutionJob()).job?.job_id).toBe(targetId);
    await expect(api.currentExecutionJob()).rejects.toMatchObject({ name: 'ManagerApiError' });
  });
  it('discovers one current job through a closed authenticated no-store response', async () => {
    for (const body of [{ job: null }, { job }]) {
      const fetcher = vi.fn<typeof fetch>().mockResolvedValue(raw(body)); const api = createManagerApi(fetcher);
      expect(await api.currentExecutionJob()).toEqual(body);
      expect(fetcher).toHaveBeenCalledWith('/api/v1/jobs/current', expect.objectContaining({ credentials: 'same-origin', cache: 'no-store', method: 'GET' }));
    }
    for (const body of [{ job, idempotency_key: targetId }, { job: { ...job, admission_blocked: 'false' } }, { job: { ...job, admission_blocked: undefined } }]) {
      await expect(createManagerApi(vi.fn<typeof fetch>().mockResolvedValue(raw(body))).currentExecutionJob()).rejects.toMatchObject({ name: 'ManagerApiError' });
    }
  });
  it.each(['9007199254740993', '9223372036854775807'])('preserves raw int64 release %s inbound and outbound', async (id) => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(new Response(`{"providers":[${JSON.stringify(provider).replace(`"${release}"`, id)}]}`)).mockResolvedValueOnce(raw(readiness));
    const api = createManagerApi(fetcher);
    const result = await api.executionProviders();
    expect(result.providers[0]!.release_id).toBe(id);
    await api.setExecutionBinding(targetId, { expected_revision: 1, enabled: true, provider_id: provider.provider_id, runner_release_id: result.providers[0]!.release_id, installation_profile_sha256: hash, wazuh_connection_id: targetId, wazuh_connection_revision: 1, wazuh_agent_id: '001' });
    expect(fetcher.mock.calls[1]![1]?.body).toContain(`"runner_release_id":${id}`);
    expect(fetcher.mock.calls[1]![1]?.body).not.toContain(`"runner_release_id":"`);
  });
  it('uses shared CSRF, exact routes/statuses, no-store and abort signals', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(raw({ csrf_token: 'fresh', authenticated: false, user: null, expires_at: null }))
      .mockResolvedValueOnce(raw({ providers: [provider] })).mockResolvedValueOnce(raw(readiness)).mockResolvedValueOnce(raw(preview, 201))
      .mockResolvedValueOnce(raw(job, 201)).mockResolvedValueOnce(raw(job)).mockResolvedValueOnce(raw(job));
    const api = createManagerApi(fetcher); const controller = new AbortController(); await api.session();
    await api.executionProviders(controller.signal); await api.executionDevice(targetId, controller.signal);
    await api.previewExecution({ device_id: targetId, provider_id: provider.provider_id, binding_revision: 1, run_label: 'A', rule_revision: 'baseline' }, controller.signal);
    await api.approveExecution({ preview_id: targetId, preview_sha256: hash, idempotency_key: targetId }, controller.signal);
    await api.executionJob(targetId, controller.signal); await api.cancelExecution(targetId, controller.signal);
    expect(fetcher.mock.calls.slice(1).map(([url]) => url)).toEqual(['/api/v1/execution/providers', `/api/v1/execution/devices/${targetId}`, '/api/v1/jobs/preview', '/api/v1/jobs/approve', `/api/v1/jobs/${targetId}`, `/api/v1/jobs/${targetId}/cancel`]);
    expect(fetcher.mock.calls.slice(1).every(([, init]) => init?.signal === controller.signal && init.credentials === 'same-origin' && init.cache === 'no-store')).toBe(true);
    expect(fetcher.mock.calls[4]![1]?.headers).toMatchObject({ 'X-CSRFToken': 'fresh' });
    expect(fetcher.mock.calls[6]![1]?.body).toBe('{}');
  });
  it.each(['9223372036854775808', '0', '-1', '1.5', '1e3', 'true', '"9007199254740993"'])('rejects invalid wire release token %s', async (token) => {
    const api = createManagerApi(vi.fn<typeof fetch>().mockResolvedValue(new Response(`{"providers":[${JSON.stringify(provider).replace(`"${release}"`, token)}]}`)));
    await expect(api.executionProviders()).rejects.toMatchObject({ name: 'ManagerApiError' });
  });
  it.each([
    '{"providers":[],"providers":[]}', '{"providers":[],"config_path":"private"}',
    JSON.stringify({ providers: [{ ...provider, timeout_seconds: true }] }),
  ])('rejects duplicate/unknown keys and wrong types', async (body) => {
    await expect(createManagerApi(vi.fn<typeof fetch>().mockResolvedValue(new Response(body))).executionProviders()).rejects.toMatchObject({ name: 'ManagerApiError' });
  });
  it('rejects private fields and nonsecond timestamps from summaries', async () => {
    for (const summary of [{ ...preview.summary, config_path: 'private' }, { ...preview.summary, not_before: '2099-01-01T00:00:00.000Z' }]) {
      const api = createManagerApi(vi.fn<typeof fetch>().mockResolvedValue(raw({ ...preview, summary }, 201)));
      await expect(api.previewExecution({ device_id: targetId, provider_id: provider.provider_id, binding_revision: 1, run_label: 'A', rule_revision: 'baseline' })).rejects.toMatchObject({ name: 'ManagerApiError' });
    }
  });
  it('invalidates a late execution response after session invalidation', async () => {
    let finish!: (response: Response) => void; const api = createManagerApi(vi.fn<typeof fetch>().mockImplementation(() => new Promise((resolve) => { finish = resolve; })));
    const pending = api.executionProviders(); api.invalidate(); finish(raw({ providers: [provider] }));
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
  });
  it.each([
    { execution_state: ['started'] }, { collection_state: ['pending'] }, { evaluation_state: ['not_evaluated'] },
    { summary: { ...job.summary, parameters: { ...job.summary.parameters, run_label: ['A'] } } },
  ])('rejects array values masquerading as execution enum strings', async (patch) => {
    await expect(createManagerApi(vi.fn<typeof fetch>().mockResolvedValue(raw({ ...job, ...patch }))).executionJob(targetId)).rejects.toMatchObject({ name: 'ManagerApiError' });
  });
  it('rejects oversized and excessive-depth execution responses', async () => {
    for (const body of [' '.repeat(4 * 1024 * 1024 + 1), '{"report":' + '['.repeat(13) + '0' + ']'.repeat(13) + '}']) {
      await expect(createManagerApi(vi.fn<typeof fetch>().mockResolvedValue(new Response(body))).executionProviders()).rejects.toMatchObject({ name: 'ManagerApiError' });
    }
  });
  it('rejects noncanonical release ID input before binding serialization or fetch', async () => {
    const fetcher = vi.fn<typeof fetch>(); const api = createManagerApi(fetcher);
    await expect(api.setExecutionBinding(targetId, { expected_revision: null, enabled: true, provider_id: provider.provider_id, runner_release_id: '1,"enabled":false' as typeof release, installation_profile_sha256: hash, wazuh_connection_id: targetId, wazuh_connection_revision: 1, wazuh_agent_id: '001' })).rejects.toThrow(); expect(fetcher).not.toHaveBeenCalled();
  });
  it('bounds container depth including empty containers and retains frozen opaque reports', async () => {
    let nested: unknown = []; for (let i = 0; i < 10; i++) nested = [nested];
    const tooDeep = createManagerApi(vi.fn<typeof fetch>().mockResolvedValue(raw({ ...job, report: { nested } })));
    await expect(tooDeep.executionJob(targetId)).rejects.toMatchObject({ name: 'ManagerApiError' });
    const report = { opaque: { value: 'not interpreted as execution authority' } }; const api = createManagerApi(vi.fn<typeof fetch>().mockResolvedValue(raw({ ...job, report })));
    const result = await api.executionJob(targetId); expect(result.report).toEqual(report); expect(Object.isFrozen(result.report)).toBe(true); expect(Object.isFrozen(result.report?.opaque)).toBe(true);
  });
  it('accepts empty/model100 opaque job codes but rejects controls and longer strings', async () => {
    for (const error_code of ['', 'x'.repeat(100)]) { const api = createManagerApi(vi.fn<typeof fetch>().mockResolvedValue(raw({ ...job, error_code }))); expect((await api.executionJob(targetId)).error_code).toBe(error_code); }
    for (const error_code of ['x'.repeat(101), 'bad\ncode']) { const api = createManagerApi(vi.fn<typeof fetch>().mockResolvedValue(raw({ ...job, error_code }))); await expect(api.executionJob(targetId)).rejects.toMatchObject({ name: 'ManagerApiError' }); }
  });
});
