import { describe, expect, it, vi } from 'vitest';
import { createConnectionsApi, ConnectionsApiError } from './connectionsApi';
import { syntheticInput, syntheticSource, sourceId, tested } from './connections-test-fixtures';

function response(value: unknown, status = 200) { return new Response(JSON.stringify(value), { status }); }
describe('Connections closed API', () => {
  it('uses dedicated no-store same-origin routes and current CSRF for every write', async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(response({ results: [syntheticSource], count: 1, page: 1, page_size: 50, candidate_id: null }))
      .mockResolvedValueOnce(response(tested(), 201)).mockResolvedValueOnce(response(syntheticSource, 201))
      .mockResolvedValueOnce(response({ source: { ...syntheticSource, status: 'candidate' }, candidate_id: sourceId }));
    const api = createConnectionsApi(fetcher);
    await api.list(1); await api.test(syntheticInput, 'fresh-csrf'); await api.save(sourceId, sourceId, 'new-csrf'); await api.prepare(sourceId, null, 'newest-csrf');
    expect(fetcher.mock.calls.map((call) => call[0])).toEqual(['/api/v1/connections/?page=1', '/api/v1/connections/wazuh/test', '/api/v1/connections/wazuh/save', `/api/v1/connections/${sourceId}/prepare`]);
    expect(fetcher.mock.calls[1]?.[1]).toMatchObject({ credentials: 'same-origin', cache: 'no-store', headers: { 'X-CSRFToken': 'fresh-csrf', 'Content-Type': 'application/json' } });
    expect(fetcher.mock.calls[2]?.[1].headers['X-CSRFToken']).toBe('new-csrf');
    expect(JSON.parse(fetcher.mock.calls[3]?.[1].body)).toEqual({ expected_candidate_id: null });
  });
  it.each([
    { ...syntheticSource, password: 'never retain me' }, { ...syntheticSource, environment_id: null },
    { ...syntheticSource, product_version: 'unknown' }, { ...syntheticSource, status: 'ready' },
    { ...syntheticSource, endpoint: 'http://indexer.example' }, { ...syntheticSource, ca_sha256: 'no' },
    { ...syntheticSource, tested_at: 'yesterday' }, { ...syntheticSource, version: 0 },
  ])('rejects malformed or open source DTO %#', async (source) => {
    const api = createConnectionsApi(vi.fn().mockResolvedValue(response(source, 201)));
    await expect(api.save(sourceId, sourceId, 'csrf')).rejects.toBeInstanceOf(ConnectionsApiError);
  });
  it('accepts unknown legacy environment as null without reading credentials', async () => {
    const legacy = { ...syntheticSource, kind: 'legacy', product_version: null, status: 'legacy', worker_state: 'legacy', environment_id: null, endpoint: null, index: null, ca_sha256: null, tested_at: null };
    const api = createConnectionsApi(vi.fn().mockResolvedValue(response({ results: [legacy], count: 1, page: 1, page_size: 50, candidate_id: null })));
    expect((await api.list()).results[0]?.environment_id).toBeNull();
  });
  it.each([{ ...tested(), username: 'leak' }, { ...tested(), checks: { policy: 'passed' } }, { ...tested(), summary: { ...tested().summary, version: 0 } }])('rejects malformed test result %#', async (value) => {
    await expect(createConnectionsApi(vi.fn().mockResolvedValue(response(value, 201))).test(syntheticInput, 'csrf')).rejects.toBeInstanceOf(ConnectionsApiError);
  });
  it.each(['<html>private upstream text</html>', JSON.stringify({ error: { code: 'private upstream text' } }), 'x'.repeat(2048)])('never exposes arbitrary error body %#', async (body) => {
    const api = createConnectionsApi(vi.fn().mockResolvedValue(new Response(body, { status: 409 })));
    await expect(api.test(syntheticInput, 'csrf')).rejects.toMatchObject({ message: 'Connection request failed', code: undefined, status: 409 });
  });
  it('retains fixed diagnostic code and refuses stale responses even if fetch ignores abort', async () => {
    const api = createConnectionsApi(vi.fn().mockResolvedValue(response({ error: { code: 'tls_failed' } }, 409)));
    await expect(api.test(syntheticInput, 'csrf')).rejects.toMatchObject({ code: 'tls_failed' });
    const controller = new AbortController(); controller.abort();
    await expect(createConnectionsApi(vi.fn().mockResolvedValue(response(tested(), 201))).test(syntheticInput, 'csrf', controller.signal)).rejects.toMatchObject({ name: 'AbortError' });
  });
  it('rejects unexpected success status, oversized success and invalid outbound fields before fetch', async () => {
    await expect(createConnectionsApi(vi.fn().mockResolvedValue(response(tested(), 200))).test(syntheticInput, 'csrf')).rejects.toBeInstanceOf(ConnectionsApiError);
    await expect(createConnectionsApi(vi.fn().mockResolvedValue(new Response('x'.repeat(300000), { status: 201 }))).test(syntheticInput, 'csrf')).rejects.toBeInstanceOf(ConnectionsApiError);
    const fetcher = vi.fn(); const api = createConnectionsApi(fetcher);
    await expect(api.test({ ...syntheticInput, endpoint: 'https://indexer.example/path' }, 'csrf')).rejects.toBeInstanceOf(ConnectionsApiError);
    expect(fetcher).not.toHaveBeenCalled();
  });
  it('refuses a legacy save response, wrong prepared version and mismatched pagination', async () => {
    const legacy = { ...syntheticSource, kind: 'legacy', product_version: null, status: 'legacy', worker_state: 'legacy', environment_id: null, endpoint: null, index: null, ca_sha256: null, tested_at: null };
    await expect(createConnectionsApi(vi.fn().mockResolvedValue(response(legacy, 201))).save(sourceId, sourceId, 'csrf')).rejects.toBeInstanceOf(ConnectionsApiError);
    const otherId = '12345678-1234-4234-8234-123456789abd';
    await expect(createConnectionsApi(vi.fn().mockResolvedValue(response({ source: { ...syntheticSource, status: 'candidate' }, candidate_id: sourceId }))).prepare(otherId, null, 'csrf')).rejects.toBeInstanceOf(ConnectionsApiError);
    await expect(createConnectionsApi(vi.fn().mockResolvedValue(response({ results: [], count: 0, page: 2, page_size: 50, candidate_id: null }))).list(1)).rejects.toBeInstanceOf(ConnectionsApiError);
  });
});
