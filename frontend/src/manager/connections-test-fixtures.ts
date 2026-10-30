// Synthetic public responses; never imported by the Manager entry.
import { vi } from 'vitest';
import type { ConnectionsApi } from './connectionsApi';
import type { ConnectionSource, ConnectionTest, WazuhInput } from './connectionsTypes';
export const sourceId = '12345678-1234-4234-8234-123456789abc';
export const syntheticSource: ConnectionSource = {
  id: sourceId, source_id: sourceId, version: 1, name: 'Synthetic source', kind: 'managed', product: 'wazuh', product_version: '4.14.4',
  environment_id: 'synthetic', endpoint: 'https://indexer.example:9200', index: 'reviewed-alerts-*', ca_sha256: 'a'.repeat(64),
  status: 'saved', worker_state: 'waiting_configuration', tested_at: new Date().toISOString(), created_at: new Date().toISOString(),
};
export function tested(): ConnectionTest {
  const now = Date.now();
  return { draft_id: sourceId, tested_at: new Date(now).toISOString(), expires_at: new Date(now + 300000).toISOString(),
    checks: { policy: 'passed', tls: 'passed', authentication: 'passed', query: 'passed' },
    summary: { name: syntheticSource.name, environment_id: 'synthetic', endpoint: syntheticSource.endpoint!, index: syntheticSource.index!, ca_sha256: syntheticSource.ca_sha256!, source_id: null, version: 1 } };
}
export const syntheticInput: WazuhInput = { name: 'Synthetic source', environment_id: 'synthetic', endpoint: 'https://indexer.example:9200', index: 'reviewed-alerts-*', username: 'synthetic-reader', password: 'synthetic-test-secret', ca_pem: 'synthetic public CA', source_id: null, expected_version: null };
export function connectionsFixture(): ConnectionsApi {
  return { list: vi.fn(async () => ({ results: [], count: 0, page: 1, page_size: 50 as const, candidate_id: null })),
    test: vi.fn(async () => tested()), save: vi.fn(async () => syntheticSource),
    prepare: vi.fn(async () => ({ source: { ...syntheticSource, status: 'candidate' as const }, candidate_id: sourceId })) };
}
