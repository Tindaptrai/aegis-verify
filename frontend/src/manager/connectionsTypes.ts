export interface WazuhInput {
  name: string; environment_id: string; endpoint: string; index: string; username: string; password: string; ca_pem: string;
  source_id: string | null; expected_version: number | null;
}
export interface ConnectionSummary {
  name: string; environment_id: string; endpoint: string; index: string; ca_sha256: string; source_id: string | null; version: number;
}
export interface ConnectionTest {
  draft_id: string; expires_at: string; tested_at: string;
  checks: { policy: 'passed'; tls: 'passed'; authentication: 'passed'; query: 'passed' }; summary: ConnectionSummary;
}
export interface ConnectionSource {
  id: string; source_id: string; version: number; name: string; kind: 'managed' | 'legacy'; product: 'wazuh'; product_version: '4.14.4' | null;
  environment_id: string | null; endpoint: string | null; index: string | null; ca_sha256: string | null;
  status: 'saved' | 'candidate' | 'legacy'; worker_state: 'waiting_configuration' | 'legacy'; tested_at: string | null; created_at: string;
}
export interface ConnectionList { results: ConnectionSource[]; count: number; page: number; page_size: 50; candidate_id: string | null }
export interface ConnectionCandidate { source: ConnectionSource; candidate_id: string }

type Obj = Record<string, unknown>;
function object(value: unknown): value is Obj { return !!value && typeof value === 'object' && !Array.isArray(value); }
export function closed(value: unknown, keys: string[]): value is Obj { return object(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key)); }
export function uuid(value: unknown): value is string { return typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value); }
const positive = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value > 0 && value <= 2147483647;
const text = (value: unknown, maximum: number): value is string => typeof value === 'string' && value.trim().length > 0 && value.length <= maximum && !/[\u0000-\u001f]/.test(value);
const stamp = (value: unknown): value is string => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$/.test(value) && Number.isFinite(Date.parse(value));
const environment = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value);
const indexName = (value: unknown): value is string => typeof value === 'string' && /^[a-z0-9][a-z0-9._*-]{0,127}$/.test(value) && !value.includes('..');
const digest = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
export function httpsOrigin(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 2048 || !/^https:\/\/[a-z0-9.[\]:-]+$/.test(value) || /[%\\?#\s]/.test(value)) return false;
  try {
    const parsed = new URL(value);
    // URL.origin drops explicit :443; that spelling is also accepted by the server.
    const origin = `https://${parsed.hostname}${parsed.port ? `:${parsed.port}` : value.endsWith(':443') ? ':443' : ''}`;
    return origin === value && !parsed.hostname.endsWith('.') && !parsed.username && !parsed.password;
  } catch { return false; }
}
function summary(value: unknown): value is ConnectionSummary {
  return closed(value, ['name', 'environment_id', 'endpoint', 'index', 'ca_sha256', 'source_id', 'version']) && text(value.name, 80) && environment(value.environment_id) && httpsOrigin(value.endpoint) && indexName(value.index) && digest(value.ca_sha256) && (value.source_id === null || uuid(value.source_id)) && positive(value.version);
}
export function validTest(value: unknown): value is ConnectionTest {
  return closed(value, ['draft_id', 'expires_at', 'tested_at', 'checks', 'summary']) && uuid(value.draft_id) && stamp(value.expires_at) && stamp(value.tested_at) && Date.parse(value.expires_at) > Date.parse(value.tested_at) && Date.parse(value.expires_at) - Date.parse(value.tested_at) <= 300000 && closed(value.checks, ['policy', 'tls', 'authentication', 'query']) && Object.values(value.checks).every((item) => item === 'passed') && summary(value.summary);
}
export function validSource(value: unknown): value is ConnectionSource {
  if (!closed(value, ['id', 'source_id', 'version', 'name', 'kind', 'product', 'product_version', 'environment_id', 'endpoint', 'index', 'ca_sha256', 'status', 'worker_state', 'tested_at', 'created_at']) || !uuid(value.id) || !uuid(value.source_id) || !positive(value.version) || !text(value.name, 80) || value.product !== 'wazuh' || !stamp(value.created_at)) return false;
  if (value.kind === 'legacy') return value.status === 'legacy' && value.worker_state === 'legacy' && value.product_version === null && (value.environment_id === null || environment(value.environment_id)) && value.endpoint === null && value.index === null && value.ca_sha256 === null && value.tested_at === null;
  return value.kind === 'managed' && value.product_version === '4.14.4' && ['saved', 'candidate'].includes(value.status as string) && value.worker_state === 'waiting_configuration' && environment(value.environment_id) && httpsOrigin(value.endpoint) && indexName(value.index) && digest(value.ca_sha256) && stamp(value.tested_at);
}
export function validList(value: unknown): value is ConnectionList {
  return closed(value, ['results', 'count', 'page', 'page_size', 'candidate_id']) && Array.isArray(value.results) && value.results.length <= 50 && value.results.every(validSource) && typeof value.count === 'number' && Number.isSafeInteger(value.count) && value.count >= value.results.length && positive(value.page) && value.page_size === 50 && (value.candidate_id === null || uuid(value.candidate_id)) && new Set(value.results.map((source) => source.id)).size === value.results.length && value.results.every((source) => (source.status === 'candidate') === (source.id === value.candidate_id));
}
export function validCandidate(value: unknown): value is ConnectionCandidate {
  return closed(value, ['source', 'candidate_id']) && validSource(value.source) && value.source.kind === 'managed' && value.source.status === 'candidate' && value.candidate_id === value.source.id;
}
export function validInput(value: unknown): value is WazuhInput {
  return closed(value, ['name', 'environment_id', 'endpoint', 'index', 'username', 'password', 'ca_pem', 'source_id', 'expected_version']) && text(value.name, 80) && environment(value.environment_id) && httpsOrigin(value.endpoint) && indexName(value.index) && text(value.username, 128) && !value.username.includes(':') && text(value.password, 1024) && typeof value.ca_pem === 'string' && value.ca_pem.length > 0 && new TextEncoder().encode(value.ca_pem).length <= 65536 && (value.source_id === null ? value.expected_version === null : uuid(value.source_id) && positive(value.expected_version));
}
