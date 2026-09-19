export interface Bootstrap {
  environment_id: string; agent_ids: string[];
  capabilities: { collection: boolean; inventory: boolean }; error_code: string | null;
}
export interface CollectionRequest { agent_id: string; start: string; end: string; adaptive: boolean; request_id: string }
export interface Job extends CollectionRequest {
  id: string; state: 'running' | 'completed' | 'failed' | 'interrupted'; created_at: string;
  finished_at: string | null; error_code: string | null;
  result: { record_count: number; query_complete: true; collection_assurance: 'unknown'; cleanup_failed: boolean } | null;
}
export interface Agent {
  environment_id: string; agent_id: string; name: string | null; os_name: string | null;
  os_version: string | null; source_status: string | null; last_keepalive: string | null; fetched_at: string;
}
export interface Snapshot {
  state: 'not_configured' | 'unavailable' | 'ready' | 'stale'; agents: Agent[];
  fetched_at: string | null; error_code: string | null; refreshing: boolean;
}
export type Parsed<T> = { ok: true; value: T } | { ok: false };
type Obj = Record<string, unknown>;
const object = (x: unknown): x is Obj => typeof x === 'object' && x !== null && !Array.isArray(x);
const str = (x: unknown): x is string => typeof x === 'string' && x.length <= 512;
const nullable = (x: unknown) => x === null || str(x);
export const uuid = (x: unknown): x is string => typeof x === 'string' && /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(x);
export const utc = (x: unknown): x is string => typeof x === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|\+00:00)$/.test(x) && Number.isFinite(Date.parse(x)) && new Date(x).toISOString().slice(0, 19) === x.slice(0, 19);
const exact = (x: Obj, names: string) => Object.keys(x).sort().join(',') === names.split(' ').sort().join(',');

export function parseBootstrap(x: unknown): Parsed<Bootstrap & { session_token: string }> {
  if (!object(x) || !exact(x, 'environment_id agent_ids capabilities error_code session_token') ||
      !str(x.environment_id) || !Array.isArray(x.agent_ids) || x.agent_ids.length < 1 || x.agent_ids.length > 100 ||
      !x.agent_ids.every(i => typeof i === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(i)) ||
      new Set(x.agent_ids).size !== x.agent_ids.length || !object(x.capabilities) ||
      !exact(x.capabilities, 'collection inventory') || typeof x.capabilities.collection !== 'boolean' ||
      typeof x.capabilities.inventory !== 'boolean' || !nullable(x.error_code) ||
      typeof x.session_token !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(x.session_token)) return { ok: false };
  return { ok: true, value: x as unknown as Bootstrap & { session_token: string } };
}

export function parseJob(x: unknown): Parsed<Job> {
  if (!object(x) || !exact(x, 'id request_id agent_id start end adaptive state created_at finished_at result error_code') ||
      !uuid(x.id) || !uuid(x.request_id) || !str(x.agent_id) || !utc(x.start) || !utc(x.end) ||
      Date.parse(x.start) >= Date.parse(x.end) || typeof x.adaptive !== 'boolean' ||
      !['running', 'completed', 'failed', 'interrupted'].includes(String(x.state)) || !utc(x.created_at) ||
      !(x.finished_at === null || utc(x.finished_at)) || !nullable(x.error_code)) return { ok: false };
  if (x.state === 'completed') {
    const r = x.result;
    if (!object(r) || !exact(r, 'record_count query_complete collection_assurance cleanup_failed') ||
        !Number.isInteger(r.record_count) || Number(r.record_count) < 0 || Number(r.record_count) > 6300 ||
        r.query_complete !== true || r.collection_assurance !== 'unknown' || typeof r.cleanup_failed !== 'boolean' ||
        x.error_code !== null || x.finished_at === null) return { ok: false };
  } else if (x.result !== null || (x.state === 'running' && (x.finished_at !== null || x.error_code !== null))) return { ok: false };
  return { ok: true, value: x as unknown as Job };
}

export function parseSnapshot(x: unknown): Parsed<Snapshot> {
  if (!object(x) || !exact(x, 'state agents fetched_at error_code refreshing') ||
      !['not_configured', 'unavailable', 'ready', 'stale'].includes(String(x.state)) ||
      !Array.isArray(x.agents) || x.agents.length > 100 || typeof x.refreshing !== 'boolean' ||
      !nullable(x.error_code) || !(x.fetched_at === null || utc(x.fetched_at))) return { ok: false };
  for (const a of x.agents) {
    if (!object(a) || !exact(a, 'environment_id agent_id name os_name os_version source_status last_keepalive fetched_at') ||
        !str(a.environment_id) || !str(a.agent_id) || !utc(a.fetched_at) ||
        !['name', 'os_name', 'os_version', 'source_status', 'last_keepalive'].every(k => nullable(a[k]))) return { ok: false };
  }
  if (new Set(x.agents.map(a => a.agent_id)).size !== x.agents.length) return { ok: false };
  return { ok: true, value: x as unknown as Snapshot };
}

export function parseJobs(x: unknown): Parsed<{ jobs: Job[]; error_code: string | null }> {
  if (!object(x) || !exact(x, 'jobs error_code') || !Array.isArray(x.jobs) || x.jobs.length > 100 || !nullable(x.error_code)) return { ok: false };
  const jobs: Job[] = [];
  for (const item of x.jobs) { const p = parseJob(item); if (!p.ok) return { ok: false }; jobs.push(p.value); }
  if (new Set(jobs.map(j => j.id)).size !== jobs.length) return { ok: false };
  return { ok: true, value: { jobs, error_code: x.error_code as string | null } };
}
