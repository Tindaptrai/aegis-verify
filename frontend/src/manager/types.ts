// Frozen human pairing wire contract. Presence never grants execution readiness.
export interface DeviceDTO {
  id: string;
  hostname: string | null;
  environment_id: string;
  wazuh_agent_id: string | null;
  connection_kind: 'legacy_v1' | 'paired_presence';
  os: 'windows' | 'linux' | null;
  architecture: 'x64' | null;
  agent_version: string | null;
  generation: number;
  status: 'online' | 'offline' | 'expired' | 'revoked' | 'unknown';
  last_heartbeat_at: string | null;
  certificate_expires_at: string | null;
  execution_supported: false;
}
export interface DevicesDTO { results: DeviceDTO[]; count: number; page: number; page_size: 50 }
export interface PairingCodeDTO { id: string; code: string; environment_id: string; expires_at: string }
const uuid = (value: unknown) => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
function date(value: unknown) {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(value)) return false;
  const parsed = new Date(value);
  return Number.isFinite(parsed.valueOf()) && parsed.toISOString().slice(0, 19) === value.slice(0, 19);
}
export const validEnvironment = (value: string) => /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(value);
const record = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
function closed(value: unknown, keys: string): value is Record<string, unknown> {
  return record(value) && Object.keys(value).sort().join(',') === keys.split(',').sort().join(',');
}
const nullable = (value: unknown, validate: (value: unknown) => boolean) => value === null || validate(value);
const text = (value: unknown) => typeof value === 'string';
const positive = (value: unknown) => Number.isSafeInteger(value) && Number(value) > 0;
function validDevice(value: unknown): value is DeviceDTO {
  if (!closed(value, 'id,hostname,environment_id,wazuh_agent_id,connection_kind,os,architecture,agent_version,generation,status,last_heartbeat_at,certificate_expires_at,execution_supported')) return false;
  return uuid(value.id) && (value.hostname === null ? value.connection_kind === 'legacy_v1' : typeof value.hostname === 'string' && value.hostname.length > 0 && value.hostname.length <= 255)
    && typeof value.environment_id === 'string' && validEnvironment(value.environment_id) && nullable(value.wazuh_agent_id, text)
    && typeof value.connection_kind === 'string' && ['legacy_v1', 'paired_presence'].includes(value.connection_kind)
    && nullable(value.os, (item) => item === 'windows' || item === 'linux') && nullable(value.architecture, (item) => item === 'x64')
    && nullable(value.agent_version, text) && positive(value.generation)
    && typeof value.status === 'string' && ['online', 'offline', 'expired', 'revoked', 'unknown'].includes(value.status)
    && (value.connection_kind === 'legacy_v1' ? ['unknown', 'expired', 'revoked'].includes(String(value.status)) : value.status !== 'unknown')
    && nullable(value.last_heartbeat_at, date) && nullable(value.certificate_expires_at, date) && value.execution_supported === false;
}
export function validDevices(value: unknown): value is DevicesDTO {
  return closed(value, 'results,count,page,page_size') && Array.isArray(value.results) && value.results.length <= 50 && value.results.every(validDevice)
    && Number.isSafeInteger(value.count) && Number(value.count) >= value.results.length && positive(value.page) && value.page_size === 50;
}
export function validPairingCode(value: unknown): value is PairingCodeDTO {
  return closed(value, 'id,code,environment_id,expires_at') && uuid(value.id) && typeof value.code === 'string' && /^[0-9a-f]{64}$/.test(value.code)
    && typeof value.environment_id === 'string' && validEnvironment(value.environment_id) && date(value.expires_at);
}
