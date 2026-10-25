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

export interface DeviceV2DTO extends Omit<DeviceDTO, 'status'> {
  status: DeviceDTO['status'] | 'archived';
  reported_ips: string[] | null;
  ip_collection_status: 'unknown' | 'ok' | 'unavailable';
  reported_ips_truncated: boolean;
  reported_ips_received_at: string | null;
  observed_ip: string | null;
  observed_ip_received_at: string | null;
  reported_agent_version: string | null;
  archived_at: string | null;
  archived_by_id: number | null;
  can_archive: boolean;
  archive_block_reason: 'legacy_device' | 'device_busy' | 'already_archived' | null;
}
export interface DevicesV2DTO { results: DeviceV2DTO[]; count: number; page: number; page_size: 50 }
export interface DeviceHistoryRow { action: string; created_at: string; actor_id: number | null; code_id: string | null; device_id: string | null }
export interface DeviceHistoryDTO { results: DeviceHistoryRow[]; count: number; page: number; page_size: 50 }
const networkKeys = ['reported_ips', 'ip_collection_status', 'reported_ips_truncated', 'reported_ips_received_at', 'observed_ip', 'observed_ip_received_at', 'reported_agent_version', 'archived_at', 'archived_by_id', 'can_archive', 'archive_block_reason'];
const ip = (value: unknown) => typeof value === 'string' && value.length <= 45 && (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) ? value.split('.').every((n) => Number(n) <= 255 && String(Number(n)) === n) : value.includes(':') && /^[0-9a-f:]+$/.test(value) && (() => { try { return new URL(`http://[${value}]/`).hostname.length > 0; } catch { return false; } })());
export function validDeviceV2(value: unknown): value is DeviceV2DTO {
  if (!record(value) || networkKeys.some((key) => !Object.hasOwn(value, key))) return false;
  const base = Object.fromEntries(Object.entries(value).filter(([key]) => !networkKeys.includes(key)));
  if (base.status === 'archived') base.status = 'revoked';
  return validDevice(base) && typeof value.ip_collection_status === 'string' && ['unknown', 'ok', 'unavailable'].includes(String(value.ip_collection_status))
    && (value.reported_ips === null || Array.isArray(value.reported_ips) && value.reported_ips.length <= 32 && value.reported_ips.every(ip) && new Set(value.reported_ips).size === value.reported_ips.length)
    && (value.ip_collection_status === 'ok' ? Array.isArray(value.reported_ips) : value.reported_ips === null)
    && typeof value.reported_ips_truncated === 'boolean' && (!value.reported_ips_truncated || Array.isArray(value.reported_ips) && value.reported_ips.length === 32)
    && nullable(value.reported_ips_received_at, date) && nullable(value.observed_ip, ip) && nullable(value.observed_ip_received_at, date)
    && nullable(value.reported_agent_version, (v) => typeof v === 'string' && v.length <= 32 && /^(0|[1-9]\d{0,4})\.(0|[1-9]\d{0,4})\.(0|[1-9]\d{0,4})$/.test(v))
    && nullable(value.archived_at, date) && nullable(value.archived_by_id, positive)
    && (value.status === 'archived') === (value.archived_at !== null)
    && typeof value.can_archive === 'boolean' && (value.archive_block_reason === null || typeof value.archive_block_reason === 'string' && ['legacy_device', 'device_busy', 'already_archived'].includes(value.archive_block_reason))
    && value.can_archive === (value.archive_block_reason === null)
    && (value.status !== 'archived' || value.archive_block_reason === 'already_archived')
    && (value.connection_kind !== 'legacy_v1' || value.archive_block_reason === 'legacy_device' || value.archive_block_reason === 'already_archived');
}
function page(value: unknown, row: (value: unknown) => boolean) {
 return closed(value, 'results,count,page,page_size') && Array.isArray(value.results) && value.results.length <= 50 && value.results.every(row) && Number.isSafeInteger(value.count) && Number(value.count) >= value.results.length && positive(value.page) && value.page_size === 50;
}
export const validDevicesV2 = (value: unknown): value is DevicesV2DTO => page(value, validDeviceV2);
export const validDeviceHistory = (value: unknown): value is DeviceHistoryDTO => page(value, (row) => closed(row, 'action,created_at,actor_id,code_id,device_id') && typeof row.action === 'string' && ['pairing_code_created', 'pairing_code_revoked', 'device_enrolled', 'device_revoked', 'device_archived'].includes(row.action) && date(row.created_at) && nullable(row.actor_id, positive) && nullable(row.code_id, uuid) && nullable(row.device_id, uuid));
