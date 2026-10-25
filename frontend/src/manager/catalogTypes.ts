export type CatalogStatus = 'draft' | 'published' | 'unpublished';
export interface CatalogItemDTO {
  id: string; scenario_id: string; name: string; version: string; platform: 'windows';
  runner: 'windows-powershell-script@1'; timeout_seconds: number; sha256: string; status: CatalogStatus;
  created_at: string; created_by: string | null; published_at: string | null; published_by: string | null;
}
export interface CatalogListDTO { results: CatalogItemDTO[]; count: number; page: number; page_size: 50 }
export interface CatalogPackageDTO extends CatalogItemDTO {
  validation: { valid: true; codes: [] };
  files: { path: string; size: number; sha256: string }[];
  audit: { action: 'imported' | 'published' | 'unpublished'; actor: string | null; at: string }[];
  execution_supported: false;
}
export interface CatalogFileDTO { path: string; text: string }
export interface CatalogQuery { page?: number; q?: string; status?: CatalogStatus | '' }
export const catalogValidationCodes = [
  'invalid_zip', 'package_too_large', 'too_many_members', 'member_too_large', 'expanded_too_large',
  'compression_ratio', 'invalid_path', 'duplicate_member', 'unsupported_member', 'encrypted_member',
  'unsupported_compression', 'nested_archive', 'invalid_utf8', 'invalid_json', 'invalid_metadata',
  'inventory_mismatch', 'hash_mismatch', 'invalid_scenario', 'scenario_mismatch', 'invalid_profile', 'profile_mismatch',
] as const;
export type CatalogValidationCode = typeof catalogValidationCodes[number];
const keys = 'id,scenario_id,name,version,platform,runner,timeout_seconds,sha256,status,created_at,created_by,published_at,published_by';
const record = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const closed = (value: unknown, fields: string): value is Record<string, unknown> => record(value) && Object.keys(value).sort().join(',') === fields.split(',').sort().join(',');
const text = (value: unknown, max = 512) => typeof value === 'string' && value.length > 0 && value.length <= max;
const nullable = (value: unknown, check: (value: unknown) => boolean) => value === null || check(value);
const hash = (value: unknown) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const integer = (value: unknown, min: number, max = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(value) && Number(value) >= min && Number(value) <= max;
function date(value: unknown) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(value)) return false;
  const parsed = new Date(value);
  return Number.isFinite(parsed.valueOf()) && parsed.toISOString().slice(0, 19) === value.slice(0, 19);
}
export function validCatalogPath(value: unknown): value is string {
  return text(value, 512) && typeof value === 'string' && !/[\\:\x00-\x1f\x7f]/.test(value) && !value.startsWith('/') && value.split('/').every((part) => part.length > 0 && part !== '.' && part !== '..' && !/[. ]$/.test(part));
}
function itemFields(value: Record<string, unknown>) {
  return typeof value.id === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value.id)
    && text(value.scenario_id, 64) && text(value.name) && text(value.version, 128)
    && value.platform === 'windows' && value.runner === 'windows-powershell-script@1' && integer(value.timeout_seconds, 1, 600)
    && hash(value.sha256) && ['draft', 'published', 'unpublished'].includes(String(value.status))
    && date(value.created_at) && nullable(value.created_by, text) && nullable(value.published_at, date) && nullable(value.published_by, text)
    && (value.status !== 'published' || value.published_at !== null);
}
export const validCatalogItem = (value: unknown): value is CatalogItemDTO => closed(value, keys) && itemFields(value);
export function validCatalogList(value: unknown): value is CatalogListDTO {
  return closed(value, 'results,count,page,page_size') && Array.isArray(value.results) && value.results.length <= 50 && value.results.every(validCatalogItem)
    && integer(value.count, value.results.length) && integer(value.page, 1) && value.page_size === 50;
}
export function validCatalogPackage(value: unknown): value is CatalogPackageDTO {
  if (!closed(value, `${keys},validation,files,audit,execution_supported`) || !itemFields(value)) return false;
  return value.execution_supported === false && closed(value.validation, 'valid,codes') && value.validation.valid === true && Array.isArray(value.validation.codes) && value.validation.codes.length === 0
    && Array.isArray(value.files) && value.files.length > 0 && value.files.length <= 200
    && value.files.every((file) => closed(file, 'path,size,sha256') && validCatalogPath(file.path) && integer(file.size, 0, 1024 * 1024) && hash(file.sha256))
    && new Set(value.files.map((file) => (file as { path: string }).path.toLowerCase())).size === value.files.length
    && Array.isArray(value.audit) && value.audit.every((entry) => closed(entry, 'action,actor,at') && ['imported', 'published', 'unpublished'].includes(String(entry.action)) && nullable(entry.actor, text) && date(entry.at));
}
export function validCatalogFile(value: unknown): value is CatalogFileDTO {
  return closed(value, 'path,text') && validCatalogPath(value.path) && typeof value.text === 'string' && new TextEncoder().encode(value.text).length <= 1024 * 1024;
}
