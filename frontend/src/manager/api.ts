import { validDeviceV2, validDevicesV2, validDeviceHistory, validPairingCode, type DeviceV2DTO, type DeviceHistoryDTO, type DevicesV2DTO, type PairingCodeDTO } from './types';
import type { CreateUserInput, OverviewDTO, PermissionsDTO, SessionDTO, UpdateUserInput, UserDTO, UsersDTO } from './contracts';
import { catalogValidationCodes, validCatalogFile, validCatalogList, validCatalogPackage, type CatalogValidationCode, type CatalogFileDTO, type CatalogListDTO, type CatalogPackageDTO, type CatalogQuery } from './catalogTypes';

const accountErrorStatuses = {
  invalid_request: 400, invalid_username: 400, invalid_display_name: 400, invalid_password: 400,
  invalid_capabilities: 400, view_required: 400, inherited_capabilities_required: 409,
  username_exists: 409, user_not_found: 400, self_lock: 409, last_admin: 409,
  technical_account_readonly: 403, permission_denied: 403, unauthenticated: 401,
  invalid_credentials: 401, current_password_invalid: 400,
} as const;
const deviceErrorStatuses = { device_conflict: 409, device_busy: 409, device_not_found: 404 } as const;
const catalogErrorStatuses = { ...Object.fromEntries(catalogValidationCodes.map((code) => [code, code === 'package_too_large' ? 413 : 400])), invalid_package: 400, version_conflict: 409, content_conflict: 409, package_not_found: 404, storage_unavailable: 503 };
type ManagerErrorCode = keyof typeof accountErrorStatuses | keyof typeof deviceErrorStatuses | typeof catalogValidationCodes[number] | 'invalid_package' | 'version_conflict' | 'content_conflict' | 'package_not_found' | 'storage_unavailable';
const errorStatuses: Record<string, number> = { ...accountErrorStatuses, ...deviceErrorStatuses, ...catalogErrorStatuses };
export class ManagerApiError extends Error {
  readonly code: ManagerErrorCode | undefined;
  readonly validationCodes: CatalogValidationCode[];
  constructor(public readonly status: number, code?: unknown, validation?: unknown) {
    super('Manager request failed'); this.name = 'ManagerApiError';
    this.code = typeof code === 'string' && Object.hasOwn(errorStatuses, code) && errorStatuses[code as ManagerErrorCode] === status ? code as ManagerErrorCode : undefined;
    const report = validation as { valid?: unknown; codes?: unknown } | null;
    this.validationCodes = [400, 413].includes(status) && report?.valid === false && Array.isArray(report.codes) && report.codes.length <= catalogValidationCodes.length && report.codes.every((item: unknown) => catalogValidationCodes.some((code) => item === code)) ? [...new Set(report.codes as CatalogValidationCode[])] : [];
  }
}

async function readFailure(response: Response): Promise<{ code?: unknown; validation?: unknown }> {
  // Error responses have a tiny fixed contract. Never retain arbitrary source
  // text, and stop reading if a proxy returns a large HTML/diagnostic body.
  const reader = response.body?.getReader();
  if (!reader) return {};
  const bytes = new Uint8Array(1024); let length = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      if (length + chunk.value.length > bytes.length) { await reader.cancel(); return {}; }
      bytes.set(chunk.value, length); length += chunk.value.length;
    }
    const body = JSON.parse(new TextDecoder().decode(bytes.subarray(0, length))) as { error?: { code?: unknown }; validation?: unknown } | null;
    return { code: body?.error?.code, validation: body?.validation };
  } catch { return {}; }
  finally { reader.releaseLock(); }
}

export function createManagerApi(fetcher: typeof fetch = fetch) {
  let csrfToken = '';
  let generation = 0;
  const invalidate = () => { generation += 1; csrfToken = ''; };
  const stale = () => new DOMException('Request superseded', 'AbortError');

  async function request<T>(path: string, method = 'GET', body?: unknown, signal?: AbortSignal, token = csrfToken, expectedStatus?: number | number[], validate?: (value: unknown) => boolean, version: 'v1' | 'v2' = 'v1'): Promise<T> {
    const multipart = body instanceof FormData;
    const response = await fetcher(`/api/${version}/${path}`, {
      method, credentials: 'same-origin', cache: 'no-store', signal,
      headers: body === undefined ? undefined : multipart ? { 'X-CSRFToken': token } : { 'Content-Type': 'application/json', 'X-CSRFToken': token },
      ...(body === undefined ? {} : { body: multipart ? body : JSON.stringify(body) }),
    });
    if (!response.ok) { const failure = await readFailure(response); throw new ManagerApiError(response.status, failure.code, failure.validation); }
    if (expectedStatus !== undefined && !(Array.isArray(expectedStatus) ? expectedStatus : [expectedStatus]).includes(response.status)) throw new ManagerApiError(response.status);
    if (response.status === 204) return undefined as T;
    let result: unknown;
    try { result = await response.json(); } catch { throw new ManagerApiError(response.status); }
    if (validate && !validate(result)) throw new ManagerApiError(response.status);
    return result as T;
  }

  async function authenticate(path: string, body?: unknown, signal?: AbortSignal) {
    const current = ++generation;
    const result = await request<SessionDTO>(path, body === undefined ? 'GET' : 'POST', body, signal);
    if (current !== generation || signal?.aborted) throw stale();
    csrfToken = result.csrf_token;
    return result;
  }

  return {
    invalidate,
    listCatalog: (query: CatalogQuery = {}, signal?: AbortSignal) => {
      const params = new URLSearchParams({ page: String(query.page ?? 1), q: query.q ?? '', status: query.status ?? '' });
      return request<CatalogListDTO>(`catalog?${params}`, 'GET', undefined, signal, csrfToken, 200, validCatalogList);
    },
    importCatalog: (file: File, signal?: AbortSignal) => {
      const body = new FormData(); body.append('package', file);
      return request<CatalogPackageDTO>('catalog/import', 'POST', body, signal, csrfToken, [200, 201], validCatalogPackage);
    },
    catalogPackage: (id: string, signal?: AbortSignal) => request<CatalogPackageDTO>(`catalog/${encodeURIComponent(id)}`, 'GET', undefined, signal, csrfToken, 200, validCatalogPackage),
    catalogFile: (id: string, path: string, signal?: AbortSignal) => request<CatalogFileDTO>(`catalog/${encodeURIComponent(id)}/file?${new URLSearchParams({ path })}`, 'GET', undefined, signal, csrfToken, 200, validCatalogFile),
    publishCatalog: (id: string, sha256: string, signal?: AbortSignal) => request<CatalogPackageDTO>(`catalog/${encodeURIComponent(id)}/publish`, 'POST', { sha256 }, signal, csrfToken, 200, validCatalogPackage),
    unpublishCatalog: (id: string, sha256: string, signal?: AbortSignal) => request<CatalogPackageDTO>(`catalog/${encodeURIComponent(id)}/unpublish`, 'POST', { sha256 }, signal, csrfToken, 200, validCatalogPackage),
    session: (signal?: AbortSignal) => authenticate('auth/session', undefined, signal),
    login: (input: { username: string; password: string }, signal?: AbortSignal) => authenticate('auth/login', input, signal),
    logout: (signal?: AbortSignal) => {
      const token = csrfToken;
      invalidate();
      return request<void>('auth/logout', 'POST', {}, signal, token);
    },
    changePassword: (input: { current_password: string; new_password: string }, signal?: AbortSignal) => request<void>('auth/password', 'POST', input, signal),
    listUsers: (query: { page?: number; q?: string } = {}, signal?: AbortSignal) => {
      const params = new URLSearchParams({ page: String(query.page ?? 1) });
      if (query.q !== undefined) params.set('q', query.q);
      return request<UsersDTO>(`users?${params}`, 'GET', undefined, signal);
    },
    createUser: (input: CreateUserInput, signal?: AbortSignal) => request<UserDTO>('users', 'POST', input, signal),
    updateUser: (id: number, input: UpdateUserInput, signal?: AbortSignal) => request<UserDTO>(`users/${id}`, 'PUT', input, signal),
    resetPassword: (id: number, input: { new_password: string }, signal?: AbortSignal) => request<void>(`users/${id}/reset-password`, 'POST', input, signal),
    listDevices: (query: { page?: number; search?: string; scope?: 'managed' | 'archived' } = {}, signal?: AbortSignal) => {
      const params = new URLSearchParams({ page: String(query.page ?? 1) });
      params.set('scope', query.scope ?? 'managed');
      if (query.search !== undefined) params.set('search', query.search);
      return request<DevicesV2DTO>(`devices?${params}`, 'GET', undefined, signal, csrfToken, 200, validDevicesV2, 'v2');
    },
    device: (id: string, signal?: AbortSignal) => request<DeviceV2DTO>(`devices/${encodeURIComponent(id)}`, 'GET', undefined, signal, csrfToken, 200, validDeviceV2, 'v2'),
    deviceHistory: (id: string, page = 1, signal?: AbortSignal) => request<DeviceHistoryDTO>(`devices/${encodeURIComponent(id)}/history?page=${page}`, 'GET', undefined, signal, csrfToken, 200, validDeviceHistory, 'v2'),
    archiveDevice: (id: string, signal?: AbortSignal) => request<void>(`devices/${encodeURIComponent(id)}/archive`, 'POST', {}, signal, csrfToken, 204, undefined, 'v2'),
    createPairingCode: (input: { environment_id: string }, signal?: AbortSignal) => request<PairingCodeDTO>('pairing-codes', 'POST', input, signal, csrfToken, 201, validPairingCode),
    revokePairingCode: (id: string, signal?: AbortSignal) => request<void>(`pairing-codes/${encodeURIComponent(id)}/revoke`, 'POST', {}, signal, csrfToken, 204),
    revokeDevice: (id: string, signal?: AbortSignal) => request<void>(`devices/${encodeURIComponent(id)}/revoke`, 'POST', {}, signal, csrfToken, 204),
    permissions: (signal?: AbortSignal) => request<PermissionsDTO>('users/permissions', 'GET', undefined, signal),
    overview: (signal?: AbortSignal) => request<OverviewDTO>('overview', 'GET', undefined, signal),
  };
}
export type ManagerApi = ReturnType<typeof createManagerApi>;
