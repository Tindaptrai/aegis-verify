import type { CreateUserInput, OverviewDTO, PermissionsDTO, SessionDTO, UpdateUserInput, UserDTO, UsersDTO } from './contracts';

const accountErrorStatuses = {
  invalid_request: 400, invalid_username: 400, invalid_display_name: 400, invalid_password: 400,
  invalid_capabilities: 400, view_required: 400, inherited_capabilities_required: 409,
  username_exists: 409, user_not_found: 400, self_lock: 409, last_admin: 409,
  technical_account_readonly: 403, permission_denied: 403, unauthenticated: 401,
  invalid_credentials: 401, current_password_invalid: 400,
} as const;
type AccountErrorCode = keyof typeof accountErrorStatuses;
export class ManagerApiError extends Error {
  readonly code: AccountErrorCode | undefined;
  constructor(public readonly status: number, code?: unknown) {
    super('Manager request failed'); this.name = 'ManagerApiError';
    this.code = typeof code === 'string' && Object.hasOwn(accountErrorStatuses, code) && accountErrorStatuses[code as AccountErrorCode] === status ? code as AccountErrorCode : undefined;
  }
}

async function readErrorCode(response: Response): Promise<unknown> {
  // Error responses have a tiny fixed contract. Never retain arbitrary source
  // text, and stop reading if a proxy returns a large HTML/diagnostic body.
  const reader = response.body?.getReader();
  if (!reader) return undefined;
  const bytes = new Uint8Array(1024); let length = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      if (length + chunk.value.length > bytes.length) { await reader.cancel(); return undefined; }
      bytes.set(chunk.value, length); length += chunk.value.length;
    }
    return (JSON.parse(new TextDecoder().decode(bytes.subarray(0, length))) as { error?: { code?: unknown } } | null)?.error?.code;
  } catch { return undefined; }
  finally { reader.releaseLock(); }
}

export function createManagerApi(fetcher: typeof fetch = fetch) {
  let csrfToken = '';
  let generation = 0;
  const invalidate = () => { generation += 1; csrfToken = ''; };
  const stale = () => new DOMException('Request superseded', 'AbortError');

  async function request<T>(path: string, method = 'GET', body?: unknown, signal?: AbortSignal, token = csrfToken): Promise<T> {
    const response = await fetcher(`/api/v1/${path}`, {
      method, credentials: 'same-origin', cache: 'no-store', signal,
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json', 'X-CSRFToken': token },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    if (!response.ok) throw new ManagerApiError(response.status, await readErrorCode(response));
    return response.status === 204 ? undefined as T : await response.json() as T;
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
    permissions: (signal?: AbortSignal) => request<PermissionsDTO>('users/permissions', 'GET', undefined, signal),
    overview: (signal?: AbortSignal) => request<OverviewDTO>('overview', 'GET', undefined, signal),
  };
}
export type ManagerApi = ReturnType<typeof createManagerApi>;
