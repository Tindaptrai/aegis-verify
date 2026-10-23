import type { CreateUserInput, OverviewDTO, PermissionsDTO, SessionDTO, UpdateUserInput, UserDTO, UsersDTO } from './contracts';

export class ManagerApiError extends Error {
  constructor(public readonly status: number) { super('Manager request failed'); this.name = 'ManagerApiError'; }
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
    if (!response.ok) throw new ManagerApiError(response.status);
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
