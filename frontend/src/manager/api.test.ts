import { describe, expect, it, vi } from 'vitest';
import { createManagerApi, ManagerApiError } from './api';

const session = (csrf_token: string) => ({ authenticated: false, csrf_token, user: null, expires_at: null });
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });

describe('Manager same-origin API', () => {
  it('uses cookie credentials and refreshed in-memory CSRF after login', async () => {
    const persist = vi.spyOn(Storage.prototype, 'setItem');
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(json(session('initial')))
      .mockResolvedValueOnce(json(session('rotated'))).mockResolvedValueOnce(new Response(null, { status: 204 }));
    const api = createManagerApi(fetcher);
    await api.session();
    await api.login({ username: 'synthetic', password: 'synthetic-only' });
    await api.changePassword({ current_password: 'synthetic-only', new_password: 'replacement-only' });
    expect(fetcher.mock.calls[0]).toEqual(['/api/v1/auth/session', expect.objectContaining({ credentials: 'same-origin', cache: 'no-store' })]);
    expect(fetcher.mock.calls[1]?.[1]).toMatchObject({ headers: { 'Content-Type': 'application/json', 'X-CSRFToken': 'initial' } });
    expect(fetcher.mock.calls[2]?.[1]).toMatchObject({ headers: { 'X-CSRFToken': 'rotated' } });
    expect(localStorage.length).toBe(0);
    expect(persist).not.toHaveBeenCalled();
    persist.mockRestore();
  });

  it.each(['session', 'login'] as const)('ignores a late %s CSRF token after logout and a new login', async (method) => {
    let finish!: (response: Response) => void;
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(json(session('initial')))
      .mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(json(session('new-user-token')))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    const api = createManagerApi(fetcher);
    await api.session();
    const old = method === 'session' ? api.session() : api.login({ username: 'old', password: 'synthetic' });
    await api.logout();
    expect(fetcher.mock.calls[2]?.[1]).toMatchObject({ headers: { 'X-CSRFToken': 'initial' } });
    await api.login({ username: 'new', password: 'synthetic' });
    finish(json(session('old-user-token')));
    await expect(old).rejects.toMatchObject({ name: 'AbortError' });
    await api.changePassword({ current_password: 'synthetic', new_password: 'synthetic-new' });
    expect(fetcher.mock.calls[4]?.[1]).toMatchObject({ headers: { 'X-CSRFToken': 'new-user-token' } });
  });

  it('preserves 401 and 403 for UI decisions without exposing server text', async () => {
    for (const status of [401, 403]) {
      const api = createManagerApi(vi.fn<typeof fetch>().mockResolvedValue(json({ error: { code: 'private-source-value' } }, status)));
      await expect(api.overview()).rejects.toEqual(new ManagerApiError(status));
    }
  });

  it('maps all account endpoints and bounded query values without Operations auth', async () => {
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async () => json({}));
    const api = createManagerApi(fetcher);
    await api.listUsers({ page: 2, q: 'a & b' });
    await api.permissions();
    await api.overview();
    await api.createUser({ username: 'synthetic', display_name: '', password: 'test-only', capabilities: ['view'], is_active: true });
    await api.updateUser(42, { display_name: 'test', capabilities: ['view'], is_active: false });
    await api.resetPassword(42, { new_password: 'test-only' });
    expect(fetcher.mock.calls.map(([url]) => url)).toEqual([
      '/api/v1/users?page=2&q=a+%26+b', '/api/v1/users/permissions', '/api/v1/overview',
      '/api/v1/users', '/api/v1/users/42', '/api/v1/users/42/reset-password',
    ]);
    expect(fetcher.mock.calls.every(([, init]) => !('Authorization' in (init?.headers ?? {})))).toBe(true);
  });
});
