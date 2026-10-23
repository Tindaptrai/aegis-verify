// Synthetic responses for tests only. Never imported by the Manager entry.
import { vi } from 'vitest';
import type { ManagerApi } from './api';
import { CAPABILITIES, type SessionDTO, type UsersDTO, type PermissionsDTO } from './contracts';

export const anonymousSession: SessionDTO = { authenticated: false, csrf_token: 'synthetic-csrf', user: null, expires_at: null };
export function userSession(role: 'admin' | 'operator' | 'viewer'): SessionDTO {
  return { authenticated: true, csrf_token: 'synthetic-csrf', expires_at: Math.floor(Date.now() / 1000) + 3600,
    user: { id: 42, username: 'synthetic', display_name: 'Synthetic test user', is_active: true, role,
      capabilities: role === 'admin' ? [...CAPABILITIES] : role === 'operator' ? ['view', 'run_jobs', 'export_evidence'] : ['view'], inherited_capabilities: [], editable: role === 'admin' } };
}
export function signedInApiFixture(role: 'admin' | 'operator' | 'viewer', options?: { technicalTarget?: boolean }): ManagerApi {
  let current = userSession(role);
  const target = { ...current.user!, ...(options?.technicalTarget ? { role: 'technical' as const, editable: false } : {}) };
  return {
    invalidate: vi.fn(),
    session: vi.fn(async () => current),
    login: vi.fn(async () => { current = userSession(role); return current; }),
    logout: vi.fn(async () => { current = anonymousSession; }),
    changePassword: vi.fn(async () => undefined),
    overview: vi.fn(async () => ({ registered_devices: 17, recorded_jobs: 8, recorded_releases: 3 })),
    listUsers: vi.fn(async (): Promise<UsersDTO> => ({ results: [target], count: 1, page: 1, page_size: 50 })),
    createUser: vi.fn(async (input) => ({ ...target, ...input, id: 43 })),
    updateUser: vi.fn(async (id, input) => ({ ...target, ...input, id })),
    resetPassword: vi.fn(async () => undefined),
    permissions: vi.fn(async (): Promise<PermissionsDTO> => ({ capabilities: CAPABILITIES.map((key) => ({ key, label: key, description: `Synthetic ${key}` })), presets: { admin: [...CAPABILITIES], operator: ['view', 'run_jobs', 'export_evidence'], viewer: ['view'] }, inheritance_explanation: 'Synthetic test inheritance description' })),
  };
}
