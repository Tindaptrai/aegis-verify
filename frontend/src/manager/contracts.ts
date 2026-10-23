export const CAPABILITIES = ['view', 'run_jobs', 'import_scenarios', 'publish_scenarios', 'manage_devices', 'manage_connections', 'export_evidence', 'manage_users'] as const;
export type Capability = typeof CAPABILITIES[number];
export interface UserDTO {
  id: number;
  username: string;
  display_name: string;
  is_active: boolean;
  role: 'admin' | 'operator' | 'viewer' | 'custom' | 'technical';
  capabilities: Capability[];
  inherited_capabilities: Capability[];
  editable: boolean;
}
export interface SessionDTO {
  authenticated: boolean;
  csrf_token: string;
  user: UserDTO | null;
  expires_at: number | null;
}
export interface OverviewDTO { registered_devices: number; recorded_jobs: number; recorded_releases: number }
export interface UsersDTO { results: UserDTO[]; count: number; page: number; page_size: 50 }
export interface PermissionsDTO {
  capabilities: { key: Capability; label: string; description: string }[];
  presets: Record<'admin' | 'operator' | 'viewer', Capability[]>;
  inheritance_explanation: string;
}
export interface UpdateUserInput { display_name: string; capabilities: Capability[]; is_active: boolean }
export interface CreateUserInput extends UpdateUserInput { username: string; password: string }
