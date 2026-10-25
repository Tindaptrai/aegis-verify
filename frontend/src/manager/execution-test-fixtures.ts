// Explicitly synthetic execution responses, imported by tests only.
import { vi } from 'vitest';
import { signedInApiFixture } from './test-fixtures';
import type { ExecutionDeviceDTO, ProviderDTO, PublicSummary, PreviewDTO, JobDTO, ReleaseId } from './executionTypes';
import type { DeviceV2DTO } from './types';
export const targetId = '11111111-1111-4111-8111-111111111111';
export const hash = 'a'.repeat(64);
export const release = '9007199254740993' as ReleaseId;
export const provider: ProviderDTO = { provider_id: 'reviewed-scn001-windows/1', scenario_id: 'SCN-001', runner_id: 'scn001-safe-demo', runner_version: '0.3.0', release_id: release, release_sha256: hash, allow_rehearsal: false, timeout_seconds: 300 };
export const device: DeviceV2DTO = { id: targetId, hostname: 'Synthetic Windows', environment_id: 'training', wazuh_agent_id: null, connection_kind: 'paired_presence', os: 'windows', architecture: 'x64', agent_version: '0.3.0', generation: 1, status: 'online', last_heartbeat_at: null, certificate_expires_at: null, execution_supported: false, reported_ips: null, ip_collection_status: 'unknown', reported_ips_truncated: false, reported_ips_received_at: null, observed_ip: null, observed_ip_received_at: null, reported_agent_version: null, archived_at: null, archived_by_id: null, can_archive: true, archive_block_reason: null };
export const readiness: ExecutionDeviceDTO = { device_id: targetId, provider_id: provider.provider_id, binding_id: targetId, binding_revision: 1, capability: 'installed_supported', ready: true, blocking_codes: [], checked_at: '2099-01-01T00:00:00Z', readiness_expires_at: '2099-01-01T00:00:30Z', release_id: release, release_sha256: hash, wazuh_connection_id: targetId, wazuh_agent_id: '001' };
export const summary: PublicSummary = { device_id: targetId, environment_id: 'training', wazuh_connection_id: targetId, wazuh_agent_id: '001', provider_id: provider.provider_id, binding_id: targetId, binding_revision: 1, release_id: release, release_sha256: hash, scenario_id: 'SCN-001', runner_id: 'scn001-safe-demo', runner_version: '0.3.0', parameters: { run_label: 'A', rule_revision: 'baseline', rule_sha256: hash }, timeout_seconds: 300, not_before: '2099-01-01T00:00:00Z', expires_at: '2099-01-01T00:02:00Z', collection_start: '2098-12-31T23:59:30Z', collection_end: '2099-01-01T00:07:00Z', artifact_pins: { scenario_sha256: hash, profile_sha256: hash, runner_sha256: hash, kit_sha256: hash, payload_sha256: hash }, rule_pins: { baseline: hash, behavioral: hash }, cleanup_policy: 'bounded_process_tree', execution_receipt_is_detection_evidence: false, run_binding: 'unknown', collection_assurance: 'unknown' };
export const preview: PreviewDTO = { preview_id: targetId, preview_sha256: hash, expires_at: summary.expires_at, summary };
export const job: JobDTO = { job_id: targetId, summary, execution_state: 'succeeded', collection_state: 'pending', evaluation_state: 'not_evaluated', created_at: summary.not_before, started_authorized_at: summary.not_before, finished_at: '2099-01-01T00:01:00Z', error_code: null, report: null };
export function executionFixture() {
  const api = signedInApiFixture('admin');
  api.listDevices = vi.fn(async () => ({ results: [device], count: 1, page: 1, page_size: 50 as const }));
  api.executionProviders = vi.fn(async () => ({ providers: [provider] }));
  api.executionDevice = vi.fn(async (id) => ({ ...readiness, device_id: id }));
  api.previewExecution = vi.fn(async () => preview);
  api.approveExecution = vi.fn(async () => job);
  api.executionJob = vi.fn(async () => job);
  api.setExecutionBinding = vi.fn(async () => readiness);
  api.cancelExecution = vi.fn(async () => ({ ...job, execution_state: 'cancelled' as const }));
  return api;
}
