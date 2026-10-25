// Execution v2 public records only. Private snapshots and connection config never cross this boundary.
export type ReleaseId = string & { readonly __releaseId: unique symbol };
export const PROVIDER = 'reviewed-scn001-windows/1' as const;
export const blockingLabels = {
  profile_mismatch: 'Profile cài đặt không khớp', artifact_mismatch: 'Artifact không khớp', clock_uncertain: 'Đồng hồ chưa đủ chính xác',
  local_not_ready: 'Agent chưa sẵn sàng', unsupported_platform: 'Nền tảng không hỗ trợ', upgrade_required: 'Agent cần nâng cấp',
  binding_missing: 'Chưa có binding', binding_disabled: 'Binding đã tắt', identity_unavailable: 'Danh tính không khả dụng',
  environment_invalid: 'Môi trường không hợp lệ', mapping_missing: 'Thiếu mapping Wazuh', ownership_conflict: 'Xung đột quyền sở hữu',
  local_stale: 'Readiness đã cũ', worker_unavailable: 'Worker chưa sẵn sàng', source_unavailable: 'Nguồn evidence không khả dụng',
  busy: 'Đang bận', reconciliation_required: 'Cần đối soát tác vụ',
} as const;
export type BlockingCode = keyof typeof blockingLabels;
export type RunLabel = 'A' | 'B' | 'C' | 'Rehearsal';
export interface ProviderDTO { provider_id: typeof PROVIDER; scenario_id: 'SCN-001'; runner_id: 'scn001-safe-demo'; runner_version: '0.3.0'; release_id: ReleaseId; release_sha256: string; allow_rehearsal: boolean; timeout_seconds: number }
export interface ProviderList { providers: ProviderDTO[] }
export interface ExecutionDeviceDTO { device_id: string; provider_id: typeof PROVIDER | null; binding_id: string | null; binding_revision: number | null; capability: 'installed_supported' | 'upgrade_required' | 'unsupported'; ready: boolean; blocking_codes: BlockingCode[]; checked_at: string | null; readiness_expires_at: string | null; release_id: ReleaseId | null; release_sha256: string | null; wazuh_connection_id: string | null; wazuh_agent_id: string | null }
export interface BindingInput { expected_revision: number | null; enabled: boolean; provider_id: typeof PROVIDER; runner_release_id: ReleaseId; installation_profile_sha256: string; wazuh_connection_id: string; wazuh_connection_revision: number; wazuh_agent_id: string }
export interface PreviewInput { device_id: string; provider_id: typeof PROVIDER; binding_revision: number; run_label: RunLabel; rule_revision: 'baseline' | 'behavioral' }
export interface ApproveInput { preview_id: string; preview_sha256: string; idempotency_key: string }
export interface Parameters { run_label: RunLabel; rule_revision: 'baseline' | 'behavioral'; rule_sha256: string }
export interface ArtifactPins { scenario_sha256: string; profile_sha256: string; runner_sha256: string; kit_sha256: string; payload_sha256: string }
export interface PublicSummary { device_id: string; environment_id: string; wazuh_connection_id: string; wazuh_agent_id: string; provider_id: typeof PROVIDER; binding_id: string; binding_revision: number; release_id: ReleaseId; release_sha256: string; scenario_id: 'SCN-001'; runner_id: 'scn001-safe-demo'; runner_version: '0.3.0'; parameters: Parameters; timeout_seconds: number; not_before: string; expires_at: string; collection_start: string; collection_end: string; artifact_pins: ArtifactPins; rule_pins: { baseline: string; behavioral: string }; cleanup_policy: 'bounded_process_tree'; execution_receipt_is_detection_evidence: false; run_binding: 'unknown'; collection_assurance: 'unknown' }
export interface PreviewDTO { preview_id: string; preview_sha256: string; expires_at: string; summary: PublicSummary }
export type ExecutionState = 'draft' | 'queued' | 'leased' | 'started' | 'succeeded' | 'failed' | 'execution_unknown' | 'cancelled' | 'expired';
export interface JobDTO { job_id: string; summary: PublicSummary; execution_state: ExecutionState; collection_state: 'pending' | 'collecting' | 'evaluated' | 'empty' | 'failed' | 'reconciled'; evaluation_state: 'not_evaluated' | 'evaluated'; created_at: string; started_authorized_at: string | null; finished_at: string | null; error_code: string | null; report: Readonly<Record<string, unknown>> | null }

const record = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const closed = (v: unknown, keys: string): v is Record<string, unknown> => record(v) && Object.keys(v).sort().join(',') === keys.split(',').sort().join(',');
const nullable = (v: unknown, f: (v: unknown) => boolean) => v === null || f(v);
export const executionHash = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
export const executionUuid = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(v) && v !== '00000000-0000-0000-0000-000000000000';
export const executionRevision = (v: unknown): v is number => Number.isInteger(v) && Number(v) >= 1 && Number(v) <= 2147483647;
export const validReleaseId = (v: unknown): v is ReleaseId => typeof v === 'string' && /^[1-9][0-9]{0,18}$/.test(v) && (v.length < 19 || v <= '9223372036854775807');
const agent = (v: unknown) => typeof v === 'string' && /^[0-9]{1,64}$/.test(v);
export function executionTime(v: unknown): v is string { return typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(v) && Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v.replace('Z', '.000Z'); }
const timeout = (v: unknown) => Number.isInteger(v) && Number(v) >= 180 && Number(v) <= 300;
const providerFields = (v: Record<string, unknown>) => v.provider_id === PROVIDER && v.scenario_id === 'SCN-001' && v.runner_id === 'scn001-safe-demo' && v.runner_version === '0.3.0' && validReleaseId(v.release_id) && executionHash(v.release_sha256) && timeout(v.timeout_seconds);
export function validProviderList(v: unknown): v is ProviderList { return closed(v, 'providers') && Array.isArray(v.providers) && v.providers.length <= 1000 && v.providers.every((p) => closed(p, 'provider_id,scenario_id,runner_id,runner_version,release_id,release_sha256,allow_rehearsal,timeout_seconds') && providerFields(p) && typeof p.allow_rehearsal === 'boolean'); }
export function validExecutionDevice(v: unknown): v is ExecutionDeviceDTO {
  return closed(v, 'device_id,provider_id,binding_id,binding_revision,capability,ready,blocking_codes,checked_at,readiness_expires_at,release_id,release_sha256,wazuh_connection_id,wazuh_agent_id')
    && executionUuid(v.device_id) && nullable(v.provider_id, (p) => p === PROVIDER) && nullable(v.binding_id, executionUuid) && nullable(v.binding_revision, executionRevision)
    && ['installed_supported', 'upgrade_required', 'unsupported'].some((item) => item === v.capability) && typeof v.ready === 'boolean'
    && Array.isArray(v.blocking_codes) && v.blocking_codes.length <= 8 && v.blocking_codes.every((c) => typeof c === 'string' && Object.hasOwn(blockingLabels, c)) && new Set(v.blocking_codes).size === v.blocking_codes.length
    && (!v.ready || (v.blocking_codes.length === 0 && v.capability === 'installed_supported')) && nullable(v.checked_at, executionTime) && nullable(v.readiness_expires_at, executionTime)
    && nullable(v.release_id, validReleaseId) && nullable(v.release_sha256, executionHash) && nullable(v.wazuh_connection_id, executionUuid) && nullable(v.wazuh_agent_id, agent);
}
export function validSummary(v: unknown): v is PublicSummary {
  if (!closed(v, 'device_id,environment_id,wazuh_connection_id,wazuh_agent_id,provider_id,binding_id,binding_revision,release_id,release_sha256,scenario_id,runner_id,runner_version,parameters,timeout_seconds,not_before,expires_at,collection_start,collection_end,artifact_pins,rule_pins,cleanup_policy,execution_receipt_is_detection_evidence,run_binding,collection_assurance') || !providerFields(v)) return false;
  if (!executionUuid(v.device_id) || !executionUuid(v.wazuh_connection_id) || !agent(v.wazuh_agent_id) || !executionUuid(v.binding_id) || !executionRevision(v.binding_revision) || typeof v.environment_id !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(v.environment_id)) return false;
  if (!closed(v.parameters, 'run_label,rule_revision,rule_sha256')) return false;
  const p = v.parameters;
  if (!['A', 'B', 'C', 'Rehearsal'].some((item) => item === p.run_label) || !['baseline', 'behavioral'].some((item) => item === p.rule_revision) || !executionHash(p.rule_sha256)) return false;
  if (!closed(v.artifact_pins, 'scenario_sha256,profile_sha256,runner_sha256,kit_sha256,payload_sha256') || !Object.values(v.artifact_pins).every(executionHash) || !closed(v.rule_pins, 'baseline,behavioral') || !Object.values(v.rule_pins).every(executionHash)) return false;
  if (p.run_label !== 'Rehearsal' && p.rule_revision !== (p.run_label === 'C' ? 'behavioral' : 'baseline')) return false;
  if (p.rule_sha256 !== v.rule_pins[p.rule_revision as 'baseline' | 'behavioral']) return false;
  if (![v.not_before, v.expires_at, v.collection_start, v.collection_end].every(executionTime)) return false;
  const start = Date.parse(v.not_before as string), expires = Date.parse(v.expires_at as string), collectStart = Date.parse(v.collection_start as string), collectEnd = Date.parse(v.collection_end as string);
  return expires > start && expires - start <= 120000 && collectStart <= start && collectEnd >= expires + Number(v.timeout_seconds) * 1000 && collectEnd - collectStart <= 900000
    && v.cleanup_policy === 'bounded_process_tree' && v.execution_receipt_is_detection_evidence === false && v.run_binding === 'unknown' && v.collection_assurance === 'unknown';
}
export function validPreview(v: unknown): v is PreviewDTO { return closed(v, 'preview_id,preview_sha256,expires_at,summary') && executionUuid(v.preview_id) && executionHash(v.preview_sha256) && executionTime(v.expires_at) && validSummary(v.summary) && v.expires_at === v.summary.expires_at; }
export function validJob(v: unknown): v is JobDTO {
  return closed(v, 'job_id,summary,execution_state,collection_state,evaluation_state,created_at,started_authorized_at,finished_at,error_code,report') && executionUuid(v.job_id) && validSummary(v.summary)
    && ['draft', 'queued', 'leased', 'started', 'succeeded', 'failed', 'execution_unknown', 'cancelled', 'expired'].some((item) => item === v.execution_state)
    && ['pending', 'collecting', 'evaluated', 'empty', 'failed', 'reconciled'].some((item) => item === v.collection_state) && ['not_evaluated', 'evaluated'].some((item) => item === v.evaluation_state)
    && executionTime(v.created_at) && nullable(v.started_authorized_at, executionTime) && nullable(v.finished_at, executionTime) && nullable(v.error_code, (e) => typeof e === 'string' && Array.from(e).length <= 100 && !/[\x00-\x1f\x7f-\x9f]/.test(e)) && nullable(v.report, record);
}
export function validBinding(v: unknown): v is BindingInput { return closed(v, 'expected_revision,enabled,provider_id,runner_release_id,installation_profile_sha256,wazuh_connection_id,wazuh_connection_revision,wazuh_agent_id') && nullable(v.expected_revision, executionRevision) && typeof v.enabled === 'boolean' && v.provider_id === PROVIDER && validReleaseId(v.runner_release_id) && executionHash(v.installation_profile_sha256) && executionUuid(v.wazuh_connection_id) && executionRevision(v.wazuh_connection_revision) && agent(v.wazuh_agent_id); }
export function validPreviewInput(v: unknown): v is PreviewInput { return closed(v, 'device_id,provider_id,binding_revision,run_label,rule_revision') && executionUuid(v.device_id) && v.provider_id === PROVIDER && executionRevision(v.binding_revision) && ['A', 'B', 'C', 'Rehearsal'].some((item) => item === v.run_label) && ['baseline', 'behavioral'].some((item) => item === v.rule_revision) && (v.run_label === 'Rehearsal' || v.rule_revision === (v.run_label === 'C' ? 'behavioral' : 'baseline')); }
export function validApprove(v: unknown): v is ApproveInput { return closed(v, 'preview_id,preview_sha256,idempotency_key') && executionUuid(v.preview_id) && executionHash(v.preview_sha256) && executionUuid(v.idempotency_key); }
