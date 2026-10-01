// Display text for the fixed codes the overview backend returns. Unknown codes are
// shown verbatim; nothing here changes a status or turns a missing value into one.

export const OPS_LABEL: Record<string, string> = {
  healthy: 'Healthy',
  degraded: 'Degraded',
  error: 'Error',
  unknown: 'Unknown',
  not_configured: 'Not configured',
  no_data: 'No data',
};

export const OPS_TONE: Record<string, 'ok' | 'warn' | 'bad' | 'neutral'> = {
  healthy: 'ok',
  degraded: 'warn',
  error: 'bad',
  unknown: 'neutral',
  not_configured: 'neutral',
  no_data: 'neutral',
};

export const COMPONENT_TEXT: Record<string, { title: string; description: string }> = {
  api: { title: 'Dashboard API', description: 'Server chỉ đọc phục vụ trang này.' },
  scenario_registry: { title: 'Scenario registry', description: 'Manifest kịch bản đọc từ thư mục --scenarios.' },
  report_storage: { title: 'Report storage', description: 'Report JSON của aegis validate / compare trong thư mục --reports.' },
  validation_engine: { title: 'Validation engine', description: 'Dashboard chỉ đọc kết quả có sẵn, không chạy engine.' },
  evidence_collection: { title: 'Evidence collection', description: 'Thu bằng chứng giới hạn từ Wazuh Indexer (Operations).' },
  connector_wazuh: { title: 'Wazuh connector', description: 'Parser Wazuh; thu live chỉ qua Operations.' },
  connector_suricata: { title: 'Suricata connector', description: 'Parser EVE JSON; không có thu live.' },
  connector_pfsense: { title: 'pfSense connector', description: 'Parser filterlog; không có thu live.' },
  connector_cowrie: { title: 'Cowrie connector', description: 'Parser Cowrie JSON; không có thu live.' },
};

const REASON_TEXT: Record<string, string> = {
  dashboard_started_without_scenarios: 'Dashboard chạy không có --scenarios',
  registry_unreadable: 'Không đọc được thư mục manifest',
  resource_limit: 'Vượt giới hạn số file',
  invalid_manifests: 'Có manifest lỗi hoặc trùng ID',
  unregistered_reports: 'Có report không có manifest',
  no_manifests: 'Chưa có manifest',
  storage_unreadable: 'Không đọc được thư mục report',
  unreadable_reports: 'Có report không đọc được',
  no_reports: 'Chưa có report',
  dashboard_does_not_run_engine: 'Dashboard không chạy engine',
  dashboard_started_without_operations: 'Chưa bật Operations',
  indexer_not_configured: 'Operations chưa cấu hình Indexer',
  no_collection_jobs: 'Chưa có job thu nào',
  collection_running: 'Đang có job thu chạy',
  unknown_job_state: 'Trạng thái job không xác định',
  no_live_connector: 'Không có connector live',
};

const SOURCE_TEXT: Record<string, string> = {
  this_response: 'phản hồi của chính API này',
  scenarios_directory: 'thư mục --scenarios',
  reports_directory: 'thư mục --reports',
  reports: 'các report đã đọc',
  operations_job_store: 'job store của Operations',
  none: 'không có nguồn dữ liệu live',
};

export function reasonText(code: string | null): string | null {
  if (code === null) return null;
  return REASON_TEXT[code] ?? code;
}

export function sourceText(code: string): string {
  return SOURCE_TEXT[code] ?? code;
}

export const RUN_STATE_TEXT: Record<string, string> = {
  run: 'Đã chạy',
  not_run: 'Chưa chạy',
  stale_only: 'Chỉ có lượt của manifest cũ',
};

export const MISMATCH_TEXT: Record<string, string> = {
  version: 'version manifest khác',
  fingerprint: 'nội dung manifest đã đổi',
};

/** Render an ISO-8601 UTC time without converting it; null stays "no data". */
export function when(value: string | null): string | null {
  if (value === null) return null;
  return value.replace('T', ' ').replace(/Z$/, ' UTC');
}
