import { parseBootstrap, parseJob, parseJobs, parseSnapshot, uuid, type Bootstrap, type Parsed, type CollectionRequest } from './contracts';

export const errorMessage = (error: unknown): string => {
  const code = error instanceof Error ? error.message : '';
  const messages: Record<string, string> = {
    session_expired: 'Phiên vận hành đã đổi hoặc hết hạn. Tải lại trang; yêu cầu không được tự gửi lại.',
    rate_limited: 'Vui lòng đợi ít nhất 30 giây giữa hai lần làm mới.',
    job_busy: 'Đang có một collection chạy. Hãy đợi job hiện tại hoàn tất.',
    refresh_busy: 'Đang cập nhật inventory. Hãy đợi lượt hiện tại.',
    not_configured: 'Nguồn dữ liệu chưa được cấu hình cho chức năng này.',
    invalid_request: 'Yêu cầu không hợp lệ. Kiểm tra agent và khoảng thời gian UTC.',
    invalid_response: 'Backend trả dữ liệu không đúng cấu trúc; không hiển thị kết quả này.',
    permission_denied: 'Tài khoản nguồn chưa có quyền đọc cần thiết.',
    authentication_failed: 'Nguồn từ chối xác thực. Kiểm tra cấu hình tại backend.',
    connection_or_tls_failed: 'Không kết nối được nguồn hoặc kiểm tra TLS thất bại.',
    incomplete_snapshot: 'Inventory chưa đầy đủ. Giữ lại snapshot trước đó.',
    disk_space: 'Không đủ dung lượng dự phòng để bắt đầu collection.',
    job_limit: 'Đã đạt giới hạn lưu job. Cần operator kiểm tra lưu trữ.',
  };
  return messages[code] ?? 'Không thực hiện được yêu cầu. Kiểm tra backend; không tự chạy lại collection.';
};

type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;
export type OperationsClient = ReturnType<typeof createOperationsClient>;
export function createOperationsClient(fetchImpl: FetchLike = (url, init) => fetch(url, init)) {
  let token: string | null = null;
  let epoch = 0;
  let scope: Bootstrap | null = null;
  const scopedJob: typeof parseJob = value => {
    const parsed = parseJob(value);
    return parsed.ok && scope?.agent_ids.includes(parsed.value.agent_id) ? parsed : { ok: false };
  };
  const scopedSnapshot: typeof parseSnapshot = value => {
    const parsed = parseSnapshot(value);
    return parsed.ok && parsed.value.agents.every(a => a.environment_id === scope?.environment_id && scope.agent_ids.includes(a.agent_id)) ? parsed : { ok: false };
  };
  const scopedJobs: typeof parseJobs = value => {
    const parsed = parseJobs(value);
    return parsed.ok && parsed.value.jobs.every(j => scope?.agent_ids.includes(j.agent_id)) ? parsed : { ok: false };
  };
  async function request<T>(path: string, parse: (x: unknown) => Parsed<T>, signal?: AbortSignal, body?: unknown): Promise<T> {
    const current = token, generation = epoch;
    if (path !== 'bootstrap' && !current) throw new Error('session_expired');
    const headers: Record<string, string> = { Accept: 'application/json', 'X-Aegis-Client': 'operations-v1' };
    if (current) headers['X-Aegis-Session'] = current;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const response = await fetchImpl(`/api/operations/${path}`, { method: body === undefined ? 'GET' : 'POST',
      headers, signal, credentials: 'same-origin', cache: 'no-store',
      ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    if (generation !== epoch) throw new Error('session_expired');
    if (response.status === 403) { token = null; epoch++; throw new Error('session_expired'); }
    const text = await response.text();
    if (generation !== epoch) throw new Error('session_expired');
    if (signal?.aborted) throw new DOMException('Aborted', 'AbortError');
    if (text.length > 2 * 1024 * 1024) throw new Error('invalid_response');
    let value: unknown;
    try { value = JSON.parse(text); } catch { throw new Error('invalid_response'); }
    if (!response.ok) {
      const code = (value as { error?: { code?: unknown } } | null)?.error?.code;
      throw new Error(typeof code === 'string' && /^[a-z_]{1,64}$/.test(code) ? code : 'request_failed');
    }
    const parsed = parse(value);
    if (!parsed.ok) throw new Error('invalid_response');
    return parsed.value;
  }
  return {
    async bootstrap(signal?: AbortSignal) {
      epoch++; token = null; scope = null;
      const data = await request('bootstrap', parseBootstrap, signal);
      token = data.session_token;
      const { session_token: _secret, ...config } = data;
      scope = config;
      return config;
    },
    agents: (signal?: AbortSignal) => request('agents', scopedSnapshot, signal),
    refreshAgents: (signal?: AbortSignal) => request('agents/refresh', scopedSnapshot, signal, {}),
    collections: (signal?: AbortSignal) => request('collections', scopedJobs, signal),
    collection(id: string, signal?: AbortSignal) {
      if (!uuid(id)) return Promise.reject(new Error('invalid_request'));
      return request(`collections/${id}`, scopedJob, signal);
    },
    submitCollection: (data: CollectionRequest, signal?: AbortSignal) => request('collections', scopedJob, signal, data),
  };
}
