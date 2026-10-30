import { closed, uuid, validCandidate, validInput, validList, validSource, validTest, type ConnectionCandidate, type ConnectionList, type ConnectionSource, type ConnectionTest, type WazuhInput } from './connectionsTypes';

const codes = {
  invalid_request: 400, permission_denied: 403, unauthenticated: 401, connection_unavailable: 409, policy_denied: 409,
  invalid_ca: 400, tls_failed: 409, authentication_failed: 409, query_denied: 409, query_failed: 409,
  draft_expired: 409, draft_conflict: 409, source_conflict: 409, candidate_conflict: 409, storage_unavailable: 503, rate_limited: 429,
} as const;
export type ConnectionErrorCode = keyof typeof codes;
export class ConnectionsApiError extends Error {
  readonly code: ConnectionErrorCode | undefined;
  constructor(public readonly status: number, code?: unknown) {
    super('Connection request failed'); this.name = 'ConnectionsApiError';
    this.code = typeof code === 'string' && Object.hasOwn(codes, code) && codes[code as ConnectionErrorCode] === status ? code as ConnectionErrorCode : undefined;
  }
}
async function readBounded(response: Response, cap: number): Promise<unknown> {
  const reader = response.body?.getReader(); if (!reader) throw new Error('Missing body');
  const chunks: Uint8Array[] = []; let size = 0;
  try {
    while (true) {
      const next = await reader.read(); if (next.done) break;
      size += next.value.length; if (size > cap) { await reader.cancel(); throw new Error('Response limit'); }
      chunks.push(next.value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } finally { reader.releaseLock(); }
}
export function createConnectionsApi(fetcher: typeof fetch = fetch) {
  async function request<T>(path: string, statuses: number[], validate: (value: unknown) => value is T, signal?: AbortSignal, body?: unknown, csrfToken?: string): Promise<T> {
    if (signal?.aborted) throw new DOMException('Request superseded', 'AbortError');
    const response = await fetcher(`/api/v1/connections/${path}`, { method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store', signal,
      ...(body === undefined ? {} : { headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken ?? '' }, body: JSON.stringify(body) }) });
    let value: unknown;
    try { value = await readBounded(response, response.ok ? 262144 : 1024); }
    catch { if (signal?.aborted) throw new DOMException('Request superseded', 'AbortError'); throw new ConnectionsApiError(response.status); }
    if (signal?.aborted) throw new DOMException('Request superseded', 'AbortError');
    if (!response.ok) throw new ConnectionsApiError(response.status, closed(value, ['error']) && closed(value.error, ['code']) ? value.error.code : undefined);
    if (!statuses.includes(response.status) || !validate(value)) throw new ConnectionsApiError(response.status);
    return value;
  }
  return {
    list: (page = 1, signal?: AbortSignal): Promise<ConnectionList> => {
      if (!Number.isSafeInteger(page) || page < 1) return Promise.reject(new ConnectionsApiError(400, 'invalid_request'));
      return request(`?page=${page}`, [200], (value): value is ConnectionList => validList(value) && value.page === page, signal);
    },
    test: (input: WazuhInput, csrfToken: string, signal?: AbortSignal): Promise<ConnectionTest> => {
      if (!validInput(input) || new TextEncoder().encode(JSON.stringify(input)).length > 98304) return Promise.reject(new ConnectionsApiError(400, 'invalid_request'));
      return request('wazuh/test', [201], validTest, signal, input, csrfToken);
    },
    save: (draftId: string, idempotencyKey: string, csrfToken: string, signal?: AbortSignal): Promise<ConnectionSource> => {
      if (!uuid(draftId) || !uuid(idempotencyKey)) return Promise.reject(new ConnectionsApiError(400, 'invalid_request'));
      return request('wazuh/save', [200, 201], (value): value is ConnectionSource => validSource(value) && value.kind === 'managed', signal, { draft_id: draftId, idempotency_key: idempotencyKey }, csrfToken);
    },
    prepare: (sourceId: string, expectedCandidateId: string | null, csrfToken: string, signal?: AbortSignal): Promise<ConnectionCandidate> => {
      if (!uuid(sourceId) || (expectedCandidateId !== null && !uuid(expectedCandidateId))) return Promise.reject(new ConnectionsApiError(400, 'invalid_request'));
      return request(`${sourceId}/prepare`, [200], (value): value is ConnectionCandidate => validCandidate(value) && value.source.id === sourceId, signal, { expected_candidate_id: expectedCandidateId }, csrfToken);
    },
  };
}
export type ConnectionsApi = ReturnType<typeof createConnectionsApi>;
