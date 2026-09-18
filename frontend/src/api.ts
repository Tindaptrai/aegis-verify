// Thin fetch layer. Every outcome is an explicit state the UI can render:
// the caller never receives a partially decoded report or a guessed value.

import {
  parseComparisonReport,
  parseEvaluationReport,
  parseReportIndex,
  type ComparisonReport,
  type EvaluationReport,
  type ReportIndex,
} from './contracts';

export type LoadState<T> =
  | { status: 'loading' }
  | { status: 'ready'; value: T }
  | { status: 'malformed'; reason: string }
  | { status: 'backend-error'; reason: string };

export type AnyReport =
  | { kind: 'evaluation'; report: EvaluationReport }
  | { kind: 'comparison'; report: ComparisonReport };

export interface ApiClient {
  index(): Promise<LoadState<ReportIndex>>;
  report(name: string): Promise<LoadState<AnyReport>>;
}

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

async function readJson(
  fetchImpl: FetchLike,
  url: string,
): Promise<{ status: 'ok'; body: unknown } | { status: 'malformed'; reason: string } | { status: 'backend-error'; reason: string }> {
  let response: Response;
  try {
    response = await fetchImpl(url, { headers: { Accept: 'application/json' } });
  } catch {
    return { status: 'backend-error', reason: `Không kết nối được backend (${url}).` };
  }
  let body: unknown = null;
  let bodyText = '';
  try {
    bodyText = await response.text();
    body = bodyText.length > 0 ? JSON.parse(bodyText) : null;
  } catch {
    if (response.ok) return { status: 'malformed', reason: 'Backend trả về JSON không đọc được.' };
    return { status: 'backend-error', reason: `Backend trả HTTP ${response.status} với nội dung không phải JSON.` };
  }
  if (response.status === 422) {
    const code = errorCode(body);
    return { status: 'malformed', reason: `Backend từ chối report: ${code}.` };
  }
  if (!response.ok) {
    return { status: 'backend-error', reason: `Backend trả HTTP ${response.status} (${errorCode(body)}).` };
  }
  return { status: 'ok', body };
}

function errorCode(body: unknown): string {
  if (typeof body === 'object' && body !== null && 'error' in body) {
    const error = (body as { error: unknown }).error;
    if (typeof error === 'object' && error !== null && 'code' in error) {
      const code = (error as { code: unknown }).code;
      if (typeof code === 'string') return code;
    }
  }
  return 'không có mã lỗi';
}

export function createApiClient(fetchImpl: FetchLike = (input, init) => fetch(input, init), base = ''): ApiClient {
  return {
    async index() {
      const result = await readJson(fetchImpl, `${base}/api/reports`);
      if (result.status !== 'ok') return result;
      const parsed = parseReportIndex(result.body);
      return parsed.ok ? { status: 'ready', value: parsed.value } : { status: 'malformed', reason: parsed.reason };
    },
    async report(name) {
      const result = await readJson(fetchImpl, `${base}/api/reports/${encodeURIComponent(name)}`);
      if (result.status !== 'ok') return result;
      const body = result.body;
      const kind = typeof body === 'object' && body !== null ? (body as { kind?: unknown }).kind : undefined;
      if (kind === 'evaluation') {
        const parsed = parseEvaluationReport(body);
        return parsed.ok
          ? { status: 'ready', value: { kind: 'evaluation', report: parsed.value } }
          : { status: 'malformed', reason: parsed.reason };
      }
      if (kind === 'comparison') {
        const parsed = parseComparisonReport(body);
        return parsed.ok
          ? { status: 'ready', value: { kind: 'comparison', report: parsed.value } }
          : { status: 'malformed', reason: parsed.reason };
      }
      return { status: 'malformed', reason: 'report.kind không phải "evaluation" hay "comparison".' };
    },
  };
}
