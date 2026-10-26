import { validCurrentJob, type CurrentJobDTO, validProviderList, validExecutionDevice, validPreview, validJob, validBinding, validPreviewInput, validApprove, executionUuid, validReleaseId, type BindingInput, type PreviewInput, type ApproveInput, type ProviderList, type ExecutionDeviceDTO, type PreviewDTO, type JobDTO } from './executionTypes';

// Only execution success responses use this bounded JSON reader. It rejects duplicates
// and retains raw release integer tokens before JavaScript can round int64 IDs.
export async function readExecutionResponse(response: Response, currentJobFraming = false): Promise<unknown> {
  const reader = response.body?.getReader(); if (!reader) throw new Error('Invalid execution response');
  const chunks: Uint8Array[] = []; let size = 0;
  try { while (true) { const part = await reader.read(); if (part.done) break; size += part.value.length; if (size > 4 * 1024 * 1024 + (currentJobFraming ? 8 : 0)) { await reader.cancel(); throw new Error('Execution response too large'); } chunks.push(part.value); } }
  finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  const source = new TextDecoder('utf-8', { fatal: true }).decode(bytes); let pos = 0;
  const fail = (): never => { throw new Error('Invalid execution response'); };
  const space = () => { while (/[\t\n\r ]/.test(source[pos] ?? '') && pos < source.length) pos++; };
  function string(): string { const start = pos++; while (pos < source.length) { const c = source[pos++]; if (c === '\\') pos++; else if (c === '"') return JSON.parse(source.slice(start, pos)) as string; } return fail(); }
  function value(depth: number, release = false, opaque = false): unknown {
    space(); const c = source[pos]; if (depth > (currentJobFraming ? 13 : 12) && (c === '{' || c === '[')) return fail();
    if (release && c !== 'n') { const token = /^[1-9][0-9]*/.exec(source.slice(pos))?.[0]; if (!validReleaseId(token)) return fail(); pos += token.length; return token; }
    if (c === '{') { pos++; space(); const object: Record<string, unknown> = Object.create(null); if (source[pos] === '}') { pos++; return Object.freeze(object); } while (true) { space(); if (source[pos] !== '"') return fail(); const key = string(); if (Object.hasOwn(object, key)) return fail(); space(); if (source[pos++] !== ':') return fail(); object[key] = value(depth + 1, !opaque && key === 'release_id', opaque || key === 'report'); space(); const next = source[pos++]; if (next === '}') return Object.freeze(object); if (next !== ',') return fail(); } }
    if (c === '[') { pos++; space(); const array: unknown[] = []; if (source[pos] === ']') { pos++; return Object.freeze(array); } while (true) { array.push(value(depth + 1, false, opaque)); space(); const next = source[pos++]; if (next === ']') return Object.freeze(array); if (next !== ',') return fail(); } }
    if (c === '"') return string();
    const token = /^(?:null|true|false|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(source.slice(pos))?.[0]; if (!token) return fail(); pos += token.length;
    const parsed: unknown = JSON.parse(token); if (typeof parsed === 'number' && !Number.isFinite(parsed)) return fail(); return parsed;
  }
  const result = value(1); space(); if (pos !== source.length) return fail(); return result;
}
export function serializeBinding(input: BindingInput): string {
  if (!validBinding(input)) throw new Error('Invalid binding');
  return `{${Object.entries(input).map(([key, value]) => `${JSON.stringify(key)}:${key === 'runner_release_id' ? input.runner_release_id : JSON.stringify(value)}`).join(',')}}`;
}
export interface ExecutionTransport { <T>(path: string, method: string, body: unknown, signal: AbortSignal | undefined, statuses: number[], validate: (v: unknown) => boolean, serialize?: (input: never) => string): Promise<T> }
export function createExecutionMethods(request: ExecutionTransport) {
  const id = (value: string) => { if (!executionUuid(value)) throw new Error('Invalid device/job ID'); return value; };
  return {
    executionProviders: (signal?: AbortSignal) => request<ProviderList>('execution/providers', 'GET', undefined, signal, [200], validProviderList),
    executionDevice: (deviceId: string, signal?: AbortSignal) => request<ExecutionDeviceDTO>(`execution/devices/${id(deviceId)}`, 'GET', undefined, signal, [200], validExecutionDevice),
    setExecutionBinding: (deviceId: string, input: BindingInput, signal?: AbortSignal) => { if (!validBinding(input)) return Promise.reject(new Error('Invalid binding')); return request<ExecutionDeviceDTO>(`execution/devices/${id(deviceId)}/binding`, 'PUT', input, signal, [200], validExecutionDevice, serializeBinding); },
    previewExecution: (input: PreviewInput, signal?: AbortSignal) => { if (!validPreviewInput(input)) return Promise.reject(new Error('Invalid preview')); return request<PreviewDTO>('jobs/preview', 'POST', input, signal, [201], validPreview); },
    approveExecution: (input: ApproveInput, signal?: AbortSignal) => { if (!validApprove(input)) return Promise.reject(new Error('Invalid approval')); return request<JobDTO>('jobs/approve', 'POST', input, signal, [200, 201], validJob); },
    currentExecutionJob: (signal?: AbortSignal) => request<CurrentJobDTO>('jobs/current', 'GET', undefined, signal, [200], validCurrentJob),
    executionJob: (jobId: string, signal?: AbortSignal) => request<JobDTO>(`jobs/${id(jobId)}`, 'GET', undefined, signal, [200], validJob),
    cancelExecution: (jobId: string, signal?: AbortSignal) => request<JobDTO>(`jobs/${id(jobId)}/cancel`, 'POST', {}, signal, [200], validJob),
  };
}
