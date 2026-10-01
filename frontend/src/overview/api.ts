// Fetch layer for the overview endpoints. Same explicit states as ../api.ts:
// ready, malformed (contract violation or 422) or backend-error (network, 4xx/5xx).

import { readJson, type FetchLike, type LoadState } from '../api';
import {
  parseScenarioDetail,
  parseScenarioIndex,
  parseSystemStatus,
  type ScenarioDetail,
  type ScenarioIndex,
  type SystemStatus,
} from './contracts';
import type { Parsed } from '../contracts';

export interface OverviewClient {
  scenarios(): Promise<LoadState<ScenarioIndex>>;
  scenario(id: string): Promise<LoadState<ScenarioDetail>>;
  systemStatus(): Promise<LoadState<SystemStatus>>;
}

async function load<T>(fetchImpl: FetchLike, url: string, parse: (body: unknown) => Parsed<T>): Promise<LoadState<T>> {
  const result = await readJson(fetchImpl, url);
  if (result.status !== 'ok') return result;
  const parsed = parse(result.body);
  return parsed.ok ? { status: 'ready', value: parsed.value } : { status: 'malformed', reason: parsed.reason };
}

export function createOverviewClient(fetchImpl: FetchLike = (input, init) => fetch(input, init), base = ''): OverviewClient {
  return {
    scenarios: () => load(fetchImpl, `${base}/api/scenarios`, parseScenarioIndex),
    scenario: (id) => load(fetchImpl, `${base}/api/scenarios/${encodeURIComponent(id)}`, parseScenarioDetail),
    systemStatus: () => load(fetchImpl, `${base}/api/system/status`, parseSystemStatus),
  };
}
