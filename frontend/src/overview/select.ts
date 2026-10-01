// Search, filter and ordering of the scenario rows. Pure presentation: the result of
// each scenario is the backend's latest final_status; this only decides the order.

import { FINAL_STATUSES } from '../contracts';
import type { ScenarioRow } from './contracts';

export type ResultFilter = 'all' | 'not_run' | 'other' | (typeof FINAL_STATUSES)[number];
export type SortKey = 'attention' | 'id' | 'run_time';

export interface RowQuery {
  query: string;
  manifestStatus: string;
  result: ResultFilter;
  sort: SortKey;
}

export const DEFAULT_QUERY: RowQuery = { query: '', manifestStatus: 'all', result: 'all', sort: 'attention' };

/** The latest result a row is filed under; "not_run" covers stale-only rows too. */
export function resultKey(row: ScenarioRow): Exclude<ResultFilter, 'all'> {
  if (row.run_state !== 'run' || row.latest_run === null) return 'not_run';
  const status = row.latest_run.final_status;
  return (FINAL_STATUSES as readonly (string | null)[]).includes(status)
    ? (status as (typeof FINAL_STATUSES)[number])
    : 'other';
}

/**
 * Approved attention order (#119): unreadable reports are listed above the table,
 * then False negative, Missing telemetry, Inconclusive or unknown, not run, and
 * finally Detected / Prevented.
 */
export function attentionRank(row: ScenarioRow): number {
  switch (resultKey(row)) {
    case 'False negative':
      return 1;
    case 'Missing telemetry':
      return 2;
    case 'Inconclusive':
    case 'other':
      return 3;
    case 'not_run':
      return 4;
    default:
      return 5;
  }
}

function matches(row: ScenarioRow, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (needle === '') return true;
  return [row.id, row.name, row.latest_run?.profile_id ?? null]
    .some((value) => value !== null && value.toLowerCase().includes(needle));
}

const byId = (a: ScenarioRow, b: ScenarioRow) => a.id.localeCompare(b.id);

export function selectRows(rows: readonly ScenarioRow[], query: RowQuery): ScenarioRow[] {
  const kept = rows.filter((row) =>
    matches(row, query.query)
    && (query.manifestStatus === 'all' || row.status === query.manifestStatus)
    && (query.result === 'all' || resultKey(row) === query.result));
  if (query.sort === 'id') return [...kept].sort(byId);
  if (query.sort === 'run_time') {
    // ISO-8601 UTC strings from the same backend compare in time order; rows
    // without a run window go last instead of being given a guessed time.
    return [...kept].sort((a, b) => {
      const left = a.latest_run?.window_end ?? null;
      const right = b.latest_run?.window_end ?? null;
      if (left === right) return byId(a, b);
      if (left === null) return 1;
      if (right === null) return -1;
      return left < right ? 1 : -1;
    });
  }
  return [...kept].sort((a, b) => attentionRank(a) - attentionRank(b) || byId(a, b));
}
