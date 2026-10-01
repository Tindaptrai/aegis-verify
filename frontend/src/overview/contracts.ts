// Structural readers for the overview endpoints: /api/scenarios, /api/scenarios/<id>
// and /api/system/status.
//
// Like ../contracts.ts they only check shape and type. Statuses, counts and times
// are kept exactly as the backend sent them; a null stays null and an unknown
// status string is shown verbatim, never mapped to a guessed meaning.

import type { Parsed } from '../contracts';

export type RunState = 'run' | 'not_run' | 'stale_only';
export type Mismatch = 'version' | 'fingerprint' | null;

export interface AssertionTally {
  total: number | null;
  satisfied: number | null;
  false_negative: number | null;
  missing_telemetry: number | null;
  inconclusive: number | null;
}

export interface RunSummary {
  name: string;
  scenario_id: string | null;
  scenario_version: string | null;
  run_id: string | null;
  final_status: string | null;
  profile_id: string | null;
  profile_version: string | null;
  assertions: AssertionTally;
  evidence_referenced: number | null;
  collection_assurance: Record<string, number>;
  sources: Record<string, number>;
  window_start: string | null;
  window_end: string | null;
  file_modified: string | null;
  /** Present on scenario-detail runs only. */
  manifest_match: boolean | null;
  mismatch: Mismatch;
}

export interface ComparisonSummary {
  name: string;
  comparison_status: string | null;
  before_run_id: string | null;
  after_run_id: string | null;
  before_status: string | null;
  after_status: string | null;
  window_end: string | null;
  file_modified: string | null;
}

export interface ScenarioRow {
  id: string;
  name: string;
  version: string;
  status: string;
  description: string;
  expected_outcome: string;
  expected_sources: string[];
  tags: string[] | null;
  file: string;
  fingerprint: string;
  run_state: RunState;
  latest_run: RunSummary | null;
  run_count: number;
  stale_run_count: number;
  comparison_count: number;
}

export interface ReportError {
  name: string;
  code: string;
  stage: string | null;
  field: string | null;
}

export interface ScenarioIndex {
  registry: { configured: boolean; error: string | null; manifest_count: number; errors: { file: string; code: string }[] };
  kpi: { total: number; run: number; not_run: number; by_status: Record<string, number> };
  scenarios: ScenarioRow[];
  unregistered: { scenario_id: string | null; reports: string[]; latest_run: RunSummary | null }[];
  report_errors: ReportError[];
  report_storage_error: string | null;
  last_report_modified: string | null;
}

export interface ManifestAssertion {
  id: string;
  description: string;
  source: string;
}

export interface ScenarioDetail {
  scenario: Omit<ScenarioRow, 'run_state' | 'latest_run' | 'run_count' | 'stale_run_count' | 'comparison_count'> & {
    assertions: ManifestAssertion[];
    safety: { destructive: boolean; authorization_required: boolean; notes: string };
  };
  run_state: RunState;
  latest_run: RunSummary | null;
  runs: RunSummary[];
  comparisons: ComparisonSummary[];
  report_errors: ReportError[];
}

export interface SystemComponent {
  id: string;
  name: string;
  status: string;
  summary: string;
  source: string;
  last_activity: string | null;
  reason: string | null;
  details: Record<string, unknown>;
}

export interface SystemStatus {
  generated_at: string;
  overall: { status: string; reasons: { component: string; status: string; reason: string | null }[] };
  components: SystemComponent[];
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

function record(value: unknown, where: string): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(`${where}: expected an object`);
  return value;
}

function list(value: unknown, where: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${where}: expected a list`);
  return value;
}

function str(source: Record<string, unknown>, key: string, where: string): string {
  const value = source[key];
  if (typeof value !== 'string') throw new Error(`${where}.${key}: expected a string`);
  return value;
}

function nstr(source: Record<string, unknown>, key: string, where: string): string | null {
  const value = key in source ? source[key] : null;
  if (value !== null && typeof value !== 'string') throw new Error(`${where}.${key}: expected a string or null`);
  return value;
}

const isCount = (value: unknown): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;

function count(source: Record<string, unknown>, key: string, where: string): number {
  const value = source[key];
  if (!isCount(value)) throw new Error(`${where}.${key}: expected a non-negative integer`);
  return value;
}

function ncount(source: Record<string, unknown>, key: string, where: string): number | null {
  const value = key in source ? source[key] : null;
  if (value !== null && !isCount(value)) throw new Error(`${where}.${key}: expected a non-negative integer or null`);
  return value;
}

function bool(source: Record<string, unknown>, key: string, where: string): boolean {
  const value = source[key];
  if (typeof value !== 'boolean') throw new Error(`${where}.${key}: expected a boolean`);
  return value;
}

function strings(value: unknown, where: string): string[] {
  const items = list(value, where);
  if (!items.every((item) => typeof item === 'string')) throw new Error(`${where}: expected a list of strings`);
  return items as string[];
}

function tally(value: unknown, where: string): Record<string, number> {
  const source = record(value, where);
  const result: Record<string, number> = Object.create(null);
  for (const [key, item] of Object.entries(source)) {
    if (!isCount(item)) throw new Error(`${where}.${key}: expected a non-negative integer`);
    result[key] = item;
  }
  return result;
}

function runState(value: unknown, where: string): RunState {
  if (value !== 'run' && value !== 'not_run' && value !== 'stale_only') throw new Error(`${where}: unknown run_state`);
  return value;
}

function runSummary(value: unknown, where: string): RunSummary {
  const source = record(value, where);
  const assertions = record(source['assertions'], `${where}.assertions`);
  const mismatch = 'mismatch' in source ? source['mismatch'] : null;
  if (mismatch !== null && mismatch !== 'version' && mismatch !== 'fingerprint') {
    throw new Error(`${where}.mismatch: unknown value`);
  }
  const match = 'manifest_match' in source ? source['manifest_match'] : null;
  if (match !== null && typeof match !== 'boolean') throw new Error(`${where}.manifest_match: expected a boolean`);
  return {
    name: str(source, 'name', where),
    scenario_id: nstr(source, 'scenario_id', where),
    scenario_version: nstr(source, 'scenario_version', where),
    run_id: nstr(source, 'run_id', where),
    final_status: nstr(source, 'final_status', where),
    profile_id: nstr(source, 'profile_id', where),
    profile_version: nstr(source, 'profile_version', where),
    assertions: {
      total: ncount(assertions, 'total', `${where}.assertions`),
      satisfied: ncount(assertions, 'satisfied', `${where}.assertions`),
      false_negative: ncount(assertions, 'false_negative', `${where}.assertions`),
      missing_telemetry: ncount(assertions, 'missing_telemetry', `${where}.assertions`),
      inconclusive: ncount(assertions, 'inconclusive', `${where}.assertions`),
    },
    evidence_referenced: ncount(source, 'evidence_referenced', where),
    collection_assurance: tally(source['collection_assurance'], `${where}.collection_assurance`),
    sources: tally(source['sources'], `${where}.sources`),
    window_start: nstr(source, 'window_start', where),
    window_end: nstr(source, 'window_end', where),
    file_modified: nstr(source, 'file_modified', where),
    manifest_match: match,
    mismatch,
  };
}

function nullableRun(value: unknown, where: string): RunSummary | null {
  return value === null || value === undefined ? null : runSummary(value, where);
}

function comparisonSummary(value: unknown, where: string): ComparisonSummary {
  const source = record(value, where);
  return {
    name: str(source, 'name', where),
    comparison_status: nstr(source, 'comparison_status', where),
    before_run_id: nstr(source, 'before_run_id', where),
    after_run_id: nstr(source, 'after_run_id', where),
    before_status: nstr(source, 'before_status', where),
    after_status: nstr(source, 'after_status', where),
    window_end: nstr(source, 'window_end', where),
    file_modified: nstr(source, 'file_modified', where),
  };
}

function reportErrors(value: unknown, where: string): ReportError[] {
  return list(value, where).map((item, index) => {
    const source = record(item, `${where}[${index}]`);
    return {
      name: str(source, 'name', `${where}[${index}]`),
      code: str(source, 'code', `${where}[${index}]`),
      stage: nstr(source, 'stage', `${where}[${index}]`),
      field: nstr(source, 'field', `${where}[${index}]`),
    };
  });
}

function manifestFields(source: Record<string, unknown>, where: string) {
  const tags = source['tags'] ?? null;
  return {
    id: str(source, 'id', where),
    name: str(source, 'name', where),
    version: str(source, 'version', where),
    status: str(source, 'status', where),
    description: str(source, 'description', where),
    expected_outcome: str(source, 'expected_outcome', where),
    expected_sources: strings(source['expected_sources'], `${where}.expected_sources`),
    tags: tags === null ? null : strings(tags, `${where}.tags`),
    file: str(source, 'file', where),
    fingerprint: str(source, 'fingerprint', where),
  };
}

function wrap<T>(read: () => T, fallback: string): Parsed<T> {
  try {
    return { ok: true, value: read() };
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.message : fallback };
  }
}

export function parseScenarioIndex(input: unknown): Parsed<ScenarioIndex> {
  return wrap(() => {
    const source = record(input, 'scenarios');
    if (source['kind'] !== 'scenario_index') throw new Error('scenarios.kind: expected "scenario_index"');
    const registry = record(source['registry'], 'scenarios.registry');
    const kpi = record(source['kpi'], 'scenarios.kpi');
    return {
      registry: {
        configured: bool(registry, 'configured', 'scenarios.registry'),
        error: nstr(registry, 'error', 'scenarios.registry'),
        manifest_count: count(registry, 'manifest_count', 'scenarios.registry'),
        errors: list(registry['errors'], 'scenarios.registry.errors').map((item, index) => {
          const where = `scenarios.registry.errors[${index}]`;
          const entry = record(item, where);
          return { file: str(entry, 'file', where), code: str(entry, 'code', where) };
        }),
      },
      kpi: {
        total: count(kpi, 'total', 'scenarios.kpi'),
        run: count(kpi, 'run', 'scenarios.kpi'),
        not_run: count(kpi, 'not_run', 'scenarios.kpi'),
        by_status: tally(kpi['by_status'], 'scenarios.kpi.by_status'),
      },
      scenarios: list(source['scenarios'], 'scenarios.scenarios').map((item, index) => {
        const where = `scenarios.scenarios[${index}]`;
        const row = record(item, where);
        return {
          ...manifestFields(row, where),
          run_state: runState(row['run_state'], `${where}.run_state`),
          latest_run: nullableRun(row['latest_run'], `${where}.latest_run`),
          run_count: count(row, 'run_count', where),
          stale_run_count: count(row, 'stale_run_count', where),
          comparison_count: count(row, 'comparison_count', where),
        };
      }),
      unregistered: list(source['unregistered'], 'scenarios.unregistered').map((item, index) => {
        const where = `scenarios.unregistered[${index}]`;
        const group = record(item, where);
        return {
          scenario_id: nstr(group, 'scenario_id', where),
          reports: strings(group['reports'], `${where}.reports`),
          latest_run: nullableRun(group['latest_run'], `${where}.latest_run`),
        };
      }),
      report_errors: reportErrors(source['report_errors'], 'scenarios.report_errors'),
      report_storage_error: nstr(source, 'report_storage_error', 'scenarios'),
      last_report_modified: nstr(source, 'last_report_modified', 'scenarios'),
    };
  }, 'unreadable scenario index');
}

export function parseScenarioDetail(input: unknown): Parsed<ScenarioDetail> {
  return wrap(() => {
    const source = record(input, 'scenario');
    if (source['kind'] !== 'scenario_detail') throw new Error('scenario.kind: expected "scenario_detail"');
    const manifest = record(source['scenario'], 'scenario.scenario');
    const safety = record(manifest['safety'], 'scenario.scenario.safety');
    return {
      scenario: {
        ...manifestFields(manifest, 'scenario.scenario'),
        assertions: list(manifest['assertions'], 'scenario.scenario.assertions').map((item, index) => {
          const where = `scenario.scenario.assertions[${index}]`;
          const entry = record(item, where);
          return { id: str(entry, 'id', where), description: str(entry, 'description', where),
            source: str(entry, 'source', where) };
        }),
        safety: {
          destructive: bool(safety, 'destructive', 'scenario.scenario.safety'),
          authorization_required: bool(safety, 'authorization_required', 'scenario.scenario.safety'),
          notes: str(safety, 'notes', 'scenario.scenario.safety'),
        },
      },
      run_state: runState(source['run_state'], 'scenario.run_state'),
      latest_run: nullableRun(source['latest_run'], 'scenario.latest_run'),
      runs: list(source['runs'], 'scenario.runs').map((item, index) => runSummary(item, `scenario.runs[${index}]`)),
      comparisons: list(source['comparisons'], 'scenario.comparisons')
        .map((item, index) => comparisonSummary(item, `scenario.comparisons[${index}]`)),
      report_errors: reportErrors(source['report_errors'], 'scenario.report_errors'),
    };
  }, 'unreadable scenario detail');
}

export function parseSystemStatus(input: unknown): Parsed<SystemStatus> {
  return wrap(() => {
    const source = record(input, 'status');
    if (source['kind'] !== 'system_status') throw new Error('status.kind: expected "system_status"');
    const overall = record(source['overall'], 'status.overall');
    return {
      generated_at: str(source, 'generated_at', 'status'),
      overall: {
        status: str(overall, 'status', 'status.overall'),
        reasons: list(overall['reasons'], 'status.overall.reasons').map((item, index) => {
          const where = `status.overall.reasons[${index}]`;
          const entry = record(item, where);
          return { component: str(entry, 'component', where), status: str(entry, 'status', where),
            reason: nstr(entry, 'reason', where) };
        }),
      },
      components: list(source['components'], 'status.components').map((item, index) => {
        const where = `status.components[${index}]`;
        const entry = record(item, where);
        return {
          id: str(entry, 'id', where),
          name: str(entry, 'name', where),
          status: str(entry, 'status', where),
          summary: str(entry, 'summary', where),
          source: str(entry, 'source', where),
          last_activity: nstr(entry, 'last_activity', where),
          reason: nstr(entry, 'reason', where),
          details: record(entry['details'] ?? {}, `${where}.details`),
        };
      }),
    };
  }, 'unreadable system status');
}
