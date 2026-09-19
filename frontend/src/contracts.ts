// Structural readers for the backend report contracts (`aegis validate --format json`,
// `aegis compare --format json`, and the dashboard server index).
//
// These functions only check that the shape the dashboard needs is present and
// well-typed. They never evaluate assertions, derive statuses, reorder evidence
// or fill in values the backend left null: an unknown stays unknown on screen.

export type FinalStatus =
  | 'Detected'
  | 'Prevented'
  | 'Missing telemetry'
  | 'False negative'
  | 'Inconclusive';

export const FINAL_STATUSES: readonly FinalStatus[] = [
  'Detected',
  'Prevented',
  'Missing telemetry',
  'False negative',
  'Inconclusive',
];

export type Outcome = 'satisfied' | 'missing_telemetry' | 'false_negative' | 'inconclusive';
export type Assurance = 'unknown' | 'caller-attested';

export interface WitnessPair {
  target_event_id: string;
  anchor_event_id: string;
}

export interface AssertionResult {
  assertion_id: string;
  role: string;
  outcome: Outcome;
  reason_code: string;
  evidence_ids: string[];
  witness_pairs: WitnessPair[];
  unevaluable_evidence_ids: string[];
  collection_reference: string | null;
  collection_assurance: Assurance;
}

export interface EvidenceEntry {
  event_id: string;
  raw_event_ref: string;
  raw_event_hash: string;
}

export interface OutcomeCounts {
  satisfied: number;
  missing_telemetry: number;
  false_negative: number;
  inconclusive: number;
}

export interface TimelineEvent {
  event_id: string;
  timestamp: string | null;
  ingested_at: string | null;
  source_type: string | null;
  event_provider: string | null;
  hostname: string | null;
  event_action: string | null;
  rule_id: string | null;
  signature_id: string | null;
  process_name: string | null;
  raw_event_ref: string | null;
}

export interface Timeline {
  version: string;
  order: string;
  events: TimelineEvent[];
}

/**
 * Optional context copied from `comparison_inputs.scenario` when the report
 * carries it. Every field is null when absent; nothing is inferred.
 */
export interface ScenarioDetails {
  status: string | null;
  description: string | null;
  expected_outcome: string | null;
  assertion_descriptions: Record<string, string>;
}

export interface RunBinding {
  run_id: string;
  status: 'unknown' | 'conflict' | 'caller_reviewed';
  reasons: string[];
  both_sides_caller_declared: boolean;
}

export interface EvaluationReport {
  run_binding: RunBinding | null;
  kind: 'evaluation';
  cli_report_version: string;
  scenario: { id: string; name: string; version: string };
  scenario_details: ScenarioDetails | null;
  evaluation: {
    run_id: string;
    final_status: FinalStatus;
    profile_id: string;
    profile_version: string;
    assertions: AssertionResult[];
    counts: OutcomeCounts;
    evidence_index: EvidenceEntry[];
  };
  counts: { parsed: number; skipped: number; referenced: number };
  /** Absent in reports produced before the timeline section existed. */
  timeline: Timeline | null;
}

export interface ComparisonSide {
  outcome: Outcome;
  reason_code: string;
  evidence_ids: string[];
  unevaluable_evidence_ids: string[];
  collection_assurance: Assurance;
}

export interface ComparisonAssertion {
  assertion_id: string;
  state: string;
  evidence_changes: { added: string[]; removed: string[]; retained: string[] };
  before: ComparisonSide;
  after: ComparisonSide;
}

export interface ComparisonReport {
  run_binding: { before: RunBinding | null; after: RunBinding | null };
  kind: 'comparison';
  cli_report_version: string;
  scenario: { id: string; name: string; version: string };
  before: { run_id: string; final_status: FinalStatus };
  after: { run_id: string; final_status: FinalStatus };
  comparison: {
    status: string;
    assertion_count: number;
    assertion_state_counts: Record<string, number>;
    assertions: ComparisonAssertion[];
  };
}

export interface IndexEntry {
  name: string;
  kind: 'evaluation' | 'comparison' | null;
  scenario_id: string | null;
  scenario_version: string | null;
  run_id: string | null;
  final_status: string | null;
  comparison_status: string | null;
  error: { code: string; stage: string | null; field: string | null } | null;
}

export interface ReportIndex {
  kind: 'report_index';
  reports: IndexEntry[];
}

export type Parsed<T> = { ok: true; value: T } | { ok: false; reason: string };

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const isString = (value: unknown): value is string => typeof value === 'string';
const isNullableString = (value: unknown): value is string | null => value === null || isString(value);
const isCount = (value: unknown): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;

const stringList = (value: unknown, where: string): string[] => {
  if (!Array.isArray(value) || !value.every(isString)) throw new Error(`${where}: expected a list of strings`);
  return value;
};

const requireString = (record: Record<string, unknown>, key: string, where: string): string => {
  const value = record[key];
  if (!isString(value)) throw new Error(`${where}.${key}: expected a string`);
  return value;
};

const requireRecord = (value: unknown, where: string): Record<string, unknown> => {
  if (!isRecord(value)) throw new Error(`${where}: expected an object`);
  return value;
};

const nullableString = (record: Record<string, unknown>, key: string, where: string): string | null => {
  const value = key in record ? record[key] : null;
  if (!isNullableString(value)) throw new Error(`${where}.${key}: expected a string or null`);
  return value;
};

const OUTCOMES: readonly Outcome[] = ['satisfied', 'missing_telemetry', 'false_negative', 'inconclusive'];
const ASSURANCES: readonly Assurance[] = ['unknown', 'caller-attested'];

function outcome(value: unknown, where: string): Outcome {
  if (!isString(value) || !(OUTCOMES as readonly string[]).includes(value)) {
    throw new Error(`${where}: unknown outcome`);
  }
  return value as Outcome;
}

function assurance(value: unknown, where: string): Assurance {
  if (!isString(value) || !(ASSURANCES as readonly string[]).includes(value)) {
    throw new Error(`${where}: unknown collection assurance`);
  }
  return value as Assurance;
}

function finalStatus(value: unknown, where: string): FinalStatus {
  if (!isString(value) || !(FINAL_STATUSES as readonly string[]).includes(value)) {
    throw new Error(`${where}: unknown final status`);
  }
  return value as FinalStatus;
}

function scenario(value: unknown): EvaluationReport['scenario'] {
  const record = requireRecord(value, 'scenario');
  return {
    id: requireString(record, 'id', 'scenario'),
    name: requireString(record, 'name', 'scenario'),
    version: requireString(record, 'version', 'scenario'),
  };
}

function assertion(value: unknown, index: number): AssertionResult {
  const where = `assertions[${index}]`;
  const record = requireRecord(value, where);
  const pairsRaw = record['witness_pairs'] ?? [];
  if (!Array.isArray(pairsRaw)) throw new Error(`${where}.witness_pairs: expected a list`);
  const witness_pairs = pairsRaw.map((pair, i) => {
    const pairRecord = requireRecord(pair, `${where}.witness_pairs[${i}]`);
    return {
      target_event_id: requireString(pairRecord, 'target_event_id', `${where}.witness_pairs[${i}]`),
      anchor_event_id: requireString(pairRecord, 'anchor_event_id', `${where}.witness_pairs[${i}]`),
    };
  });
  return {
    assertion_id: requireString(record, 'assertion_id', where),
    role: requireString(record, 'role', where),
    outcome: outcome(record['outcome'], `${where}.outcome`),
    reason_code: requireString(record, 'reason_code', where),
    evidence_ids: stringList(record['evidence_ids'] ?? [], `${where}.evidence_ids`),
    witness_pairs,
    unevaluable_evidence_ids: stringList(record['unevaluable_evidence_ids'] ?? [], `${where}.unevaluable_evidence_ids`),
    collection_reference: nullableString(record, 'collection_reference', where),
    collection_assurance: assurance(record['collection_assurance'] ?? 'unknown', `${where}.collection_assurance`),
  };
}

function timeline(value: unknown): Timeline | null {
  if (value === undefined || value === null) return null;
  const record = requireRecord(value, 'timeline');
  const eventsRaw = record['events'];
  if (!Array.isArray(eventsRaw)) throw new Error('timeline.events: expected a list');
  const events = eventsRaw.map((item, index) => {
    const where = `timeline.events[${index}]`;
    const event = requireRecord(item, where);
    return {
      event_id: requireString(event, 'event_id', where),
      timestamp: nullableString(event, 'timestamp', where),
      ingested_at: nullableString(event, 'ingested_at', where),
      source_type: nullableString(event, 'source_type', where),
      event_provider: nullableString(event, 'event_provider', where),
      hostname: nullableString(event, 'hostname', where),
      event_action: nullableString(event, 'event_action', where),
      rule_id: nullableString(event, 'rule_id', where),
      signature_id: nullableString(event, 'signature_id', where),
      process_name: nullableString(event, 'process_name', where),
      raw_event_ref: nullableString(event, 'raw_event_ref', where),
    };
  });
  return {
    version: requireString(record, 'version', 'timeline'),
    order: requireString(record, 'order', 'timeline'),
    events,
  };
}

function scenarioDetails(value: unknown): ScenarioDetails | null {
  if (!isRecord(value) || !isRecord(value['scenario'])) return null;
  const source = value['scenario'];
  const assertion_descriptions: Record<string, string> = Object.create(null);
  const list = source['assertions'];
  if (Array.isArray(list)) {
    for (const item of list) {
      if (isRecord(item) && isString(item['id']) && isString(item['description'])) {
        assertion_descriptions[item['id']] = item['description'];
      }
    }
  }
  const optional = (key: string): string | null => (isString(source[key]) ? (source[key] as string) : null);
  return {
    status: optional('status'),
    description: optional('description'),
    expected_outcome: optional('expected_outcome'),
    assertion_descriptions,
  };
}

function counts(value: unknown): OutcomeCounts {
  const record = requireRecord(value, 'evaluation.counts');
  const read = (key: keyof OutcomeCounts): number => {
    const item = record[key];
    if (!isCount(item)) throw new Error(`evaluation.counts.${key}: expected a nonnegative safe integer`);
    return item;
  };
  return {
    satisfied: read('satisfied'),
    missing_telemetry: read('missing_telemetry'),
    false_negative: read('false_negative'),
    inconclusive: read('inconclusive'),
  };
}

function runBinding(value: unknown, runId: string): RunBinding | null {
  if (value === undefined || value === null) return null;
  const record = requireRecord(value, 'run_binding');
  const status = record['status'];
  if (status !== 'unknown' && status !== 'conflict' && status !== 'caller_reviewed') {
    throw new Error('run_binding.status: unknown status');
  }
  const run_id = requireString(record, 'run_id', 'run_binding');
  if (run_id !== runId) throw new Error('run_binding.run_id: does not match report');
  const declared = record['both_sides_caller_declared'];
  if (typeof declared !== 'boolean') throw new Error('run_binding.both_sides_caller_declared: expected a boolean');
  return { run_id, status, reasons: stringList(record['reasons'], 'run_binding.reasons'), both_sides_caller_declared: declared };
}

function comparisonBinding(value: unknown, beforeId: string, afterId: string): ComparisonReport['run_binding'] {
  if (value === undefined || value === null) return { before: null, after: null };
  const record = requireRecord(value, 'run_binding');
  return {
    before: runBinding(requireRecord(record['before'], 'run_binding.before'), beforeId),
    after: runBinding(requireRecord(record['after'], 'run_binding.after'), afterId),
  };
}

export function parseEvaluationReport(input: unknown): Parsed<EvaluationReport> {
  try {
    const record = requireRecord(input, 'report');
    if (record['kind'] !== 'evaluation') throw new Error('report.kind: expected "evaluation"');
    const evaluation = requireRecord(record['evaluation'], 'evaluation');
    const assertionsRaw = evaluation['assertions'];
    if (!Array.isArray(assertionsRaw) || assertionsRaw.length === 0) {
      throw new Error('evaluation.assertions: expected a non-empty list');
    }
    const indexRaw = evaluation['evidence_index'] ?? [];
    if (!Array.isArray(indexRaw)) throw new Error('evaluation.evidence_index: expected a list');
    const evidence_index = indexRaw.map((item, i) => {
      const where = `evaluation.evidence_index[${i}]`;
      const entry = requireRecord(item, where);
      return {
        event_id: requireString(entry, 'event_id', where),
        raw_event_ref: requireString(entry, 'raw_event_ref', where),
        raw_event_hash: requireString(entry, 'raw_event_hash', where),
      };
    });
    const topCounts = requireRecord(record['counts'], 'counts');
    const readCount = (key: 'parsed' | 'skipped' | 'referenced'): number => {
      const item = topCounts[key];
      if (!isCount(item)) throw new Error(`counts.${key}: expected a nonnegative safe integer`);
      return item;
    };
    return {
      ok: true,
      value: {
        kind: 'evaluation',
        run_binding: runBinding(record['run_binding'], requireString(evaluation, 'run_id', 'evaluation')),
        cli_report_version: requireString(record, 'cli_report_version', 'report'),
        scenario: scenario(record['scenario']),
        scenario_details: scenarioDetails(record['comparison_inputs']),
        evaluation: {
          run_id: requireString(evaluation, 'run_id', 'evaluation'),
          final_status: finalStatus(evaluation['final_status'], 'evaluation.final_status'),
          profile_id: requireString(evaluation, 'profile_id', 'evaluation'),
          profile_version: requireString(evaluation, 'profile_version', 'evaluation'),
          assertions: assertionsRaw.map(assertion),
          counts: counts(evaluation['counts']),
          evidence_index,
        },
        counts: { parsed: readCount('parsed'), skipped: readCount('skipped'), referenced: readCount('referenced') },
        timeline: timeline(record['timeline']),
      },
    };
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.message : 'unreadable report' };
  }
}

function side(value: unknown, where: string): ComparisonSide {
  const record = requireRecord(value, where);
  return {
    outcome: outcome(record['outcome'], `${where}.outcome`),
    reason_code: requireString(record, 'reason_code', where),
    evidence_ids: stringList(record['evidence_ids'] ?? [], `${where}.evidence_ids`),
    unevaluable_evidence_ids: stringList(record['unevaluable_evidence_ids'] ?? [], `${where}.unevaluable_evidence_ids`),
    collection_assurance: assurance(record['collection_assurance'] ?? 'unknown', `${where}.collection_assurance`),
  };
}

function run(value: unknown, where: string): { run_id: string; final_status: FinalStatus } {
  const record = requireRecord(value, where);
  return {
    run_id: requireString(record, 'run_id', where),
    final_status: finalStatus(record['final_status'], `${where}.final_status`),
  };
}

export function parseComparisonReport(input: unknown): Parsed<ComparisonReport> {
  try {
    const record = requireRecord(input, 'report');
    if (record['kind'] !== 'comparison') throw new Error('report.kind: expected "comparison"');
    const comparison = requireRecord(record['comparison'], 'comparison');
    const assertionsRaw = comparison['assertions'];
    if (!Array.isArray(assertionsRaw)) throw new Error('comparison.assertions: expected a list');
    const countsRaw = requireRecord(comparison['assertion_state_counts'], 'comparison.assertion_state_counts');
    const assertion_state_counts: Record<string, number> = Object.create(null);
    for (const [key, item] of Object.entries(countsRaw)) {
      if (!isCount(item)) throw new Error(`comparison.assertion_state_counts.${key}: expected a nonnegative safe integer`);
      assertion_state_counts[key] = item;
    }
    const assertionCount = comparison['assertion_count'];
    if (!isCount(assertionCount)) throw new Error('comparison.assertion_count: expected a nonnegative safe integer');
    const assertions = assertionsRaw.map((item, index) => {
      const where = `comparison.assertions[${index}]`;
      const entry = requireRecord(item, where);
      const changes = requireRecord(entry['evidence_changes'], `${where}.evidence_changes`);
      return {
        assertion_id: requireString(entry, 'assertion_id', where),
        state: requireString(entry, 'state', where),
        evidence_changes: {
          added: stringList(changes['added'] ?? [], `${where}.evidence_changes.added`),
          removed: stringList(changes['removed'] ?? [], `${where}.evidence_changes.removed`),
          retained: stringList(changes['retained'] ?? [], `${where}.evidence_changes.retained`),
        },
        before: side(entry['before'], `${where}.before`),
        after: side(entry['after'], `${where}.after`),
      };
    });
    return {
      ok: true,
      value: {
        kind: 'comparison',
        run_binding: comparisonBinding(record['run_binding'], run(record['before'], 'before').run_id, run(record['after'], 'after').run_id),
        cli_report_version: requireString(record, 'cli_report_version', 'report'),
        scenario: scenario(record['scenario']),
        before: run(record['before'], 'before'),
        after: run(record['after'], 'after'),
        comparison: {
          status: requireString(comparison, 'status', 'comparison'),
          assertion_count: assertionCount,
          assertion_state_counts,
          assertions,
        },
      },
    };
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.message : 'unreadable report' };
  }
}

export function parseReportIndex(input: unknown): Parsed<ReportIndex> {
  try {
    const record = requireRecord(input, 'index');
    if (record['kind'] !== 'report_index') throw new Error('index.kind: expected "report_index"');
    const reportsRaw = record['reports'];
    if (!Array.isArray(reportsRaw)) throw new Error('index.reports: expected a list');
    const reports = reportsRaw.map((item, index) => {
      const where = `index.reports[${index}]`;
      const entry = requireRecord(item, where);
      const kind = entry['kind'] ?? null;
      if (kind !== null && kind !== 'evaluation' && kind !== 'comparison') {
        throw new Error(`${where}.kind: unknown report kind`);
      }
      const errorRaw = entry['error'] ?? null;
      let error: IndexEntry['error'] = null;
      if (errorRaw !== null) {
        const errorRecord = requireRecord(errorRaw, `${where}.error`);
        error = {
          code: requireString(errorRecord, 'code', `${where}.error`),
          stage: nullableString(errorRecord, 'stage', `${where}.error`),
          field: nullableString(errorRecord, 'field', `${where}.error`),
        };
      }
      return {
        name: requireString(entry, 'name', where),
        kind: kind as IndexEntry['kind'],
        scenario_id: nullableString(entry, 'scenario_id', where),
        scenario_version: nullableString(entry, 'scenario_version', where),
        run_id: nullableString(entry, 'run_id', where),
        final_status: nullableString(entry, 'final_status', where),
        comparison_status: nullableString(entry, 'comparison_status', where),
        error,
      };
    });
    return { ok: true, value: { kind: 'report_index', reports } };
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.message : 'unreadable index' };
  }
}
