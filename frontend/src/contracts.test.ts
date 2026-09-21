import { describe, expect, it } from 'vitest';
import { parseComparisonReport, parseEvaluationReport, parseReportIndex } from './contracts';
import afterFixture from '../../tests/fixtures/dashboard/after-detected.json';
import beforeFixture from '../../tests/fixtures/dashboard/before-false-negative.json';
import comparisonFixture from '../../tests/fixtures/dashboard/comparison-regression-passed.json';

describe('parseEvaluationReport', () => {
  it.each([-1, 0.5, Number.MAX_SAFE_INTEGER + 1])('rejects invalid count %s', (value) => {
    expect(parseEvaluationReport({ ...afterFixture, counts: { ...afterFixture.counts, parsed: value } }).ok).toBe(false);
    expect(parseEvaluationReport({ ...afterFixture, evaluation: { ...afterFixture.evaluation,
      counts: { ...afterFixture.evaluation.counts, satisfied: value } } }).ok).toBe(false);
  });

  it('does not inherit assertion descriptions from Object.prototype', () => {
    const parsed = parseEvaluationReport(afterFixture);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) expect(parsed.value.scenario_details?.assertion_descriptions['__proto__']).toBeUndefined();
  });
  it('reads the backend fixture and preserves the timeline order it was given', () => {
    const parsed = parseEvaluationReport(afterFixture);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.value.evaluation.final_status).toBe('Detected');
    expect(parsed.value.evaluation.run_id).toBe('synthetic-run-after-fix');
    expect(parsed.value.evaluation.assertions.map((a) => a.assertion_id)).toEqual(['SCN-999-A01', 'SCN-999-A02']);
    const stamps = parsed.value.timeline?.events.map((e) => e.timestamp) ?? [];
    expect(stamps).toEqual(['2026-01-01T00:00:01Z', '2026-01-01T00:00:02Z']);
    expect(parsed.value.timeline?.events[0]?.signature_id).toBeNull();
  });

  it('reads the configured source label and ref without touching the observed host', () => {
    const parsed = parseEvaluationReport(afterFixture);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const events = parsed.value.timeline?.events ?? [];
    const activity = events.find((e) => e.raw_event_ref === 'synthetic-activity#record=1');
    const alert = events.find((e) => e.raw_event_ref === 'synthetic-alert#record=1');
    expect(activity?.source_ref).toBe('synthetic-activity');
    expect(activity?.source_label).toBe('Synthetic endpoint');
    expect(activity?.hostname).toBe('synthetic-host');
    // The second entry configures no label, so it stays null rather than reusing
    // the first label or the observed hostname.
    expect(alert?.source_ref).toBe('synthetic-alert');
    expect(alert?.source_label).toBeNull();
  });

  it('reads a report written before the label existed as null, not as an error', () => {
    const timeline = afterFixture.timeline as { version: string; order: string; events: Record<string, unknown>[] };
    const legacy = {
      ...afterFixture,
      timeline: {
        ...timeline,
        version: '0.1.0',
        events: timeline.events.map(({ source_ref: _ref, source_label: _label, ...rest }) => rest),
      },
    };
    const parsed = parseEvaluationReport(legacy);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.value.timeline?.events[0]?.source_ref).toBeNull();
    expect(parsed.value.timeline?.events[0]?.source_label).toBeNull();
  });

  it('keeps a false negative and its caller-attested assurance verbatim', () => {
    const parsed = parseEvaluationReport(beforeFixture);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const detection = parsed.value.evaluation.assertions.find((a) => a.assertion_id === 'SCN-999-A02');
    expect(detection?.outcome).toBe('false_negative');
    expect(detection?.reason_code).toBe('expected_detection_absent');
    expect(detection?.collection_assurance).toBe('caller-attested');
  });

  it('copies optional scenario details from comparison_inputs and leaves them null otherwise', () => {
    const parsed = parseEvaluationReport(afterFixture);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.value.scenario_details?.status).toBe('draft');
    expect(parsed.value.scenario_details?.assertion_descriptions['SCN-999-A01']).toBe('Synthetic activity exists.');
    const { comparison_inputs: _omitted, ...bare } = afterFixture;
    const withoutInputs = parseEvaluationReport(bare);
    expect(withoutInputs.ok).toBe(true);
    if (withoutInputs.ok) expect(withoutInputs.value.scenario_details).toBeNull();
  });

  it('treats a missing timeline as null rather than inventing one', () => {
    const { timeline: _omitted, ...withoutTimeline } = afterFixture;
    const parsed = parseEvaluationReport(withoutTimeline);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) expect(parsed.value.timeline).toBeNull();
  });

  it.each([
    ['wrong kind', { ...afterFixture, kind: 'comparison' }],
    ['unknown final status', { ...afterFixture, evaluation: { ...afterFixture.evaluation, final_status: 'Passed' } }],
    ['assertions not a list', { ...afterFixture, evaluation: { ...afterFixture.evaluation, assertions: {} } }],
    ['evidence id not a string', {
      ...afterFixture,
      evaluation: {
        ...afterFixture.evaluation,
        assertions: [{ ...afterFixture.evaluation.assertions[0], evidence_ids: [1] }],
      },
    }],
    ['timeline event without id', { ...afterFixture, timeline: { version: '0.1.0', order: 'x', events: [{}] } }],
    ['not an object', 'text'],
    ['null', null],
  ])('rejects a malformed report: %s', (_label, input) => {
    const parsed = parseEvaluationReport(input);
    expect(parsed.ok).toBe(false);
    if (!parsed.ok) expect(parsed.reason.length).toBeGreaterThan(0);
  });
});

describe('parseComparisonReport', () => {
  it.each([-1, 0.5, Number.MAX_SAFE_INTEGER + 1])('rejects invalid comparison count %s', (value) => {
    expect(parseComparisonReport({ ...comparisonFixture, comparison: { ...comparisonFixture.comparison,
      assertion_count: value } }).ok).toBe(false);
    expect(parseComparisonReport({ ...comparisonFixture, comparison: { ...comparisonFixture.comparison,
      assertion_state_counts: { improvement: value } } }).ok).toBe(false);
  });
  it('reads the Regression Passed fixture with per-assertion states', () => {
    const parsed = parseComparisonReport(comparisonFixture);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.value.comparison.status).toBe('Regression Passed');
    expect(parsed.value.before.final_status).toBe('False negative');
    expect(parsed.value.after.final_status).toBe('Detected');
    const detection = parsed.value.comparison.assertions.find((a) => a.assertion_id === 'SCN-999-A02');
    expect(detection?.state).toBe('improvement');
    expect(detection?.evidence_changes.added.length).toBeGreaterThan(0);
  });

  it('rejects a comparison whose counts are not numbers', () => {
    const broken = {
      ...comparisonFixture,
      comparison: { ...comparisonFixture.comparison, assertion_state_counts: { improvement: 'one' } },
    };
    expect(parseComparisonReport(broken).ok).toBe(false);
  });
});

describe('parseReportIndex', () => {
  it('keeps null summaries and error entries as they are', () => {
    const parsed = parseReportIndex({
      kind: 'report_index',
      version: '0.1.0',
      reports: [
        { name: 'a.json', kind: 'evaluation', scenario_id: 'S', scenario_version: '0.1.0', run_id: null,
          final_status: 'Detected', comparison_status: null, error: null },
        { name: 'b.json', kind: null, scenario_id: null, scenario_version: null, run_id: null,
          final_status: null, comparison_status: null, error: { code: 'invalid_json', stage: 'inputs', field: null } },
      ],
    });
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.value.reports[0]?.run_id).toBeNull();
    expect(parsed.value.reports[1]?.error?.code).toBe('invalid_json');
  });

  it('rejects an index with an unknown report kind', () => {
    expect(parseReportIndex({ kind: 'report_index', reports: [{ name: 'x.json', kind: 'note' }] }).ok).toBe(false);
  });
});
