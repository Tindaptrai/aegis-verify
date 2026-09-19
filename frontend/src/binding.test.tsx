import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { parseEvaluationReport, parseComparisonReport } from './contracts';
import { RunView } from './components/RunView';
import { ComparisonView } from './components/ComparisonView';
import run from '../../tests/fixtures/dashboard/after-detected.json';
import comparison from '../../tests/fixtures/dashboard/comparison-regression-passed.json';

const binding = (run_id: string) => ({ run_id, status: 'unknown',
  reasons: ['companion_record_unmatched', 'native_review_missing'], both_sides_caller_declared: true });

describe('run binding presentation', () => {
  it.each([{}, { status: 'caller_reviewed' }, { before: binding(comparison.before.run_id) },
    { before: binding(comparison.before.run_id), after: null },
    { before: binding(comparison.before.run_id), after: { ...binding(comparison.after.run_id), reasons: false } },
  ])('rejects malformed comparison binding wrappers: %j', (run_binding) => {
    expect(parseComparisonReport({ ...comparison, run_binding }).ok).toBe(false);
  });
  it('renders conflict prominently without replacing detection status', () => {
    const parsed = parseEvaluationReport({ ...run, run_binding: {
      ...binding(run.evaluation.run_id), status: 'conflict', reasons: ['parent_pid_mismatch'],
    } });
    if (!parsed.ok) throw new Error(parsed.reason);
    render(<RunView report={parsed.value} tab="assertions" onTab={() => {}} />);
    expect(screen.getByRole('alert')).toHaveTextContent('Run binding: conflict');
    expect(screen.getByRole('alert')).toHaveTextContent('parent_pid_mismatch');
    expect(parsed.value.evaluation.final_status).toBe('Detected');
  });
  it('preserves unknown reasons beside a detected result', () => {
    const parsed = parseEvaluationReport({ ...run, run_binding: binding(run.evaluation.run_id) });
    if (!parsed.ok) throw new Error(parsed.reason);
    render(<RunView report={parsed.value} tab="assertions" onTab={() => {}} />);
    expect(screen.getByText('Run binding: unknown')).toBeInTheDocument();
    expect(screen.getByText('companion_record_unmatched')).toBeInTheDocument();
    expect(screen.getByText('native_review_missing')).toBeInTheDocument();
    expect(parsed.value.evaluation.final_status).toBe('Detected');
  });
  it('explains missing binding in older reports', () => {
    const parsed = parseEvaluationReport(run);
    if (!parsed.ok) throw new Error(parsed.reason);
    render(<RunView report={parsed.value} tab="assertions" onTab={() => {}} />);
    expect(screen.getByText('Run binding: chưa có dữ liệu')).toBeInTheDocument();
  });
  it('keeps before and after binding separate without changing Regression Passed', () => {
    const parsed = parseComparisonReport({ ...comparison, run_binding: {
      before: binding(comparison.before.run_id),
      after: { ...binding(comparison.after.run_id), status: 'caller_reviewed', reasons: [] },
    } });
    if (!parsed.ok) throw new Error(parsed.reason);
    render(<ComparisonView report={parsed.value} />);
    expect(within(screen.getByRole('region', { name: 'Run binding — Trước' })).getByText('Run binding: unknown')).toBeInTheDocument();
    expect(within(screen.getByRole('region', { name: 'Run binding — Sau' })).getByText('Run binding: caller_reviewed')).toBeInTheDocument();
    expect(screen.getAllByText(/không phải xác minh độc lập/).length).toBe(2);
    expect(parsed.value.comparison.status).toBe('Regression Passed');
  });
  it('shows missing binding on both sides of an older comparison', () => {
    const parsed = parseComparisonReport(comparison);
    if (!parsed.ok) throw new Error(parsed.reason);
    render(<ComparisonView report={parsed.value} />);
    expect(screen.getAllByText('Run binding: chưa có dữ liệu')).toHaveLength(2);
  });
  it.each([
    { status: 'verified' }, { reasons: [42] }, { both_sides_caller_declared: 'true' }, { run_id: 'other-run' },
  ])('rejects malformed or cross-run attachments: %j', (change) => {
    expect(parseEvaluationReport({ ...run, run_binding: { ...binding(run.evaluation.run_id), ...change } }).ok).toBe(false);
    expect(parseComparisonReport({ ...comparison, run_binding: {
      before: { ...binding(comparison.before.run_id), ...change }, after: binding(comparison.after.run_id),
    } }).ok).toBe(false);
  });
});
