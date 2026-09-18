import type { ComparisonAssertion, ComparisonReport, ComparisonSide } from '../contracts';
import { IdList } from './RunView';
import { StatusBadge } from './StatusBadge';

const STATE_ORDER = [
  'unchanged_pass',
  'unchanged_fail',
  'improvement',
  'regression',
  'unchanged_unknown',
  'unknown_changed',
  'became_evaluable',
  'became_unevaluable',
];

export function ComparisonView({ name, report }: { name: string; report: ComparisonReport }) {
  const { scenario, before, after, comparison } = report;
  const countKeys = [
    ...STATE_ORDER.filter((key) => key in comparison.assertion_state_counts),
    ...Object.keys(comparison.assertion_state_counts).filter((key) => !STATE_ORDER.includes(key)),
  ];
  return (
    <article className="report" aria-label={`Comparison ${before.run_id} → ${after.run_id}`}>
      <header className="report-header">
        <p className="eyebrow">Report comparison · {name}</p>
        <h2>
          {scenario.id} — {scenario.name} (v{scenario.version})
        </h2>
      </header>

      <section aria-labelledby="compare-summary">
        <h3 id="compare-summary">Trước / sau</h3>
        <div className="before-after">
          <div className="side">
            <p className="eyebrow">Trước (gap)</p>
            <p>
              <code>{before.run_id}</code>
            </p>
            <StatusBadge value={before.final_status} />
          </div>
          <div className="arrow" aria-hidden="true">
            →
          </div>
          <div className="side">
            <p className="eyebrow">Sau (re-test)</p>
            <p>
              <code>{after.run_id}</code>
            </p>
            <StatusBadge value={after.final_status} />
          </div>
        </div>
        <dl className="facts">
          <div className="fact">
            <dt>Trạng thái so sánh</dt>
            <dd>
              <StatusBadge value={comparison.status} />
            </dd>
          </div>
          <div className="fact">
            <dt>Assertions</dt>
            <dd>
              {comparison.assertion_count} ·{' '}
              {countKeys.map((key) => `${key} ${comparison.assertion_state_counts[key] ?? 0}`).join(' · ')}
            </dd>
          </div>
        </dl>
      </section>

      <section aria-labelledby="compare-assertions">
        <h3 id="compare-assertions">Chuyển trạng thái từng assertion</h3>
        <table className="table">
          <thead>
            <tr>
              <th>Assertion</th>
              <th>Chuyển</th>
              <th>Trước</th>
              <th>Sau</th>
              <th>Evidence thay đổi</th>
            </tr>
          </thead>
          <tbody>
            {comparison.assertions.map((item) => (
              <ComparisonRow key={item.assertion_id} item={item} />
            ))}
          </tbody>
        </table>
      </section>
    </article>
  );
}

function ComparisonRow({ item }: { item: ComparisonAssertion }) {
  const tone =
    item.state === 'improvement' || item.state === 'unchanged_pass'
      ? 'good'
      : item.state === 'regression' || item.state === 'unchanged_fail'
        ? 'bad'
        : 'unknown';
  return (
    <tr>
      <td>
        <code>{item.assertion_id}</code>
      </td>
      <td>
        <span className={`badge ${tone}`}>{item.state}</span>
      </td>
      <td>
        <Side side={item.before} />
      </td>
      <td>
        <Side side={item.after} />
      </td>
      <td>
        <div>
          thêm: <IdList ids={item.evidence_changes.added} empty="không" />
        </div>
        <div>
          bỏ: <IdList ids={item.evidence_changes.removed} empty="không" />
        </div>
        <div>
          giữ: <IdList ids={item.evidence_changes.retained} empty="không" />
        </div>
      </td>
    </tr>
  );
}

function Side({ side }: { side: ComparisonSide }) {
  return (
    <div>
      <div>
        <span className={`badge ${side.outcome === 'satisfied' ? 'good' : side.outcome === 'false_negative' ? 'bad' : 'unknown'}`}>
          {side.outcome}
        </span>
      </div>
      <div className="muted">
        <code>{side.reason_code}</code> · {side.collection_assurance}
      </div>
      <div>
        <IdList ids={side.evidence_ids} empty="không có evidence" />
      </div>
      {side.unevaluable_evidence_ids.length > 0 ? (
        <div className="muted">
          unevaluable: <IdList ids={side.unevaluable_evidence_ids} empty="" />
        </div>
      ) : null}
    </div>
  );
}
