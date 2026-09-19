import { useState } from 'react';
import type { ComparisonAssertion, ComparisonReport, ComparisonSide } from '../contracts';
import { MISSING, shortId } from '../format';
import { StatusBadge } from './StatusBadge';

const STATE_ORDER = [
  'improvement',
  'regression',
  'unchanged_pass',
  'unchanged_fail',
  'became_evaluable',
  'became_unevaluable',
  'unknown_changed',
  'unchanged_unknown',
];

export function ComparisonView({ report }: { report: ComparisonReport }) {
  const { before, after, comparison } = report;
  const countKeys = [
    ...STATE_ORDER.filter((key) => key in comparison.assertion_state_counts),
    ...Object.keys(comparison.assertion_state_counts).filter((key) => !STATE_ORDER.includes(key)),
  ];
  return (
    <div className="comparison">
      <section className="before-after" aria-label="Trước và sau">
        <div className="side">
          <p className="side-label">Trước · gap</p>
          <p className="side-run mono">{before.run_id}</p>
          <StatusBadge value={before.final_status} />
        </div>
        <div className="transition" aria-hidden="true">
          <span className="transition-line" />
          <span className="transition-arrow">→</span>
        </div>
        <div className="side">
          <p className="side-label">Sau · re-test</p>
          <p className="side-run mono">{after.run_id}</p>
          <StatusBadge value={after.final_status} />
        </div>
      </section>

      <section className="summary" aria-label="Tóm tắt so sánh">
        <div className="summary-status">
          <p className="stat-label">Comparison status</p>
          <StatusBadge value={comparison.status} />
        </div>
        <dl className="summary-counts">
          <div>
            <dt>assertions</dt>
            <dd className="num">{comparison.assertion_count}</dd>
          </div>
          {countKeys.map((key) => (
            <div key={key} className={comparison.assertion_state_counts[key] === 0 ? 'zero' : undefined}>
              <dt>{key}</dt>
              <dd className="num">{comparison.assertion_state_counts[key] ?? 0}</dd>
            </div>
          ))}
        </dl>
      </section>

      <section aria-labelledby="transitions-heading">
        <h2 id="transitions-heading" className="section-title">
          Chuyển trạng thái từng assertion
        </h2>
        <div className="table-wrap">
          <table className="table transitions">
            <thead>
              <tr>
                <th scope="col">Assertion</th>
                <th scope="col">Trước</th>
                <th scope="col">Chuyển</th>
                <th scope="col">Sau</th>
                <th scope="col">Evidence thay đổi</th>
              </tr>
            </thead>
            <tbody>
              {comparison.assertions.map((item) => (
                <TransitionRow key={item.assertion_id} item={item} />
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function TransitionRow({ item }: { item: ComparisonAssertion }) {
  return (
    <tr>
      <td>
        <span className="mono strong">{item.assertion_id}</span>
      </td>
      <td>
        <Side side={item.before} />
      </td>
      <td>
        <StatusBadge value={item.state} size="sm" />
      </td>
      <td>
        <Side side={item.after} />
      </td>
      <td>
        <Changes changes={item.evidence_changes} />
      </td>
    </tr>
  );
}

function Side({ side }: { side: ComparisonSide }) {
  return (
    <div className="side-cell">
      <StatusBadge value={side.outcome} size="sm" />
      <p className="mono small">{side.reason_code}</p>
      <p className="small muted">assurance {side.collection_assurance}</p>
      <p className="small">
        {side.evidence_ids.length === 0 ? (
          <span className="muted">evidence: {MISSING}</span>
        ) : (
          <>evidence {side.evidence_ids.length}{side.unevaluable_evidence_ids.length > 0 ? ` · unevaluable ${side.unevaluable_evidence_ids.length}` : ''}</>
        )}
      </p>
    </div>
  );
}

function Changes({ changes }: { changes: ComparisonAssertion['evidence_changes'] }) {
  const [open, setOpen] = useState(false);
  const rows: Array<[string, string[]]> = [
    ['thêm', changes.added],
    ['bỏ', changes.removed],
    ['giữ', changes.retained],
  ];
  return (
    <div className="changes">
      <p className="small">{rows.map(([label, ids]) => `${label} ${ids.length}`).join(' · ')}</p>
      <button type="button" className="btn ghost sm" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
        {open ? 'Ẩn ID' : 'Xem ID'}
      </button>
      {open ? (
        <dl className="changes-list">
          {rows.map(([label, ids]) => (
            <div key={label}>
              <dt>{label}</dt>
              <dd>
                {ids.length === 0 ? (
                  <span className="muted">{MISSING}</span>
                ) : (
                  <ul className="plain">
                    {ids.map((id) => (
                      <li key={id} className="mono wrap" title={id}>
                        {shortId(id)}
                      </li>
                    ))}
                  </ul>
                )}
              </dd>
            </div>
          ))}
        </dl>
      ) : null}
    </div>
  );
}
