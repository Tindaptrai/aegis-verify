import type { ReactNode } from 'react';
import type { AssertionResult, EvaluationReport, TimelineEvent } from '../contracts';
import { StateNotice } from './StateNotice';
import { StatusBadge } from './StatusBadge';

export function RunView({ name, report }: { name: string; report: EvaluationReport }) {
  const { scenario, evaluation, counts } = report;
  return (
    <article className="report" aria-label={`Run ${evaluation.run_id}`}>
      <header className="report-header">
        <p className="eyebrow">Report evaluation · {name}</p>
        <h2>
          {scenario.id} — {scenario.name}
        </h2>
      </header>

      <section aria-labelledby="summary-heading">
        <h3 id="summary-heading">Tổng quan</h3>
        <dl className="facts">
          <Fact label="Scenario" value={`${scenario.id} v${scenario.version}`} />
          <Fact label="Run ID" value={evaluation.run_id} />
          <Fact label="Kết quả cuối" value={<StatusBadge value={evaluation.final_status} />} />
          <Fact
            label="Phân loại assertion"
            value={
              <span className="counts">
                satisfied {evaluation.counts.satisfied} · missing_telemetry {evaluation.counts.missing_telemetry} ·
                false_negative {evaluation.counts.false_negative} · inconclusive {evaluation.counts.inconclusive}
              </span>
            }
          />
          <Fact
            label="Evidence"
            value={`${evaluation.evidence_index.length} evidence được tham chiếu · parsed ${counts.parsed} · skipped ${counts.skipped}`}
          />
          <Fact label="Profile" value={`${evaluation.profile_id} v${evaluation.profile_version}`} />
        </dl>
      </section>

      <section aria-labelledby="assertions-heading">
        <h3 id="assertions-heading">Assertions</h3>
        <table className="table">
          <thead>
            <tr>
              <th>Assertion</th>
              <th>Vai trò</th>
              <th>Kết quả</th>
              <th>Lý do</th>
              <th>Assurance</th>
              <th>Evidence IDs</th>
            </tr>
          </thead>
          <tbody>
            {evaluation.assertions.map((assertion) => (
              <AssertionRow key={assertion.assertion_id} assertion={assertion} />
            ))}
          </tbody>
        </table>
      </section>

      <section aria-labelledby="timeline-heading">
        <h3 id="timeline-heading">Evidence timeline</h3>
        <Timeline report={report} />
      </section>
    </article>
  );
}

function Fact({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="fact">
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function AssertionRow({ assertion }: { assertion: AssertionResult }) {
  return (
    <tr className={`outcome-${assertion.outcome}`}>
      <td>
        <code>{assertion.assertion_id}</code>
      </td>
      <td>{assertion.role}</td>
      <td>
        <span className={`badge ${assertion.outcome === 'satisfied' ? 'good' : assertion.outcome === 'false_negative' ? 'bad' : 'unknown'}`}>
          {assertion.outcome}
        </span>
      </td>
      <td>
        <code>{assertion.reason_code}</code>
      </td>
      <td>
        {assertion.collection_assurance}
        {assertion.collection_reference ? <small className="muted"> · {assertion.collection_reference}</small> : null}
      </td>
      <td>
        <IdList ids={assertion.evidence_ids} empty="không có" />
        {assertion.unevaluable_evidence_ids.length > 0 ? (
          <div className="muted">
            unevaluable: <IdList ids={assertion.unevaluable_evidence_ids} empty="" />
          </div>
        ) : null}
        {assertion.witness_pairs.length > 0 ? (
          <div className="muted">
            witness: {assertion.witness_pairs.map((pair) => `${shortId(pair.target_event_id)} ← ${shortId(pair.anchor_event_id)}`).join('; ')}
          </div>
        ) : null}
      </td>
    </tr>
  );
}

export function IdList({ ids, empty }: { ids: string[]; empty: string }) {
  if (ids.length === 0) return <span className="muted">{empty}</span>;
  return (
    <ul className="ids">
      {ids.map((id) => (
        <li key={id}>
          <a href={`#evidence-${id}`} title={id}>
            <code>{shortId(id)}</code>
          </a>
        </li>
      ))}
    </ul>
  );
}

export function shortId(id: string): string {
  return id.length > 28 ? `${id.slice(0, 14)}…${id.slice(-10)}` : id;
}

function Timeline({ report }: { report: EvaluationReport }) {
  const { timeline, evaluation } = report;
  if (timeline === null) {
    return (
      <>
        <StateNotice tone="warning" title="Report này không có mục timeline">
          Report được tạo trước khi CLI thêm <code>timeline</code>, nên không có thời điểm sự kiện. Bên dưới là
          evidence index theo ID, không theo thời gian.
        </StateNotice>
        <ol className="timeline" aria-label="Evidence index, không theo thời gian">
          {evaluation.evidence_index.map((entry) => (
            <li key={entry.event_id} id={`evidence-${entry.event_id}`}>
              <div className="time muted">thời điểm: không có trong report</div>
              <div>
                <code title={entry.event_id}>{shortId(entry.event_id)}</code> · ref <code>{entry.raw_event_ref}</code>
              </div>
            </li>
          ))}
        </ol>
      </>
    );
  }
  if (timeline.events.length === 0) {
    return <StateNotice tone="neutral" title="Không có evidence nào được tham chiếu trong run này" />;
  }
  return (
    <>
      <p className="muted">
        Thứ tự do backend cung cấp ({timeline.order}); dashboard không sắp xếp lại và không suy ra giá trị thiếu.
      </p>
      <ol className="timeline" aria-label="Evidence timeline theo thứ tự thời gian">
        {timeline.events.map((event) => (
          <TimelineItem key={event.event_id} event={event} />
        ))}
      </ol>
    </>
  );
}

function TimelineItem({ event }: { event: TimelineEvent }) {
  return (
    <li id={`evidence-${event.event_id}`}>
      <div className="time">{event.timestamp ?? <span className="muted">timestamp: null</span>}</div>
      <div>
        <code title={event.event_id}>{shortId(event.event_id)}</code>
        <div className="muted">
          {field('source', event.source_type)} · {field('provider', event.event_provider)} · {field('host', event.hostname)}{' '}
          · {field('action', event.event_action)} · {field('rule', event.rule_id)} · {field('signature', event.signature_id)}{' '}
          · {field('process', event.process_name)}
        </div>
        <div className="muted">ref {event.raw_event_ref ?? 'null'} · ingested {event.ingested_at ?? 'null'}</div>
      </div>
    </li>
  );
}

function field(label: string, value: string | null): string {
  return `${label}: ${value ?? 'null'}`;
}
