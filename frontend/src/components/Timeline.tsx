import { useEffect, useRef, useState } from 'react';
import type { EvaluationReport, TimelineEvent } from '../contracts';
import { MISSING, shortId, text } from '../format';
import { Notice } from './Feedback';

export function Timeline({ report, highlight }: { report: EvaluationReport; highlight: string | null }) {
  const [fullIds, setFullIds] = useState(false);
  const { timeline, evaluation } = report;
  const listRef = useRef<HTMLOListElement>(null);

  useEffect(() => {
    if (highlight === null || listRef.current === null) return;
    const target = Array.from(listRef.current.querySelectorAll<HTMLElement>('[data-event-id]')).find(
      (item) => item.dataset['eventId'] === highlight,
    );
    if (target && typeof target.scrollIntoView === 'function') {
      target.scrollIntoView({ block: 'center', behavior: 'smooth' });
    }
  }, [highlight, timeline]);

  const toolbar = (
    <div className="toolbar">
      <p className="muted">
        {timeline === null
          ? 'Evidence index theo ID; report này không có thời điểm.'
          : `Thứ tự do backend cung cấp (${timeline.order}); không sắp xếp lại, không suy ra giá trị thiếu.`}
      </p>
      <label className="switch">
        <input type="checkbox" checked={fullIds} onChange={(event) => setFullIds(event.target.checked)} />
        <span>Hiện ID đầy đủ</span>
      </label>
    </div>
  );

  if (timeline === null) {
    return (
      <>
        <Notice tone="warn" title="Report này không có mục timeline">
          <p>
            Report được tạo trước khi CLI thêm <code>timeline</code>, nên không có thời điểm sự kiện. Bên dưới là evidence
            index đúng như report ghi.
          </p>
        </Notice>
        {toolbar}
        <ol ref={listRef} className="timeline" aria-label="Evidence index, không theo thời gian">
          {evaluation.evidence_index.map((entry) => (
            <li key={entry.event_id} data-event-id={entry.event_id} className={highlight === entry.event_id ? 'highlight' : undefined}>
              <div className="time">
                <span className="muted">{MISSING}</span>
              </div>
              <div className="event">
                <p className="event-title mono wrap" title={entry.event_id}>
                  {fullIds ? entry.event_id : shortId(entry.event_id)}
                </p>
                <p className="event-meta">
                  <span>raw ref</span> <span className="mono wrap">{entry.raw_event_ref}</span>
                </p>
              </div>
            </li>
          ))}
        </ol>
      </>
    );
  }

  if (timeline.events.length === 0) {
    return <Notice tone="info" title="Run này không tham chiếu evidence nào" />;
  }

  return (
    <>
      {toolbar}
      <ol ref={listRef} className="timeline" aria-label="Evidence timeline theo thứ tự thời gian">
        {timeline.events.map((event) => (
          <TimelineItem key={event.event_id} event={event} fullIds={fullIds} highlighted={highlight === event.event_id} />
        ))}
      </ol>
    </>
  );
}

function TimelineItem({ event, fullIds, highlighted }: { event: TimelineEvent; fullIds: boolean; highlighted: boolean }) {
  return (
    <li data-event-id={event.event_id} className={highlighted ? 'highlight' : undefined}>
      <div className="time">
        <span className="mono">{text(event.timestamp)}</span>
        <span className="muted small">ingested {text(event.ingested_at)}</span>
      </div>
      <div className="event">
        <p className="event-title">
          <span className="strong">{text(event.source_type)}</span>
          <span className="sep">·</span>
          <span>{text(event.event_provider)}</span>
        </p>
        <dl className="event-fields">
          <SourceField event={event} />
          <Field label="Host (quan sát)" value={event.hostname} />
          <Field label="Hành động" value={event.event_action} />
          <Field label="Rule" value={event.rule_id} mono />
          <Field label="Signature" value={event.signature_id} mono />
          <Field label="Process" value={event.process_name} />
        </dl>
        <p className="event-meta">
          <span>evidence</span>{' '}
          <span className="mono wrap" title={event.event_id}>
            {fullIds ? event.event_id : shortId(event.event_id)}
          </span>
          <span className="sep">·</span>
          <span>raw ref</span> <span className="mono wrap">{text(event.raw_event_ref)}</span>
        </p>
      </div>
    </li>
  );
}

function Field({ label, value, mono = false }: { label: string; value: string | null; mono?: boolean }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd className={value === null ? 'muted' : mono ? 'mono' : undefined}>{text(value)}</dd>
    </div>
  );
}

/**
 * The source column never pretends to be observed telemetry. A configured
 * label is shown as such; without one the manifest entry ref is shown and
 * marked as a ref; with neither the usual no-data text appears.
 *
 * Bytes the manifest declares as extracted are marked too, so an extract is
 * never read as a capture straight from the source. Saying nothing about it is
 * not the same as saying it is native, so only an explicit `false` is quiet.
 */
function SourceField({ event }: { event: TimelineEvent }) {
  const configured = event.source_label !== null;
  const value = event.source_label ?? event.source_ref;
  return (
    <div>
      <dt>Nguồn</dt>
      <dd className={value === null ? 'muted' : configured ? undefined : 'mono'}>
        {text(value)}
        {value === null ? null : (
          <span className="muted small"> {configured ? '(cấu hình)' : '(source ref)'}</span>
        )}
        {event.source_derived === true ? <span className="badge warn sm">bản trích</span> : null}
        {event.source_derived === null ? (
          <span className="muted small"> nguồn bytes: không có dữ liệu</span>
        ) : null}
      </dd>
    </div>
  );
}
