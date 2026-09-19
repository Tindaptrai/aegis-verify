import { useState } from 'react';
import type { AssertionResult, ScenarioDetails } from '../contracts';
import { MISSING, shortId, text } from '../format';
import { StatusBadge } from './StatusBadge';

export function AssertionsTable({
  assertions,
  details,
  onShowEvidence,
}: {
  assertions: AssertionResult[];
  details: ScenarioDetails | null;
  onShowEvidence: (eventId: string) => void;
}) {
  const [open, setOpen] = useState<Set<string>>(() => new Set());
  const toggle = (id: string) => {
    setOpen((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };
  return (
    <div className="table-wrap">
      <table className="table assertions">
        <thead>
          <tr>
            <th scope="col">Assertion</th>
            <th scope="col">Mô tả</th>
            <th scope="col">Vai trò</th>
            <th scope="col">Outcome</th>
            <th scope="col">Evidence</th>
            <th scope="col">
              <span className="visually-hidden">Chi tiết</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {assertions.map((assertion) => {
            const expanded = open.has(assertion.assertion_id);
            const description = details?.assertion_descriptions[assertion.assertion_id] ?? null;
            return (
              <AssertionRows
                key={assertion.assertion_id}
                assertion={assertion}
                description={description}
                expanded={expanded}
                onToggle={() => toggle(assertion.assertion_id)}
                onShowEvidence={onShowEvidence}
              />
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function AssertionRows({
  assertion,
  description,
  expanded,
  onToggle,
  onShowEvidence,
}: {
  assertion: AssertionResult;
  description: string | null;
  expanded: boolean;
  onToggle: () => void;
  onShowEvidence: (eventId: string) => void;
}) {
  const detailId = `assertion-details-${assertion.assertion_id}`;
  return (
    <>
      <tr className={expanded ? 'expanded' : undefined}>
        <td>
          <span className="mono strong">{assertion.assertion_id}</span>
        </td>
        <td className="wrap">{description ?? <span className="muted">{MISSING}</span>}</td>
        <td>{assertion.role}</td>
        <td>
          <StatusBadge value={assertion.outcome} size="sm" />
        </td>
        <td>
          <EvidenceLinks ids={assertion.evidence_ids} onShowEvidence={onShowEvidence} />
        </td>
        <td className="cell-action">
          <button
            type="button"
            className="btn ghost sm"
            aria-expanded={expanded}
            aria-controls={detailId}
            onClick={onToggle}
          >
            {expanded ? 'Ẩn' : 'Chi tiết'}
          </button>
        </td>
      </tr>
      {expanded ? (
        <tr className="details-row" id={detailId}>
          <td colSpan={6}>
            <dl className="details">
              <div>
                <dt>Reason code</dt>
                <dd>
                  <span className="mono">{assertion.reason_code}</span>
                </dd>
              </div>
              <div>
                <dt>Collection assurance</dt>
                <dd>
                  <StatusBadge value={assertion.collection_assurance} size="sm" />
                </dd>
              </div>
              <div>
                <dt>Collection reference</dt>
                <dd className="wrap">{text(assertion.collection_reference)}</dd>
              </div>
              <div className="span-2">
                <dt>Evidence IDs ({assertion.evidence_ids.length})</dt>
                <dd>
                  <FullIdList ids={assertion.evidence_ids} onShowEvidence={onShowEvidence} />
                </dd>
              </div>
              <div className="span-2">
                <dt>Unevaluable IDs ({assertion.unevaluable_evidence_ids.length})</dt>
                <dd>
                  <FullIdList ids={assertion.unevaluable_evidence_ids} onShowEvidence={onShowEvidence} />
                </dd>
              </div>
              <div className="span-2">
                <dt>Witness pairs ({assertion.witness_pairs.length})</dt>
                <dd>
                  {assertion.witness_pairs.length === 0 ? (
                    <span className="muted">{MISSING}</span>
                  ) : (
                    <ul className="plain">
                      {assertion.witness_pairs.map((pair) => (
                        <li key={`${pair.target_event_id}|${pair.anchor_event_id}`} className="mono wrap">
                          target {pair.target_event_id} ← anchor {pair.anchor_event_id}
                        </li>
                      ))}
                    </ul>
                  )}
                </dd>
              </div>
            </dl>
          </td>
        </tr>
      ) : null}
    </>
  );
}

function EvidenceLinks({ ids, onShowEvidence }: { ids: string[]; onShowEvidence: (eventId: string) => void }) {
  if (ids.length === 0) return <span className="muted">{MISSING}</span>;
  return (
    <ul className="chips">
      {ids.map((id) => (
        <li key={id}>
          <button type="button" className="chip mono" title={id} onClick={() => onShowEvidence(id)}>
            {shortId(id)}
          </button>
        </li>
      ))}
    </ul>
  );
}

function FullIdList({ ids, onShowEvidence }: { ids: string[]; onShowEvidence: (eventId: string) => void }) {
  if (ids.length === 0) return <span className="muted">{MISSING}</span>;
  return (
    <ul className="plain">
      {ids.map((id) => (
        <li key={id}>
          <button type="button" className="linklike mono wrap" onClick={() => onShowEvidence(id)}>
            {id}
          </button>
        </li>
      ))}
    </ul>
  );
}
