import { useState } from 'react';
import type { EvaluationReport } from '../contracts';
import { MISSING } from '../format';
import { AssertionsTable } from './AssertionsTable';
import { Notice } from './Feedback';
import { StatusBadge } from './StatusBadge';
import { Tabs, TabPanel } from './Tabs';
import { Timeline } from './Timeline';
import { RunCharts } from './RunCharts';
import { BindingNotice } from './BindingNotice';

export type RunTab = 'assertions' | 'timeline';

export function RunView({
  report,
  tab,
  onTab,
}: {
  report: EvaluationReport;
  tab: RunTab;
  onTab: (tab: RunTab) => void;
}) {
  const [highlight, setHighlight] = useState<string | null>(null);
  const { evaluation, counts, scenario_details } = report;
  const total = evaluation.assertions.length;
  const attested = evaluation.assertions.filter((a) => a.collection_assurance === 'caller-attested');
  const showEvidence = (eventId: string) => {
    setHighlight(eventId);
    onTab('timeline');
  };

  return (
    <div className="run">
      <section className="overview" aria-label="Tổng quan">
        <div className="stat">
          <p className="stat-label">Result</p>
          <p className="stat-value">
            <StatusBadge value={evaluation.final_status} />
          </p>
          <p className="stat-sub">
            profile <span className="mono">{evaluation.profile_id}</span> v{evaluation.profile_version}
          </p>
        </div>
        <div className="stat">
          <p className="stat-label">Assertions</p>
          <p className="stat-value">
            <span className="num">{evaluation.counts.satisfied}</span>
            <span className="stat-of">/ {total} satisfied</span>
          </p>
          <p className="stat-sub">
            {[
              ['false_negative', evaluation.counts.false_negative],
              ['missing_telemetry', evaluation.counts.missing_telemetry],
              ['inconclusive', evaluation.counts.inconclusive],
            ]
              .map(([label, value]) => `${label} ${value}`)
              .join(' · ')}
          </p>
        </div>
        <div className="stat">
          <p className="stat-label">Evidence</p>
          <p className="stat-value">
            <span className="num">{evaluation.evidence_index.length}</span>
            <span className="stat-of">được tham chiếu</span>
          </p>
          <p className="stat-sub">
            parsed {counts.parsed} · skipped {counts.skipped} · referenced {counts.referenced}
          </p>
        </div>
      </section>

      <RunCharts outcomes={evaluation.counts} intake={counts} />

      <div className="notices">
        <BindingNotice binding={report.run_binding} />
        {scenario_details && (scenario_details.status !== null || scenario_details.description !== null) ? (
          <Notice tone="info" title={`Scenario status: ${scenario_details.status ?? MISSING}`}>
            <p>{scenario_details.description ?? MISSING}</p>
          </Notice>
        ) : null}
        {attested.length > 0 ? (
          <Notice tone="warn" title="Có assertion dựa trên collection attestation do người thu thập khai (caller-attested)">
            <p>
              {attested.map((a) => a.assertion_id).join(', ')} — reference:{' '}
              {Array.from(new Set(attested.map((a) => a.collection_reference ?? MISSING))).join('; ')}. Attestation không
              phải bằng chứng độc lập; người review phải kiểm tra nguồn evidence và collection.
            </p>
          </Notice>
        ) : (
          <Notice tone="info" title="Collection assurance: unknown cho mọi assertion">
            <p>Thiếu alert trong report này không tự chứng minh detection gap; chưa có attestation thu thập đầy đủ.</p>
          </Notice>
        )}
      </div>

      <Tabs
        label="Nội dung run"
        active={tab}
        onChange={(id) => onTab(id === 'timeline' ? 'timeline' : 'assertions')}
        items={[
          { id: 'assertions', label: 'Assertions', count: total },
          { id: 'timeline', label: 'Timeline', count: report.timeline ? report.timeline.events.length : evaluation.evidence_index.length },
        ]}
      />
      <TabPanel id="assertions" active={tab}>
        <AssertionsTable assertions={evaluation.assertions} details={scenario_details} onShowEvidence={showEvidence} />
      </TabPanel>
      <TabPanel id="timeline" active={tab}>
        <Timeline report={report} highlight={highlight} />
      </TabPanel>
    </div>
  );
}
