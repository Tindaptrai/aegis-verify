import type { EvaluationReport, OutcomeCounts } from '../contracts';

const OUTCOMES = [
  { key: 'satisfied', label: 'Đạt', color: 'var(--ok)' },
  { key: 'false_negative', label: 'False negative', color: 'var(--bad)' },
  { key: 'missing_telemetry', label: 'Thiếu telemetry', color: 'var(--warn)' },
  { key: 'inconclusive', label: 'Chưa kết luận', color: 'var(--text-2)' },
] as const;

export function RunCharts({ outcomes, intake }: {
  outcomes: OutcomeCounts;
  intake: EvaluationReport['counts'];
}) {
  const total = OUTCOMES.reduce((sum, item) => sum + outcomes[item.key], 0);
  // Normalize by the largest value first so large valid counts cannot overflow.
  const largest = Math.max(1, ...OUTCOMES.map((item) => outcomes[item.key]));
  const scaledTotal = OUTCOMES.reduce((sum, item) => sum + outcomes[item.key] / largest, 0);
  let cursor = 0;
  const segments = OUTCOMES.map((item) => {
    const start = cursor;
    cursor += scaledTotal === 0 ? 0 : (outcomes[item.key] / largest / scaledTotal) * 100;
    return { ...item, value: outcomes[item.key], start, length: cursor - start };
  });
  const evidence = [
    { label: 'Đã parse', value: intake.parsed, color: 'var(--accent)' },
    { label: 'Được tham chiếu', value: intake.referenced, color: 'var(--ok)' },
    { label: 'Bị skip', value: intake.skipped, color: 'var(--warn)' },
  ];
  const maximum = Math.max(1, ...evidence.map((item) => item.value));

  return (
    <div className="run-charts">
      <section className="chart-panel" aria-label="Phân bố assertion">
        <div className="chart-heading">
          <h2>Phân bố assertion</h2>
          <span className="chart-caption">Kết quả đánh giá</span>
        </div>
        <div className="outcome-chart">
          <div className="donut-frame">
            {total > 0 ? (
              <svg className="outcome-donut" viewBox="0 0 160 160" role="img"
                aria-label={`Phân bố assertion: ${segments.map((item) => `${item.label} ${item.value}`).join(', ')}`}>
                <circle cx="80" cy="80" r="62" fill="none" stroke="var(--line)" strokeWidth="15" />
                {segments.filter((item) => item.value > 0).map((item) => (
                  <circle key={item.key} cx="80" cy="80" r="62" fill="none" stroke={item.color}
                    strokeWidth="15" pathLength="100" strokeDasharray={`${item.length} ${100 - item.length}`}
                    strokeDashoffset={-item.start} transform="rotate(-90 80 80)" />
                ))}
              </svg>
            ) : <div className="donut-empty" aria-hidden="true" />}
            <div className="donut-center" aria-hidden="true">
              <strong>{Number.isFinite(total) ? total : '—'}</strong><span>assertions</span>
            </div>
          </div>
          <ul className="chart-legend">
            {segments.map((item) => (
              <li key={item.key}>
                <span className="chart-dot" style={{ background: item.color }} aria-hidden="true" />
                <span>{item.label}</span><strong>{item.value}</strong>
              </li>
            ))}
          </ul>
        </div>
        <p className="chart-note">{total === 0 ? 'Chưa có assertion' : 'Phân bố trong run này · không phải tỷ lệ coverage toàn hệ thống.'}</p>
      </section>
      <section className="chart-panel" aria-label="Evidence trong run">
        <div className="chart-heading">
          <h2>Evidence trong run</h2>
          <span className="chart-caption">Số lượng bản ghi</span>
        </div>
        <ul className="evidence-bars">
          {evidence.map((item) => (
            <li key={item.label}>
              <div className="bar-label"><span>{item.label}</span><strong>{item.value}</strong></div>
              <div className="bar-track" aria-hidden="true">
                <span style={{ width: `${item.value / maximum * 100}%`, background: item.color }} />
              </div>
            </li>
          ))}
        </ul>
        <p className="chart-note">{evidence.every((item) => item.value === 0)
          ? 'Chưa có evidence được ghi nhận'
          : 'Các số đếm độc lập; evidence được tham chiếu thuộc dữ liệu đã parse.'}</p>
      </section>
    </div>
  );
}
