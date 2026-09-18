export function StatusBadge({ value }: { value: string | null }) {
  if (value === null) return <span className="badge null">null</span>;
  const tone =
    value === 'Detected' || value === 'Prevented' || value === 'Regression Passed' || value === 'Unchanged pass'
      ? 'good'
      : value === 'False negative' || value === 'Regression' || value === 'Unchanged fail'
        ? 'bad'
        : 'unknown';
  return <span className={`badge ${tone}`}>{value}</span>;
}
