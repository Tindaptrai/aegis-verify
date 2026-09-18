import { MISSING } from '../format';

type Tone = 'ok' | 'bad' | 'warn' | 'neutral' | 'accent';

// Colour only. The strings are the backend's own status, outcome and transition
// values; anything not listed is shown verbatim in the neutral tone.
const TONES: Record<string, Tone> = {
  Detected: 'ok',
  Prevented: 'ok',
  'Regression Passed': 'ok',
  'Unchanged pass': 'ok',
  satisfied: 'ok',
  unchanged_pass: 'ok',
  improvement: 'ok',
  'False negative': 'bad',
  Regression: 'bad',
  'Unchanged fail': 'bad',
  false_negative: 'bad',
  regression: 'bad',
  unchanged_fail: 'bad',
  'Missing telemetry': 'warn',
  Inconclusive: 'warn',
  'Improved with remaining gaps': 'warn',
  'Unchanged mixed': 'warn',
  missing_telemetry: 'warn',
  inconclusive: 'warn',
  unchanged_unknown: 'warn',
  unknown_changed: 'warn',
  became_evaluable: 'warn',
  became_unevaluable: 'warn',
  'caller-attested': 'accent',
};

export function StatusBadge({ value, size = 'md' }: { value: string | null; size?: 'sm' | 'md' }) {
  if (value === null) {
    return <span className={`badge neutral ${size}`}>{MISSING}</span>;
  }
  return <span className={`badge ${TONES[value] ?? 'neutral'} ${size}`}>{value}</span>;
}
