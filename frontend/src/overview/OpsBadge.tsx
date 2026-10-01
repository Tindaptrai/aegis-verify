import { OPS_LABEL, OPS_TONE } from './labels';

/** Operational status with its text label; colour is never the only signal. */
export function OpsBadge({ status, size = 'md' }: { status: string; size?: 'sm' | 'md' }) {
  return (
    <span className={`badge ${OPS_TONE[status] ?? 'neutral'} ${size}`} data-status={status}>
      {OPS_LABEL[status] ?? status}
    </span>
  );
}
