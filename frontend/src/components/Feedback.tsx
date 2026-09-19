import type { ReactNode } from 'react';

export function Notice({
  tone,
  title,
  children,
}: {
  tone: 'info' | 'warn' | 'error';
  title: string;
  children?: ReactNode;
}) {
  return (
    <div className={`notice ${tone}`} role={tone === 'error' ? 'alert' : 'status'}>
      <p className="notice-title">{title}</p>
      {children ? <div className="notice-body">{children}</div> : null}
    </div>
  );
}

export function ErrorPanel({
  title,
  message,
  details,
  onRetry,
}: {
  title: string;
  message: string;
  details?: string | null;
  onRetry?: () => void;
}) {
  return (
    <div className="notice error" role="alert">
      <p className="notice-title">{title}</p>
      <div className="notice-body">
        <p>{message}</p>
        <div className="notice-actions">
          {onRetry ? (
            <button type="button" className="btn" onClick={onRetry}>
              Thử lại
            </button>
          ) : null}
          {details ? (
            <details className="tech">
              <summary>Chi tiết kỹ thuật</summary>
              <pre>{details}</pre>
            </details>
          ) : null}
        </div>
      </div>
    </div>
  );
}

export function Skeleton({ lines = 3, label = 'Đang tải' }: { lines?: number; label?: string }) {
  return (
    <div className="skeleton" role="status" aria-label={label} aria-live="polite">
      {Array.from({ length: lines }, (_, index) => (
        <span key={index} className="skeleton-line" style={{ width: `${88 - (index % 3) * 18}%` }} />
      ))}
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty" role="status">
      <div className="empty-mark" aria-hidden="true" />
      <p className="empty-title">{title}</p>
      {children ? <div className="empty-body">{children}</div> : null}
    </div>
  );
}
