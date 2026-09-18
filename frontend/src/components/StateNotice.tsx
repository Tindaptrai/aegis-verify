import type { ReactNode } from 'react';

export function StateNotice({
  tone,
  title,
  children,
}: {
  tone: 'neutral' | 'warning' | 'error';
  title: string;
  children?: ReactNode;
}) {
  return (
    <div className={`notice ${tone}`} role={tone === 'error' ? 'alert' : 'status'}>
      <strong>{title}</strong>
      {children ? <p>{children}</p> : null}
    </div>
  );
}
