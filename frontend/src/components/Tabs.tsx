import type { KeyboardEvent, ReactNode } from 'react';

export interface TabItem {
  id: string;
  label: string;
  count?: number | null;
}

export function Tabs({
  items,
  active,
  onChange,
  label,
}: {
  items: TabItem[];
  active: string;
  onChange: (id: string) => void;
  label: string;
}) {
  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const ids = items.map((item) => item.id);
    const current = ids.indexOf(active);
    if (current < 0) return;
    let next: number | null = null;
    if (event.key === 'ArrowRight') next = (current + 1) % ids.length;
    else if (event.key === 'ArrowLeft') next = (current - 1 + ids.length) % ids.length;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = ids.length - 1;
    if (next === null) return;
    event.preventDefault();
    const id = ids[next];
    if (id === undefined) return;
    onChange(id);
    const button = event.currentTarget.querySelector<HTMLButtonElement>(`#tab-${id}`);
    button?.focus();
  };
  return (
    <div className="tabs" role="tablist" aria-label={label} onKeyDown={onKeyDown}>
      {items.map((item) => {
        const selected = item.id === active;
        return (
          <button
            key={item.id}
            type="button"
            role="tab"
            id={`tab-${item.id}`}
            aria-selected={selected}
            aria-controls={`panel-${item.id}`}
            tabIndex={selected ? 0 : -1}
            className={`tab${selected ? ' active' : ''}`}
            onClick={() => onChange(item.id)}
          >
            {item.label}
            {item.count !== undefined && item.count !== null ? <span className="tab-count">{item.count}</span> : null}
          </button>
        );
      })}
    </div>
  );
}

export function TabPanel({ id, active, children }: { id: string; active: string; children: ReactNode }) {
  const shown = id === active;
  return (
    <div id={`panel-${id}`} role="tabpanel" aria-labelledby={`tab-${id}`} hidden={!shown} className="tab-panel">
      {shown ? children : null}
    </div>
  );
}
