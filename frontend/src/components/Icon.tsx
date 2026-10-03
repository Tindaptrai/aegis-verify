import type { CSSProperties } from 'react';

const paths = {
  shield: 'M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3ZM8 12l3 3 5-6',
  overview: 'M3 3h7v7H3V3Zm11 0h7v7h-7V3ZM3 14h7v7H3v-7Zm11 0h7v7h-7v-7Z',
  reports: 'M6 3h8l4 4v14H6V3Zm8 0v5h4M9 12h6m-6 4h6',
  collections: 'M4 5h16v5H4V5Zm0 9h16v5H4v-5Zm4-7h.01M8 16h.01',
  agents: 'M4 4h16v12H4V4Zm4 16h8m-4-4v4',
  search: 'M17 17l4 4M19 10a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z',
  refresh: 'M20 7v5h-5M4 17v-5h5M6 6a8 8 0 0 1 13 2M5 16a8 8 0 0 0 13 2',
};

export function Icon({ name, className, style }: { name: keyof typeof paths; className?: string; style?: CSSProperties }) {
  return <svg className={`icon${className ? ` ${className}` : ''}`} style={style} viewBox="0 0 24 24"
    fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"
    aria-hidden="true" focusable="false"><path d={paths[name]} /></svg>;
}
