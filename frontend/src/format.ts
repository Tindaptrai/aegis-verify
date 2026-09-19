// Presentation helpers. They never change a contract value: a null stays null
// in the parsed report and is only *rendered* as the "no data" label.

export const MISSING = 'Không có dữ liệu';

export function text(value: string | number | null | undefined): string {
  if (value === null || value === undefined) return MISSING;
  const rendered = String(value);
  return rendered.trim() === '' ? MISSING : rendered;
}

export function shortId(id: string): string {
  return id.length > 30 ? `${id.slice(0, 16)}…${id.slice(-10)}` : id;
}

export function plural(count: number, singular: string, pluralForm = singular): string {
  return `${count} ${count === 1 ? singular : pluralForm}`;
}
