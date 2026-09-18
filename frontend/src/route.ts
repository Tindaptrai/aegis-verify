// Selection lives in the URL hash so a reload, a shared link or a headless
// screenshot lands on the same report and tab. Nothing else is stored.

export interface Route {
  report: string | null;
  tab: string | null;
}

export function readRoute(hash: string = window.location.hash): Route {
  const params = new URLSearchParams(hash.replace(/^#/, ''));
  return { report: params.get('report'), tab: params.get('tab') };
}

export function routeHash(route: Route): string {
  const params = new URLSearchParams();
  if (route.report) params.set('report', route.report);
  if (route.tab) params.set('tab', route.tab);
  const encoded = params.toString();
  return encoded === '' ? '' : `#${encoded}`;
}

export function writeRoute(route: Route): void {
  const next = routeHash(route);
  if (window.location.hash === next) return;
  const base = window.location.pathname + window.location.search;
  window.history.replaceState(null, '', next === '' ? base : base + next);
}
