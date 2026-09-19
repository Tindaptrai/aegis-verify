// Selection lives in the URL hash so a reload, a shared link or a headless
// screenshot lands on the same report and tab. Nothing else is stored.

export interface Route {
  report: string | null;
  tab: string | null;
  page?: 'reports' | 'agents' | 'collections';
  job?: string | null;
}

export function readRoute(hash: string = window.location.hash): Route {
  const params = new URLSearchParams(hash.replace(/^#/, ''));
  const page = params.get('page');
  const job = params.get('job');
  return { report: params.get('report'), tab: params.get('tab'),
    page: page === 'agents' || page === 'collections' ? page : 'reports',
    job: job && /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(job) ? job : null };
}

export function routeHash(route: Route): string {
  const params = new URLSearchParams();
  if (route.report) params.set('report', route.report);
  if (route.tab) params.set('tab', route.tab);
  if (route.page === 'agents' || route.page === 'collections') params.set('page', route.page);
  if (route.page === 'collections' && route.job && /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(route.job)) params.set('job', route.job);
  const encoded = params.toString();
  return encoded === '' ? '' : `#${encoded}`;
}

export function writeRoute(route: Route): void {
  const next = routeHash(route);
  if (window.location.hash === next) return;
  const base = window.location.pathname + window.location.search;
  window.history.replaceState(null, '', next === '' ? base : base + next);
}
