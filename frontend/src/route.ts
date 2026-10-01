// Selection lives in the URL hash so a reload, a shared link or a headless
// screenshot lands on the same page, report, tab or scenario. Nothing else is stored.

export type Page = 'overview' | 'reports' | 'agents' | 'collections';

export interface Route {
  report: string | null;
  tab: string | null;
  page?: Page;
  job?: string | null;
  scenario?: string | null;
}

const PAGES: readonly Page[] = ['overview', 'reports', 'agents', 'collections'];
const JOB = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/;
const SCENARIO = /^SCN-[0-9]{3}$/;

export function readRoute(hash: string = window.location.hash): Route {
  const params = new URLSearchParams(hash.replace(/^#/, ''));
  const requested = params.get('page');
  const report = params.get('report');
  const job = params.get('job');
  const scenario = params.get('scenario');
  // An old link with only a report keeps opening that report; otherwise the
  // scenario overview is the landing page.
  const page: Page = PAGES.includes(requested as Page) ? (requested as Page) : report !== null ? 'reports' : 'overview';
  return { report, tab: params.get('tab'), page,
    job: job && JOB.test(job) ? job : null,
    scenario: scenario && SCENARIO.test(scenario) ? scenario : null };
}

export function routeHash(route: Route): string {
  const params = new URLSearchParams();
  const page = route.page ?? 'overview';
  if (page === 'overview') {
    if (route.scenario && SCENARIO.test(route.scenario)) params.set('scenario', route.scenario);
  } else {
    if (route.report) params.set('report', route.report);
    if (route.tab) params.set('tab', route.tab);
    if (page !== 'reports' || !route.report) params.set('page', page);
    if (page === 'collections' && route.job && JOB.test(route.job)) params.set('job', route.job);
  }
  const encoded = params.toString();
  return encoded === '' ? '' : `#${encoded}`;
}

export function writeRoute(route: Route): void {
  const next = routeHash(route);
  if (window.location.hash === next) return;
  const base = window.location.pathname + window.location.search;
  window.history.replaceState(null, '', next === '' ? base : base + next);
}
