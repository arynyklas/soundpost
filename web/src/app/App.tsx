// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { bindSession, releaseSession } from '../api/client';
import { getDirectory } from '../api/console';
import { bindElevation, releaseElevation } from '../api/elevation';
import { AccountPage } from '../account/AccountPage';
import { SessionContext } from '../auth/ElevationDialog';
import { DashboardsRoute } from '../dashboards/DashboardsRoute';
import { LogsRoute } from '../explore/LogsRoute';
import { MetricsRoute } from '../explore/MetricsRoute';
import { HomeRoute } from '../home/HomeRoute';
import { IncidentsRoute } from '../incidents/IncidentsRoute';
import { IssuesRoute } from '../issues/IssuesRoute';
import { JobsRoute } from '../jobs/JobsRoute';
import { OnboardingRoute } from '../onboarding/OnboardingRoute';
import { ProfilesRoute } from '../profiles/ProfilesRoute';
import { ReleasesRoute } from '../releases/ReleasesRoute';
import { ReplaysRoute } from '../replays/ReplaysRoute';
import { RoutingRoute } from '../routing/RoutingRoute';
import { RulesRoute } from '../alerts/RulesRoute';
import { ServicesRoute } from '../services/ServicesRoute';
import { CutoverRoute } from '../settings/CutoverRoute';
import { EventsRoute } from '../settings/EventsRoute';
import { GitlabRoute } from '../settings/GitlabRoute';
import { SettingsRoute } from '../settings/SettingsRoute';
import { NeedScope } from '../shell/Frames';
import { Shell } from '../shell/Shell';
import { linkFor, NO_NAMES, type LinkOptions, type Names } from '../shell/ShellContext';
import { TracesRoute } from '../traces/TracesRoute';
import { SECTIONS, decodeHash, encodeHash, scopeKey, windowEndingAt, type Navigation, type SectionId, type ViewContext } from './context';

/** Focus is free to move to a heading while it is on the page itself or, when `origin` is given, still on that control and the control is inside
 * the page content (about to be replaced by what the user asked for). A control outside it (the skip link, which survives the session boundary
 * re-mounting the console) is the user's choice and is never taken. */
const focusIsFree = (origin: Element | null): boolean => {
 const a = document.activeElement;
 // Nothing is focused: the page itself holds focus, which a browser reports as the body or, in an empty or blurred document, the document element.
 if (a === null || a === document.body || a === document.documentElement) return true;
 if (origin !== null && a !== origin) return false;
 return document.querySelector('.app')?.contains(a) === true;
};

/** After a screen or an entity is opened, focus moves to the page's own h1 as soon as it exists, so keyboard and screen-reader users land on the result
 * instead of staying on the control they used. (The session boundary re-mounts the console on every address change, so this also runs when a page is
 * opened from a deep link.) The heading can appear seconds after the effect starts; if the user has meanwhile moved focus to some control (the skip
 * link, a form field), that choice wins: focus moves only while it is still on the control that held it when the effect started and that control is
 * inside the page, or on the page itself. */
function useFocusPageHeading(key: string): void {
 const first = React.useRef(true);
 React.useEffect(() => {
  const initial = first.current;
  first.current = false;
  // The first run is a deep link or the session boundary re-mounting the console after it revalidated access (it does so every time the window
  // regains focus). A control the user holds outside the page (the skip link) is not taken from them then.
  if (initial && !focusIsFree(null)) return;
  const origin = document.activeElement;
  const find = (): HTMLElement | null => document.querySelector<HTMLElement>('main h1');
  const land = (h: HTMLElement): void => { if (!focusIsFree(origin)) return; h.setAttribute('tabindex', '-1'); h.focus(); };
  const now = find();
  if (now) { land(now); return; }
  const observer = new MutationObserver(() => { const h = find(); if (h) { observer.disconnect(); land(h); } });
  observer.observe(document.body, { childList: true, subtree: true });
  const stop = window.setTimeout(() => observer.disconnect(), 10_000);
  return () => { observer.disconnect(); window.clearTimeout(stop); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key]);
}

function useDirectory(context: ViewContext | null): Names {
 const [names, setNames] = React.useState<Names>(NO_NAMES);
 const key = context ? `${context.org}|${context.projects.join(',')}` : '';
 React.useEffect(() => {
  if (!context) { setNames(NO_NAMES); return; }
  const ctl = new AbortController();
  setNames(NO_NAMES);
  getDirectory(context.org, undefined, ctl.signal).then(
   (r) => {
    if (ctl.signal.aborted) return;
    if (r.kind === 'not_built') setNames({ ...NO_NAMES, state: 'not_built' });
    else if (r.kind === 'fault') setNames({ ...NO_NAMES, state: 'unavailable' });
    else setNames({ state: 'ready', forOrg: context.org, ...(r.data.orgName ? { orgName: r.data.orgName } : {}), projects: new Map(r.data.projects.map((p) => [p.id, p.name])), members: new Map(r.data.members.flatMap((m) => (m.displayName ? [[m.id, m.displayName] as const] : []))), canSetNames: r.data.canSetNames });
   },
   () => { if (!ctl.signal.aborted) setNames({ ...NO_NAMES, state: 'unavailable' }); },
  );
  return () => ctl.abort();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key]);
 return names;
}


function Screen(props: { nav: Navigation; context: ViewContext }): React.JSX.Element {
 const { nav, context } = props;
 switch (nav.section) {
  case 'home': return <HomeRoute context={context} />;
  case 'incidents': return <IncidentsRoute context={context} nav={nav} />;
  case 'rules': return <RulesRoute context={context} />;
  case 'routing': return <RoutingRoute context={context} />;
  case 'issues': return <IssuesRoute context={context} nav={nav} />;
  case 'releases': return <ReleasesRoute context={context} nav={nav} />;
  case 'services': return <ServicesRoute key={nav.service} context={context} nav={nav} />;
  case 'jobs': return <JobsRoute context={context} nav={nav} />;
  case 'traces': return <TracesRoute context={context} nav={nav} />;
  case 'logs': return <LogsRoute context={context} />;
  case 'metrics': return <MetricsRoute context={context} />;
  case 'replays': return <ReplaysRoute context={context} nav={nav} />;
  case 'profiles': return <ProfilesRoute context={context} nav={nav} />;
  case 'dashboards': return <DashboardsRoute />;
  case 'onboarding': return <OnboardingRoute context={context} />;
  case 'settings': return <SettingsRoute context={context} nav={nav} />;
  case 'gitlab': return <GitlabRoute context={context} />;
  case 'events': return <EventsRoute context={context} />;
  case 'cutover': return <CutoverRoute context={context} />;
  case 'account': return <AccountPage />;
 }
}

/** The console: the shell and one screen per section. Scope lives in the URL hash (IDs, nanosecond strings, time zone, section) so back and forward
 * restore it; held data never outlives its scope. */
export function App(): React.JSX.Element {
 const session = React.useContext(SessionContext);
 const generation = React.useRef(0);
 const [nav, setNav] = React.useState(() => decodeHash(window.location.hash, 0));
 const csrf = session?.session.csrf ?? '';
 // Both bindings name this console instance as their owner and are released only by it: when the boundary mounts the console again (a new elevation keys
 // it anew) the new instance renders, and so binds, before the old one's cleanup runs, and the token and elevation may be the very same values.
 const owner = React.useRef<object>({}).current;
 // Bound during render (an idempotent in-memory assignment) so reads issued by child effects already carry the token.
 bindSession(csrf, owner);
 // The audited elevation (D60) rides the same way.
 bindElevation(session?.elevation ?? null, owner);
 React.useEffect(() => () => { releaseSession(owner); releaseElevation(owner); }, [owner]);
 // A revalidation that found the session still valid keeps the console mounted (view state survives) but every view reads its scope again, so access
 // that was withdrawn meanwhile (a revoked grant) clears what is shown. The first run is the mount itself.
 const epoch = session?.epoch ?? 0;
 const seenEpoch = React.useRef(epoch);
 React.useEffect(() => {
  if (seenEpoch.current === epoch) return;
  seenEpoch.current = epoch;
  generation.current += 1;
  setNav(decodeHash(window.location.hash, generation.current));
 }, [epoch]);
 React.useEffect(() => {
  const onHash = (): void => { generation.current += 1; setNav(decodeHash(window.location.hash, generation.current)); };
  window.addEventListener('hashchange', onHash);
  return () => window.removeEventListener('hashchange', onHash);
 }, []);
 const context = nav.context;
 const navigate = React.useCallback((hash: string): void => {
  if (hash === window.location.hash) { generation.current += 1; setNav(decodeHash(hash, generation.current)); } else window.location.hash = hash;
 }, []);
 const go = React.useCallback((section: SectionId, options: LinkOptions = {}): void => { navigate(linkFor(context, section, options)); }, [context, navigate]);
 const refresh = React.useCallback((): void => {
  if (!context) return;
  // A relative window slides to now; an absolute one is read again as it is.
  const slid: ViewContext = context.span ? { ...context, ...windowEndingAt(Date.now(), context.span) } : context;
  navigate(encodeHash(slid, nav.section, nav.service, nav.incident, nav.target, nav.page));
 }, [context, nav, navigate]);
 const applyScope = React.useCallback((next: Omit<ViewContext, 'generation'>): void => {
  generation.current += 1;
  navigate(encodeHash({ ...next, generation: generation.current }, nav.section));
 }, [nav.section, navigate]);
 const names = useDirectory(context);
 const section = SECTIONS.find((s) => s.id === nav.section) ?? SECTIONS[0]!;
 const scope = context ? scopeKey(context) : '';
 const entity = `${nav.incident ? `${nav.incident.project}:${nav.incident.id}` : ''}${nav.target ? `${nav.target.project}:${nav.target.id}` : ''}${nav.service}`;
 // A route change is announced by moving focus to the page's h1: when the section or the scope changes, or an entity is opened or closed.
 useFocusPageHeading(`${nav.section}|${scope}|${entity}|${nav.page}`);
 React.useEffect(() => { document.title = `${section.label} — Soundpost`; }, [section.label]);
 return (
  <Shell nav={nav} go={go} refresh={refresh} applyScope={applyScope} names={names} orgs={session?.orgs ?? []} user={session?.session.user ?? ''} busy={session?.busy ?? false} signOut={() => { void session?.action('logout'); }}>
   {nav.section === 'account' ? <AccountPage /> : context ? <Screen nav={nav} context={context} /> : <NeedScope title={section.label} />}
  </Shell>
 );
}
