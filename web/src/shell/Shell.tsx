// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { SECTIONS, type Navigation, type SectionId, type ViewContext } from '../app/context';
import { Icon, type IconName } from '../ui/Icon';
import { shortId } from '../ui/primitives';
import { useTheme } from '../ui/theme';
import { Palette } from './Palette';
import { ScopePicker, scopeSummary, type KnownOrg } from './ScopePicker';
import { ScopeDetails } from './Frames';
import { ShellProvider, linkFor, memberName, type LinkOptions, type Names, type ShellApi, type ShellCounts } from './ShellContext';

interface NavItem { id: SectionId; icon?: IconName; sub?: boolean }
const MAIN: readonly NavItem[] = [
 { id: 'home', icon: 'home' }, { id: 'incidents', icon: 'bell' }, { id: 'rules', sub: true }, { id: 'routing', sub: true },
 { id: 'issues', icon: 'bug' }, { id: 'releases', sub: true }, { id: 'services', icon: 'box' }, { id: 'jobs', icon: 'job' },
];
const EXPLORE: readonly NavItem[] = [
 { id: 'traces', icon: 'trace' }, { id: 'logs', icon: 'logs' }, { id: 'metrics', icon: 'chart' }, { id: 'replays', icon: 'replay' }, { id: 'profiles', icon: 'flame' }, { id: 'dashboards', icon: 'dash' },
];
const labelOf = (id: SectionId): string => SECTIONS.find((s) => s.id === id)?.label ?? id;

export interface ShellProps {
 nav: Navigation;
 go: (section: SectionId, options?: LinkOptions) => void;
 refresh: () => void;
 applyScope: (next: Omit<ViewContext, 'generation'>) => void;
 names: Names;
 /** The organizations the account can name (administrators); others enter IDs. */
 orgs: readonly KnownOrg[];
 user: string;
 signOut: () => void;
 busy: boolean;
 children: React.ReactNode;
}

function NavLinks(props: { items: readonly NavItem[]; current: SectionId; context: ViewContext | null; counts: ShellCounts }): React.JSX.Element {
 return (
  <ul>
   {props.items.map((item) => {
    const count = item.id === 'incidents' ? props.counts.incidents : undefined;
    return (
     <li key={item.id}>
      <a className={item.sub ? 'nav-link sub' : 'nav-link'} href={linkFor(props.context, item.id)} aria-current={props.current === item.id ? 'page' : undefined} aria-describedby={count !== undefined ? `nav-count-${item.id}` : undefined}>
       {item.icon && <Icon name={item.icon} />}{labelOf(item.id)}
       {count !== undefined && <span className={count > 0 ? 'count hot' : 'count'} aria-hidden="true">{count}</span>}
      </a>
      {count !== undefined && <span id={`nav-count-${item.id}`} className="sr-only">{count} open</span>}
     </li>
    );
   })}
  </ul>
 );
}

/** The console shell: one labelled sidebar (a drawer on narrow screens), the search palette, the scope picker and the page column. */
export function Shell(props: ShellProps): React.JSX.Element {
 const { nav } = props;
 const context = nav.context;
 const [navOpen, setNavOpen] = React.useState(false);
 const [scopeOpen, setScopeOpen] = React.useState(false);
 const [searchOpen, setSearchOpen] = React.useState(false);
 const [counts, setCounts] = React.useState<ShellCounts>({});
 const [theme, setTheme] = useTheme();
 const current = SECTIONS.find((s) => s.id === nav.section)?.owner ?? 'home';
 const scopeKeyId = context ? `${context.org}|${context.projects.join(',')}` : '';
 // The figures a page published belong to the scope it read; another scope starts without them.
 React.useEffect(() => { setCounts({}); }, [scopeKeyId]);
 React.useEffect(() => { setNavOpen(false); }, [nav.section, nav.incident, nav.target, nav.service]);
 React.useEffect(() => {
  const key = (e: KeyboardEvent): void => {
   if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setSearchOpen((v) => !v); }
   else if (e.key === 'Escape') setNavOpen(false);
  };
  document.addEventListener('keydown', key);
  return () => document.removeEventListener('keydown', key);
 }, []);
 const api = React.useMemo<ShellApi>(() => ({
  nav, context, section: nav.section,
  href: (section, options) => linkFor(context, section, options),
  go: props.go, refresh: props.refresh, applyScope: props.applyScope,
  openScope: () => setScopeOpen(true), openSearch: () => setSearchOpen(true),
  names: props.names, counts, setCounts,
 }), [nav, context, props.go, props.refresh, props.applyScope, props.names, counts]);
 const orgName = props.orgs.find((o) => o.id === context?.org)?.name ?? (props.names.forOrg === context?.org ? props.names.orgName : undefined);
 const summary = scopeSummary(context, orgName, props.names.state === 'ready' && props.names.projects.size > 0 ? props.names.projects.size : undefined);
 return (
  <ShellProvider value={api}>
   <div className="app" data-nav={navOpen ? 'open' : 'closed'}>
    <nav className="side" aria-label="Main" id="sidebar">
     <div className="brand"><span className="logo"><Icon name="pulse" size="s" /></span>Soundpost</div>
     <button type="button" className="scope-btn" aria-haspopup="dialog" onClick={() => setScopeOpen(true)} title="Change organization or projects">
      <span className="org-mark" aria-hidden="true">{summary.mark}</span>
      <span className="m"><span className="bold">{summary.title}</span><span>{summary.detail}</span></span>
      <Icon name="caret" size="xs" />
     </button>
     <button type="button" className="jump" aria-haspopup="dialog" onClick={() => setSearchOpen(true)}><Icon name="search" size="s" /><span className="grow left">Search</span><span className="kbd">Ctrl K</span></button>
     <NavLinks items={MAIN} current={current} context={context} counts={counts} />
     <div className="nav-group" id="nav-explore">Explore</div>
     <div role="group" aria-labelledby="nav-explore"><NavLinks items={EXPLORE} current={current} context={context} counts={counts} /></div>
     <span className="side-spacer" />
     <NavLinks items={[{ id: 'onboarding', icon: 'plug' }, { id: 'settings', icon: 'gear' }]} current={current} context={context} counts={counts} />
     <div className="me">
      <a className="who nav-link" href={linkFor(context, 'account')} aria-current={nav.section === 'account' ? 'page' : undefined} title="Account access"><span className="avatar avatar-3" aria-hidden="true">{props.user.slice(0, 2).toUpperCase()}</span><span className="ellipsis">{memberName(props.names, props.user) ?? `Account ${shortId(props.user)}`}</span></a>
      <button type="button" className="btn-icon" role="switch" aria-checked={theme === 'light'} aria-label={theme === 'light' ? 'Light theme' : 'Dark theme'} title={theme === 'light' ? 'Light theme: switch to dark' : 'Dark theme: switch to light'} onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')}><Icon name={theme === 'light' ? 'sun' : 'moon'} size="s" /></button>
      <button type="button" className="btn-icon" aria-label="Sign out" title="Sign out" disabled={props.busy} onClick={props.signOut}><Icon name="logout" size="s" /></button>
     </div>
    </nav>
    <button type="button" className="scrim" aria-label="Close navigation" tabIndex={-1} onClick={() => setNavOpen(false)} />
    <main className="main" id="main" data-screen={nav.section}>
     <div className="mobile-bar">
      <button type="button" className="btn-icon" aria-label="Open navigation" aria-expanded={navOpen} aria-controls="sidebar" onClick={() => setNavOpen(true)}><Icon name="menu" size="s" /></button>
      <span className="logo"><Icon name="pulse" size="s" /></span>
      <button type="button" className="btn-ghost bold" onClick={() => setScopeOpen(true)}>{summary.title} · {summary.detail}</button>
      <button type="button" className="btn-icon ml-auto" aria-label="Search" onClick={() => setSearchOpen(true)}><Icon name="search" size="s" /></button>
     </div>
     {props.children}
     <ScopeDetails />
    </main>
   </div>
   <ScopePicker open={scopeOpen} onClose={() => setScopeOpen(false)} orgs={props.orgs} />
   <Palette open={searchOpen} onClose={() => setSearchOpen(false)} />
  </ShellProvider>
 );
}
