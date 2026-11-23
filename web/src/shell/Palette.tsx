// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { SECTIONS, isId, type SectionId } from '../app/context';
import { hashForPath } from '../app/route';
import { Icon, type IconName } from '../ui/Icon';
import { linkFor, useShell } from './ShellContext';

const SECTION_ICON: Record<SectionId, IconName> = {
 home: 'home', incidents: 'bell', rules: 'rule', routing: 'route', issues: 'bug', releases: 'tag', services: 'box', jobs: 'job', traces: 'trace', logs: 'logs', metrics: 'chart', replays: 'replay', profiles: 'flame', dashboards: 'dash', onboarding: 'plug', settings: 'gear', gitlab: 'git', events: 'send', cutover: 'move', account: 'user',
};

export interface PaletteEntry { key: string; group: string; label: string; detail?: string; href: string; icon: IconName }

/** A pasted 32-hex ID or console link becomes "open as ..." entries for each kind of entity; nothing is looked up until one is chosen. */
const ENTITY_KINDS: readonly { section: SectionId; noun: string; param: 'incident' | 'target' | 'service' }[] = [
 { section: 'incidents', noun: 'incident', param: 'incident' }, { section: 'issues', noun: 'issue', param: 'target' }, { section: 'releases', noun: 'release', param: 'target' }, { section: 'traces', noun: 'trace', param: 'target' },
 { section: 'services', noun: 'service', param: 'service' }, { section: 'jobs', noun: 'job', param: 'target' }, { section: 'replays', noun: 'replay', param: 'target' }, { section: 'profiles', noun: 'profile', param: 'target' },
];

export function paletteEntries(query: string, link: (section: SectionId, o?: { service?: string; incident?: { project: string; id: string } | null; target?: { project: string; id: string } | null }) => string, projects: readonly string[]): PaletteEntry[] {
 const q = query.trim();
 const out: PaletteEntry[] = [];
 // A pasted console link opens as itself.
 if (/^https?:\/\//i.test(q) || q.startsWith('/')) {
  try {
   const url = new URL(q, typeof window === 'undefined' ? 'https://console.invalid' : window.location.origin);
   const hash = url.hash.startsWith('#') ? url.hash : hashForPath(url.pathname, url.search);
   if (hash) out.push({ key: 'link', group: 'Open', label: 'Open this console link', detail: url.pathname, href: hash, icon: 'link' });
  } catch { /* not a link */ }
 }
 const id = q.toLowerCase();
 if (isId(id) && projects.length > 0) {
  const project = projects[0]!;
  for (const k of ENTITY_KINDS) {
   const ref = { project, id };
   const href = k.param === 'service' ? link(k.section, { service: id }) : link(k.section, k.param === 'incident' ? { incident: ref } : { target: ref });
   out.push({ key: `id:${k.noun}`, group: 'Open by ID', label: `Open as ${k.noun === 'issue' || k.noun === 'incident' ? 'an' : 'a'} ${k.noun}`, ...(projects.length > 1 ? { detail: `in project ${project.slice(0, 8)}…` } : {}), href, icon: SECTION_ICON[k.section] });
 }
 }
 const needle = q.toLowerCase();
 for (const s of SECTIONS) {
  if (s.id === 'account' && needle === '') continue;
  if (needle === '' || s.label.toLowerCase().includes(needle)) out.push({ key: `go:${s.id}`, group: 'Go to', label: s.label, href: link(s.id), icon: SECTION_ICON[s.id] });
 }
 return out;
}

/** The search palette (Ctrl or Cmd K): jump to a screen, or paste an ID or a console link to open it. */
export function Palette(props: { open: boolean; onClose: () => void }): React.JSX.Element | null {
 const shell = useShell();
 const ref = React.useRef<HTMLDialogElement>(null);
 const [query, setQuery] = React.useState('');
 const [active, setActive] = React.useState(0);
 const { open, onClose } = props;
 React.useLayoutEffect(() => {
  const el = ref.current;
  if (!open || !el) return;
  if (!el.open) el.showModal();
  el.querySelector<HTMLElement>('input')?.focus();
  return () => { if (el.open) el.close(); };
 }, [open]);
 React.useEffect(() => { if (!open) { setQuery(''); setActive(0); } }, [open]);
 if (!open) return null;
 const entries = paletteEntries(query, (s, o) => linkFor(shell.context, s, o), shell.context?.projects ?? []);
 const choose = (e: PaletteEntry): void => { onClose(); window.location.hash = e.href; };
 const groups = [...new Set(entries.map((e) => e.group))];
 const onKey = (e: React.KeyboardEvent): void => {
  if (e.key === 'ArrowDown') { e.preventDefault(); setActive((a) => Math.min(entries.length - 1, a + 1)); }
  else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((a) => Math.max(0, a - 1)); }
  else if (e.key === 'Enter') { const pick = entries[active]; if (pick) { e.preventDefault(); choose(pick); } }
 };
 return (
  <dialog ref={ref} className="palette" aria-label="Search or jump" onCancel={(e) => { e.preventDefault(); onClose(); }} onClick={(e) => { if (e.target === ref.current) onClose(); }} data-testid="palette">
   <div className="palette-input">
    <Icon name="search" />
    <input role="combobox" aria-expanded="true" aria-controls="palette-results" aria-activedescendant={entries[active] ? `palette-${entries[active]!.key}` : undefined} aria-label="Search screens, or paste an ID or a console link" value={query} onChange={(e) => { setQuery(e.target.value); setActive(0); }} onKeyDown={onKey} autoComplete="off" spellCheck={false} />
    <span className="kbd">Esc</span>
   </div>
   <ul id="palette-results" role="listbox" aria-label="Results" className="palette-list">
    {entries.length === 0 && <li className="palette-group" role="presentation">Nothing matches. Paste a 32-character ID or a Soundpost link to open it directly.</li>}
    {groups.map((g) => (
     <React.Fragment key={g}>
      <li className="palette-group" role="presentation">{g}</li>
      {entries.filter((e) => e.group === g).map((e) => (
       <li key={e.key} role="presentation">
        <a id={`palette-${e.key}`} role="option" aria-selected={entries[active]?.key === e.key} href={e.href} onClick={(ev) => { ev.preventDefault(); choose(e); }}>
         <Icon name={e.icon} size="s" className="t3" /><span className="grow">{e.label}</span>{e.detail && <span className="t3 small">{e.detail}</span>}
        </a>
       </li>
      ))}
     </React.Fragment>
    ))}
   </ul>
   <div className="palette-foot"><span><span className="kbd">↑</span> <span className="kbd">↓</span> move</span><span><span className="kbd">↵</span> open</span><span className="ml-auto">Paste a 32-character ID or a Soundpost link to open it directly</span></div>
  </dialog>
 );
}
