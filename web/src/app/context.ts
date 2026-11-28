// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { investigate, isAbort, stateOfFault, stateOfView } from '../api/client';
import type { Id, InvestigationKind, InvestigationRequest, InvestigationView, LoadState } from '../api/types';

/** Navigation state only. It names what the user asked to look at; it is not an
 * authorization token and the server re-derives every scope from the credential. */
export interface ViewContext {
 org: Id;
 projects: Id[];
 /** The selected environment ID, or '' for all. The server narrows service views to it; other sections ignore it and say so. */
 environment: Id | '';
 /** Half-open [start,end) nanoseconds since the epoch, canonical decimal strings. */
 start: string;
 end: string;
 timezone: string;
 /** Bumped on every navigation or refresh; a response for an older generation is dropped. */
 generation: number;
 /** Minutes of a relative window ("last hour"): Refresh slides such a window to now. Absent for an absolute window. */
 span?: number;
}
export type SectionId = 'home' | 'incidents' | 'rules' | 'routing' | 'issues' | 'releases' | 'services' | 'jobs' | 'traces' | 'logs' | 'metrics' | 'replays' | 'profiles' | 'dashboards' | 'onboarding' | 'settings' | 'gitlab' | 'events' | 'cutover' | 'account';
export interface SectionDef { id: SectionId; label: string; kind: InvestigationKind | null; /** The sidebar item that stays highlighted while this screen is open. */ owner: SectionId }
export const SECTIONS: readonly SectionDef[] = [
 { id: 'home', label: 'Home', kind: null, owner: 'home' },
 { id: 'incidents', label: 'Incidents', kind: 'incident', owner: 'incidents' },
 { id: 'rules', label: 'Alert rules', kind: null, owner: 'rules' },
 { id: 'routing', label: 'Notification routes', kind: null, owner: 'routing' },
 { id: 'issues', label: 'Issues', kind: 'issue', owner: 'issues' },
 { id: 'releases', label: 'Releases', kind: 'release', owner: 'releases' },
 { id: 'services', label: 'Services', kind: 'service', owner: 'services' },
 { id: 'jobs', label: 'Jobs', kind: 'job', owner: 'jobs' },
 { id: 'traces', label: 'Traces', kind: 'trace', owner: 'traces' },
 { id: 'logs', label: 'Logs', kind: null, owner: 'logs' },
 { id: 'metrics', label: 'Metrics', kind: null, owner: 'metrics' },
 { id: 'replays', label: 'Replays', kind: 'replay', owner: 'replays' },
 { id: 'profiles', label: 'Profiles', kind: 'profile', owner: 'profiles' },
 { id: 'dashboards', label: 'Dashboards', kind: null, owner: 'dashboards' },
 { id: 'onboarding', label: 'Add data source', kind: null, owner: 'onboarding' },
 { id: 'settings', label: 'Settings', kind: null, owner: 'settings' },
 { id: 'gitlab', label: 'GitLab', kind: null, owner: 'settings' },
 { id: 'events', label: 'Event webhooks', kind: null, owner: 'settings' },
 { id: 'cutover', label: 'Migration and cutover', kind: null, owner: 'settings' },
 { id: 'account', label: 'Account access', kind: null, owner: 'settings' },
];
/** Section names of earlier console addresses that still open: the queue is the incident list and Explore is the log explorer. */
export const SECTION_ALIASES: Readonly<Record<string, SectionId>> = { queue: 'incidents', explore: 'logs' };
export function sectionOf(name: string | null): SectionId | undefined { return SECTIONS.find((s) => s.id === name)?.id ?? (name !== null ? SECTION_ALIASES[name] : undefined); }
export const MAX_PROJECTS = 16;
export const PAGE_LIMIT = 100;
const ID = /^[0-9a-f]{32}$/;
const NS = /^(0|[1-9][0-9]{0,18})$/;
const MAX_NS = 9223372036854775807n;
export function isId(v: string): boolean { return ID.test(v); }
export function validTimezone(tz: string): boolean {
 if (tz.length === 0 || tz.length > 64) return false;
 try { new Intl.DateTimeFormat('en', { timeZone: tz }); return true; } catch { return false; }
}
export function validWindow(start: string, end: string): boolean {
 if (!NS.test(start) || !NS.test(end)) return false;
 const s = BigInt(start), e = BigInt(end);
 return s < e && e <= MAX_NS;
}
export function windowEndingAt(nowMs: number, minutes: number): { start: string; end: string } {
 const end = BigInt(nowMs) * 1_000_000n;
 const span = BigInt(minutes) * 60n * 1_000_000_000n;
 return { start: String(end > span ? end - span : 0n), end: String(end) };
}
export function formatNs(ns: string, timezone: string): string {
 const ms = Number(BigInt(ns) / 1_000_000n);
 return new Intl.DateTimeFormat('en-GB', { timeZone: timezone, dateStyle: 'medium', timeStyle: 'medium' }).format(new Date(ms));
}
/** The identity of what data may be shown: changing any part discards held data.
 * Timezone only changes presentation, so it is not part of it. */
export function scopeKey(c: ViewContext): string {
 return [c.org, c.projects.join(','), c.environment, c.start, c.end].join('|');
}

/** The URL carries only stable IDs, nanosecond strings, the timezone name and the
 * section: never telemetry text, queries or credentials. */
export function encodeHash(c: ViewContext, section: SectionId, service = '', incident: IncidentRef | null = null, target: IncidentRef | null = null, page = ''): string {
 const params = new URLSearchParams({ org: c.org, projects: c.projects.join(','), start: c.start, end: c.end, tz: c.timezone, view: section });
 if (c.environment) params.set('env', c.environment);
 if (c.span) params.set('span', String(c.span));
 if (service) params.set('service', service);
 if (incident) params.set('incident', `${incident.project}:${incident.id}`);
 if (target) params.set('target', `${target.project}:${target.id}`);
 if (page) params.set('page', page);
 return `#${params}`;
}
/** The address of a screen that needs no scope (or when none is chosen yet). */
export function bareHash(section: SectionId): string { return `#view=${section}`; }
/** A sub-page name inside a section (a settings page, for example): lowercase words only. */
const PAGE = /^[a-z][a-z0-9-]{0,31}$/;
/** One incident inside the selected projects: the project is part of its identity. */
export interface IncidentRef { project: Id; id: Id }
export interface Navigation { context: ViewContext | null; section: SectionId; service: Id | ''; incident: IncidentRef | null; /** The issue or release of the issues and releases sections. */ target: IncidentRef | null; /** A sub-page of the section ('' for its main page). */ page: string }
/** DEFAULT_LINK_MINUTES is the window a notification deep link opens with: the link names an organization, projects and one entity (IDs only), never a time, so the view opens on the last day ending now, in UTC. */
export const DEFAULT_LINK_MINUTES = 24 * 60;
export function decodeHash(hash: string, generation: number, nowMs: number = Date.now()): Navigation {
 const params = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash);
 const section = sectionOf(params.get('view')) ?? 'home';
 const service = params.get('service') ?? '';
 const rawPage = params.get('page') ?? '';
 const page = PAGE.test(rawPage) ? rawPage : '';
 const none: Navigation = { context: null, section, service: '', incident: null, target: null, page };
 const org = params.get('org') ?? '';
 let start = params.get('start') ?? '', end = params.get('end') ?? '', tz = params.get('tz') ?? '';
 if (!params.has('start') && !params.has('end') && !params.has('tz')) {
  ({ start, end } = windowEndingAt(nowMs, DEFAULT_LINK_MINUTES));
  tz = 'UTC';
 }
 const projects = (params.get('projects') ?? '').split(',').filter((p) => p !== '');
 if (!isId(org) || projects.length === 0 || projects.length > MAX_PROJECTS || !projects.every(isId) || new Set(projects).size !== projects.length) return none;
 const environment = params.get('env') ?? '';
 if (!validWindow(start, end) || !validTimezone(tz) || (service !== '' && !isId(service)) || (environment !== '' && !isId(environment))) return none;
 const refOf = (name: string): IncidentRef | null => {
  const [rproject = '', rid = ''] = (params.get(name) ?? '').split(':');
  return isId(rproject) && isId(rid) && projects.includes(rproject) ? { project: rproject, id: rid } : null;
 };
 const spanRaw = Number(params.get('span') ?? '');
 const span = Number.isInteger(spanRaw) && spanRaw > 0 && spanRaw <= 60 * 24 * 366 ? spanRaw : undefined;
 return { context: { org, projects, environment, start, end, timezone: tz, generation, ...(span ? { span } : {}) }, section, service, incident: refOf('incident'), target: refOf('target'), page };
}

export function requestFor(c: ViewContext, kind: InvestigationKind, target?: Id): InvestigationRequest {
 return { org: c.org, kind, projects: c.projects, ...(target ? { target } : {}), ...(c.environment && kind === 'service' ? { environment: c.environment } : {}), window: { start: c.start, end: c.end }, limit: PAGE_LIMIT };
}

/** Only the most recent begun read may publish. begin() aborts the previous read;
 * current() is false once a newer read began or this one was aborted, so a slow
 * response for an older scope can never reach the state of a newer one. */
export interface Latest { begin(): { signal: AbortSignal; current(): boolean }; stop(): void }
export function latestOnly(): Latest {
 let active: AbortController | null = null;
 return {
  begin() {
   active?.abort();
   const mine = new AbortController();
   active = mine;
   return { signal: mine.signal, current: () => active === mine && !mine.signal.aborted };
  },
  stop() { active?.abort(); active = null; },
 };
}

/** Loads one investigation view for the context. Data is keyed to the scope it was
 * requested for: a change of scope shows loading immediately, aborts the old read,
 * and the held state of another scope is never returned. */
export function useInvestigation(context: ViewContext, kind: InvestigationKind, target?: Id): LoadState<InvestigationView> {
 const key = `${scopeKey(context)}|${kind}|${target ?? ''}|${context.generation}`;
 const [held, setHeld] = React.useState<{ key: string; state: LoadState<InvestigationView> }>({ key: '', state: { kind: 'loading' } });
 const latest = React.useRef<Latest>(latestOnly());
 React.useEffect(() => {
  const read = latest.current.begin();
  setHeld({ key, state: { kind: 'loading' } });
  investigate(requestFor(context, kind, target), read.signal).then(
   (view) => { if (read.current()) setHeld({ key, state: stateOfView(view) }); },
   (error: unknown) => { if (read.current() && !isAbort(error)) setHeld({ key, state: stateOfFault(error) }); },
  );
  return () => latest.current.stop();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key]);
 return held.key === key ? held.state : { kind: 'loading' };
}
