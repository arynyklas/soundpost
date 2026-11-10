// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { investigate, isAbort, stateOfFault, stateOfView } from '../api/client';
import type { Id, InvestigationKind, InvestigationRequest, InvestigationView, LoadState } from '../api/types';

/** Navigation state only. It names what the user asked to look at; it is not an
 * authorization token and the server re-derives every scope from the credential. */
export interface ViewContext {
 org: Id;
 projects: Id[];
 /** No environment filter exists on the server yet, so this is always ''. */
 environment: Id | '';
 /** Half-open [start,end) nanoseconds since the epoch, canonical decimal strings. */
 start: string;
 end: string;
 timezone: string;
 /** Bumped on every navigation or refresh; a response for an older generation is dropped. */
 generation: number;
}
export type SectionId = 'queue' | 'incidents' | 'issues' | 'explore' | 'services' | 'jobs' | 'replays' | 'profiles' | 'settings';
export const SECTIONS: readonly { id: SectionId; label: string; kind: InvestigationKind | null }[] = [
 { id: 'queue', label: 'Queue', kind: 'queue' },
 { id: 'incidents', label: 'Incidents', kind: 'incident' },
 { id: 'issues', label: 'Issues', kind: 'issue' },
 { id: 'explore', label: 'Explore', kind: null },
 { id: 'services', label: 'Services', kind: 'service' },
 { id: 'jobs', label: 'Jobs', kind: 'job' },
 { id: 'replays', label: 'Replays', kind: 'replay' },
 { id: 'profiles', label: 'Profiles', kind: 'profile' },
 { id: 'settings', label: 'Project settings', kind: null },
];
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
 return [c.org, c.projects.join(','), c.start, c.end].join('|');
}

/** The URL carries only stable IDs, nanosecond strings, the timezone name and the
 * section: never telemetry text, queries or credentials. */
export function encodeHash(c: ViewContext, section: SectionId, service = '', incident: IncidentRef | null = null): string {
 const params = new URLSearchParams({ org: c.org, projects: c.projects.join(','), start: c.start, end: c.end, tz: c.timezone, view: section });
 if (service) params.set('service', service);
 if (incident) params.set('incident', `${incident.project}:${incident.id}`);
 return `#${params}`;
}
/** One incident inside the selected projects: the project is part of its identity. */
export interface IncidentRef { project: Id; id: Id }
export interface Navigation { context: ViewContext | null; section: SectionId; service: Id | ''; incident: IncidentRef | null }
export function decodeHash(hash: string, generation: number): Navigation {
 const params = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash);
 const section = SECTIONS.find((s) => s.id === params.get('view'))?.id ?? 'queue';
 const service = params.get('service') ?? '';
 const none: Navigation = { context: null, section, service: '', incident: null };
 const org = params.get('org') ?? '', start = params.get('start') ?? '', end = params.get('end') ?? '', tz = params.get('tz') ?? '';
 const projects = (params.get('projects') ?? '').split(',').filter((p) => p !== '');
 if (!isId(org) || projects.length === 0 || projects.length > MAX_PROJECTS || !projects.every(isId) || new Set(projects).size !== projects.length) return none;
 if (!validWindow(start, end) || !validTimezone(tz) || (service !== '' && !isId(service))) return none;
 const [iproject = '', iid = ''] = (params.get('incident') ?? '').split(':');
 const incident = isId(iproject) && isId(iid) && projects.includes(iproject) ? { project: iproject, id: iid } : null;
 return { context: { org, projects, environment: '', start, end, timezone: tz, generation }, section, service, incident };
}

export function requestFor(c: ViewContext, kind: InvestigationKind, target?: Id): InvestigationRequest {
 return { org: c.org, kind, projects: c.projects, ...(target ? { target } : {}), window: { start: c.start, end: c.end }, limit: PAGE_LIMIT };
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
