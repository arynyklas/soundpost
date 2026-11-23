// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// What the incident page derives from one IncidentView: the lineage chips, the evidence links with the incident window, the words of the
// resolve dialog. Nothing here reads anything the view does not carry: a record the view does not link is shown as not linked.
import { encodeHash, type SectionId, type ViewContext } from '../app/context';
import type { Id, IncidentLink, IncidentView } from '../api/types';
import type { IconName } from '../ui/Icon';
import { shortId, type LineageItem } from '../ui/primitives';
import { openedAt } from './timelineModel';

export interface LinkMaker { (section: SectionId, o?: { service?: Id; incident?: { project: Id; id: Id } | null; target?: { project: Id; id: Id } | null }): string }

const linksOf = (v: IncidentView, kind: IncidentLink['kind']): IncidentLink[] => v.links.filter((l) => l.kind === kind);

/** "open, not acknowledged", "acknowledged by Ravi", "resolved": the incident's response state in a few words. */
export function responseState(v: IncidentView, ownerName?: string): { label: string; tone: 'crit' | 'high' | 'warn' | 'ok' | 'info' | 'unk' } {
 if (v.status === 'resolved') return { label: v.source_firing ? 'resolved, source still firing' : 'resolved', tone: v.source_firing ? 'high' : 'ok' };
 if (v.maintenance?.active) return { label: 'in maintenance', tone: 'info' };
 if (v.snooze?.active) return { label: 'reminders snoozed', tone: 'info' };
 if (v.ack?.current) return { label: `acknowledged${ownerName ? ` by ${ownerName}` : ''}`, tone: 'info' };
 if (v.ack) return { label: 'acknowledged an earlier impact only', tone: 'high' };
 return { label: 'not acknowledged', tone: 'crit' };
}

/** Rule → Incident → Issue → Release → Service. A link the incident does not carry is shown as not linked, never dropped. */
export function lineageItems(v: IncidentView, href: LinkMaker, ackName?: string): LineageItem[] {
 const state = v.condition.state;
 const items: LineageItem[] = [
  { kind: 'Rule', name: shortId(v.condition.id), state: state === 'unknown' ? 'state unknown' : state, tone: state === 'firing' ? 'crit' : state === 'recovered' ? 'ok' : 'unk', icon: 'rule', href: href('rules') },
 ];
 const r = responseState(v, ackName);
 items.push({ kind: 'Incident', name: shortId(v.incident_id), state: r.label, tone: r.tone, icon: 'bell', current: true });
 const project = v.project_id;
 const issues = linksOf(v, 'issue');
 if (issues.length === 0) items.push({ kind: 'Issue', name: 'none linked', icon: 'bug', unavailable: true });
 for (const l of issues) items.push({ kind: 'Issue', name: shortId(l.id), icon: 'bug', href: href('issues', { target: { project, id: l.id } }) });
 const releases = linksOf(v, 'release');
 if (releases.length === 0) items.push({ kind: 'Release', name: 'none linked', icon: 'tag', unavailable: true });
 for (const l of releases) items.push({ kind: 'Release', name: shortId(l.id), icon: 'tag', href: href('releases', { target: { project, id: l.id } }) });
 const services = linksOf(v, 'service');
 if (services.length === 0) items.push({ kind: 'Service', name: 'none linked', icon: 'box', unavailable: true });
 for (const l of services) items.push({ kind: 'Service', name: shortId(l.id), icon: 'box', href: href('services', { service: l.id }) });
 return items;
}

const LEAD_NS = 15n * 60n * 1_000_000_000n;
/** The window evidence is looked at in: from 15 minutes before the incident opened until it was resolved, or until now while it is open. */
export function evidenceWindow(v: IncidentView, nowMs: number): { start: string; end: string; open: boolean } {
 const opened = BigInt(openedAt(v) ?? v.last_activity);
 const start = opened > LEAD_NS ? opened - LEAD_NS : 0n;
 const stillOpen = v.status === 'open' || v.resolved_at === undefined;
 const nowNs = BigInt(nowMs) * 1_000_000n;
 const wanted = stillOpen ? nowNs : BigInt(v.resolved_at!);
 const end = (wanted > BigInt(v.last_activity) ? wanted : BigInt(v.last_activity)) + 1n;
 return { start: String(start), end: String(end > start ? end : start + 1n), open: stillOpen };
}

export interface EvidenceLink { key: string; label: string; detail?: string; icon: IconName; href: string }
/** Where to look next, scoped to the incident's project and window. No counts: the links open the screens, which state their own figures. */
export function evidenceLinks(v: IncidentView, context: ViewContext, nowMs: number): { links: EvidenceLink[]; window: { start: string; end: string; open: boolean } } {
 const w = evidenceWindow(v, nowMs);
 const scoped: ViewContext = { org: context.org, projects: [v.project_id], environment: context.environment, start: w.start, end: w.end, timezone: context.timezone, generation: context.generation };
 const to = (section: SectionId, service = '', target: { project: Id; id: Id } | null = null): string => encodeHash(scoped, section, service, null, target);
 const links: EvidenceLink[] = [
  { key: 'traces', label: 'Traces in the incident window', icon: 'trace', href: to('traces') },
  { key: 'logs', label: 'Logs in the incident window', icon: 'logs', href: to('logs') },
  { key: 'metrics', label: 'Metrics in the incident window', icon: 'chart', href: to('metrics') },
 ];
 for (const l of linksOf(v, 'issue')) links.push({ key: `issue:${l.id}`, label: 'Linked error issue', detail: shortId(l.id), icon: 'bug', href: to('issues', '', { project: v.project_id, id: l.id }) });
 for (const l of linksOf(v, 'release')) links.push({ key: `release:${l.id}`, label: 'Linked release', detail: shortId(l.id), icon: 'tag', href: to('releases', '', { project: v.project_id, id: l.id }) });
 for (const l of linksOf(v, 'service')) links.push({ key: `service:${l.id}`, label: 'Linked service', detail: shortId(l.id), icon: 'box', href: to('services', l.id) });
 return { links, window: w };
}

export interface Consequence { icon: IconName; tone: 'ok' | 'crit' | 'high' | 'unk' | 'info'; text: string }
/** What resolving does, and what it does not do to the other entities: their lifecycles are independent. */
export function resolveConsequences(v: IncidentView): Consequence[] {
 const out: Consequence[] = [{ icon: 'check', tone: 'ok', text: 'Closes your team’s response: the incident moves to Resolved with your reason in its timeline.' }];
 out.push(v.source_firing
  ? { icon: 'fire', tone: 'crit', text: 'The alert source keeps firing. The incident shows “Resolved, source still firing” until the source recovers.' }
  : { icon: 'info', tone: 'info', text: 'The alert source has recovered. Resolving only closes the response; it never changes the source.' });
 const issues = linksOf(v, 'issue').length;
 out.push(issues > 0
  ? { icon: 'bug', tone: 'high', text: `The linked error issue${issues === 1 ? '' : 's'} keep${issues === 1 ? 's' : ''} ${issues === 1 ? 'its' : 'their'} own state. Mark ${issues === 1 ? 'it' : 'them'} fixed on ${issues === 1 ? 'its' : 'their'} own page when a release contains the fix.` }
  : { icon: 'bug', tone: 'unk', text: 'No error issue is linked to this incident, so there is no issue whose state could be affected.' });
 out.push({ icon: 'bell', tone: 'unk', text: 'If the impact gets worse, a new incident opens and links back to this one. This one is never reopened.' });
 return out;
}

export const LOST_RACE_WORDS = 'If someone else changes this incident first, nothing is applied and you see their change.';

/** Whether a failed request means "this server has no such action". Only an older server answers that way: a plain 405, an unknown action kind, or a bare 501 with no detail. Every answer of this installation
 * to a title, a note or an owner carries its own detail (a 400 `incident_title_invalid`, a 501 `needs_contracted_installation`, ...): that is a refusal of this very request and is never read as "not served". */
export function notServed(status: number, detail: string): boolean {
 return status === 405 || (status === 501 && detail === '') || (status === 400 && detail === 'action_kind_unknown');
}
