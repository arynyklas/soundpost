// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// The incident timeline: the real TimelineEntry list (source observations, people's actions and notes) plus the deliveries the notification
// outbox holds, in one newest-first list with lanes. Nothing is invented: a lane with nothing in it simply has a count of 0.
import { parseGitlabLink } from '../api/console';
import type { DeliveryEntryView, IncidentView, TimelineEntry } from '../api/types';
import type { IconName } from '../ui/Icon';
import { shortId } from '../ui/primitives';
import { deliveryEntryText } from './model';

export type Lane = 'person' | 'alert' | 'error' | 'deploy' | 'notification';
export type LaneFilter = 'all' | Lane;
export const LANE_FILTERS: readonly { value: LaneFilter; label: string }[] = [
 { value: 'all', label: 'Everything' }, { value: 'person', label: 'People' }, { value: 'alert', label: 'Alert' }, { value: 'error', label: 'Errors' }, { value: 'deploy', label: 'Deploys' }, { value: 'notification', label: 'Notifications' },
];

export type ItemTone = 'crit' | 'ok' | 'acc' | 'high' | 'dep' | 'sys';
export interface TimelineItem {
 key: string;
 /** Nanoseconds. */
 at: string;
 lane: Lane;
 /** The entry type (`ack`, `note`, `open` ...), or `delivery`. */
 type: string;
 /** The incident revision this entry created; deliveries have none. */
 version?: string;
 /** The person (or system principal) who acted. Source observations and deliveries have no actor. */
 actor?: string;
 system: boolean;
 /** A sentence that follows the actor's name. For a source observation or a delivery it is the whole sentence. */
 text: string;
 /** A person the sentence is about (the new owner). */
 owner?: string;
 /** Text a person wrote (a note or a reason). Shown as plain text, never as markup. */
 quote?: string;
 /** The lane word shown on the entry: `Note` for a note, else the lane. */
 tag: string;
 icon: IconName;
 tone: ItemTone;
}

const SEVERITY_WORDS = (e: TimelineEntry): string => (e.impact ? `severity ${e.impact.severity}, source ${e.impact.state}, ${e.impact.freshness} data` : '');

function laneOf(e: TimelineEntry): Lane {
 if (e.type === 'open' || e.type === 'impact') return 'alert';
 if (e.type === 'link' && e.link?.kind === 'issue') return 'error';
 if (e.type === 'link' && e.link?.kind === 'release') return 'deploy';
 return 'person';
}

function textOf(e: TimelineEntry, fmt: (ns: string) => string): { text: string; icon: IconName; tone: ItemTone; owner?: string } {
 switch (e.type) {
  case 'open': return { text: e.impact ? `Alert source reported the incident opening (${SEVERITY_WORDS(e)})` : 'Alert source reported the incident opening', icon: 'fire', tone: 'crit' };
  case 'impact': return { text: `Source impact observation: ${SEVERITY_WORDS(e) || 'no detail'}`, icon: 'fire', tone: 'crit' };
  case 'assign': return e.owner !== undefined ? { text: 'assigned', owner: e.owner, icon: 'user', tone: 'acc' } : { text: 'removed the owner', icon: 'user', tone: 'acc' };
  case 'ack': return { text: 'acknowledged', icon: 'check', tone: 'acc' };
  case 'resolve': return { text: 'resolved the incident', icon: 'check', tone: 'ok' };
  case 'link': return { text: `linked ${e.link?.kind ?? 'evidence'} ${e.link ? shortId(e.link.id) : ''}`.trim(), icon: e.link?.kind === 'issue' ? 'bug' : e.link?.kind === 'release' ? 'tag' : 'link', tone: e.link?.kind === 'issue' ? 'high' : e.link?.kind === 'release' ? 'dep' : 'acc' };
  case 'snooze': return { text: e.until !== undefined ? `snoozed reminders until ${fmt(e.until)}` : 'snoozed reminders', icon: 'snooze', tone: 'acc' };
  case 'unsnooze': return { text: 'ended the snooze', icon: 'snooze', tone: 'acc' };
  case 'maintenance': return { text: e.until !== undefined ? `started maintenance until ${fmt(e.until)}` : 'started maintenance', icon: 'wrench', tone: 'acc' };
  case 'maintenance_end': return { text: 'ended maintenance', icon: 'wrench', tone: 'acc' };
  case 'title': return { text: e.title ? `set the title to “${e.title}”` : 'set the title', icon: 'edit', tone: 'acc' };
  case 'note': return { text: 'added a note', icon: 'note', tone: 'acc' };
  case 'external_begin': return { text: 'started creating a GitLab issue', icon: 'git', tone: 'acc' };
  case 'external_end': case 'external_adopt': case 'external_link': {
   const link = (() => { const x = (e as unknown as Record<string, unknown>).external as Record<string, unknown> | undefined; return x && x.result === 'linked' ? parseGitlabLink({ url: x.url, gitlab_project: x.project, iid: x.iid }) : undefined; })() ?? parseGitlabLink((e as unknown as Record<string, unknown>).external_link) ?? parseGitlabLink(e);
   return { text: link ? `linked GitLab issue ${link.gitlab_project}#${link.iid}` : 'recorded the outcome of creating a GitLab issue', icon: 'git', tone: 'acc' };
  }
  default: return { text: 'recorded an action', icon: 'info' as IconName, tone: 'sys' };
 }
}

function deliveryItem(d: DeliveryEntryView, fmt: (ns: string) => string): TimelineItem {
 const bad = d.status === 'failed' || d.status === 'uncertain';
 return { key: `delivery:${d.id}`, at: d.last_at ?? d.eligible_at, lane: 'notification', type: 'delivery', system: true, text: deliveryEntryText(d, fmt), tag: 'Notification', icon: 'send', tone: bad ? 'high' : 'sys' };
}

const newestFirst = (a: TimelineItem, b: TimelineItem): number => {
 const d = BigInt(b.at) - BigInt(a.at);
 if (d !== 0n) return d > 0n ? 1 : -1;
 const v = Number(BigInt(b.version ?? '0') - BigInt(a.version ?? '0'));
 return v !== 0 ? v : a.key < b.key ? -1 : 1;
};

/** Every timeline entry and every delivery, newest first. */
export function buildTimeline(view: IncidentView, fmt: (ns: string) => string): TimelineItem[] {
 const items: TimelineItem[] = (view.timeline ?? []).map((e) => {
  const t = textOf(e, fmt);
  const lane = laneOf(e);
  const quote = e.type === 'note' ? e.note : e.reason;
  return {
   key: `v${e.version}`, at: e.at, lane, type: e.type, version: e.version, system: e.origin === 'system', ...(lane === 'alert' ? {} : { actor: e.actor }),
   text: t.text, ...(t.owner !== undefined ? { owner: t.owner } : {}), ...(quote ? { quote } : {}), tag: e.type === 'note' ? 'Note' : { person: 'Person', alert: 'Alert', error: 'Error', deploy: 'Deploy', notification: 'Notification' }[lane], icon: t.icon, tone: t.tone,
  };
 });
 const deliveries = view.notification.delivery.state === 'ready' ? (view.notification.delivery.entries ?? []) : [];
 return [...items, ...deliveries.map((d) => deliveryItem(d, fmt))].sort(newestFirst);
}

export function filterTimeline(items: readonly TimelineItem[], lane: LaneFilter): TimelineItem[] { return lane === 'all' ? [...items] : items.filter((i) => i.lane === lane); }
export function laneCounts(items: readonly TimelineItem[]): Record<LaneFilter, number> {
 const out: Record<LaneFilter, number> = { all: items.length, person: 0, alert: 0, error: 0, deploy: 0, notification: 0 };
 for (const i of items) out[i.lane]++;
 return out;
}

/** When the incident opened: its first timeline entry (the source reporting it), or undefined when the view carries no timeline. */
export function openedAt(view: IncidentView): string | undefined { return view.timeline?.[0]?.at; }
