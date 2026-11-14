// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import type { ActionPayload, ActionRequest, ConditionFreshness, ConditionState, Id, IncidentActionKind, IncidentView, LinkKind, Severity, TimelineEntry } from '../api/types';

export const ACTION_LABEL: Record<IncidentActionKind, string> = {
 assign: 'Assign owner', ack: 'Acknowledge', resolve: 'Resolve', link: 'Link evidence', impact: 'Report impact',
 snooze: 'Snooze reminders', unsnooze: 'End snooze', maintenance: 'Start maintenance', maintenance_end: 'End maintenance',
};
export const DURATIONS: readonly { minutes: number; label: string }[] = [
 { minutes: 15, label: '15 minutes' }, { minutes: 60, label: '1 hour' }, { minutes: 240, label: '4 hours' }, { minutes: 1440, label: '24 hours' }, { minutes: 10080, label: '7 days (maximum)' },
];
export const LINK_KINDS: readonly LinkKind[] = ['condition', 'issue', 'release', 'service', 'incident'];
export const SEVERITIES: readonly Severity[] = ['minor', 'major', 'critical'];
export const CONDITION_STATES: readonly ConditionState[] = ['firing', 'recovered', 'unknown'];
export const FRESHNESS: readonly ConditionFreshness[] = ['fresh', 'stale', 'unknown'];
const MAX_REASON_BYTES = 512;

/** The actions an incident can take in its current state. The server still decides: this only
 * avoids offering what C08 would refuse (a resolved incident accepts nothing; a window can only
 * be ended while active and only started while inactive). */
export function availableActions(view: IncidentView): IncidentActionKind[] {
 if (view.status !== 'open') return [];
 const out: IncidentActionKind[] = ['assign'];
 if (!(view.ack && view.ack.current)) out.push('ack');
 out.push('resolve', 'link', 'impact');
 out.push(view.snooze?.active ? 'unsnooze' : 'snooze');
 out.push(view.maintenance?.active ? 'maintenance_end' : 'maintenance');
 return out;
}

export function reasonRequired(kind: IncidentActionKind): boolean { return kind === 'resolve' || kind === 'snooze' || kind === 'unsnooze' || kind === 'maintenance' || kind === 'maintenance_end'; }

export interface Draft {
 kind: IncidentActionKind;
 reason: string;
 owner: string;
 linkKind: LinkKind;
 linkId: string;
 severity: Severity;
 state: ConditionState;
 freshness: ConditionFreshness;
 minutes: number;
}
export function emptyDraft(kind: IncidentActionKind): Draft {
 return { kind, reason: '', owner: '', linkKind: 'issue', linkId: '', severity: 'major', state: 'firing', freshness: 'fresh', minutes: 60 };
}

/** A fresh random 128-bit command ID (32 lowercase hexadecimal characters). */
export function newCommandId(): Id {
 const bytes = new Uint8Array(16);
 crypto.getRandomValues(bytes);
 return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

const ID = /^[0-9a-f]{32}$/;
export function validReason(reason: string): boolean {
 return new TextEncoder().encode(reason).length <= MAX_REASON_BYTES && !/\p{Cc}/u.test(reason);
}

export type Built = { ok: true; request: ActionRequest } | { ok: false; error: string };
/** Builds the wire request for a draft against the incident revision the user is looking at.
 * Nothing here is committed or shown as committed: it only prepares the request. */
export function buildRequest(view: IncidentView, draft: Draft, commandId: Id, nowMs: number): Built {
 const reason = draft.reason.trim();
 if (!validReason(reason)) return { ok: false, error: 'The reason may be at most 512 bytes and must not contain control characters.' };
 if (reasonRequired(draft.kind) && reason === '') return { ok: false, error: 'A reason is required for this action.' };
 const payload: ActionPayload = reason ? { reason } : {};
 switch (draft.kind) {
  case 'assign': {
   const owner = draft.owner.trim();
   if (owner !== '') {
    if (!ID.test(owner)) return { ok: false, error: 'The owner must be a user ID of 32 lowercase hexadecimal characters, or empty to unassign.' };
    payload.owner = owner;
   } else if (!view.owner) return { ok: false, error: 'The incident has no owner to remove. Enter a user ID to assign one.' };
   break;
  }
  case 'snooze': case 'maintenance': {
   if (!DURATIONS.some((d) => d.minutes === draft.minutes)) return { ok: false, error: 'Choose one of the listed durations.' };
   payload.until = String((BigInt(nowMs) + BigInt(draft.minutes) * 60_000n) * 1_000_000n);
   break;
  }
  case 'impact':
   if (draft.state === 'recovered' && draft.freshness !== 'fresh') return { ok: false, error: 'Recovery can only be reported from fresh data. Missing or stale data is unknown, not recovered.' };
   payload.impact = { condition: view.condition.id, episode: view.episode_id, severity: draft.severity, state: draft.state, freshness: draft.freshness };
   break;
  case 'link': {
   const id = draft.linkId.trim();
   if (!ID.test(id)) return { ok: false, error: 'The linked ID must be 32 lowercase hexadecimal characters.' };
   payload.link = { kind: draft.linkKind, id };
   break;
  }
  default:
 }
 return { ok: true, request: { org: view.org, command_id: commandId, expected_version: view.version, project_id: view.project_id, target_id: view.incident_id, entity_kind: 'incident', kind: draft.kind, payload } };
}

const FAULT_TEXT: Record<string, string> = {
 incident_reason_invalid: 'A reason is required for this action (at most 512 bytes, no control characters).',
 incident_resolved: 'This incident is already resolved. A resolved incident accepts no further actions.',
 incident_already_acknowledged: 'The current impact is already acknowledged.',
 incident_owner_unchanged: 'That owner is already assigned.',
 incident_owner_unknown: 'That user is not a member of this organization.',
 incident_owner_invalid: 'The owner ID is not valid.',
 incident_snooze_active: 'A snooze is already active.',
 incident_no_active_snooze: 'There is no active snooze to end.',
 incident_maintenance_active: 'A maintenance window is already active.',
 incident_no_active_maintenance: 'There is no active maintenance window to end.',
 incident_window_invalid: 'The window must end in the future and at most 7 days from now.',
 incident_link_exists: 'That evidence is already linked.',
 incident_links_full: 'The incident already has the maximum number of links.',
 incident_timeline_full: 'The incident timeline is full and accepts no further actions.',
 incident_command_reused: 'This command ID was already used for a different request. Nothing was applied.',
 incident_condition_mismatch: 'That impact names a different condition than this incident is linked to.',
 incident_action_invalid: 'The server rejected the action as invalid.',
 action_payload_invalid: 'The server rejected the action fields as invalid.',
};
export function faultText(detail: string, status: number): string {
 if (status === 401) return 'Your session has ended. Sign in again; nothing was applied.';
 if (status === 403 || status === 404) return 'This incident was not found or is not available to this account. Nothing was applied.';
 if (status === 429) return 'Too many requests. Wait and retry; nothing was applied.';
 return FAULT_TEXT[detail] ?? 'The server refused this action. Nothing was applied.';
}

/** The honest rate of an incident's source. No denominator is recorded anywhere in an incident,
 * so a rate is never computed: an unknown rate is shown as unknown (never 0%) next to what was
 * observed and how fresh it is. */
export function rateText(view: IncidentView, timezoneFormat: (ns: string) => string): string {
 const n = view.observed_impacts;
 return `Rate unknown: no denominator is recorded for this condition. Observed ${n} impact observation${n === 1 ? '' : 's'}; the condition was last observed ${timezoneFormat(view.condition.observed_at)} with ${view.condition.freshness} data.`;
}

/** Spells the response state in words. Source state is reported separately and never changed by it. */
export function responseWords(view: IncidentView): string[] {
 const out: string[] = [];
 out.push(view.status === 'resolved' ? 'Resolved by a person' : 'Open');
 out.push(view.owner ? `Owner ${view.owner}` : 'Unassigned');
 if (view.ack) out.push(view.ack.current ? 'Acknowledged for the current impact' : 'Acknowledged an earlier impact only; the impact has worsened since');
 if (view.snooze?.active) out.push('Reminders snoozed');
 if (view.maintenance?.active) out.push('In maintenance');
 return out;
}
export function sourceWords(view: IncidentView): string {
 return `Source ${view.condition.state}, ${view.condition.freshness} data`;
}

/** Timeline split by the three separate concerns: only an open or impact entry is the source's;
 * every other entry is a person's incident-response action. */
export function splitTimeline(timeline: TimelineEntry[]): { condition: TimelineEntry[]; response: TimelineEntry[] } {
 return { condition: timeline.filter((e) => e.type === 'open' || e.type === 'impact'), response: timeline.filter((e) => e.type !== 'open' && e.type !== 'impact') };
}

/** Milliseconds until the first active window ends, or null when none is active. */
export function msUntilExpiry(view: IncidentView, nowMs: number): number | null {
 const ends = [view.snooze, view.maintenance].filter((w) => w?.active).map((w) => Number(BigInt(w!.until) / 1_000_000n) - nowMs);
 if (ends.length === 0) return null;
 return Math.max(0, Math.min(...ends));
}

const REASONS: Record<string, string> = {
 issue_control_handler_not_built: 'Issue actions are not available: the issue service has no control handler in this installation yet. Nothing was changed.',
 notification_outbox_not_built: 'Delivery attempts are not available: the durable notification outbox is not built yet. No delivery is claimed, whether sent, failed or uncertain.',
 digest_policy_not_built: 'Digest state is not available: the digest policy is not built yet. Entries are shown immediately, not held for a digest.',
 urgency_policy_not_built: 'Urgency is not available: the canonical urgency policy is not built yet. The order below is by status, then impact severity, then recent activity.',
 unread_change_tracking_not_built: 'Unread changes are not available: change tracking is not built yet. Nothing is marked read or unread.',
 lifecycle_operation_store_not_wired: 'Operation progress is not available: the lifecycle operation store is not wired in this installation.',
 sections_not_available: 'Some parts of this view are not available yet; the parts shown are real.',
};
/** Plain-language text for a closed reason code; an unknown code is never shown raw. */
export function describeReason(reason: string): string { return REASONS[reason] ?? 'Not available.'; }
