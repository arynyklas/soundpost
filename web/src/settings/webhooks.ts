// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { EVENT_NAMES, type DeliveryView, type EndpointSave, type EndpointState, type EndpointView } from '../api/events';
import type { Id } from '../api/types';
import { validEndpoint, type Built } from './policy';

/** The pure half of the event webhook screen: drafts are text, builders turn them into the save the route takes or say why not, and every state is a sentence. */
export const MIN_SECRET_BYTES = 16;
export const MAX_SECRET_BYTES = 256;
export const MAX_NAME_CHARS = 64;

export interface EndpointDraft { name: string; url: string; events: string[]; enabled: boolean; secret: string }
export const emptyEndpointDraft = (): EndpointDraft => ({ name: '', url: '', events: [], enabled: true, secret: '' });
export const endpointDraftOf = (e: EndpointView): EndpointDraft => ({ name: e.name, url: '', events: [...e.events], enabled: e.enabled, secret: '' });

const bytes = (s: string): number => new TextEncoder().encode(s).length;

/** A new endpoint needs an https address and a secret; a change keeps the stored address and secret unless new ones are typed. A new secret on an existing endpoint rotates it. */
export function buildEndpointSave(id: Id, d: EndpointDraft, existing: EndpointView | undefined): Built<EndpointSave> {
 const name = d.name.trim();
 if (name === '' || name.length > MAX_NAME_CHARS) return { ok: false, error: `A name of 1 to ${MAX_NAME_CHARS} characters is required.` };
 const url = d.url.trim();
 if (url === '' ? existing === undefined : !validEndpoint(url)) return { ok: false, error: 'An endpoint needs an https address without credentials, query or fragment. Put a token in the secret, not in the address.' };
 const events = EVENT_NAMES.filter((n) => d.events.includes(n));
 if (events.length === 0) return { ok: false, error: 'Choose at least one event: an endpoint with none is never called.' };
 if (d.secret === '') {
  if (existing === undefined || !existing.hasSecret) return { ok: false, error: 'A new endpoint needs a secret: every request is signed with it.' };
 } else if (bytes(d.secret) < MIN_SECRET_BYTES || bytes(d.secret) > MAX_SECRET_BYTES) {
  return { ok: false, error: `The secret is ${MIN_SECRET_BYTES} to ${MAX_SECRET_BYTES} bytes.` };
 }
 if (existing !== undefined && url === '' && d.secret === '' && name === existing.name && d.enabled === existing.enabled && [...events].sort().join('\n') === [...existing.events].sort().join('\n')) {
  return { ok: false, error: 'Nothing to save: change the name, the events, the enabled state, the address or the secret.' };
 }
 return { ok: true, value: { id, name, ...(url !== '' ? { url } : {}), events, enabled: d.enabled, ...(d.secret !== '' ? { secret: d.secret } : {}) } };
}

export interface StateWords { label: string; tone: 'ok' | 'high' | 'crit' | 'line'; text: string }
/** The state of an endpoint in words. A paused endpoint is paused whatever its last delivery did, and an endpoint that never received a delivery has no state to report. */
export function endpointWords(e: Pick<EndpointView, 'enabled' | 'state'>): StateWords {
 if (!e.enabled) return { label: 'Paused', tone: 'line', text: 'Paused: no event is sent to it.' };
 const by: Record<EndpointState, StateWords> = {
  working: { label: 'Working', tone: 'ok', text: 'Its last deliveries were accepted.' },
  retrying: { label: 'Retrying', tone: 'high', text: 'A delivery failed and is being retried (12 attempts within 24 hours).' },
  failing: { label: 'Failing', tone: 'crit', text: 'Deliveries keep failing: the receiver does not accept them.' },
  pending: { label: 'Pending', tone: 'line', text: 'Deliveries exist but none was attempted yet, so its health is not known.' },
  no_deliveries: { label: 'No deliveries yet', tone: 'line', text: 'Nothing was sent to it yet, so its health is not known.' },
 };
 return by[e.state];
}

const PHASES: Record<string, { label: string; tone: 'ok' | 'high' | 'crit' | 'line' }> = {
 accepted: { label: 'Accepted', tone: 'ok' }, complete: { label: 'Accepted', tone: 'ok' }, delivered: { label: 'Accepted', tone: 'ok' },
 pending: { label: 'Waiting', tone: 'line' }, queued: { label: 'Waiting', tone: 'line' }, claimed: { label: 'In flight', tone: 'line' },
 retry: { label: 'Retrying', tone: 'high' }, retrying: { label: 'Retrying', tone: 'high' }, lapsed: { label: 'Lapsed', tone: 'high' },
 failed: { label: 'Failed', tone: 'crit' }, refused: { label: 'Refused', tone: 'crit' }, expired: { label: 'Gave up', tone: 'crit' }, cancelled: { label: 'Cancelled', tone: 'line' }, suppressed: { label: 'Suppressed', tone: 'line' },
};
/** A delivery's phase in words. An uncertain delivery is told as such, never as accepted: the receiver may have it and may get it again. An unknown phase is shown as it came, never guessed. */
export function deliveryWords(d: Pick<DeliveryView, 'phase' | 'uncertain'>): { label: string; tone: 'ok' | 'high' | 'crit' | 'line' | 'unk'; text: string } {
 if (d.uncertain || d.phase === 'uncertain') return { label: 'Uncertain', tone: 'unk', text: 'The outcome is not known: the receiver may have received it and may receive it again. Deduplicate by delivery ID.' };
 const p = PHASES[d.phase];
 return p ? { ...p, text: '' } : { label: d.phase.replace(/_/g, ' '), tone: 'line', text: '' };
}

/** The secret rotation of an endpoint: two signatures are sent while the previous secret is still valid. */
export function rotationWords(e: Pick<EndpointView, 'secretRotatedAt' | 'previousSecretUntil'>, format: (ns: string) => string): string {
 if (e.previousSecretUntil !== undefined) return `The secret was rotated${e.secretRotatedAt !== undefined ? ` at ${format(e.secretRotatedAt)}` : ''}. Until ${format(e.previousSecretUntil)} every request carries two signatures, one per secret; then only the new one.`;
 if (e.secretRotatedAt !== undefined) return `The secret was last rotated at ${format(e.secretRotatedAt)}; the previous secret is no longer used.`;
 return 'The secret was never rotated.';
}
