// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import type { DestinationSave, Id, ManagedDestination } from '../api/types';
import { validEndpoint, type Built } from './policy';

/** The pure half of the destination settings page (POST /api/v1/destinations): drafts are text, builders turn them into the save the
 * route takes or say why not. Nothing here talks to the server, and nothing here is shown as committed. Saving a destination needs
 * organization administration (decision D30): a destination routes every project of the organization. */
export const CHANNELS: readonly { id: string; label: string }[] = [{ id: 'webhook', label: 'Webhook' }, { id: 'smtp', label: 'Email (SMTP)' }, { id: 'telegram', label: 'Telegram' }];
export const channelLabel = (id: string): string => CHANNELS.find((c) => c.id === id)?.label ?? id;

const CHAT = /^(-?[0-9]{1,20}|@[A-Za-z0-9_]{5,32})$/;
const EMAIL = /^[A-Za-z0-9.!#$%&'*+/=?^_{|}~-]{1,64}@[A-Za-z0-9.-]{1,253}$/;
export const MAX_SECRET_BYTES = 4096;

export interface NewDestinationDraft { channel: string; endpoint: string; address: string; enabled: boolean; secret: string }
export const emptyNewDestination = (): NewDestinationDraft => ({ channel: 'webhook', endpoint: '', address: '', enabled: true, secret: '' });

/** A new destination (version 0): its channel, its one target (a webhook has an https endpoint, email and Telegram have an address), enabled and an optional write-only secret. */
export function buildNewDestination(id: Id, d: NewDestinationDraft): Built<DestinationSave> {
 if (!CHANNELS.some((c) => c.id === d.channel)) return { ok: false, error: 'Choose a destination type.' };
 const endpoint = d.endpoint.trim(), address = d.address.trim();
 if (d.channel === 'webhook' && !validEndpoint(endpoint)) return { ok: false, error: 'A webhook needs an https endpoint without credentials, query or fragment. Put a token in the secret field, not in the address.' };
 if (d.channel === 'smtp' && !EMAIL.test(address)) return { ok: false, error: 'An email destination needs one recipient address such as ops@example.test.' };
 if (d.channel === 'telegram' && !CHAT.test(address)) return { ok: false, error: 'A Telegram destination needs a chat: a numeric chat ID or an @channel name.' };
 if (new TextEncoder().encode(d.secret).length > MAX_SECRET_BYTES) return { ok: false, error: 'The secret is too long.' };
 return { ok: true, value: { id, type: d.channel, enabled: d.enabled, ...(d.channel === 'webhook' ? { endpoint } : { address }), ...(d.secret !== '' ? { secret: d.secret } : {}) } };
}

/** A change to a destination the page read: only the enabled state and a new secret can change. The channel and the target stay as committed
 * (the page never held the endpoint path, so it cannot send it back). */
export function buildDestinationChange(current: ManagedDestination, enabled: boolean, secret: string): Built<DestinationSave> {
 if (enabled === current.enabled && secret === '') return { ok: false, error: 'Nothing to save: change the enabled state or enter a new secret.' };
 if (new TextEncoder().encode(secret).length > MAX_SECRET_BYTES) return { ok: false, error: 'The secret is too long.' };
 return { ok: true, value: { id: current.id, enabled, ...(secret !== '' ? { secret } : {}) } };
}

/** What the page says a destination is: its channel and the coarse target the server reports (a host or a domain, never a path or an address). */
export function destinationWords(d: ManagedDestination): string {
 const target = d.display !== '' ? ` to ${d.display}` : '';
 return `${channelLabel(d.channel)}${target}; ${d.enabled ? 'enabled' : 'disabled'}; secret ${d.has_secret ? 'set (write-only, never shown)' : 'not set'}; version ${d.version}.`;
}

/** The destination as the next list shows it once a save committed: replaces the one with the same ID, or appends it in ID order. */
export function withSaved(list: readonly ManagedDestination[], saved: ManagedDestination): ManagedDestination[] {
 const rest = list.filter((d) => d.id !== saved.id);
 return [...rest, saved].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}
