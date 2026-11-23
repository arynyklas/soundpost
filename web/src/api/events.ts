// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Client of the event webhook routes (console API contract section 9, POST /api/v1/events/webhooks, organization administrators). Every operation is a POST
// {op, org, ...}. An installation that does not serve the route yet is the explicit `not_built` result; nothing here invents an endpoint, a delivery or a count.
import { ApiFault, type Id } from './types';
import { consolePost, isDec, isHexId, isRecord, type ConsoleResult } from './console';
import { unwrapWrite } from './consoleWrite';

const PATH = '/api/v1/events/webhooks';

/** The events an endpoint may subscribe to, with what each one says. Identifiers and links only: no title, message, note or user text is ever part of one. */
export const EVENTS: readonly { name: string; about: string }[] = [
 { name: 'incident.opened', about: 'an incident opened, with severity and service' },
 { name: 'incident.acknowledged', about: 'someone took it' },
 { name: 'incident.resolved', about: 'a person resolved it' },
 { name: 'issue.new', about: 'a new error issue appeared' },
 { name: 'issue.regressed', about: 'a resolved error came back, with the release' },
 { name: 'issue.resolved', about: 'a person resolved an error issue' },
 { name: 'issue.reopened', about: 'a person reopened an error issue (not a regression)' },
 { name: 'release.registered', about: 'a release was registered' },
];
export const EVENT_NAMES: readonly string[] = EVENTS.map((e) => e.name);

export const ENDPOINT_STATES = ['working', 'retrying', 'failing', 'pending', 'no_deliveries'] as const;
export type EndpointState = (typeof ENDPOINT_STATES)[number];

export interface DeliveryView { id?: string; event: string; entity?: string; phase: string; attempts: number | null; uncertain: boolean; /** Present only when the receiver may already have it and may get it again: deduplicate by delivery ID. */ possibleDuplicate?: true; code?: string; /** The closed code of the last attempt that did not settle it. */ lastCode?: string; at?: string }
export interface EndpointView {
 id: Id; name: string; host: string; events: string[]; enabled: boolean; hasSecret: boolean; version: string;
 secretRotatedAt?: string; previousSecretUntil?: string; state: EndpointState; lastDelivery?: DeliveryView;
}
export interface EndpointList { endpoints: EndpointView[]; events: string[] }

const invalid = (): never => { throw new ApiFault(200, 'invalid_response', '', 'response does not match the request'); };
const text = (v: unknown, max: number): string => (typeof v === 'string' && v.length <= max ? v : invalid());
const optText = (v: unknown, max: number): string | undefined => (typeof v === 'string' && v !== '' && v.length <= max ? v : undefined);

export function parseDelivery(raw: unknown): DeliveryView {
 if (!isRecord(raw) || typeof raw.event !== 'string' || typeof raw.phase !== 'string') return invalid();
 const attempts = typeof raw.attempts === 'number' && Number.isInteger(raw.attempts) && raw.attempts >= 0 ? raw.attempts : isDec(raw.attempts) ? Number(raw.attempts) : null;
 const id = optText(raw.id ?? raw.delivery_id, 128), entity = optText(raw.entity ?? raw.entity_id, 128), code = optText(raw.code ?? raw.closed_code, 64), lastCode = optText(raw.last_code, 64);
 const at = isDec(raw.at) ? raw.at : isDec(raw.at_ns) ? raw.at_ns : isDec(raw.last_at) ? raw.last_at : undefined;
 return { ...(id ? { id } : {}), event: text(raw.event, 64), ...(entity ? { entity } : {}), phase: text(raw.phase, 64), attempts, uncertain: raw.uncertain === true, ...(raw.possible_duplicate === true ? { possibleDuplicate: true as const } : {}), ...(code ? { code } : {}), ...(lastCode ? { lastCode } : {}), ...(at ? { at } : {}) };
}

export function parseEndpoint(raw: unknown): EndpointView {
 if (!isRecord(raw) || !isHexId(raw.id) || typeof raw.name !== 'string' || typeof raw.host !== 'string' || !Array.isArray(raw.events) || typeof raw.enabled !== 'boolean' || typeof raw.has_secret !== 'boolean' || !isDec(raw.version)) return invalid();
 const state = (ENDPOINT_STATES as readonly unknown[]).includes(raw.state) ? raw.state as EndpointState : invalid();
 const events = raw.events.map((e): string => text(e, 64));
 const rotated = isDec(raw.secret_rotated_at) ? raw.secret_rotated_at : undefined, previous = isDec(raw.previous_secret_until) ? raw.previous_secret_until : undefined;
 return {
  id: raw.id, name: text(raw.name, 256), host: text(raw.host, 256), events, enabled: raw.enabled, hasSecret: raw.has_secret, version: raw.version, state,
  ...(rotated ? { secretRotatedAt: rotated } : {}), ...(previous ? { previousSecretUntil: previous } : {}), ...(raw.last_delivery ? { lastDelivery: parseDelivery(raw.last_delivery) } : {}),
 };
}

/** The endpoints and the event names the installation offers. The secret of an endpoint is never part of an answer, so none is held here. */
export function parseEndpointList(raw: unknown): EndpointList {
 if (!isRecord(raw) || !Array.isArray(raw.endpoints)) return invalid();
 const events = Array.isArray(raw.events) ? raw.events.map((e): string => text(e, 64)) : [...EVENT_NAMES];
 return { endpoints: raw.endpoints.map(parseEndpoint).sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id)), events };
}
export function parseDeliveries(raw: unknown): DeliveryView[] {
 if (!isRecord(raw) || !Array.isArray(raw.deliveries)) return invalid();
 return raw.deliveries.map(parseDelivery);
}

export function listEndpoints(org: Id, signal: AbortSignal): Promise<ConsoleResult<EndpointList>> {
 return consolePost(PATH, { op: 'list', org }, signal, parseEndpointList);
}
export function listDeliveries(org: Id, endpoint: Id, signal: AbortSignal): Promise<ConsoleResult<DeliveryView[]>> {
 return consolePost(PATH, { op: 'deliveries', org, endpoint, limit: 20 }, signal, parseDeliveries);
}

export interface EndpointSave { id: Id; name: string; /** Omitted on a change: the stored address is kept (the page only ever holds its host). */ url?: string; events: string[]; enabled: boolean; secret?: string }
export interface EndpointSaveRequest { org: Id; commandId: Id; expectedVersion: string; reason: string; endpoint: EndpointSave }

const committed = (raw: unknown): EndpointView | null => {
 if (!isRecord(raw) || (raw.state !== 'committed' && !isRecord(raw.endpoint))) return invalid();
 return isRecord(raw.endpoint) ? parseEndpoint(raw.endpoint) : null;
};

/** One audited save of one endpoint, based on the version the page read (0 = it must not exist). `secret` is write-only: sending one on an existing endpoint rotates it. */
export async function saveEndpoint(req: EndpointSaveRequest, signal: AbortSignal): Promise<EndpointView | null> {
 const body = { op: 'save', org: req.org, command_id: req.commandId, expected_version: req.expectedVersion, reason: req.reason, endpoint: req.endpoint };
 return unwrapWrite(await consolePost(PATH, body, signal, (raw) => { const saved = committed(raw); if (saved !== null && saved.id !== req.endpoint.id) return invalid(); return saved; }));
}
/** Requests one `test.ping` delivery to the endpoint: the answer is `{state: "requested", endpoint, project}`, and the leader's next worker pass (about 5 s) creates the delivery. Nothing is claimed about the receiver: the delivery list shows what happened to it. */
export async function testEndpoint(req: { org: Id; endpoint: Id; commandId: Id }, signal: AbortSignal): Promise<void> {
 unwrapWrite(await consolePost(PATH, { op: 'test', org: req.org, endpoint: req.endpoint, command_id: req.commandId }, signal, (raw) => { if (!isRecord(raw) || raw.state !== 'requested' || raw.endpoint !== req.endpoint) return invalid(); return true; }));
}
