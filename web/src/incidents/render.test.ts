// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Components are rendered to static markup: what a person reads, in words, and that text a person wrote reaches the page only as text.
import { describe, expect, test } from 'bun:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { IncidentView, TimelineEntry } from '../api/types';
import type { ViewContext } from '../app/context';
import { NO_NAMES } from '../shell/ShellContext';
import { ActionDialog, OutcomeView } from './ActionDialogs';
import { IncidentTable, Stats } from './IncidentsList';
import { NoteComposer, NOTES_UNAVAILABLE } from './NoteComposer';
import { NotificationsCard } from './NotificationsCard';
import { TimelineCard } from './TimelineCard';
import { summarize } from './listModel';
import { buildTimeline } from './timelineModel';
import type { IncidentActions, Outcome } from './useIncidentActions';
import { emptyDraft } from './model';

const A = 'a'.repeat(32), P = '1'.repeat(32), I = '2'.repeat(32), C = '3'.repeat(32), E = '4'.repeat(32), U = '5'.repeat(32), X = '7'.repeat(32);
const NS = (min: number): string => String(BigInt(1_700_000_000_000 + min * 60_000) * 1_000_000n);
const CANARY = '<img src=x onerror="window.__pwn=1"> & <script>window.__pwn=2</script>';
const view = (over: Partial<IncidentView> = {}): IncidentView => ({
 incident_id: I, org: A, project_id: P, version: '3', status: 'open', condition: { id: C, state: 'firing', freshness: 'fresh', observed_at: NS(0) }, episode_id: E, severity: 'major', impact_revision: '1', source_firing: true,
 notification: { reminders_paused: false, worse_impact_eligible: true, urgency: { state: 'empty', reason: 'no_notification_policy_state' }, delivery: { state: 'empty', reason: 'no_delivery_created', attention: 'none' }, digest: { state: 'empty', reason: 'no_notification_policy_state', sent: 0 }, unread_change: { state: 'empty', reason: 'no_notification_policy_state', changed: false, queue_revision: '0', seen_revision: '0' } },
 links: [], observed_impacts: 1, last_activity: NS(5), ...over,
});
const noHtml = (html: string): void => {
 expect(html).not.toMatch(/<img/i);
 expect(html).not.toMatch(/<script/i);
 // Every onerror= in the output is part of the escaped canary text (inside a text node or an attribute value), never an attribute of a created element.
 expect((html.match(/onerror=/g) ?? []).length).toBe((html.match(/&lt;img src=x onerror=/g) ?? []).length);
 expect(html).toContain('&lt;img src=x onerror=');
};
const entries: TimelineEntry[] = [
 { version: '1', at: NS(0), type: 'open', origin: 'system', actor: U },
 { version: '2', at: NS(2), type: 'ack', origin: 'human', actor: U, reason: CANARY },
 { version: '3', at: NS(4), type: 'note', origin: 'human', actor: U, note: CANARY },
];
const nameOf = (id: string): string | undefined => (id === U ? 'Ravi Patel' : undefined);

describe('the timeline', () => {
 const items = buildTimeline(view({ timeline: entries }), (ns) => ns);
 test('a note and a reason are text, never markup', () => {
  noHtml(renderToStaticMarkup(React.createElement(TimelineCard, { items, tz: 'UTC', nameOf, composer: null })));
 });
 test('names come from the directory, else a person is the short ID and a system entry is System', () => {
  const html = renderToStaticMarkup(React.createElement(TimelineCard, { items, tz: 'UTC', nameOf: () => undefined, composer: null }));
  expect(html).toContain('55555555…');
  const named = renderToStaticMarkup(React.createElement(TimelineCard, { items, tz: 'UTC', nameOf, composer: null }));
  expect(named).toContain('Ravi Patel');
 });
 test('every lane has a chip with its real count and one is pressed', () => {
  const html = renderToStaticMarkup(React.createElement(TimelineCard, { items, tz: 'UTC', nameOf, composer: null }));
  for (const label of ['Everything', 'People', 'Alert', 'Errors', 'Deploys', 'Notifications']) expect(html).toContain(label);
  expect(html).toContain('aria-pressed="true"');
  expect(html).toContain('data-type="note"');
  expect(html).toContain('>Note<');
 });
 test('a lane with nothing in it says so instead of showing a blank', () => {
  expect(renderToStaticMarkup(React.createElement(TimelineCard, { items, tz: 'UTC', nameOf, composer: null, initial: 'deploy' }))).toContain('No entry in this lane');
  expect(renderToStaticMarkup(React.createElement(TimelineCard, { items: [], tz: 'UTC', nameOf, composer: null }))).toContain('Nothing is recorded on this incident yet');
 });
});

describe('the notes composer', () => {
 const props = { view: view(), reloading: false, onCommitted: () => undefined, onReload: () => undefined };
 test('it is a labelled form with a byte counter', () => {
  const html = renderToStaticMarkup(React.createElement(NoteComposer, props));
  expect(html).toContain('aria-label="Add a timeline note"');
  expect(html).toContain('Add a note to the timeline');
  expect(html).toContain('0 of 2000 bytes');
  expect(html).toContain('never sent to GitLab');
 });
 test('when notes are not served the composer is disabled and says so', () => {
  const html = renderToStaticMarkup(React.createElement(NoteComposer, { ...props, unavailable: true }));
  expect(html).toContain(NOTES_UNAVAILABLE);
  expect(html).toContain('Notes are not available yet');
  expect((html.match(/disabled=""/g) ?? []).length).toBeGreaterThanOrEqual(2);
 });
});

describe('notifications never soften a failed or uncertain delivery', () => {
 const d = (status: 'failed' | 'uncertain' | 'accepted', n: number) => ({ id: String(n).repeat(32), kind: 'open', route: 'immediate', phase: 'pending', status, attempts: 1, last_outcome: 'terminal', last_at: NS(3), eligible_at: NS(1) });
 const v = view({ notification: { ...view().notification, urgency: { state: 'ready', tier: 'urgent', mode: 'active' }, delivery: { state: 'ready', attention: 'failed', counts: {}, entries: [d('failed', 1), d('uncertain', 2), d('accepted', 3)] } } });
 const html = renderToStaticMarkup(React.createElement(NotificationsCard, { view: v, tz: 'UTC', routesHref: '#routing' }));
 test('headline, entries and the failing pill name each outcome', () => {
  expect(html).toContain('data-attention="failed"');
  expect(html).toContain('Delivery failed');
  expect(html).toContain('1 failed, 1 uncertain');
  expect(html).toContain('data-status="uncertain"');
  expect(html).toContain('the provider may have accepted a message the product could not confirm');
  expect(html).toContain('Urgency: urgent, notifies immediately');
 });
 test('every testid of the notifications part is kept', () => {
  for (const id of ['reminders', 'worse-impact', 'urgency', 'delivery', 'delivery-entries', 'digest', 'unread']) expect(html).toContain(`data-testid="${id}"`);
  expect(html).toContain('data-section="notifications"');
 });
 test('no policy is said as such, not as zero or as sent', () => {
  const none = renderToStaticMarkup(React.createElement(NotificationsCard, { view: view(), tz: 'UTC', routesHref: '#routing' }));
  expect(none).toContain('No notification policy has evaluated this incident');
  expect(none).toContain('No delivery has been created');
  expect(none).not.toContain('data-testid="delivery-entries"');
 });
});

describe('the incident list', () => {
 const ack = { actor: U, at: '1', impact_revision: '1', version: '2', current: true };
 const rows = [
  view({ incident_id: 'a1'.repeat(16), title: CANARY, severity: 'critical' }),
  view({ incident_id: 'b2'.repeat(16), ack, owner: U, status: 'resolved', resolved_at: NS(3), notification: { ...view().notification, delivery: { state: 'ready', attention: 'uncertain', counts: {}, entries: [] } } }),
 ];
 const env = { context: { org: A, projects: [P], environment: '', start: NS(-60), end: NS(60), timezone: 'UTC', generation: 0 } satisfies ViewContext, names: { ...NO_NAMES, state: 'ready' as const, members: new Map([[U, 'Ravi Patel']]) }, open: () => undefined, href: (v: IncidentView) => `#incident/${v.incident_id}`, nowMs: 1_700_000_000_000 + 10 * 60_000 };
 const html = renderToStaticMarkup(React.createElement(IncidentTable, { entries: rows, env, me: U }));
 test('a title that a person set is text', () => { noHtml(html); });
 test('rows keep the contract: data-incident, data-status and the data-cell parts', () => {
  expect(html).toContain(`data-incident="${'a1'.repeat(16)}"`);
  expect(html).toContain('data-status="resolved"');
  for (const cell of ['urgency', 'delivery', 'digest', 'unread', 'notifications', 'activity']) expect(html).toContain(`data-cell="${cell}"`);
 });
 test('state is in words: source, status, owner, delivery', () => {
  expect(html).toContain('Source firing, fresh data');
  expect(html).toContain('Resolved by a person');
  expect(html).toContain('Resolved, source still firing');
  expect(html).toContain('Ravi Patel');
  expect(html).toContain('Not acknowledged');
  expect(html).toContain('Delivery uncertain');
  expect(html).toContain('Rate unknown');
 });
 test('an untitled incident is named by its short ID, and the table is a labelled region', () => {
  expect(html).toContain('Incident b2b2b2b2…');
  expect(html).toContain('role="region"');
  expect(html).toContain('tabindex="0"');
 });
 test('the next step is a named control; a resolved incident has none', () => {
  expect(html).toContain('aria-label="Acknowledge: open ');
  expect(html).toContain('>No next step<');
 });
 test('search and filters are labelled; every chip carries its count', () => {
  expect(html).toContain('aria-label="Search incidents"');
  expect(html).toContain('aria-label="Filter incidents"');
  for (const label of ['All', 'Open', 'Needs action', 'Critical', 'Assigned to me', 'Unassigned', 'Delivery problems', 'Resolved']) expect(html).toContain(label);
 });
 test('exactly one link per row: the title', () => {
  for (const row of html.split('<tr ').filter((r) => r.includes('data-incident'))) expect((row.match(/<a /g) ?? []).length).toBe(1);
 });
 test('the figures: nothing is stated as zero when the answer cannot state it', () => {
  const stats = renderToStaticMarkup(React.createElement(Stats, { summary: summarize([view({ incident_id: 'c3'.repeat(16) })]) }));
  expect(stats).toContain('Not stated');
  expect(stats).toContain('No delivery state is available');
  const known = renderToStaticMarkup(React.createElement(Stats, { summary: summarize(rows.map((r) => ({ ...r, status: 'open' as const, notification: { ...r.notification, delivery: { state: 'ready' as const, attention: 'failed' as const, counts: {}, entries: [] } } }))) }));
  expect(known).toContain('2 failed · 0 uncertain');
 });
});

describe('the action dialogs', () => {
 const base = (over: Partial<IncidentActions> = {}): IncidentActions => ({ view: view(), open: 'resolve', draft: emptyDraft('resolve'), outcome: { kind: 'idle' }, pending: false, reloading: false, openAction: () => undefined, close: () => undefined, set: () => undefined, submit: () => undefined, resend: () => undefined, reload: () => undefined, ...over });
 const render = (a: IncidentActions): string => renderToStaticMarkup(React.createElement(ActionDialog, { actions: a, members: [], me: undefined }));
 test('resolve lists what happens to the other entities and keeps the contract words', () => {
  const html = render(base({ view: view({ links: [{ kind: 'issue', id: X }] }) }));
  expect(html).toContain('Resolve incident');
  expect(html).toContain('The alert source is still firing');
  expect(html).toContain('role="note"');
  expect(html).toContain('Resolved, source still firing');
  expect(html).toContain('keeps its own state');
  expect(html).toContain('never reopened');
  expect(html).toContain('Reason (required)');
  expect(html).toContain('If someone else changes this incident first, nothing is applied and you see their change.');
  expect(html).toContain('data-testid="expected-version"');
 });
 test('a reason is optional for an acknowledgement and absent for a title', () => {
  expect(render(base({ open: 'ack', draft: emptyDraft('ack') }))).toContain('Reason (optional)');
  const title = render(base({ open: 'title', draft: emptyDraft('title') }));
  expect(title).toContain('Title (1 to 160 bytes)');
  expect(title).not.toContain('Reason');
 });
 test('assigning offers my own ID and the known members', () => {
  const html = renderToStaticMarkup(React.createElement(ActionDialog, { actions: base({ open: 'assign', draft: emptyDraft('assign') }), members: [{ id: U, name: 'Ravi Patel' }], me: U }));
  expect(html).toContain('Use my user ID');
  expect(html).toContain('Ravi Patel');
  expect(html).toContain('Owner user ID (empty removes the owner)');
 });
 test('nothing renders while no action is open', () => { expect(render(base({ open: null }))).toBe(''); });

 const outcome = (o: Outcome, over: Partial<IncidentActions> = {}): string => renderToStaticMarkup(React.createElement(OutcomeView, { actions: base(over), outcome: o }));
 test('pending says nothing is committed yet', () => { expect(outcome({ kind: 'pending' })).toContain('Nothing is committed yet'); });
 test('a lost race names both revisions, keeps the draft and offers the reload', () => {
  const html = outcome({ kind: 'conflict', expected: '3', current: '4', requestId: '' });
  expect(html).toContain('data-conflict="current"');
  expect(html).toContain('Conflict: not applied');
  expect(html).toContain('data-testid="current-version">4<');
  expect(html).toContain('Reload the current incident');
  expect(html).toContain('Your draft is kept');
  expect(outcome({ kind: 'conflict', expected: '2', current: '3', requestId: '' })).toContain('data-conflict="reloaded"');
 });
 test('an unknown outcome is not assumed to have failed, and the resend is explicit', () => {
  const html = outcome({ kind: 'unknown', request: { org: A, command_id: 'c'.repeat(32), expected_version: '3', project_id: P, target_id: I, entity_kind: 'incident', kind: 'ack', payload: {} } });
  expect(html).toContain('Outcome unknown');
  expect(html).toContain('Do not assume it failed');
  expect(html).toContain('Resend the same request');
 });
 test('committed names the revision the server acknowledged; a refusal names its code and says nothing was applied', () => {
  expect(outcome({ kind: 'committed', revision: '4', action: 'ack' })).toContain('acknowledged revision 4 (Acknowledge)');
  const refused = outcome({ kind: 'refused', status: 403, detail: '', code: 'forbidden', requestId: 'r'.repeat(32) });
  expect(refused).toContain('Nothing was applied');
  expect(refused).toContain('forbidden');
  expect(outcome({ kind: 'not_available', reason: 'action_not_served' })).toContain('does not serve this action yet');
 });
});
