// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import type { ViewContext } from '../app/context';
import { MAX_BODY_BYTES, buildLiveRequest, buildQueryRequest, defaultForm, type QueryForm } from './form';
import { PROFILES, featureSetId, profileById } from './profiles';

const A = 'a'.repeat(32), P = '1'.repeat(32), Q = '2'.repeat(32), SRC = '5'.repeat(32);
const ctx: ViewContext = { org: A, projects: [P, Q], environment: '', start: '1730000000000000000', end: '1730000060000000000', timezone: 'UTC', generation: 1 };
const form = (over: Partial<QueryForm> = {}): QueryForm => ({ ...defaultForm(ctx, 'promql'), profileId: 'promql-prometheus-3.1.0', expression: 'up', ...over });
const profile = (id: string) => { const p = profileById(id); if (p === undefined) throw new Error('profile'); return p; };
const problems = (f: QueryForm): string[] => { const b = buildQueryRequest(ctx, f); return b.ok ? [] : b.problems; };

describe('a query request is built from exactly what the form says, and the profile is never switched', () => {
 test('an instant PromQL query names the selected profile, the registered feature set and every selected project', () => {
  const b = buildQueryRequest(ctx, form({ mode: 'instant', instantTime: '1730000030000000001' }));
  if (!b.ok) throw new Error(b.problems.join());
  expect(b.request).toEqual({
   org: A, language: 'promql', profile: 'promql-prometheus-3.1.0', feature_set: featureSetId(profile('promql-prometheus-3.1.0'), []),
   expression: 'up', evaluation: { instant: true, time: '1730000030000000001', start: '0', end: '0', step: '0' }, projects: [P, Q],
   budget: { timeout_ns: '0', memory_bytes: '0', max_returned: '10000' }, allow_partial: false,
  });
 });
 test('every selected feature changes the feature set, and no other profile is ever used', () => {
  const p = profile('promql-prometheus-3.13.5');
  const b = buildQueryRequest(ctx, form({ profileId: p.id, features: ['promql-experimental-functions', 'type-and-unit-labels'] }));
  if (!b.ok) throw new Error(b.problems.join());
  expect(b.request.profile).toBe(p.id);
  expect(b.request.feature_set).toBe(featureSetId(p, ['type-and-unit-labels', 'promql-experimental-functions']));
  expect(b.request.feature_set.startsWith(`${p.id}/`)).toBe(true);
 });
 test('a range query runs over exactly the selected window with the step in exact nanoseconds', () => {
  const b = buildQueryRequest(ctx, form({ mode: 'range', stepSeconds: '15' }));
  if (!b.ok) throw new Error(b.problems.join());
  expect(b.request.evaluation).toEqual({ instant: false, time: '0', start: ctx.start, end: ctx.end, step: '15000000000' });
 });
 test('the expression is sent exactly as typed, whitespace and all', () => {
  const text = '  sum by (job) (\n  rate(x[5m])\n)  ';
  const b = buildQueryRequest(ctx, form({ expression: text }));
  expect(b.ok && b.request.expression).toBe(text);
 });
 test('LogQL adds the explicit page size and order; PromQL never sends them', () => {
  const l = buildQueryRequest(ctx, defaultFormFor('logql', { logLimit: '50', logOrder: 'forward', mode: 'range' }));
  if (!l.ok) throw new Error(l.problems.join());
  expect([l.request.log_limit, l.request.log_order, l.request.language, l.request.profile]).toEqual(['50', 'forward', 'logql', 'logql-loki-3.5.2']);
  const p = buildQueryRequest(ctx, form({ logLimit: '50', logOrder: 'forward' }));
  expect(p.ok && 'log_limit' in p.request).toBe(false);
  expect(p.ok && 'log_order' in p.request).toBe(false);
  const none = buildQueryRequest(ctx, defaultFormFor('logql', { logLimit: '' }));
  expect(none.ok && 'log_limit' in none.request).toBe(false);
 });
 test('partial results are only requested when the person opted in', () => {
  const on = buildQueryRequest(ctx, form({ allowPartial: true }));
  expect(on.ok && on.request.allow_partial).toBe(true);
  expect(buildQueryRequest(ctx, form()).ok && (buildQueryRequest(ctx, form()) as { request: { allow_partial: boolean } }).request.allow_partial).toBe(false);
 });
 test('a named restricted source is raw.read, for exactly one project, and never otherwise', () => {
  const raw = buildQueryRequest(ctx, defaultFormFor('logql', { source: SRC, projects: [P] }));
  if (!raw.ok) throw new Error(raw.problems.join());
  expect([raw.request.permission, raw.request.source]).toEqual(['raw.read', SRC]);
  expect(problems(defaultFormFor('logql', { source: SRC }))).toContain('A restricted source is read for exactly one project.');
  const plain = buildQueryRequest(ctx, form());
  expect(plain.ok && ('permission' in plain.request || 'source' in plain.request)).toBe(false);
 });
});

function defaultFormFor(language: 'promql' | 'logql', over: Partial<QueryForm> = {}): QueryForm {
 const id = language === 'promql' ? 'promql-prometheus-3.1.0' : 'logql-loki-3.5.2';
 return { ...defaultForm(ctx, language), profileId: id, expression: language === 'promql' ? 'up' : '{app="web"}', ...over };
}

describe('a form that cannot be a valid request is refused before anything is sent, with every reason', () => {
 test('empty expression, no project, a project outside the scope, a duplicate project', () => {
  expect(problems(form({ expression: '   ' }))).toContain('Enter a query expression.');
  expect(problems(form({ projects: [] }))).toContain('Select at least one project.');
  expect(problems(form({ projects: ['b'.repeat(32)] }))).toContain('Every project must be one of the projects in the selected scope.');
  expect(problems(form({ projects: [P, P] }))).toContain('Every project must be one of the projects in the selected scope.');
 });
 test('a feature the profile does not register has no feature set, and a profile of the other language is refused', () => {
  expect(problems(form({ features: ['promql-binop-fill-modifiers'] }))).toContain('This profile registers no feature set with exactly these features.');
  expect(problems(form({ profileId: 'logql-loki-3.5.2' }))).toContain('The profile does not belong to the selected language.');
  expect(problems(form({ profileId: 'promql-unknown' }))).toContain('Choose a pinned profile.');
 });
 test('times, step and sizes are exact decimal strings, never numbers that could be rounded', () => {
  expect(problems(form({ mode: 'instant', instantTime: '1.5' }))).toContain('The evaluation time must be whole nanoseconds.');
  expect(problems(form({ mode: 'instant', instantTime: '9223372036854775808' }))).toContain('The evaluation time must be whole nanoseconds.');
  expect(problems(form({ mode: 'range', stepSeconds: '0' }))).toContain('The step must be a whole number of seconds, at least 1.');
  expect(problems(form({ mode: 'range', stepSeconds: '1e3' }))).toContain('The step must be a whole number of seconds, at least 1.');
  expect(problems(form({ maxReturned: '0' }))).toContain('The result budget must be a whole number of at least 1.');
  expect(problems(form({ maxReturned: '10.5' }))).toContain('The result budget must be a whole number of at least 1.');
  expect(problems(defaultFormFor('logql', { logLimit: '20000', maxReturned: '10000' }))).toContain('The log page size cannot exceed the result budget.');
  expect(problems(defaultFormFor('logql', { logLimit: 'x' }))).toContain('The log page size must be a whole number of at least 1.');
 });
 test('a project ID or a source ID that is not 32 hex digits is refused', () => {
  expect(problems(defaultFormFor('logql', { source: 'nope', projects: [P] }))).toContain('The restricted source ID must be 32 lowercase hexadecimal characters.');
 });
 test('a body larger than the server accepts is refused here, not truncated', () => {
  const huge = 'x'.repeat(MAX_BODY_BYTES);
  expect(problems(form({ expression: huge }))).toContain(`The request is larger than the ${MAX_BODY_BYTES}-byte limit.`);
  expect(problems(form({ expression: 'x'.repeat(1000) }))).toEqual([]);
 });
 test('all problems are reported together', () => {
  expect(problems(form({ expression: '', projects: [], maxReturned: '0' })).length).toBeGreaterThanOrEqual(3);
 });
});

describe('a live request carries the same selection and never a time range or a pagination field', () => {
 test('profile, registered feature set, projects, expression and the restricted source', () => {
  const b = buildLiveRequest(ctx, defaultFormFor('logql', { expression: '{app="web"} |= "bob"' }));
  if (!b.ok) throw new Error(b.problems.join());
  expect(b.request).toEqual({ org: A, projects: [P, Q], profile: 'logql-loki-3.5.2', feature_set: featureSetId(profile('logql-loki-3.5.2'), []), expression: '{app="web"} |= "bob"', budget: { timeout_ns: '0', memory_bytes: '0', max_returned: '0' } });
  const raw = buildLiveRequest(ctx, defaultFormFor('logql', { source: SRC, projects: [P] }));
  expect(raw.ok && [raw.request.permission, raw.request.source]).toEqual(['raw.read', SRC]);
 });
 test('only a LogQL expression can be streamed', () => {
  const b = buildLiveRequest(ctx, form());
  expect(b.ok).toBe(false);
  expect(b.ok ? [] : b.problems).toContain('Only a LogQL log query can be streamed live.');
 });
 test('the registry has a default for every language', () => {
  expect(PROFILES.some((p) => p.language === 'logql')).toBe(true);
 });
});
