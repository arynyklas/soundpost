// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { afterEach, describe, expect, test } from 'bun:test';
import { profileRegistry } from '../api/client';
import { ApiFault } from '../api/types';
import { featureSetId, featuresOf, parseProfileRegistry, profileById, profilesFor } from './profiles';
import { REGISTRY, committedProfiles, registryBody } from './testRegistry.test';

const committed = committedProfiles();
const profile = (id: string) => { const p = profileById(REGISTRY, id); if (p === undefined) throw new Error(`missing ${id}`); return p; };

describe('the registry the server states is read exactly, with nothing carried by the console', () => {
 test('the same profiles, every feature set with its identifier and its enabled features, in the stated order', () => {
  expect(REGISTRY.map((p) => p.id)).toEqual(committed.map((c) => c.id));
  expect(committed.length).toBeGreaterThanOrEqual(3);
  for (const c of committed) {
   const p = profile(c.id);
   expect(p.sets.map(([id]) => id)).toEqual(c.feature_sets.map((s) => s.id));
   expect(p.sets.map(([id]) => featuresOf(p, id))).toEqual(c.feature_sets.map((s) => p.features.filter((f) => s.enabled.includes(f))));
   expect(new Set(p.features)).toEqual(new Set(c.feature_sets.flatMap((s) => s.enabled)));
  }
 });
 test('the language is the profile prefix', () => {
  for (const p of REGISTRY) expect(p.id.startsWith(`${p.language}-`)).toBe(true);
  expect(profilesFor(REGISTRY, 'promql').map((p) => p.id)).toEqual(['promql-prometheus-3.1.0', 'promql-prometheus-3.13.5']);
  expect(profilesFor(REGISTRY, 'logql').map((p) => p.id)).toEqual(['logql-loki-3.5.2']);
 });
 test('a registry with no profile for a language gives that language none, never another language\'s', () => {
  const onlyProm = REGISTRY.filter((p) => p.language === 'promql');
  expect(profilesFor(onlyProm, 'logql')).toEqual([]);
 });
});

describe('selecting features finds the registered set, in any order, or nothing', () => {
 test('every registered set is found by exactly its enabled features', () => {
  for (const c of committed) {
   const p = profile(c.id);
   for (const s of c.feature_sets) {
    expect(featureSetId(p, s.enabled)).toBe(s.id);
    expect(featureSetId(p, [...s.enabled].reverse())).toBe(s.id);
   }
  }
 });
 test('no features is the first registered set, and a feature the profile does not register finds nothing', () => {
  for (const c of committed) {
   const p = profile(c.id);
   expect(featureSetId(p, [])).toBe(c.feature_sets[0]?.id ?? null);
   expect(featureSetId(p, ['not-a-registered-feature'])).toBeNull();
   expect(featuresOf(p, 'not-a-feature-set')).toBeNull();
  }
 });
 test('the same feature name selects different sets in different profiles', () => {
  const old = profile('promql-prometheus-3.1.0');
  const next = profile('promql-prometheus-3.13.5');
  expect(featureSetId(old, ['promql-delayed-name-removal'])).not.toBe(featureSetId(next, ['promql-delayed-name-removal']));
  expect(featureSetId(old, ['promql-binop-fill-modifiers'])).toBeNull();
 });
});

describe('a registry that is not a consistent statement is a fault, never a registry to select from', () => {
 const one = (over: Record<string, unknown>): { profiles: Record<string, unknown>[] } => ({ profiles: [{ id: 'promql-x-1', language: 'promql', features: ['a', 'b'], feature_sets: [{ id: 's0', enabled: [] }, { id: 's1', enabled: ['a'] }], ...over }] });
 test('a well-formed registry parses', () => { expect(parseProfileRegistry(one({}))[0]?.sets).toEqual([['s0', 0], ['s1', 1]]); });
 test('not a registry', () => {
  for (const raw of [null, [], {}, { profiles: 'x' }, { profiles: [null] }]) expect(() => parseProfileRegistry(raw)).toThrow(ApiFault);
 });
 test('the profile must belong to its language, have an identifier and be listed once', () => {
  expect(() => parseProfileRegistry(one({ language: 'logql' }))).toThrow(ApiFault);
  expect(() => parseProfileRegistry(one({ language: 'sql' }))).toThrow(ApiFault);
  expect(() => parseProfileRegistry(one({ id: '' }))).toThrow(ApiFault);
  const p = one({}).profiles[0];
  expect(() => parseProfileRegistry({ profiles: [p, p] })).toThrow(ApiFault);
 });
 test('features are distinct non-empty strings', () => {
  expect(() => parseProfileRegistry(one({ features: ['a', 'a'] }))).toThrow(ApiFault);
  expect(() => parseProfileRegistry(one({ features: ['a', ''] }))).toThrow(ApiFault);
  expect(() => parseProfileRegistry(one({ features: ['a', 1] }))).toThrow(ApiFault);
 });
 test('a profile registers at most as many features as a feature set mask can hold', () => {
  const many = Array.from({ length: 31 }, (_, i) => `feature-${i}`);
  expect(() => parseProfileRegistry(one({ features: many, feature_sets: [{ id: 's0', enabled: [] }] }))).toThrow(ApiFault);
  expect(parseProfileRegistry(one({ features: many.slice(0, 30), feature_sets: [{ id: 's0', enabled: [] }] }))[0]?.features).toHaveLength(30);
 });
 test('a profile registers at least one feature set, with unique identifiers and unique combinations', () => {
  expect(() => parseProfileRegistry(one({ feature_sets: [] }))).toThrow(ApiFault);
  expect(() => parseProfileRegistry(one({ feature_sets: [{ id: 's0', enabled: [] }, { id: 's0', enabled: ['a'] }] }))).toThrow(ApiFault);
  expect(() => parseProfileRegistry(one({ feature_sets: [{ id: 's0', enabled: ['a'] }, { id: 's1', enabled: ['a'] }] }))).toThrow(ApiFault);
  expect(() => parseProfileRegistry(one({ feature_sets: [{ id: 's0', enabled: ['a', 'b'] }, { id: 's1', enabled: ['b', 'a'] }] }))).toThrow(ApiFault);
 });
 test('a feature set may enable only registered features, once each', () => {
  expect(() => parseProfileRegistry(one({ feature_sets: [{ id: 's0', enabled: ['zzz'] }] }))).toThrow(ApiFault);
  expect(() => parseProfileRegistry(one({ feature_sets: [{ id: 's0', enabled: ['a', 'a'] }] }))).toThrow(ApiFault);
 });
});

const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });
describe('the registry is read from the server route, once per call, with the session and nothing else', () => {
 test('GET /api/v1/query/profiles with the same-origin credential, parsed', async () => {
  const calls: { url: string; init: RequestInit | undefined }[] = [];
  globalThis.fetch = (async (url: string, init?: RequestInit) => { calls.push({ url, init }); return new Response(JSON.stringify(registryBody(committed)), { status: 200 }); }) as unknown as typeof fetch;
  const got = await profileRegistry(new AbortController().signal);
  expect(got.map((p) => p.id)).toEqual(committed.map((c) => c.id));
  expect(calls).toHaveLength(1);
  expect(calls[0]?.url).toBe('/api/v1/query/profiles');
  expect(calls[0]?.init?.method ?? 'GET').toBe('GET');
  expect(calls[0]?.init?.credentials).toBe('same-origin');
  expect(calls[0]?.init?.body).toBeUndefined();
 });
 test('a refusal is its typed fault, and an inconsistent registry is invalid_response', async () => {
  globalThis.fetch = (async () => new Response(JSON.stringify({ code: 'unauthenticated' }), { status: 401 })) as unknown as typeof fetch;
  await expect(profileRegistry(new AbortController().signal)).rejects.toMatchObject({ status: 401, code: 'unauthenticated' });
  globalThis.fetch = (async () => new Response(JSON.stringify({ profiles: [{ id: 'promql-x', language: 'logql', features: [], feature_sets: [] }] }), { status: 200 })) as unknown as typeof fetch;
  await expect(profileRegistry(new AbortController().signal)).rejects.toMatchObject({ code: 'invalid_response' });
 });
});
