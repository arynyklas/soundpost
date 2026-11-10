// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import { readFileSync, readdirSync } from 'node:fs';
import { PROFILES, featureSetId, featuresOf, profileById, profilesFor } from './profiles';

const dir = new URL('../../../profiles/query/', import.meta.url);
interface Committed { id: string; feature_sets: { id: string; enabled: string[] }[] }
const committed: Committed[] = readdirSync(dir).filter((f) => f.endsWith('.json')).sort().map((f) => JSON.parse(readFileSync(new URL(f, dir), 'utf8')) as Committed);

describe('the browser registry is exactly the committed pinned profile registry', () => {
 test('the same profiles, no more and no fewer', () => {
  expect(PROFILES.map((p) => p.id).sort()).toEqual(committed.map((c) => c.id).sort());
  expect(committed.length).toBeGreaterThanOrEqual(3);
 });
 test('every registered feature set, with its identifier and its enabled features, in the committed order', () => {
  for (const c of committed) {
   const p = profileById(c.id);
   expect(p).toBeDefined();
   if (p === undefined) continue;
   expect(p.sets.map(([id]) => id)).toEqual(c.feature_sets.map((s) => s.id));
   expect(p.sets.map(([id]) => featuresOf(p, id))).toEqual(c.feature_sets.map((s) => p.features.filter((f) => s.enabled.includes(f))));
   expect(new Set(p.features)).toEqual(new Set(c.feature_sets.flatMap((s) => s.enabled)));
  }
 });
 test('the language is the profile prefix', () => {
  for (const p of PROFILES) expect(p.id.startsWith(`${p.language}-`)).toBe(true);
  expect(profilesFor('promql').map((p) => p.id)).toEqual(['promql-prometheus-3.1.0', 'promql-prometheus-3.13.5']);
  expect(profilesFor('logql').map((p) => p.id)).toEqual(['logql-loki-3.5.2']);
 });
});

describe('selecting features finds the registered set, in any order, or nothing', () => {
 test('every registered set is found by exactly its enabled features', () => {
  for (const c of committed) {
   const p = profileById(c.id);
   if (p === undefined) throw new Error('missing profile');
   for (const s of c.feature_sets) {
    expect(featureSetId(p, s.enabled)).toBe(s.id);
    expect(featureSetId(p, [...s.enabled].reverse())).toBe(s.id);
   }
  }
 });
 test('no features is the first registered set, and a feature the profile does not register finds nothing', () => {
  for (const c of committed) {
   const p = profileById(c.id);
   if (p === undefined) throw new Error('missing profile');
   expect(featureSetId(p, [])).toBe(c.feature_sets[0]?.id ?? null);
   expect(featureSetId(p, ['not-a-registered-feature'])).toBeNull();
   expect(featuresOf(p, 'not-a-feature-set')).toBeNull();
  }
 });
 test('the same feature name selects different sets in different profiles', () => {
  const old = profileById('promql-prometheus-3.1.0');
  const next = profileById('promql-prometheus-3.13.5');
  if (old === undefined || next === undefined) throw new Error('missing profile');
  expect(featureSetId(old, ['promql-delayed-name-removal'])).not.toBe(featureSetId(next, ['promql-delayed-name-removal']));
  expect(featureSetId(old, ['promql-binop-fill-modifiers'])).toBeNull();
 });
});
