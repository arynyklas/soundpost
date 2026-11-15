// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// The pinned C06 language profile registry as the server states it (GET /api/v1/query/profiles). The browser carries no copy of
// it: every registered feature set of every accepted profile is read from the server the engine resolves requests against, and
// this module only validates that answer and looks things up in it. A feature set is selected by the exact set of registered
// features that are enabled; its identifier is looked up, never computed, and the profile is never silently switched.
import { ApiFault, QUERY_LANGUAGES, type QueryLanguage } from '../api/types';

export interface ProfileInfo {
 /** The pinned profile identifier sent as `profile`. */
 id: string;
 language: QueryLanguage;
 /** Every feature this profile registers, in the server's order; a feature set is a bit mask over it. */
 features: readonly string[];
 /** Every registered feature set: its identifier and the mask of enabled features. */
 sets: readonly (readonly [id: string, mask: number])[];
}

/** The most features one profile may register: a feature set is a bit mask over them. */
const MAX_FEATURES = 30;
const bad = (why: string): never => { throw new ApiFault(200, 'invalid_response', '', why); };
const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const strings = (v: unknown): v is string[] => Array.isArray(v) && v.every((s): boolean => typeof s === 'string' && s !== '');

/**
 * Accepts the registry only as a consistent statement: every profile belongs to its language, registers distinct features,
 * and every feature set enables only registered features, with a unique identifier and a unique feature combination (two
 * sets for one combination would make the lookup ambiguous). Anything else is a fault, never a registry the console selects from.
 */
export function parseProfileRegistry(raw: unknown): ProfileInfo[] {
 if (!isRecord(raw) || !Array.isArray(raw.profiles)) return bad('not a profile registry');
 const seen = new Set<string>();
 return raw.profiles.map((p): ProfileInfo => {
  if (!isRecord(p) || typeof p.id !== 'string' || p.id === '' || seen.has(p.id)) return bad('profile identifier');
  seen.add(p.id);
  const language = QUERY_LANGUAGES.find((l) => l === p.language);
  if (language === undefined || !p.id.startsWith(`${language}-`)) return bad('profile language');
  if (!strings(p.features) || new Set(p.features).size !== p.features.length || p.features.length > MAX_FEATURES) return bad('profile features');
  if (!Array.isArray(p.feature_sets) || p.feature_sets.length === 0) return bad('profile feature sets');
  const features: string[] = p.features;
  const ids = new Set<string>();
  const masks = new Set<number>();
  const sets = p.feature_sets.map((s): readonly [string, number] => {
   if (!isRecord(s) || typeof s.id !== 'string' || s.id === '' || ids.has(s.id) || !strings(s.enabled) || new Set(s.enabled).size !== s.enabled.length) return bad('feature set');
   let mask = 0;
   for (const name of s.enabled) {
    const bit = features.indexOf(name);
    if (bit < 0) return bad('feature set enables an unregistered feature');
    mask |= 1 << bit;
   }
   if (masks.has(mask)) return bad('two feature sets for one feature combination');
   ids.add(s.id);
   masks.add(mask);
   return [s.id, mask];
  });
  return { id: p.id, language, features, sets };
 });
}

/** The feature set identifier of exactly this set of enabled features, or null when the profile registers no such set. */
export function featureSetId(profile: ProfileInfo, enabled: readonly string[]): string | null {
 let mask = 0;
 for (const name of enabled) {
  const bit = profile.features.indexOf(name);
  if (bit < 0) return null;
  mask |= 1 << bit;
 }
 return profile.sets.find(([, m]) => m === mask)?.[0] ?? null;
}

/** The features a registered feature set enables, or null when the identifier is not registered by the profile. */
export function featuresOf(profile: ProfileInfo, featureSet: string): string[] | null {
 const set = profile.sets.find(([id]) => id === featureSet);
 return set === undefined ? null : profile.features.filter((_, bit) => (set[1] & (1 << bit)) !== 0);
}

export function profileById(registry: readonly ProfileInfo[], id: string): ProfileInfo | undefined { return registry.find((p) => p.id === id); }
export function profilesFor(registry: readonly ProfileInfo[], language: QueryLanguage): ProfileInfo[] { return registry.filter((p) => p.language === language); }
