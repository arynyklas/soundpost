// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Test support: the registry as GET /api/v1/query/profiles states it, built from the committed profiles/query/*.json files with
// the same rules the server applies (committed set order, the sorted union of enabled features, the language prefix), and
// parsed by the console's own parser. Production code has no copy of this data; only tests read the files.
import { readFileSync, readdirSync } from 'node:fs';
import { parseProfileRegistry, type ProfileInfo } from './profiles';

const dir = new URL('../../../profiles/query/', import.meta.url);
export interface CommittedProfile { id: string; feature_sets: { id: string; enabled: string[] }[] }

export const committedProfiles = (): CommittedProfile[] => readdirSync(dir).filter((f) => f.endsWith('.json')).sort().map((f) => JSON.parse(readFileSync(new URL(f, dir), 'utf8')) as CommittedProfile);

/** The wire body the server sends for these profiles. */
export function registryBody(profiles: readonly CommittedProfile[]): { profiles: { id: string; language: string; features: string[]; feature_sets: { id: string; enabled: string[] }[] }[] } {
 return {
  profiles: profiles.map((p) => ({
   id: p.id, language: p.id.split('-')[0] ?? '',
   features: [...new Set(p.feature_sets.flatMap((s) => s.enabled))].sort(),
   feature_sets: p.feature_sets.map((s) => ({ id: s.id, enabled: [...s.enabled] })),
  })),
 };
}

export const REGISTRY: readonly ProfileInfo[] = parseProfileRegistry(registryBody(committedProfiles()));
