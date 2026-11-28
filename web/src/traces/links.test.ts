// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { expect, test } from 'bun:test';
import type { SpanTarget } from '../api/types';
import { decodeHash, type ViewContext } from '../app/context';
import { targetLocation } from './links';

const P = 'a'.repeat(32), I = 'b'.repeat(32), O = 'c'.repeat(32), ORG = 'd'.repeat(32);
const ctx = decodeHash(`#view=traces&org=${ORG}&projects=${P}`, 0, 1_000_000_000_000).context as ViewContext;
const base = { span_id: '0000000000000001', relation: 'explicit', available: true } as const;

test('an error occurrence opens the issue that holds it, and has no anchor without one', () => {
 const withIssue: SpanTarget = { ...base, kind: 'error', id: O, issue_id: I };
 const href = targetLocation(ctx, P, withIssue);
 expect(href).not.toBeNull();
 const back = decodeHash(href as string, 0, 1_000_000_000_000);
 expect([back.section, back.target]).toEqual(['issues', { project: P, id: I }]);
 expect(targetLocation(ctx, P, { ...base, kind: 'error', id: O })).toBeNull();
});
test('jobs, replays and profiles open their own sections by their own id', () => {
 for (const [kind, section] of [['job', 'jobs'], ['replay', 'replays'], ['profile', 'profiles']] as const) {
  const back = decodeHash(targetLocation(ctx, P, { ...base, kind, id: O }) as string, 0, 1_000_000_000_000);
  expect([back.section, back.target]).toEqual([section, { project: P, id: O }]);
 }
});
