// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Every reason code the server can put on an investigation, trace, replay, profile or evidence view must have words in the console:
// an unknown code reads "Not available." and says nothing about why. The codes are read from the Go constants themselves, so a
// reason added to the server without words fails here.
import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { frameReasonWords, sourceWords } from '../evidence/model';
import { reasonText } from './StatusPanel';

const FILES = ['workflow_types.go', 'traces.go', 'replay_view.go', 'profile_view.go', 'evidence.go'];
const CONST = /^\s*Reason[A-Za-z]*\s+(?:Reason\s+)?=\s*"([a-z][a-z_]*)"\s*(?:\/\/.*)?$/gm;
const root = resolve(import.meta.dir, '../../../internal/httpapi');
// A code is understood when the section list, the frame panel or the source panel has its own sentence for it.
const understood = (c: string): boolean => reasonText(c) !== 'Not available.' || !frameReasonWords(c).includes('does not recognise') || sourceWords({ state: 'absent', reason: c } as Parameters<typeof sourceWords>[0]) !== 'No source content exists for this frame.';
const codes = (file: string): string[] => [...readFileSync(resolve(root, file), 'utf8').matchAll(CONST)].map((m) => m[1] ?? '');

describe('every server reason code has console words (05.09 review)', () => {
 test('the contract reads a real set of codes from each file', () => {
  for (const f of FILES) expect(codes(f).length).toBeGreaterThan(0);
 });
 for (const file of FILES) {
  test(`${file}: every Reason constant says why, not just "Not available."`, () => {
   const missing = codes(file).filter((c) => !understood(c));
   expect(missing).toEqual([]);
  });
 }
});
