// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Frame text, function names, file paths and source text are untrusted: they must reach the page only as escaped text, and the
// panel must say plainly whether a frame was mapped and whether source text was released or withheld.
import { describe, expect, test } from 'bun:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { SymbolicatedFrame } from '../api/types';
import { FramePanel } from './FramePanel';

const B = 'b'.repeat(32), A = 'a'.repeat(32), H = 'd'.repeat(64);
const CANARY = '<img src=x onerror="window.__pwn=1"> & <script>window.__pwn=2</script>';
const render = (frame: SymbolicatedFrame): string => renderToStaticMarkup(React.createElement(FramePanel, { frame, buildId: B, index: 0 }));
const original = { module_id: CANARY, function: CANARY, artifact_id: A, line: 10, column: 7, in_app: true, async: false };
const noMarkup = (html: string): void => {
 expect(html).not.toMatch(/<img/i);
 expect(html).not.toMatch(/<script/i);
 expect(html).not.toMatch(/<[^>]*\sonerror\s*=/i);
 expect(html).toContain('&lt;img src=x onerror=');
};

describe('frame text is only ever text', () => {
 test('canary in function, module, mapped path, mapped function and source context renders escaped', () => {
  const html = render({ original, reason: 'resolved', resolved: { source: `${CANARY}/app.ts`, function: CANARY, line: 4, column: 8 }, map_sha256: H, source: { state: 'present', context: CANARY } });
  noMarkup(html);
  expect(html).toContain('data-testid="frame-source"');
 });
 test('an unmapped frame with a canary function name keeps it as text', () => {
  const html = render({ original, reason: 'identity_mismatch', source: { state: 'withheld', reason: 'sources_not_requested' } });
  noMarkup(html);
 });
});

describe('what the panel says', () => {
 test('a mapped frame shows position, build and map hash, and says the source was shown only because it was granted', () => {
  const html = render({ original: { ...original, function: 'boom', module_id: '' }, reason: 'resolved', resolved: { source: 'src/app.ts', function: 'handle', line: 4, column: 8 }, map_sha256: H, source: { state: 'present', context: 'const x = 1;' } });
  expect(html).toContain('Mapped');
  expect(html).toContain('src/app.ts:4:8 in handle');
  expect(html).toContain(B);
  expect(html).toContain(H);
  expect(html).toContain('const x = 1;');
  expect(html).toContain('separate sources grant');
 });
 test('an unmapped frame keeps the original frame and a specific reason, never a mapped position', () => {
  for (const [reason, words] of [['identity_mismatch', 'not part of this build'], ['artifact_unavailable', 'no source map is available'], ['sandbox_unavailable', 'sandbox'], ['artifact_corrupt', 'integrity'], ['invalid_map', 'not a valid map'], ['artifact_read_not_granted', 'artifacts.read']] as const) {
   const html = render({ original: { ...original, function: 'boom', module_id: '' }, reason, source: { state: 'withheld', reason: 'sources_not_requested' } });
   expect(html).toContain('Not mapped');
   expect(html).toContain(words);
   expect(html).toContain(`${A}:10:7 in boom`);
   expect(html).not.toContain('data-testid="frame-mapped"');
  }
 });
 test('withheld source is stated plainly and no source element exists', () => {
  const html = render({ original: { ...original, function: 'boom', module_id: '' }, reason: 'source_context_denied', source: { state: 'withheld', reason: 'source_grant_required' } });
  expect(html).toContain('withheld');
  expect(html).toContain('separate sources grant');
  expect(html).not.toContain('data-testid="frame-source"');
 });
 test('a frame whose reason says resolved but carries no position is not shown as mapped', () => {
  const html = render({ original: { ...original, function: 'boom', module_id: '' }, reason: 'resolved', source: { state: 'absent', reason: 'no_source_content' } });
  expect(html).toContain('Not mapped');
  expect(html).not.toContain('data-testid="frame-mapped"');
 });
 test('state is never colour alone: the badge and the reason are words', () => {
  const html = render({ original: { ...original, function: 'boom', module_id: '' }, reason: 'identity_mismatch', source: { state: 'withheld', reason: 'sources_not_requested' } });
  expect(html).toMatch(/data-testid="frame-state">Not mapped</);
  expect(html).toContain('data-testid="frame-reason"');
 });
});
