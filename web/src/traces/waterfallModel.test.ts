// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import { MS, bounds, cleanPath, segment, sid, span, tree } from './fixture';
import { waterfall } from './waterfallModel';

describe('waterfall', () => {
 test('spans are ordered under their parents, placed on one axis, and the critical path is marked', () => {
  const w = waterfall(cleanPath());
  expect(w.rows.map((r) => [r.span.span_id, r.depth, r.onPath])).toEqual([[sid(1), 0, true], [sid(2), 1, true], [sid(3), 1, false]]);
  expect(w.rows.map((r) => [r.left, r.width])).toEqual([[0, 100], [0, 70], [0, 40]]);
  expect(w.spanNs).toBe(100n * MS);
  expect(w.ticks.map((t) => t.text)).toEqual(['0', '25 ms', '50 ms', '75 ms', '100 ms']);
 });
 test('a span with no measured duration has a place and no length, never a zero-length bar read as a duration', () => {
  const p = cleanPath({ spans: [span(1, null, 0, 100), span(2, 1, 10, null, { flags: ['open'] })], span_count: 2, trees: [tree(1, bounds(100n * MS), [segment(1, 0, 100)])] });
  const w = waterfall(p);
  const open = w.rows.find((r) => r.span.span_id === sid(2));
  expect(open?.measured).toBe(false);
  expect(open?.width).toBe(0);
  expect(open?.left).toBe(10);
 });
 test('an orphan, a duplicated span ID and a span in a cycle are shown detached with the reason, never under a guessed parent', () => {
  const p = cleanPath({
   spans: [span(1, null, 0, 100), span(4, 77, 5, 9), span(5, 1, 20, 30, { flags: ['duplicate_id'] }), span(5, 1, 40, 50, { flags: ['duplicate_id'] }), span(6, 7, 60, 70, { flags: ['in_cycle'] }), span(7, 6, 61, 69, { flags: ['in_cycle'] })],
   span_count: 6, trees: [tree(1, bounds(100n * MS), [segment(1, 0, 100)])],
  });
  const w = waterfall(p);
  const by = (id: number): (typeof w.rows)[number][] => w.rows.filter((r) => r.span.span_id === sid(id));
  expect(by(4)[0]?.detached).toContain('not in the data');
  expect(by(4)[0]?.depth).toBe(0);
  expect(by(5).map((r) => r.detached)).toEqual(['its span ID is recorded more than once', 'its span ID is recorded more than once']);
  expect(by(6)[0]?.detached).toContain('cycle');
  expect(by(7)[0]?.detached).toContain('cycle');
  expect(w.rows).toHaveLength(6);
 });
 test('the row count is bounded and the total says how many exist', () => {
  const w = waterfall(cleanPath(), 2);
  expect(w.shown).toBe(2);
  expect(w.total).toBe(3);
 });
});
