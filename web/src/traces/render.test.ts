// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Server-rendered markup of the critical path view. Span names, dependency aliases and every other trace-derived string are untrusted: they must reach the page only as escaped text.
import { describe, expect, test } from 'bun:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { CriticalPath } from './CriticalPath';
import { MS, bounds, cleanPath, segment, sid, span, tree, unknownBounds } from './fixture';

const CANARY = '<img src=x onerror="window.__pwn=1"> & <script>window.__pwn=2</script>';
const render = (el: React.ReactElement): string => renderToStaticMarkup(el);
const noElementsFromText = (html: string): void => {
 expect(html).not.toMatch(/<img/i);
 expect(html).not.toMatch(/<script/i);
 // An attribute named onerror, outside any quoted attribute value (the escaped text inside aria-label is not one).
 expect(html).not.toMatch(/<[a-z][^>"']*\sonerror\s*=/i);
 expect(html).toContain('&lt;img src=x onerror=');
};

describe('CriticalPath markup', () => {
 test('an XSS canary in span names, kinds, dependency aliases, statuses and links is escaped everywhere', () => {
  const p = cleanPath({
   spans: [
    span(1, null, 0, 100, { operation: CANARY, span_kind: CANARY, status: CANARY, dependency_alias: CANARY, flags: ['dependency_boundary'], links: [{ trace_id: 'e'.repeat(32), span_id: sid(9), same_trace: false, resolved: false }], job_id: 'f'.repeat(32) }),
    span(2, 1, 0, 70, { operation: CANARY }), span(3, 1, 0, 40, { operation: CANARY }),
   ],
  });
  const html = render(React.createElement(CriticalPath, { path: p, selectedSpan: sid(1), exploreHref: () => '#x' }));
  noElementsFromText(html);
  expect((html.match(/&lt;img src=x onerror=/g) ?? []).length).toBeGreaterThanOrEqual(5);
  expect(html).not.toMatch(/\sstyle=/i);
 });
 test('differing observed bounds print no single total; a 110 ms sum of the concurrent branches appears nowhere', () => {
  const html = render(React.createElement(CriticalPath, { path: cleanPath({ observed: bounds(100n * MS, 130n * MS, 'wall_clock_with_uncertainty') }), selectedSpan: null }));
  expect(html).toContain('between 100 ms and 130 ms');
  expect(html).toContain('no single total is shown');
  expect(html).not.toContain('110 ms');
 });
 test('limits, orphan trees and ambiguity are text, not colour: each appears as a sentence', () => {
  const p = cleanPath({
   reasons: ['missing_parent', 'critical_branch_ambiguous'], complete: false, edges: [{ kind: 'missing_parent', span_id: sid(4) }, { kind: 'critical_branch_ambiguous', span_id: sid(1), count: 2 }],
   spans: [span(1, null, 0, 100), span(2, 1, 0, 70), span(3, 1, 0, 75), span(4, 77, 5, 9)],
   trees: [tree(1, bounds(100n * MS), [segment(1, 0, 25), segment(2, 1, 70, { ambiguous: true }), segment(3, 1, 75, { ambiguous: true })]), tree(4, bounds(4n * MS), [segment(4, 0, 4)], true)],
   span_count: 4,
  });
  const html = render(React.createElement(CriticalPath, { path: p, selectedSpan: null }));
  expect(html).toContain('Orphan tree 2: its parent is missing or ambiguous, so it is not part of the root&#x27;s duration.');
  expect(html).toContain('one of several candidates for the critical branch');
  expect(html).toContain('data-limit="missing_parent"');
  expect(html).toContain('data-limit="critical_branch_ambiguous"');
  expect(html).toContain('Limits of this analysis');
 });
 test('time on the path itself and the observed duration are different columns with different values', () => {
  const html = render(React.createElement(CriticalPath, { path: cleanPath(), selectedSpan: null }));
  expect(html).toContain('<td>exactly 30 ms</td><td>exactly 100 ms</td>'); // the root: 100 ms long, 30 ms of it on itself
  expect(html).toContain('<td>exactly 70 ms</td><td>exactly 70 ms</td>'); // the leaf on the path
 });
 test('an unmeasured root is not zero', () => {
  const p = cleanPath({ spans: [span(1, null, 0, null, { flags: ['open'] })], span_count: 1, trees: [tree(1, unknownBounds(), [segment(1, 0, 0, { self: unknownBounds() })])], observed: unknownBounds(), reasons: ['span_open'], complete: false });
  const html = render(React.createElement(CriticalPath, { path: p, selectedSpan: null }));
  expect(html).toContain('Observed duration of this trace: not measured');
  expect(html).toContain('not measured');
  expect(html).not.toMatch(/exactly 0/);
 });
 test('accessible structure: labelled regions, a caption per tree, buttons that name the span, the selection exposed to assistive technology', () => {
  const html = render(React.createElement(CriticalPath, { path: cleanPath(), selectedSpan: sid(2) }));
  expect(html).toContain('aria-labelledby="cp-heading"');
  expect(html).toContain('aria-labelledby="cp-detail-heading"');
  expect(html).toContain('<caption>');
  expect(html).toContain('scope="col"');
  expect(html).toContain('aria-label="Show details of span op.2, internal, level 2"');
  expect(html).toMatch(/aria-pressed="true"[^>]*aria-label="Show details of span op\.2/);
  expect(html).toContain(`data-span="${sid(2)}" data-depth="1"`);
  expect(html).toContain('tabindex="-1"');
 });
 test('the selected span shows ids of its job, replay and profile as text with the statement that access is checked elsewhere', () => {
  const html = render(React.createElement(CriticalPath, { path: cleanPath({ spans: [span(1, null, 0, 100, { job_id: '1'.repeat(32), replay_id: '2'.repeat(32), profile_id: '3'.repeat(32) }), span(2, 1, 0, 70), span(3, 1, 0, 40)] }), selectedSpan: sid(1) }));
  for (const c of ['1', '2', '3']) expect(html).toContain(c.repeat(32));
  expect(html).toContain('its access is checked there, not here');
 });
});
