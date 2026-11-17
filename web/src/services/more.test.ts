// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// The investigation answers one page of metric names; `more` says there are further pages. The service pages must say so instead of
// presenting the first page as the whole answer (05.09 review: `more` of /investigate was never shown).
import { describe, expect, test } from 'bun:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MoreNote } from './ServicePage';

const render = (more: boolean, names: string[]): string => renderToStaticMarkup(React.createElement(MoreNote, { view: { more, metric_names: names } }));

describe('a truncated investigation page says so', () => {
 test('more=true says the answer covers only the first page, with its size, and where to browse the rest', () => {
  const html = render(true, ['a', 'b', 'c']);
  expect(html).toContain('data-testid="investigate-more"');
  expect(html).toContain('only the first 3 metric names');
  expect(html).toContain('Open Explore');
  expect(html).toContain('role="status"');
 });
 test('more=false says nothing', () => {
  expect(render(false, ['a'])).toBe('');
 });
});
