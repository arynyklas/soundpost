// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { ICON_NAMES } from './Icon';
import { DataTable, Lineage, NotAvailable, Person, Pill, SeverityIcon, shortId } from './primitives';

const html = (el: React.ReactElement): string => renderToStaticMarkup(el);

describe('DataTable', () => {
 const rows = [{ id: 'a', name: 'Alpha' }, { id: 'b', name: 'Beta' }];
 const markup = html(React.createElement(DataTable<{ id: string; name: string }>, { label: 'Things in scope', rows, rowKey: (r) => r.id, columns: [{ key: 'n', header: 'Name', cell: (r) => r.name }, { key: 'i', header: 'Identifier', cell: (r) => r.id, align: 'right' }], rowAttrs: (r) => ({ 'data-thing': r.id }) }));
 test('sits in a focusable, labelled scroll region and is captioned', () => {
  expect(markup).toContain('class="table-region" tabindex="0" role="region" aria-label="Things in scope"');
  expect(markup).toContain('<caption class="sr-only">Things in scope</caption>');
 });
 test('headers are scoped, the first cell is the row header, every other cell carries its label for the stacked layout', () => {
  expect(markup).toContain('scope="col"');
  expect(markup).toContain('<th scope="row" role="rowheader">Alpha</th>');
  expect(markup).toContain('data-label="Identifier"');
  expect(markup).toContain('data-thing="b"');
 });
 test('no duplicated narrow-only cells: each row has exactly as many cells as columns, and no inline style', () => {
  expect(markup.match(/<tr[ >]/g)?.length).toBe(3);
  expect(markup.match(/<t[dh][ >]/g)?.length).toBe(2 + 2 * 2);
  expect(markup).not.toMatch(/\sstyle=/);
 });
});

describe('state words and chips', () => {
 test('a pill always carries its words; severity keeps its word for assistive technology', () => {
  expect(html(React.createElement(Pill, { tone: 'crit', icon: 'fire' }, 'Firing'))).toContain('Firing');
  expect(html(React.createElement(SeverityIcon, { severity: 'major' }))).toContain('<span class="sr-only">major</span>');
 });
 test('lineage keeps the order it was given, links only what is available, and shows an unavailable record as such', () => {
  const m = html(React.createElement(Lineage, { items: [
   { kind: 'Rule', name: 'checkout-p95', icon: 'rule', href: '#rule' },
   { kind: 'Incident', name: 'INC-8f3a', icon: 'bell', current: true, href: '#me' },
   { kind: 'Issue', name: 'TypeError', icon: 'bug', unavailable: true, href: '#hidden' },
  ] }));
  expect(m.indexOf('Rule')).toBeLessThan(m.indexOf('Incident'));
  expect(m).toContain('href="#rule"');
  expect(m).not.toContain('href="#me"');
  expect(m).not.toContain('href="#hidden"');
  expect(m).toContain('aria-current="true"');
  expect(m).toContain('is-unavailable');
 });
 test('"not available" is its own state with words and is not an empty one', () => {
  const m = html(React.createElement(NotAvailable, { title: 'Dashboards are planned' }));
  expect(m).toContain('data-state="unsupported"');
  expect(m).toContain('Dashboards are planned');
 });
 test('a person without a display name shows the shortened account ID, never an invented name; nobody is Unassigned', () => {
  const id = 'abcdef0123456789abcdef0123456789';
  expect(html(React.createElement(Person, { id }))).toContain(shortId(id));
  expect(html(React.createElement(Person, { id, name: 'Ravi Patel' }))).toContain('Ravi Patel');
  expect(html(React.createElement(Person, {}))).toContain('Unassigned');
 });
});

describe('icons', () => {
 test('the icon set is small and every glyph name is unique', () => {
  expect(new Set(ICON_NAMES).size).toBe(ICON_NAMES.length);
  expect(ICON_NAMES.length).toBeLessThan(80);
 });
});
