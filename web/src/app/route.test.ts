// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import { decodeHash } from './context';
import { hashForPath, rewriteConsolePath } from './route';

const A = 'a'.repeat(32), P = '1'.repeat(32), I = '3'.repeat(32), S = '5'.repeat(32), NOW = 1_700_000_000_000;

describe('D33 path-shaped console links rewrite to the hash route', () => {
 test('an incident path with a project:id pair opens the incident in that project', () => {
  const hash = hashForPath(`/incidents/${P}:${I}`, `?org=${A}`);
  expect(hash).not.toBeNull();
  const nav = decodeHash(hash ?? '', 1, NOW);
  expect([nav.section, nav.incident, nav.context?.org, nav.context?.projects]).toEqual(['incidents', { project: P, id: I }, A, [P]]);
 });
 test('a bare id takes its project from the single project in the query', () => {
  const nav = decodeHash(hashForPath(`/issues/${I}`, `?org=${A}&projects=${P}`) ?? '', 0, NOW);
  expect([nav.section, nav.target]).toEqual(['issues', { project: P, id: I }]);
  // two projects name no single project for a bare id: the entity is not opened, the scope still is
  const two = decodeHash(hashForPath(`/issues/${I}`, `?org=${A}&projects=${P},${'2'.repeat(32)}`) ?? '', 0, NOW);
  expect([two.section, two.target, two.context?.projects.length]).toEqual(['issues', null, 2]);
 });
 test('every entity section maps to its own hash parameter', () => {
  for (const [section, field] of [['releases', 'target'], ['traces', 'target'], ['replays', 'target'], ['profiles', 'target'], ['jobs', 'target']] as const) {
   const nav = decodeHash(hashForPath(`/${section}/${P}:${I}`, `?org=${A}`) ?? '', 0, NOW);
   expect([nav.section, nav[field]]).toEqual([section, { project: P, id: I }]);
  }
  const service = decodeHash(hashForPath(`/services/${S}`, `?org=${A}&projects=${P}`) ?? '', 0, NOW);
  expect([service.section, service.service]).toEqual(['services', S]);
 });
 test('sections without an entity open on the scope; the window parameters are kept', () => {
  for (const section of ['queue', 'explore', 'settings', 'incidents']) expect(decodeHash(hashForPath(`/${section}`, `?org=${A}&projects=${P}`) ?? '', 0, NOW).section).toBe(section);
  const nav = decodeHash(hashForPath('/queue', `?org=${A}&projects=${P}&start=5&end=9&tz=UTC`) ?? '', 0, NOW);
  expect([nav.context?.start, nav.context?.end, nav.context?.timezone]).toEqual(['5', '9', 'UTC']);
 });
 test('unknown paths, extra segments and foreign query parameters are not rewritten or carried', () => {
  for (const path of ['/', '/nowhere', '/api/v1/session', `/incidents/${I}/x`, '/queue/x', '/settings/', '/incident', '/incidents/', '\\incidents']) expect(hashForPath(path, `?org=${A}`)).toBeNull();
  const hash = hashForPath('/queue', `?org=${A}&projects=${P}&secret=hunter2&view=settings&incident=x`) ?? '';
  expect(hash).not.toContain('hunter2');
  expect(new URLSearchParams(hash.slice(1)).get('view')).toBe('queue');
  expect(new URLSearchParams(hash.slice(1)).has('incident')).toBe(false);
 });
 test('a link that cannot name a scope opens no data', () => {
  expect(decodeHash(hashForPath('/incidents', '') ?? '', 0, NOW).context).toBeNull();
  expect(decodeHash(hashForPath(`/incidents/${P}:${I}`, `?org=nope`) ?? '', 0, NOW).context).toBeNull();
 });
 test('rewriting replaces the address with the hash route and drops the path and query; an existing hash is kept', () => {
  const urls: string[] = [];
  expect(rewriteConsolePath({ pathname: `/incidents/${P}:${I}`, search: `?org=${A}`, hash: '' }, (u) => urls.push(u))).toBe(true);
  expect(urls[0]?.startsWith('/#view=incidents&')).toBe(true);
  expect(urls[0]).not.toContain('?');
  expect(rewriteConsolePath({ pathname: '/queue', search: '', hash: '#view=jobs' }, (u) => urls.push(u))).toBe(true);
  expect(urls[1]).toBe('/#view=jobs');
  expect(rewriteConsolePath({ pathname: '/', search: '', hash: '#view=jobs' }, (u) => urls.push(u))).toBe(false);
  expect(urls.length).toBe(2);
 });
});
