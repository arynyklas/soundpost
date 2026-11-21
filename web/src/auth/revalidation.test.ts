// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { classifyRevalidation } from './revalidation';
const s = { csrf: 'c1', user: 'u1', expires: '100' };
describe('session revalidation outcome', () => {
 test('an unchanged session keeps the mounted console', () => expect(classifyRevalidation(s, { ...s })).toBe('keep'));
 test('a rotated token or expiry of the same account updates in place', () => {
  expect(classifyRevalidation(s, { ...s, csrf: 'c2' })).toBe('update');
  expect(classifyRevalidation(s, { ...s, expires: '200' })).toBe('update');
 });
 test('a changed account clears the console', () => expect(classifyRevalidation(s, { ...s, user: 'u2' })).toBe('remount'));
 test('no held session clears the console', () => expect(classifyRevalidation(null, s)).toBe('remount'));
});
// The window events must revalidate through checkSession (no blanking); only the initial load and a changed account use refresh.
describe('SessionBoundary wiring', () => {
 const src = readFileSync(new URL('./SessionBoundary.tsx', import.meta.url), 'utf8');
 test('focus, popstate and hashchange revalidate without remounting the console', () => {
  for (const name of ['revalidate', 'returned']) {
   const handler = new RegExp(`const ${name}=\\(\\):void=>\\{([^}]*)\\}`).exec(src)?.[1] ?? '';
   expect(handler).toContain('checkSession(');
   expect(handler).not.toContain('refresh()');
  }
  // Only a return to the window (focus after blur) re-reads the views; a navigation is already handled by App.
  expect(src).toContain('checkSession(back)');
 });
 test('a revoked session (401/403) clears the session, elevation, secrets and organizations', () => {
  const block = /e\.status===401\|\|e\.status===403\)\)\{([^}]*)\}/.exec(src)?.[1] ?? '';
  for (const part of ['setSession(null)', 'setElevation(null)', 'setSecret(\'\')', 'setCodes([])', 'setOrgs([])']) expect(block).toContain(part);
 });
 test('a valid revalidation bumps the epoch that makes every view read its scope again (a grant revoked meanwhile clears them)', () => {
  expect(src).toContain('if(reread){');
  expect(src).toContain('setEpoch(value=>value+1)');
  const app = readFileSync(new URL('../app/App.tsx', import.meta.url), 'utf8');
  expect(app).toContain('session?.epoch');
  expect(app).toMatch(/generation\.current \+= 1;\n\s*setNav\(decodeHash\(window\.location\.hash, generation\.current\)\);\n \}, \[epoch\]\)/);
 });
 test('a changed account or missing session goes through refresh via classifyRevalidation', () => {
  expect(src).toContain('classifyRevalidation(previous,current)');
  expect(src).toContain("outcome==='remount'){await refresh();return;}");
 });
});
