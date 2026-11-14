// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import { decodeHash, encodeHash, latestOnly, scopeKey, validWindow, windowEndingAt, type ViewContext } from './context';

const A = 'a'.repeat(32), P = '1'.repeat(32), Q = '2'.repeat(32);
const ctx: ViewContext = { org: A, projects: [P, Q], environment: '', start: '1700000000000000000', end: '1700000003600000000', timezone: 'UTC', generation: 0 };

describe('navigation state in the URL', () => {
 test('round trips IDs, nanosecond strings and time zone exactly', () => {
  const nav = decodeHash(encodeHash(ctx, 'services', P), 5);
  expect(nav.context).toEqual({ ...ctx, generation: 5 });
  expect([nav.section, nav.service]).toEqual(['services', P]);
 });
 test('nanoseconds beyond 2^53 stay exact', () => { expect(decodeHash(encodeHash({ ...ctx, start: '9007199254740993', end: '9007199254740995' }, 'queue'), 0).context?.start).toBe('9007199254740993'); });
 test('anything but IDs and nanoseconds is rejected, not trusted', () => {
  for (const hash of [
   `#org=${A}&projects=${P}&start=1&end=1&tz=UTC`, `#org=${A}&projects=${P}&start=2&end=1&tz=UTC`, `#org=${A}&projects=${P}&start=1&end=9223372036854775808&tz=UTC`,
   `#org=nope&projects=${P}&start=1&end=2&tz=UTC`, `#org=${A}&projects=${P},${P}&start=1&end=2&tz=UTC`, `#org=${A}&projects=&start=1&end=2&tz=UTC`,
   `#org=${A}&projects=${P}&start=1&end=2&tz=Not/AZone`, `#org=${A}&projects=${P}&start=1e3&end=2&tz=UTC`, `#org=${A}&projects=${P}&start=1&end=2&tz=UTC&service=<img>`,
  ]) expect(decodeHash(hash, 0).context).toBeNull();
 });
 test('the URL carries no query text, credential or telemetry', () => { expect(encodeHash(ctx, 'queue')).toMatch(/^#org=[0-9a-f]{32}&projects=[0-9a-f%C]+&start=\d+&end=\d+&tz=UTC&view=queue$/i); });
 test('window validation', () => { expect(validWindow('0', '1')).toBe(true); expect(validWindow('1', '1')).toBe(false); expect(validWindow('01', '2')).toBe(false); });
 test('window ends at now with a whole-nanosecond start', () => { expect(windowEndingAt(120_000, 1)).toEqual({ start: '60000000000', end: '120000000000' }); expect(windowEndingAt(1_000, 1)).toEqual({ start: '0', end: '1000000000' }); });
 test('scope key ignores presentation but not data scope', () => {
  expect(scopeKey({ ...ctx, timezone: 'Europe/Berlin', generation: 9 })).toBe(scopeKey(ctx));
  for (const other of [{ org: 'b'.repeat(32) }, { projects: [P] }, { start: '1' }, { end: '1700000003600000001' }]) expect(scopeKey({ ...ctx, ...other })).not.toBe(scopeKey(ctx));
 });
});

describe('latestOnly drops responses of an older scope', () => {
 test('a slower older read can never publish after a newer one began', () => {
  const gate = latestOnly();
  const a = gate.begin();
  expect(a.current()).toBe(true);
  const b = gate.begin();
  expect(a.signal.aborted).toBe(true);
  expect(a.current()).toBe(false);
  expect(b.current()).toBe(true);
 });
 test('stop ends the current read', () => {
  const gate = latestOnly();
  const a = gate.begin();
  gate.stop();
  expect(a.current()).toBe(false);
 });
});
