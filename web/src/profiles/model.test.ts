// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import { ApiFault } from '../api/types';
import {
 baseView, browserUnsupportedView, capability, engineSample, frame, interval, lossView, missingWakeView, nativeCpuView, nativeSample, notAvailable, offCpuView, ORG, PROFILE, PROJECT, responseOf, runtimeCpuView, stack, want,
} from './fixture';
import {
 capabilityRows, correlationOf, correlationWords, coverageRows, flame, frameList, frameText, groupDigits, headerFacts, linkLines, lossFacts, MAX_OBSERVATIONS, parseProfileResponse, sampleCoverageLines, sampling, stateWords, timeline, unitRows, utcText,
 type UnitRow,
} from './model';
import type { ProfileResponse, ProfileView } from './types';

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;
const refuses = (raw: unknown): void => {
 let thrown: unknown;
 try { parseProfileResponse(raw, want); } catch (e) { thrown = e; }
 expect(thrown).toBeInstanceOf(ApiFault);
 expect((thrown as ApiFault).code).toBe('invalid_response');
};
const mutate = (make: () => ProfileView, edit: (v: Record<string, unknown>) => void): void => {
 const r = clone(responseOf(make())) as unknown as { view: Record<string, unknown> };
 edit(r.view);
 refuses(r);
};
const row = (rows: UnitRow[], id: UnitRow['id']): UnitRow => rows.find((r) => r.id === id) as UnitRow;

describe('parseProfileResponse accepts only what it asked for', () => {
 test('every fixture shape round-trips through JSON, and an absent total stays absent', () => {
  for (const make of [nativeCpuView, runtimeCpuView, offCpuView, missingWakeView, lossView, () => browserUnsupportedView()]) {
   const r = parseProfileResponse(clone(responseOf(make())), want);
   expect(r.view?.profile_id).toBe(PROFILE);
  }
  const native = parseProfileResponse(clone(responseOf(nativeCpuView())), want).view as ProfileView;
  expect('blocked_ns' in native).toBe(false);
  expect('runnable_ns' in native).toBe(false);
  expect('unknown_ns' in native).toBe(false);
  expect(parseProfileResponse(clone(notAvailable()), want).view).toBeUndefined();
 });
 test('a Go nil slice (JSON null) reads as an empty list', () => {
  const r = clone(responseOf(baseView())) as unknown as { view: Record<string, unknown> };
  for (const k of ['frames', 'stacks', 'samples', 'intervals', 'capabilities', 'loss', 'links', 'watermarks', 'reasons']) r.view[k] = null;
  const v = parseProfileResponse(r, want).view as ProfileView;
  expect(v.frames).toEqual([]);
  expect(v.reasons).toEqual([]);
  expect(v.capabilities).toEqual([]);
 });
 test('another org, project or profile is a fault, never rendered', () => {
  for (const key of ['org', 'project', 'profile'] as const) refuses({ ...clone(responseOf(nativeCpuView())), [key]: 'f'.repeat(32) });
  mutate(nativeCpuView, (v) => { v.profile_id = 'f'.repeat(32); });
  mutate(nativeCpuView, (v) => { v.project_id = 'f'.repeat(32); });
  refuses(null);
  refuses([]);
 });
 test('a nanosecond or count JSON number is a fault: a timestamp must never pass through a JavaScript number', () => {
  mutate(nativeCpuView, (v) => { ((v.samples as Record<string, unknown>[])[0] as Record<string, unknown>).at_ns = 5000000000; });
  mutate(nativeCpuView, (v) => { ((v.samples as Record<string, unknown>[])[0] as Record<string, unknown>).count = 1; });
  mutate(nativeCpuView, (v) => { (v.clock as Record<string, unknown>).wall_ns = 1700000000000000000; });
  mutate(nativeCpuView, (v) => { v.loss_count = 0; });
  mutate(nativeCpuView, (v) => { (((v.capabilities as Record<string, unknown>[])[0] as { value: Record<string, unknown> }).value).expires_ns = 1700000000000000000; });
  mutate(offCpuView, (v) => { v.blocked_ns = 80000000; });
  mutate(offCpuView, (v) => { ((v.intervals as Record<string, unknown>[])[0] as Record<string, unknown>).end_ns = 40000000; });
  mutate(nativeCpuView, (v) => { (((v.samples as Record<string, unknown>[])[0] as { native: Record<string, unknown> }).native).period = 10101010; });
 });
 test('a malformed decimal or one beyond 64 bits is a fault', () => {
  mutate(offCpuView, (v) => { v.blocked_ns = '-1'; });
  mutate(offCpuView, (v) => { v.blocked_ns = '18446744073709551616'; });
  mutate(offCpuView, (v) => { v.blocked_ns = '01'; });
  mutate(offCpuView, (v) => { v.blocked_ns = '1.5'; });
  mutate(nativeCpuView, (v) => { ((v.samples as Record<string, unknown>[])[0] as Record<string, unknown>).count = '0'; });
 });
 test('an out-of-range stack or frame index is a fault', () => {
  mutate(nativeCpuView, (v) => { ((v.samples as Record<string, unknown>[])[0] as Record<string, unknown>).stack = 3; });
  mutate(nativeCpuView, (v) => { ((v.samples as Record<string, unknown>[])[0] as Record<string, unknown>).stack = -1; });
  mutate(offCpuView, (v) => { ((v.intervals as Record<string, unknown>[])[0] as Record<string, unknown>).stack = 99; });
  mutate(nativeCpuView, (v) => { ((v.stacks as { frames: number[] }[])[0] as { frames: number[] }).frames = [0, 4]; });
  mutate(nativeCpuView, (v) => { ((v.stacks as { frames: number[] }[])[0] as { frames: number[] }).frames = [-1]; });
  mutate(nativeCpuView, (v) => { ((v.stacks as { frames: unknown[] }[])[0] as { frames: unknown[] }).frames = [0.5]; });
 });
 test('an unknown enum is a fault: method, units, state, status, coverage, kind, completeness, relation, native loss reason', () => {
  mutate(runtimeCpuView, (v) => { v.method = 'wall_clock'; });
  mutate(runtimeCpuView, (v) => { v.units = 'cycles'; });
  mutate(nativeCpuView, (v) => { v.units = 'cycles'; });
  mutate(nativeCpuView, (v) => { v.completeness = 'mostly'; });
  mutate(nativeCpuView, (v) => { (((v.capabilities as Record<string, unknown>[])[0] as { value: Record<string, unknown> }).value).status = 'maybe'; });
  mutate(nativeCpuView, (v) => { ((((v.capabilities as Record<string, unknown>[])[0] as { value: { coverage: Record<string, unknown> } }).value).coverage).frames = 'most'; });
  mutate(offCpuView, (v) => { ((v.intervals as Record<string, unknown>[])[0] as Record<string, unknown>).kind = 'sleeping'; });
  mutate(lossView, (v) => { ((v.native_loss as Record<string, unknown>[])[0] as Record<string, unknown>).reason = 'vanished'; });
  mutate(nativeCpuView, (v) => { v.links = [{ available: true, reference: { project_id: PROJECT, build_id: 'a'.repeat(32), kind: 'trace', id: 'b'.repeat(32), relation: 'guessed' } }]; });
  refuses({ ...clone(responseOf(nativeCpuView())), state: 'great' });
 });
 test('a response whose state and view disagree is a fault', () => {
  refuses({ ...clone(responseOf(nativeCpuView())), view: undefined });
  refuses({ ...clone(notAvailable()), view: clone(nativeCpuView()) });
  refuses({ ...clone(responseOf(nativeCpuView())), state: 'empty' });
  // a partial view labelled ready, a complete view labelled incomplete
  refuses({ ...clone(responseOf(lossView())), state: 'ready', partial: false });
  refuses({ ...clone(responseOf(lossView())), state: 'ready' });
  refuses({ ...clone(responseOf(lossView())), partial: false });
  refuses({ ...clone(responseOf(nativeCpuView())), state: 'incomplete', partial: true });
  refuses({ ...clone(responseOf(nativeCpuView())), state: 'incomplete' });
  refuses({ ...clone(notAvailable()), partial: true });
 });
 test('native evidence must agree with its units, and an optional total is absent, not null', () => {
  mutate(() => nativeCpuView({ units: 'nanoseconds' }), () => undefined);
  mutate(() => offCpuView({ units: 'samples' }), () => undefined);
  mutate(() => runtimeCpuView({ native_domain: { host_id: 'h', boot_id: 'b' } }), () => undefined);
  mutate(offCpuView, (v) => { v.blocked_ns = null; });
 });
 test('links: an available link names its target, a hidden one names nothing', () => {
  mutate(nativeCpuView, (v) => { v.links = [{ available: true }]; });
  mutate(nativeCpuView, (v) => { v.links = [{ available: false, reference: { project_id: PROJECT, build_id: 'a'.repeat(32), kind: 'trace', id: 'b'.repeat(32), relation: 'explicit' } }]; });
 });
 test('oversized lists are a fault', () => {
  mutate(nativeCpuView, (v) => { v.frames = Array.from({ length: 8193 }, () => frame('m', 'f', '0')); });
  mutate(baseView, (v) => { v.samples = Array.from({ length: MAX_OBSERVATIONS + 1 }, () => engineSample(0, 0, '1')); v.stacks = [{ frames: [] }]; });
  mutate(baseView, (v) => { v.stacks = [{ frames: Array.from({ length: 129 }, () => 0) }]; v.frames = [frame('m', 'f', '0')]; });
  mutate(nativeCpuView, (v) => { v.capabilities = Array.from({ length: 513 }, () => capability('native_cpu')); });
  mutate(nativeCpuView, (v) => { v.reasons = Array.from({ length: 65 }, () => 'coverage_incomplete'); });
  mutate(lossView, (v) => { v.native_loss = Array.from({ length: 257 }, () => ({ at_ns: '1', cpu: 0, count: '1', reason: 'records_lost' })); });
  refuses({ ...clone(responseOf(nativeCpuView())), sections: Array.from({ length: 33 }, () => ({ name: 'profile', state: 'ready' })) });
 });
 test('text from the profile is bounded and not a code where a code is required', () => {
  mutate(nativeCpuView, (v) => { ((v.frames as Record<string, unknown>[])[0] as Record<string, unknown>).function = 'x'.repeat(1025); });
  mutate(nativeCpuView, (v) => { ((v.frames as Record<string, unknown>[])[2] as Record<string, unknown>).reason = '<img src=x>'; });
  mutate(nativeCpuView, (v) => { v.next_cursor = ''; });
 });
 test('interval end before start is a fault', () => {
  mutate(offCpuView, (v) => { const i = (v.intervals as Record<string, unknown>[])[0] as Record<string, unknown>; i.start_ns = '9'; i.end_ns = '5'; });
 });
 test('text-like fields carrying markup are accepted as data (they are rendered only as text)', () => {
  const canary = '<img src=x onerror="1"> & <script>1</script>';
  const r = clone(responseOf(nativeCpuView())) as unknown as { view: ProfileView };
  r.view.frames[0] = frame(canary, canary, '1', '', canary);
  expect(parseProfileResponse(r, want).view?.frames[0]?.function).toBe(canary);
 });
});

describe('numbers and times are exact', () => {
 test('counts beyond 2^53 keep every digit', () => {
  expect(groupDigits('9007199254740993')).toBe('9,007,199,254,740,993');
  expect(groupDigits(1234567n)).toBe('1,234,567');
  expect(groupDigits('-1234')).toBe('-1,234');
  expect(groupDigits(7)).toBe('7');
  const v = runtimeCpuView({ samples: [engineSample(0, 0, '9007199254740993'), engineSample(1, 0, '9007199254740993')] });
  expect(row(unitRows(v), 'engine').text).toContain('18,014,398,509,481,986 samples');
 });
 test('expiry and instants are exact UTC text computed from BigInt', () => {
  expect(utcText(1_700_000_000_123_456_789n)).toBe('2023-11-14T22:13:20.123456789 UTC');
  expect(utcText(0n)).toBe('1970-01-01T00:00:00.000000000 UTC');
  expect(utcText(-1n)).toBe('1969-12-31T23:59:59.999999999 UTC');
  expect(utcText(9_223_372_036_854_775_807n)).toBe('2262-04-11T23:47:16.854775807 UTC');
  expect(utcText(-9_223_372_036_854_775_808n)).toBe('1677-09-21T00:12:43.145224192 UTC');
 });
});

describe('five readings that are never added together', () => {
 test('native on-CPU samples: a count with its unit, period and requested rate; every other reading is not measured, never 0', () => {
  const rows = unitRows(nativeCpuView());
  const os = row(rows, 'oscpu');
  expect(os.state).toBe('measured');
  expect(os.text).toContain('5 on-CPU samples');
  expect(os.text).toContain('unit cpu_clock_nanoseconds');
  expect(os.text).toContain('period 10,101,010 cpu_clock_nanoseconds per sample');
  expect(os.text).toContain('requested 99 Hz');
  expect(row(rows, 'engine').text).toBe('not measured');
  for (const id of ['blocked', 'runnable', 'unknown-split'] as const) {
   expect(row(rows, id).state).toBe('not_measured');
   expect(row(rows, id).text).toBe('not measured');
  }
 });
 test('engine samples are engine-reported and are not OS samples', () => {
  const rows = unitRows(runtimeCpuView());
  expect(row(rows, 'engine').text).toBe('10 samples, engine-reported');
  expect(row(rows, 'oscpu').text).toBe('not measured');
  const ns = unitRows(runtimeCpuView({ units: 'nanoseconds' }));
  expect(row(ns, 'engine').text).toBe('10 ns, engine-reported deltas');
  expect(row(ns, 'oscpu').text).toBe('not measured');
 });
 test('blocked time and runnable delay are separate readings and are not summed or relabelled as CPU', () => {
  const rows = unitRows(offCpuView());
  expect(row(rows, 'blocked').text).toContain('80 ms');
  expect(row(rows, 'blocked').text).toContain('exactly 80,000,000 ns');
  expect(row(rows, 'runnable').text).toContain('15 ms');
  expect(row(rows, 'blocked').text).toContain('1 censored');
  expect(row(rows, 'oscpu').text).toBe('not measured');
  expect(row(rows, 'engine').text).toBe('not measured');
  expect(row(rows, 'unknown-split').text).toBe('not measured');
  for (const r of rows) expect(r.text).not.toContain('95 ms');
 });
 test('a missing wake reads unknown split for blocked and runnable and keeps the off-CPU time apart', () => {
  const rows = unitRows(missingWakeView());
  expect(row(rows, 'blocked').state).toBe('unknown_split');
  expect(row(rows, 'blocked').text).toContain('unknown split');
  expect(row(rows, 'runnable').state).toBe('unknown_split');
  expect(row(rows, 'runnable').text).toContain('unknown split');
  expect(row(rows, 'blocked').text).not.toContain('55 ms');
  expect(row(rows, 'runnable').text).not.toContain('55 ms');
  expect(row(rows, 'unknown-split').text).toContain('55 ms');
  expect(row(rows, 'unknown-split').text).toContain('unknown split');
 });
 test('unknown intervals without a reported total still read unknown split', () => {
  const v = missingWakeView();
  delete v.unknown_ns;
  const rows = unitRows(v);
  expect(row(rows, 'unknown-split').state).toBe('unknown_split');
  expect(row(rows, 'blocked').state).toBe('unknown_split');
 });
 test('a measured blocked time with unknown time elsewhere keeps its figure; the absent runnable reads unknown split', () => {
  const v = offCpuView({ intervals: [interval('blocked', 0, 40, 0), interval('unknown_offcpu', 100, 130, 0, { reason: 'coverage_unmeasured' })], blocked_ns: '40000000', unknown_ns: '30000000' });
  delete v.runnable_ns;
  const rows = unitRows(v);
  expect(row(rows, 'blocked').text).toContain('40 ms');
  expect(row(rows, 'runnable').state).toBe('unknown_split');
 });
 test('a method that has a capability and zero observations reads no observations, not zero', () => {
  const off = unitRows(offCpuView({ intervals: [], blocked_ns: undefined as never, runnable_ns: undefined as never }));
  for (const id of ['blocked', 'runnable', 'unknown-split'] as const) expect(row(off, id).text).toBe('no observations');
  expect(row(unitRows(nativeCpuView({ samples: [] })), 'oscpu').text).toBe('no observations');
  expect(row(unitRows(runtimeCpuView({ samples: [] })), 'engine').text).toBe('no observations');
 });
 test('an unsupported, denied or errored method reads its own word and never zero or an empty reading', () => {
  for (const status of ['unsupported', 'denied', 'error'] as const) {
   const rows = unitRows(browserUnsupportedView(status));
   const e = row(rows, 'engine');
   expect(e.state).toBe(status);
   expect(e.text.startsWith(`${status}:`)).toBe(true);
   expect(e.text).not.toMatch(/^0/);
   expect(e.text).toContain('Nothing was measured');
   expect(row(rows, 'oscpu').text).toBe('not measured');
  }
 });
 test('an unsupported native method reads unsupported in its own row even with no samples', () => {
  const v = nativeCpuView({ samples: [], capabilities: [capability('native_cpu', { status: 'unsupported', reason: 'platform_unsupported' }), capability('native_offcpu', { status: 'denied', reason: 'permission_denied' })] });
  const rows = unitRows(v);
  expect(row(rows, 'oscpu').state).toBe('unsupported');
  expect(row(rows, 'blocked').state).toBe('denied');
  expect(row(rows, 'runnable').state).toBe('denied');
  expect(row(rows, 'unknown-split').state).toBe('denied');
 });
});

describe('requested versus achieved sampling', () => {
 test('native: requested is the requested rate, achieved is only the reported period', () => {
  const s = sampling(nativeCpuView());
  expect(s.requested).toBe('99 Hz');
  expect(s.achieved).toContain('period 10,101,010 cpu_clock_nanoseconds per sample');
  expect(s.achieved).toContain('as reported');
  expect(s.achieved).not.toContain('Hz');
 });
 test('an engine profile has no reported interval and none is invented', () => {
  const s = sampling(runtimeCpuView());
  expect(s).toEqual({ requested: 'not reported', achieved: 'not reported' });
  expect(sampling(offCpuView())).toEqual({ requested: 'not reported', achieved: 'not reported' });
 });
 test('a zero requested rate is not reported; several periods are all listed up to a bound', () => {
  const zero = nativeCpuView({ samples: [nativeSample(0, 0, { requested_hz: 0 })] });
  expect(sampling(zero).requested).toBe('not reported');
  const many = nativeCpuView({ samples: Array.from({ length: 7 }, (_, i) => nativeSample(i, 0, { period: String(100 + i) })) });
  expect(sampling(many).achieved).toContain('2 other period values');
 });
});

describe('header facts and capabilities', () => {
 test('engine, version, build, OS and architecture come from the capability of this method; absent facts read not reported', () => {
  const facts = Object.fromEntries(headerFacts(runtimeCpuView()).map((f) => [f.label, f.value]));
  expect(facts['Engine or runtime']).toBe('node 22.3.0');
  expect(facts['Build']).toBe('v8-12.4');
  expect(facts['Operating system and architecture']).toBe('linux / amd64');
  expect(facts['Method']).toContain('runtime_cpu');
  expect(facts['Units']).toContain('samples');
  expect(facts['Clock uncertainty']).toContain('250 µs');
  expect(facts['Clock domain']).toContain('1'.repeat(32));
  const bare = Object.fromEntries(headerFacts(baseView()).map((f) => [f.label, f.value]));
  expect(bare['Engine or runtime']).toBe('not reported');
  expect(bare['Build']).toBe('not reported');
 });
 test('each status is a distinct word', () => {
  const words = new Set((['supported', 'denied', 'unsupported', 'error'] as const).map((status) => capabilityRows(nativeCpuView({ capabilities: [capability('native_cpu', { status })] }))[0]?.statusWord));
  expect(words.size).toBe(4);
  expect([...words].map((w) => (w ?? '').split(' ')[0]).sort()).toEqual(['denied', 'error', 'supported', 'unsupported']);
 });
 test('expiry is exact UTC text and observations are counted per method; a zero count reads no observations', () => {
  const [cpu, off, split] = capabilityRows(nativeCpuView());
  expect(cpu?.expires).toBe('expires 2023-11-14T23:13:20.000000000 UTC');
  expect(cpu?.observations).toBe('5 observations');
  expect(off?.observations).toContain('not part of this view');
  expect(split?.observations).toContain('not part of this view');
  expect(capabilityRows(nativeCpuView({ samples: [] }))[0]?.observations).toBe('no observations');
  expect(capabilityRows(browserUnsupportedView())[0]?.observations).toContain('unsupported');
  expect(capabilityRows(browserUnsupportedView())[0]?.observations).not.toMatch(/^0/);
 });
 test('coverage is stated per capability and per sample', () => {
  const rows = coverageRows(nativeCpuView());
  expect(rows[0]).toMatchObject({ frames: 'partial (some are missing)', threads: 'complete', workers: 'none (not covered)', tasks: 'unknown (not measured)' });
  const lines = sampleCoverageLines(nativeCpuView());
  expect(lines.some((l) => l.includes('incomplete frame coverage') && l.includes('frame_unresolved'))).toBe(true);
  expect(lines.some((l) => l.includes('truncated') && l.includes('callchain_truncated'))).toBe(true);
 });
});

describe('loss and truncation are stated and never interpolated', () => {
 test('loss_count, kernel losses, throttling, truncation and loss reports are words', () => {
  const f = lossFacts(lossView());
  const all = f.lines.join('\n');
  expect(all).toContain('Lost records counted for this profile: 12.');
  expect(all).toContain('Truncated: yes');
  expect(all).toContain('Kernel records lost: 12 on cpu 2.');
  expect(all).toContain('Sampling was throttled by the kernel 1 time on cpu 2');
  expect(all).toContain('No stack, sample or interval is invented');
  expect(f.reports).toHaveLength(1);
  expect(f.reports[0]?.reason).toContain('ring_overflow');
  expect(f.reports[0]?.count).toBe('12');
 });
 test('a profile with no loss says none was reported and does not claim none occurred', () => {
  const all = lossFacts(nativeCpuView()).lines.join('\n');
  expect(all).toContain('none were counted');
  expect(all).toContain('Truncated: no');
  expect(all).toContain('does not prove');
 });
 test('lost time is a loss row and a gap row; no sample or interval is invented for it', () => {
  const v = lossView();
  const t = timeline(v, 1000);
  expect(t.counts.sample).toBe(5);
  expect(t.counts.loss).toBe(2);
  expect(t.counts.gap).toBe(1);
  expect(t.total).toBe(5 + 2 + 1);
  const gap = t.rows.find((r) => r.kind === 'gap');
  expect(gap?.notes.join(' ')).toContain('no samples recorded');
  expect(gap?.notes.join(' ')).toContain('nothing is filled in');
  expect(gap?.stack).toBe('none');
  const loss = t.rows.find((r) => r.kind === 'loss');
  expect(loss?.stack).toContain('nothing was recorded');
  expect(t.rows.filter((r) => r.kind === 'sample')).toHaveLength(v.samples.length);
 });
 test('gaps between intervals of a thread are stated, and a back-to-back wait has none', () => {
  const t = timeline(offCpuView(), 1000);
  // blocked 0-40 and runnable 40-55 touch; the next blocked wait starts at 100 on the same thread.
  expect(t.counts.gap).toBe(1);
  expect(t.rows.find((r) => r.kind === 'gap')?.notes.join(' ')).toContain('no interval recorded');
  const touching = timeline(offCpuView({ intervals: [interval('blocked', 0, 40, 0), interval('runnable', 40, 55, 0)] }), 1000);
  expect(touching.counts.gap).toBe(0);
 });
 test('regular samples make no gap, and at most max rows come back with the full total', () => {
  const regular = nativeCpuView({ samples: Array.from({ length: 10 }, (_, i) => nativeSample(i * 10, 0)) });
  expect(timeline(regular, 1000).counts.gap).toBe(0);
  const t = timeline(regular, 4);
  expect(t.rows).toHaveLength(4);
  expect(t.total).toBe(10);
 });
 test('timeline rows are in time order with offsets from the earliest observation', () => {
  const t = timeline(nativeCpuView({ samples: [nativeSample(30, 0), nativeSample(10, 0), nativeSample(20, 0)] }), 100);
  expect(t.rows.map((r) => r.offset)).toEqual(['+0 ns', '+10 ms', '+20 ms']);
  expect(t.rows[0]?.quantity).toBe('1 OS on-CPU sample');
  expect(timeline(runtimeCpuView(), 100).rows[0]?.quantity).toBe('3 samples, engine-reported');
 });
 test('an empty profile has an empty timeline', () => {
  expect(timeline(baseView(), 10)).toMatchObject({ rows: [], total: 0 });
 });
});

describe('frames', () => {
 test('an unresolved frame reads unresolved frame with its reason; module, function, offset and artifact are text', () => {
  expect(frameText(frame('', '', '0', 'frame_unresolved'))).toBe('unresolved frame (frame_unresolved)');
  expect(frameText(frame('app-binary', '', '8192', 'artifact_unavailable', 'e'.repeat(32)))).toBe(`unresolved frame (artifact_unavailable), module app-binary, offset 8,192, artifact ${'e'.repeat(32)}`);
  expect(frameText(frame('libc', 'memcpy', '128'))).toBe('memcpy, module libc, offset 128');
  expect(frameText(frame('', '', '0'))).toBe('unnamed function');
 });
 test('the frame list weighs each frame once per stack and keeps weights of different kinds apart', () => {
  const l = frameList(offCpuView(), 100);
  const top = l.rows.find((r) => r.text.startsWith('handle_request'));
  expect(top?.w.samples).toBe(0n);
  expect(top?.w.blocked).toBe(80_000_000n);
  expect(top?.w.runnable).toBe(15_000_000n);
  expect(top?.w.unknown).toBe(0n);
  expect(l.present).toEqual({ samples: false, blocked: true, runnable: true, unknown: false });
  const mixed = frameList(nativeCpuView({ intervals: [interval('blocked', 0, 40, 0)] }), 100);
  const m = mixed.rows.find((r) => r.text.startsWith('handle_request'));
  expect(m?.w.samples).toBe(4n);
  expect(m?.w.blocked).toBe(40_000_000n);
 });
 test('frames repeated across chunks are one frame, and the list is bounded', () => {
  const v = baseView({ frames: [frame('m', 'f', '1'), frame('m', 'f', '1')], stacks: [stack(0), stack(1)], samples: [engineSample(0, 0, '2'), engineSample(1, 1, '3')], method: 'runtime_cpu' });
  const l = frameList(v, 100);
  expect(l.rows).toHaveLength(1);
  expect(l.rows[0]?.w.samples).toBe(5n);
  const bounded = frameList(nativeCpuView(), 2);
  expect(bounded.rows).toHaveLength(2);
  expect(bounded.total).toBe(4);
 });
 test('the stack tree nests frames in recorded order, aggregated by count, and is bounded', () => {
  const f = flame(nativeCpuView(), 100);
  const lines = f.rows.map((r) => `${r.depth}:${r.text.split(',')[0]}:${r.w.samples}`);
  expect(lines).toEqual(['0:handle_request:4', '1:memcpy:3', '1:unresolved frame (frame_unresolved):1', '0:unresolved frame (artifact_unavailable):1']);
  const cut = flame(nativeCpuView(), 2);
  expect(cut.rows).toHaveLength(2);
  expect(cut.total).toBe(4);
 });
 test('an observation without frames is a line that says so', () => {
  const v = baseView({ method: 'runtime_cpu', stacks: [stack()], samples: [engineSample(0, 0, '4')] });
  expect(flame(v, 10).rows.map((r) => r.text)).toEqual(['no frames recorded']);
  expect(timeline(v, 10).rows[0]?.stack).toBe('no frames recorded');
 });
});

describe('links and correlation', () => {
 const link = (relation: 'explicit' | 'time_overlap_inference', kind = 'trace', available = true): ProfileView['links'][number] => (available ? { available, reference: { project_id: PROJECT, build_id: 'a'.repeat(32), kind, id: '9'.repeat(32), relation } } : { available });
 test('only an explicit, available link to a trace is an exact request link', () => {
  expect(correlationOf(nativeCpuView({ links: [link('explicit')] }))).toEqual({ kind: 'exact', request: '9'.repeat(32) });
  expect(correlationOf(nativeCpuView({ links: [link('explicit', 'replay')] }))).toEqual({ kind: 'none' });
  expect(correlationOf(nativeCpuView({ links: [link('explicit', 'trace', false)] }))).toEqual({ kind: 'none' });
  expect(correlationOf(nativeCpuView({ links: [link('time_overlap_inference')] }))).toEqual({ kind: 'thread_overlap' });
  expect(correlationOf(nativeCpuView({ links: [link('time_overlap_inference'), link('explicit')] }))).toEqual({ kind: 'exact', request: '9'.repeat(32) });
  expect(correlationOf(nativeCpuView())).toEqual({ kind: 'none' });
 });
 test('correlation in words', () => {
  expect(correlationWords({ kind: 'exact', request: 'abc' })).toBe('exact request link: abc');
  expect(correlationWords({ kind: 'thread_overlap' })).toBe('overlaps in time on a thread; not attributed to a request');
  expect(correlationWords({ kind: 'none' })).toBe('no request link');
 });
 test('links are text; a hidden link names nothing', () => {
  const lines = linkLines(nativeCpuView({ links: [link('explicit'), link('time_overlap_inference', 'replay'), link('explicit', 'trace', false)] })).map((l) => l.text);
  expect(lines[0]).toBe(`trace ${'9'.repeat(32)} (explicit link): available`);
  expect(lines[1]).toContain('inferred from overlap in time; not a causal link');
  expect(lines[2]).toBe('A linked item: not available to this account');
 });
});

describe('state in words', () => {
 test('a ready response, a partial one and a service that is not wired are each their own sentence', () => {
  expect(stateWords(responseOf(nativeCpuView()))).toContain('State: Ready.');
  expect(stateWords(responseOf(nativeCpuView()))).toContain('Completeness: complete.');
  const partial = stateWords(responseOf(lossView()));
  expect(partial).toContain('State: Partial.');
  expect(partial).toContain('Completeness: partial.');
  expect(partial).toContain('coverage_incomplete');
  const nw = stateWords(notAvailable());
  expect(nw).toContain('State: Not available.');
  expect(nw).toContain('profile_service_not_wired');
  expect(nw).toContain('not an empty profile');
 });
 test('a response parsed for the wrong profile is refused with the same fault the client throws', () => {
  let fault: unknown;
  try { parseProfileResponse(clone(responseOf(nativeCpuView())), { org: ORG, project: PROJECT, profile: 'e'.repeat(32) }); } catch (e) { fault = e; }
  expect((fault as ApiFault).detail).toBe('response does not match the request');
  const r: ProfileResponse = parseProfileResponse(clone(responseOf(nativeCpuView())), want);
  expect(r.sections[0]?.name).toBe('profile');
 });
});

describe('engine capability named by the SDK runtime method', () => {
 test('an unsupported browser_js_self_profile capability makes the engine row read unsupported even though the chunk method is runtime_cpu', () => {
  const v = runtimeCpuView({ samples: [], capabilities: [capability('browser_js_self_profile', { runtime: 'firefox', status: 'unsupported', reason: 'api_unavailable' })] });
  const row = unitRows(v).find((r) => r.id === 'engine');
  expect(row?.state).toBe('unsupported');
  expect(row?.text).toContain('unsupported');
  expect(row?.text).not.toMatch(/\b0\b/);
 });
 test('a native capability never stands in for the engine row', () => {
  const v = runtimeCpuView({ samples: [], capabilities: [capability('native_cpu', { status: 'unsupported', reason: 'platform_unsupported' })] });
  expect(unitRows(v).find((r) => r.id === 'engine')?.state).toBe('no_observations');
 });
});
