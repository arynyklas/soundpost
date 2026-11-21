// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Server-rendered markup of the profile views. Function, module, artifact, runtime, reason and every other profile-derived string is untrusted:
// it must reach the page only as escaped text, and no state may rest on colour alone.
import { describe, expect, test } from 'bun:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { ViewContext } from '../app/context';
import {
 baseView, browserUnsupportedView, capability, engineSample, frame, interval, lossView, missingWakeView, nativeCpuView, nativeSample, notAvailable, offCpuView, ORG, PROJECT, PROFILE, responseOf, runtimeCpuView, stack,
} from './fixture';
import { ProfileDetails, ProfilePage } from './ProfilePage';
import { ProfileTimeline } from './ProfileTimeline';
import type { Correlation, ProfileView } from './types';

const CANARY = '<img src=x onerror="window.__pwn=1"> & <script>window.__pwn=2</script>';
const render = (el: React.ReactElement): string => renderToStaticMarkup(el);
const page = (view: ProfileView): string => render(React.createElement(ProfileDetails, { response: responseOf(view) }));
const timelineOf = (view: ProfileView, correlation: Correlation): string => render(React.createElement(ProfileTimeline, { view, correlation }));
const entities = (s: string): string => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#x27;/g, "'").replace(/&amp;/g, '&');
const textOf = (fragment: string): string => entities(fragment.replace(/<[^>]*>/g, ' ')).replace(/\s+/g, ' ').trim();

/** Every element carrying this data-testid, from its opening tag to its balanced closing tag. */
function regions(html: string, testid: string): string[] {
 const out: string[] = [];
 let from = 0;
 for (;;) {
  const at = html.indexOf(`data-testid="${testid}"`, from);
  if (at < 0) return out;
  const open = html.lastIndexOf('<', at);
  const name = (/^<([a-z0-9]+)/.exec(html.slice(open)) as RegExpExecArray)[1] as string;
  const re = new RegExp(`<(/?)${name}\\b[^>]*>`, 'g');
  re.lastIndex = open;
  let depth = 0;
  for (let m = re.exec(html); m !== null; m = re.exec(html)) {
   depth += m[1] === '' ? 1 : -1;
   if (depth === 0) { out.push(html.slice(open, re.lastIndex)); from = re.lastIndex; break; }
  }
  if (depth !== 0) return out;
 }
}
const one = (html: string, testid: string): string => {
 const r = regions(html, testid);
 expect(r.length).toBe(1);
 return r[0] as string;
};
const noElementsFromText = (html: string): void => {
 expect(html).not.toMatch(/<img/i);
 expect(html).not.toMatch(/<script/i);
 expect(html).not.toMatch(/<[a-z][^>"']*\sonerror\s*=/i);
 expect(html).toContain('&lt;img src=x onerror=');
};
// The cell that holds the value of a unit row.
const unitValue = (html: string, id: string): string => textOf(one(html, `unit-${id}`).replace(/<th[\s\S]*?<\/th>/, '').split('</td>')[0] as string);

describe('profile page markup: structure and hooks', () => {
 test('every named region exists, with headings, captions, scoped headers and labelled sections', () => {
  const html = page(nativeCpuView({ links: [{ available: true, reference: { project_id: PROJECT, build_id: 'a'.repeat(32), kind: 'trace', id: '9'.repeat(32), relation: 'explicit' } }] }));
  for (const id of ['profile-state', 'profile-method', 'profile-capabilities', 'profile-loss', 'profile-coverage', 'profile-correlation', 'frame-list', 'profile-timeline', 'unit-oscpu', 'unit-engine', 'unit-blocked', 'unit-runnable', 'unit-unknown-split', 'sampling-requested', 'sampling-achieved']) {
   expect(regions(html, id).length, id).toBeGreaterThanOrEqual(1);
  }
  expect(regions(html, 'capability-row')).toHaveLength(3);
  expect(html).toContain('<caption>');
  expect(html).toContain('scope="col"');
  expect(html).toContain('scope="row"');
  expect(html).toMatch(/<h3 id="pp-units-heading">/);
  expect(html).toContain('aria-labelledby="pp-units-heading"');
  expect(html).toContain('aria-labelledby="pt-heading"');
  expect(html).toMatch(/<h4 id="pf-heading">Frames<\/h4>/);
 });
 test('the page carries its heading, its status and the window sentence while loading, and names no data it has not read', () => {
  const context: ViewContext = { org: ORG, projects: [PROJECT], environment: '', start: '1700000000000000000', end: '1700000600000000000', timezone: 'UTC', generation: 1 };
  const html = render(React.createElement(ProfilePage, { id: PROFILE, project: PROJECT, context }));
  expect(html).toContain('<h2 id="profile-heading">Profile <code>' + PROFILE + '</code></h2>');
  expect(html).toContain('data-state="loading"');
  expect(html).toContain('Observations are read from');
  expect(html).not.toContain('data-testid="profile-state"');
  expect(html).not.toContain('capability-row');
 });
 test('no inline style, no link, no image, no script and no drawing surface is produced from profile data', () => {
  for (const v of [nativeCpuView(), runtimeCpuView(), offCpuView(), missingWakeView(), lossView(), browserUnsupportedView()]) {
   const html = page(v);
   expect(html).not.toMatch(/\sstyle=/i);
   expect(html).not.toMatch(/<(a|img|script|iframe|svg|canvas|object|embed|link)\b/i);
   expect(html).not.toContain('href=');
   expect(html).not.toContain('src=');
  }
 });
});

describe('the five readings are separate, labelled rows', () => {
 test('native on-CPU: sample count, unit, period and requested rate; the others read not measured', () => {
  const html = page(nativeCpuView());
  const os = unitValue(html, 'oscpu');
  expect(os).toContain('5 on-CPU samples');
  expect(os).toContain('unit cpu_clock_nanoseconds');
  expect(os).toContain('period 10,101,010 cpu_clock_nanoseconds per sample');
  expect(os).toContain('requested 99 Hz');
  expect(unitValue(html, 'engine')).toBe('not measured');
  for (const id of ['blocked', 'runnable', 'unknown-split']) expect(unitValue(html, id)).toBe('not measured');
  expect(textOf(one(html, 'sampling-requested'))).toBe('99 Hz');
  expect(textOf(one(html, 'sampling-achieved'))).toContain('period 10,101,010');
 });
 test('five distinct row headers: no reading shares a row with another', () => {
  const html = page(offCpuView());
  const labels = ['unit-oscpu', 'unit-engine', 'unit-blocked', 'unit-runnable', 'unit-unknown-split'].map((id) => /<th scope="row">([^<]*)<\/th>/.exec(one(html, id))?.[1]);
  expect(new Set(labels).size).toBe(5);
  expect(labels).toEqual(['OS on-CPU samples', 'Engine-reported samples', 'Blocked time', 'Runnable delay', 'Off-CPU time with an unknown split']);
 });
 test('engine samples are labelled engine-reported and are not an OS sample count', () => {
  const html = page(runtimeCpuView());
  expect(unitValue(html, 'engine')).toBe('10 samples, engine-reported');
  expect(unitValue(html, 'oscpu')).toBe('not measured');
  expect(textOf(one(html, 'sampling-requested'))).toBe('not reported');
  expect(textOf(one(html, 'sampling-achieved'))).toBe('not reported');
  expect(html).not.toMatch(/\bHz\b/);
 });
 test('blocked time and runnable delay show their own figures and are never summed', () => {
  const html = page(offCpuView());
  expect(unitValue(html, 'blocked')).toContain('80 ms');
  expect(unitValue(html, 'runnable')).toContain('15 ms');
  expect(html).not.toContain('95 ms');
  expect(unitValue(html, 'oscpu')).toBe('not measured');
 });
 test('absent blocked, runnable and unknown totals read not measured and never 0', () => {
  const html = page(nativeCpuView());
  for (const id of ['blocked', 'runnable', 'unknown-split']) {
   expect(unitValue(html, id)).toBe('not measured');
   expect(one(html, `unit-${id}`)).toContain('data-state="not_measured"');
  }
  const cells = regions(html, 'unit-blocked').join('');
  expect(cells).not.toMatch(/<td>\s*0\b/);
 });
 test('a missing wake reads unknown split for blocked and runnable', () => {
  const html = page(missingWakeView());
  expect(unitValue(html, 'blocked')).toContain('unknown split');
  expect(unitValue(html, 'runnable')).toContain('unknown split');
  expect(unitValue(html, 'blocked')).not.toContain('55 ms');
  expect(unitValue(html, 'unknown-split')).toContain('55 ms');
  expect(one(html, 'unit-blocked')).toContain('data-state="unknown_split"');
 });
});

describe('capabilities: each status is a word', () => {
 test('supported, denied, unsupported and error each have a row with its own word and status attribute', () => {
  const v = nativeCpuView({
   capabilities: [capability('native_cpu'), capability('native_offcpu', { status: 'denied', reason: 'permission_denied' }), capability('native_runqueue_split', { status: 'unsupported', reason: 'platform_unsupported' }), capability('runtime_cpu', { status: 'error', reason: 'probe_failed', runtime: 'node' })],
  });
  const rows = regions(page(v), 'capability-row');
  expect(rows).toHaveLength(4);
  const words = rows.map((r) => [/data-status="([a-z]+)"/.exec(r)?.[1], textOf(/<td><strong>(.*?)<\/strong><\/td>/.exec(r)?.[1] ?? '')]);
  expect(words.map((w) => w[0])).toEqual(['supported', 'denied', 'unsupported', 'error']);
  expect(words.map((w) => (w[1] as string).split(' ')[0])).toEqual(['supported', 'denied', 'unsupported', 'error']);
 });
 test('engine, version, build, system, method, reason and expiry are on the row; expiry is exact UTC with the word expires', () => {
  const row = regions(page(runtimeCpuView()), 'capability-row')[0] as string;
  const t = textOf(row);
  expect(t).toContain('node 22.3.0, build v8-12.4');
  expect(t).toContain('linux / amd64');
  expect(t).toContain('runtime_cpu');
  expect(t).toContain('probed');
  expect(t).toContain('expires 2023-11-14T23:13:20.000000000 UTC');
 });
 test('header facts name method, engine, build, system, clock domain and uncertainty', () => {
  const html = page(runtimeCpuView());
  expect(textOf(one(html, 'profile-method'))).toContain('runtime_cpu');
  const t = textOf(html);
  expect(t).toContain('Engine or runtime node 22.3.0');
  expect(t).toContain('Build v8-12.4');
  expect(t).toContain('Operating system and architecture linux / amd64');
  expect(t).toContain('Clock uncertainty plus or minus 250 µs');
  expect(t).toContain(`Clock domain host ${'1'.repeat(32)}`);
 });
 test('an unsupported browser reads unsupported everywhere and draws no chart and no zero', () => {
  for (const status of ['unsupported', 'denied', 'error'] as const) {
   const html = page(browserUnsupportedView(status));
   expect(one(html, 'capability-row')).toContain(`data-status="${status}"`);
   expect(unitValue(html, 'engine').startsWith(`${status}:`)).toBe(true);
   expect(one(html, 'unit-engine')).toContain(`data-state="${status}"`);
   expect(unitValue(html, 'engine')).not.toMatch(/^0/);
   expect(regions(html, 'frame-list')).toHaveLength(0);
   expect(regions(html, 'stack-tree')).toHaveLength(0);
   expect(textOf(one(html, 'profile-timeline'))).toContain('no observations');
   expect(html).not.toMatch(/<td>\s*0\s*<\/td>/);
  }
 });
 test('a supported method with zero observations reads no observations, not zero', () => {
  const html = page(runtimeCpuView({ samples: [], completeness: 'partial', reasons: ['no_observations_in_window'] }));
  expect(unitValue(html, 'engine')).toBe('no observations');
  expect(textOf(one(html, 'capability-row'))).toContain('no observations');
  expect(unitValue(page(offCpuView({ intervals: [], blocked_ns: undefined as never, runnable_ns: undefined as never })), 'blocked')).toBe('no observations');
 });
 test('coverage is stated for frames, threads, workers and tasks', () => {
  const t = textOf(one(page(nativeCpuView()), 'profile-coverage'));
  expect(t).toContain('partial (some are missing)');
  expect(t).toContain('complete');
  expect(t).toContain('none (not covered)');
  expect(t).toContain('unknown (not measured)');
  expect(t).toContain('incomplete frame coverage');
  expect(textOf(one(page(baseView()), 'profile-coverage'))).toContain('No coverage was reported.');
 });
});

describe('loss, truncation and completeness are stated in words', () => {
 test('loss_count, kernel losses, throttling and truncation', () => {
  const html = page(lossView());
  const t = textOf(one(html, 'profile-loss'));
  expect(t).toContain('Lost records counted for this profile: 12.');
  expect(t).toContain('Kernel records lost: 12 on cpu 2.');
  expect(t).toContain('throttled by the kernel 1 time');
  expect(t).toContain('Truncated: yes');
  expect(t).toContain('ring overflow'.replace(' ', '_'));
  expect(textOf(one(html, 'profile-state'))).toContain('Completeness: partial.');
  expect(textOf(one(html, 'profile-state'))).toContain('coverage_incomplete');
 });
 test('lost time is a loss row and a gap row in the timeline, never a filled value', () => {
  const html = page(lossView());
  const tl = one(html, 'profile-timeline');
  expect(tl).toContain('data-kind="loss"');
  expect(tl).toContain('data-kind="gap"');
  expect(tl).toContain('data-gap="yes"');
  expect(textOf(tl)).toContain('no samples recorded from');
  expect(textOf(tl)).toContain('nothing is filled in');
  expect(textOf(tl)).toContain('none: nothing was recorded for this time');
  expect((tl.match(/data-kind="sample"/g) ?? []).length).toBe(5);
 });
 test('a clean profile says no loss was reported without claiming none occurred', () => {
  const t = textOf(one(page(nativeCpuView()), 'profile-loss'));
  expect(t).toContain('none were counted');
  expect(t).toContain('Truncated: no.');
  expect(t).toContain('does not prove');
 });
 test('a profile that is not available shows only its state, in words', () => {
  const html = render(React.createElement(ProfileDetails, { response: notAvailable() }));
  const t = textOf(one(html, 'profile-state'));
  expect(t).toContain('State: Not available.');
  expect(t).toContain('profile_service_not_wired');
  expect(t).toContain('not an empty profile');
  expect(html).not.toContain('capability-row');
  expect(html).not.toContain('unit-oscpu');
 });
});

describe('request correlation', () => {
 const only = (html: string): string => textOf(one(html, 'profile-correlation'));
 test('exact shows the request it is linked to', () => {
  const html = timelineOf(nativeCpuView(), { kind: 'exact', request: 'f'.repeat(32) });
  expect(only(html)).toContain(`exact request link: ${'f'.repeat(32)}`);
  expect(one(html, 'profile-correlation')).toContain('data-correlation="exact"');
 });
 test('an overlap in time on a thread is never attributed to a request', () => {
  const html = timelineOf(nativeCpuView(), { kind: 'thread_overlap' });
  expect(only(html)).toContain('overlaps in time on a thread; not attributed to a request');
  expect(html).not.toContain('exact request link');
  expect(html).not.toMatch(/cost of (the|a|this) request/i);
 });
 test('no link reads no request link', () => {
  const html = timelineOf(nativeCpuView(), { kind: 'none' });
  expect(only(html)).toContain('no request link');
  expect(html).not.toContain('exact request link');
 });
 test('the page derives it from the links: an explicit trace link is exact, a time-overlap inference is not', () => {
  const link = (relation: 'explicit' | 'time_overlap_inference'): ProfileView['links'] => [{ available: true, reference: { project_id: PROJECT, build_id: 'a'.repeat(32), kind: 'trace', id: '9'.repeat(32), relation } }];
  expect(textOf(one(page(nativeCpuView({ links: link('explicit') })), 'profile-correlation'))).toContain(`exact request link: ${'9'.repeat(32)}`);
  const overlap = page(nativeCpuView({ links: link('time_overlap_inference') }));
  expect(textOf(one(overlap, 'profile-correlation'))).toContain('not attributed to a request');
  expect(overlap).not.toContain('exact request link');
 });
 test('links render as text; a hidden link names nothing and nothing is a link element', () => {
  const html = page(nativeCpuView({ links: [{ available: true, reference: { project_id: PROJECT, build_id: 'a'.repeat(32), kind: 'trace', id: '9'.repeat(32), relation: 'explicit' } }, { available: false }] }));
  const t = textOf(one(html, 'profile-links'));
  expect(t).toContain(`trace ${'9'.repeat(32)} (explicit link): available`);
  expect(t).toContain('A linked item: not available to this account');
  expect(html).not.toContain('href=');
 });
});

describe('frames', () => {
 test('an unresolved frame reads unresolved frame with its reason, in the frame list and the stack tree', () => {
  const html = page(nativeCpuView());
  const list = one(html, 'frame-list');
  expect(textOf(list)).toContain('unresolved frame (frame_unresolved)');
  expect(textOf(list)).toContain(`unresolved frame (artifact_unavailable), module app-binary, offset 8,192, artifact ${'e'.repeat(32)}`);
  expect(list).toContain('data-unresolved="yes"');
  expect(textOf(one(html, 'stack-tree'))).toContain('unresolved frame (frame_unresolved)');
 });
 test('weights of different kinds are separate columns', () => {
  const html = page(nativeCpuView({ intervals: [interval('blocked', 0, 40, 0), interval('unknown_offcpu', 50, 70, 0, { reason: 'coverage_unmeasured' })], blocked_ns: '40000000', unknown_ns: '20000000' }));
  const head = textOf(/<thead>[\s\S]*?<\/thead>/.exec(one(html, 'frame-list'))?.[0] ?? '');
  expect(head).toBe('Frame Distinct stacks OS on-CPU samples Blocked time Off-CPU time, unknown split');
  expect(textOf(one(html, 'frame-list'))).toContain('handle_request, module app-binary, offset 4,096 2 4 40 ms 20 ms');
  expect(textOf(one(html, 'frame-list'))).toContain('unresolved frame (frame_unresolved) 1 1 none none');
 });
 test('the stack tree states its order and that the profile does not say which end is innermost', () => {
  const t = textOf(one(page(nativeCpuView()), 'stack-tree'));
  expect(t).toContain('in the order they were recorded');
  expect(t).toContain('does not say whether that is the outermost or the innermost frame');
 });
});

describe('timeline', () => {
 test('rows are text with a time offset, a kind, a thread, a quantity, a stack and notes; kinds of off-CPU time are labelled separately', () => {
  const html = page(offCpuView());
  const tl = one(html, 'profile-timeline');
  expect(tl).toContain('data-kind="blocked"');
  expect(tl).toContain('data-kind="runnable"');
  expect(textOf(tl)).toContain('+0 ns blocked 101 40 ms (exactly 40,000,000 ns)');
  expect(textOf(tl)).toContain('+40 ms runnable 101 15 ms (exactly 15,000,000 ns)');
  expect(textOf(tl)).toContain('censored: the end of this wait was not observed');
  expect(textOf(tl)).toContain('no interval recorded from');
 });
 test('a missing-wake interval is labelled with its unknown split and the reason', () => {
  const t = textOf(one(page(missingWakeView()), 'profile-timeline'));
  expect(t).toContain('unknown off-CPU (split unknown)');
  expect(t).toContain('coverage_unmeasured');
 });
 test('engine and OS samples are labelled by who measured them', () => {
  expect(textOf(one(page(runtimeCpuView()), 'profile-timeline'))).toContain('engine sample');
  expect(textOf(one(page(runtimeCpuView()), 'profile-timeline'))).toContain('3 samples, engine-reported');
  expect(textOf(one(page(nativeCpuView()), 'profile-timeline'))).toContain('OS on-CPU sample');
 });
 test('rendering is bounded and says so in words', () => {
  const samples = Array.from({ length: 4000 }, (_, i) => nativeSample(i * 10, i % 3));
  const frames = Array.from({ length: 1000 }, (_, i) => frame(`m${i}`, `f${i}`, String(i)));
  const stacks = Array.from({ length: 600 }, (_, i) => stack(i, i + 1, i + 2));
  const html = page(nativeCpuView({ frames, stacks, samples: samples.map((s, i) => ({ ...s, stack: i % 600 })) }));
  const t = textOf(html);
  expect(t).toContain('Showing the first 500 of 4000 timeline rows; the rest are not drawn.');
  expect(t).toContain('Showing the first 200 of');
  expect(t).toContain('frames; the rest are not drawn.');
  expect(t).toContain('Showing the first 500 of');
  expect(t).toContain('stack lines; the rest are not drawn.');
  expect((html.match(/data-kind="sample"/g) ?? []).length).toBe(500);
 });
 test('a next cursor says more observations exist and are not shown', () => {
  expect(textOf(one(page(nativeCpuView({ next_cursor: 'abc' })), 'profile-timeline'))).toContain('More observations exist beyond this page');
  expect(textOf(one(page(nativeCpuView()), 'profile-timeline'))).not.toContain('More observations exist');
 });
});

describe('untrusted profile text', () => {
 test('an XSS canary in function, module, artifact, reasons, runtime, loss and links is escaped everywhere', () => {
  const v = nativeCpuView({
   frames: [frame(CANARY, CANARY, '1', '', CANARY), frame(CANARY, CANARY, '2', 'frame_unresolved'), frame('', CANARY, '0', CANARY)],
   stacks: [stack(0, 1, 2)],
   samples: [nativeSample(0, 0, { coverage: CANARY, truncation: CANARY, throttle_reason: CANARY, unit: CANARY, method: CANARY }), nativeSample(10, 0)],
   intervals: [interval('unknown_offcpu', 0, 30, 0, { reason: CANARY })],
   unknown_ns: '30000000',
   capabilities: [capability('native_cpu', { runtime: CANARY, version: CANARY, build: CANARY, os: CANARY, arch: CANARY, reason: CANARY }), capability('runtime_cpu', { status: 'error', runtime: CANARY, reason: CANARY })],
   loss: [{ source: '4'.repeat(32), producer: '5'.repeat(32), producer_epoch: '6'.repeat(32), start_ns: '1', end_ns: '2', signal: CANARY, reason: CANARY, count: '1', last_ack: null, queue_bytes: '0', queue_records: '0' }],
   reasons: [CANARY],
   links: [{ available: true, reference: { project_id: PROJECT, build_id: 'a'.repeat(32), kind: CANARY, id: '9'.repeat(32), relation: 'explicit' } }],
   native_loss: [{ at_ns: '5000000000', cpu: 1, count: '1', reason: 'records_lost' }],
  });
  const html = render(React.createElement(ProfileDetails, { response: responseOf(v, { reason: CANARY }) }));
  noElementsFromText(html);
  expect((html.match(/&lt;img src=x onerror=/g) ?? []).length).toBeGreaterThanOrEqual(20);
  expect(html).not.toMatch(/\sstyle=/i);
  expect(html).not.toContain('href=');
  expect(html).not.toContain('dangerouslySetInnerHTML');
  expect(html).not.toMatch(/\son[a-z]+\s*=\s*"?window/i);
 });
 test('a canary in a thread, a task, a capability method and a link id stays inert text', () => {
  const v = runtimeCpuView({ samples: [{ ...engineSample(0, 0, '1'), thread: '1' }], capabilities: [capability('runtime_cpu', { method: 'runtime_cpu', runtime: 'x' }), capability(CANARY, { runtime: CANARY })] });
  const html = page(v);
  noElementsFromText(html);
 });
 test('canary text in the timeline and frame list stays text when the page is only the timeline', () => {
  const v = baseView({ method: 'runtime_cpu', frames: [frame(CANARY, CANARY, '1')], stacks: [stack(0)], samples: [engineSample(0, 0, '1')] });
  const html = timelineOf(v, { kind: 'none' });
  noElementsFromText(html);
 });
});
