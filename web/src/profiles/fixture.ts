// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Wire-shaped profile fixtures for the unit tests. The shapes follow internal/profiles/types.go, internal/model/{telemetry,native_profile}.go and
// internal/httpapi/profile_view.go: decimal-string nanoseconds and counts, an absent blocked/runnable/unknown total when it was not measured.
import type { Capability, CapabilityRecord, ClockDomain, NativeLoss, NativeSample, NativeTask, ProfileFrame, ProfileInterval, ProfileResponse, ProfileSample, ProfileStack, ProfileView } from './types';

export const ORG = 'a'.repeat(32), PROJECT = 'b'.repeat(32), PROFILE = 'c'.repeat(32), PROCESS = 'd'.repeat(32);
export const want = { org: ORG, project: PROJECT, profile: PROFILE };
export const MS = 1_000_000n;
export const T0 = 1_700_000_000_000_000_000n;
export const MONO0 = 5_000_000_000n;
export const EXPIRES = T0 + 3_600n * 1_000_000_000n;
export const DOMAIN: ClockDomain = { host: '1'.repeat(32), boot: '2'.repeat(32), runtime: '3'.repeat(32) };
export const mono = (ms: number): string => String(MONO0 + BigInt(ms) * MS);

export const frame = (module_id: string, fn: string, offset: string, reason = '', artifact_id = ''): ProfileFrame => ({ module_id, function: fn, artifact_id, offset, reason });
export const stack = (...frames: number[]): ProfileStack => ({ frames });
export const task = (tid = 101): NativeTask => ({ boot_id: 'boot-1', pid_namespace: '4026531836', tgid: 100, tid, process_start_ns: '900', generation: '1' });
export const native = (over: Partial<NativeSample> = {}): NativeSample => ({ task: task(), method: 'software_cpu_clock', unit: 'cpu_clock_nanoseconds', requested_hz: 99, period: '10101010', ...over });
export const nativeSample = (atMs: number, stackIndex: number, over: Partial<NativeSample> = {}): ProfileSample => ({ at_ns: mono(atMs), stack: stackIndex, count: '1', thread: '101', native: native(over) });
export const engineSample = (atMs: number, stackIndex: number, count: string, thread = '1'): ProfileSample => ({ at_ns: mono(atMs), stack: stackIndex, count, thread });
export const interval = (kind: ProfileInterval['kind'], startMs: number, endMs: number, stackIndex: number, over: Partial<ProfileInterval> = {}): ProfileInterval => ({
 start_ns: mono(startMs), end_ns: mono(endMs), stack: stackIndex, kind, thread: '101', censored: false, native_task: task(), unit: 'nanoseconds', ...over,
});

export function capability(method: string, over: Partial<Capability> = {}): CapabilityRecord {
 const value: Capability = {
  runtime: 'native_linux', version: '6.6', build: 'kernel-6.6.0', os: 'linux', arch: 'amd64', signal: 'profile', method, status: 'supported', reason: 'probed',
  coverage: { frames: 'partial', threads: 'complete', workers: 'none', tasks: 'unknown' }, clock_domain: DOMAIN, expires_ns: String(EXPIRES), ...over,
 };
 const n = method === 'native_cpu' ? 1 : method === 'native_offcpu' ? 2 : method === 'native_runqueue_split' ? 3 : 4;
 return { id: String(n).repeat(32), value };
}
const nativeCaps = (over: Partial<Capability> = {}, only?: string): CapabilityRecord[] => ['native_cpu', 'native_offcpu', 'native_runqueue_split'].map((m) => capability(m, only === undefined || only === m ? over : {}));

export function baseView(over: Partial<ProfileView> = {}): ProfileView {
 return {
  profile_id: PROFILE, process_id: PROCESS, project_id: PROJECT, method: 'native_cpu', units: 'samples',
  clock: { wall_ns: String(T0), mono_ns: String(MONO0), uncertainty_ns: '250000', domain: DOMAIN },
  frames: [], stacks: [], samples: [], intervals: [], capabilities: [], loss: [], loss_count: '0', truncated: false,
  links: [], watermarks: [], completeness: 'complete', reasons: [], ...over,
 };
}

const NATIVE_FRAMES: ProfileFrame[] = [
 frame('app-binary', 'handle_request', '4096'),
 frame('libc', 'memcpy', '128'),
 frame('', '', '0', 'frame_unresolved'),
 frame('app-binary', '', '8192', 'artifact_unavailable', 'e'.repeat(32)),
];
const NATIVE_STACKS: ProfileStack[] = [stack(0, 1), stack(0, 2), stack(3)];

/** OS on-CPU samples of an approved native build: native period and requested rate, one unresolved frame and one unavailable artifact. blocked/runnable/unknown totals are absent: scheduler time was not collected. */
export function nativeCpuView(over: Partial<ProfileView> = {}): ProfileView {
 return baseView({
  frames: NATIVE_FRAMES, stacks: NATIVE_STACKS, native_domain: { host_id: 'host-1', boot_id: 'boot-1' },
  samples: [nativeSample(0, 0), nativeSample(10, 0), nativeSample(20, 1, { coverage: 'frame_unresolved' }), nativeSample(30, 2, { truncation: 'callchain_truncated' }), nativeSample(40, 0)],
  capabilities: nativeCaps(), ...over,
 });
}

/** Engine (runtime) CPU samples: counts reported by the engine in `samples`. No native fields, no sampling interval. */
export function runtimeCpuView(over: Partial<ProfileView> = {}): ProfileView {
 return baseView({
  method: 'runtime_cpu', units: 'samples',
  frames: [frame('app.js', 'render', '0'), frame('app.js', 'parse', '12'), frame('node:internal', '(garbage collector)', '0')],
  stacks: [stack(0, 1), stack(0), stack(2)],
  samples: [engineSample(0, 0, '3'), engineSample(20, 1, '5'), engineSample(40, 2, '2')],
  capabilities: [capability('runtime_cpu', { runtime: 'node', version: '22.3.0', build: 'v8-12.4', coverage: { frames: 'complete', threads: 'partial', workers: 'unknown', tasks: 'none' } })], ...over,
 });
}

/** Native off-CPU: a wait with a wake observed (40 ms blocked, then 15 ms runnable) and a censored final wait. */
export function offCpuView(over: Partial<ProfileView> = {}): ProfileView {
 return baseView({
  method: 'native_offcpu', units: 'nanoseconds', native_domain: { host_id: 'host-1', boot_id: 'boot-1' },
  frames: NATIVE_FRAMES, stacks: NATIVE_STACKS,
  intervals: [interval('blocked', 0, 40, 0), interval('runnable', 40, 55, 0), interval('blocked', 100, 140, 1, { censored: true, reason: 'acquisition_pending' })],
  blocked_ns: '80000000', runnable_ns: '15000000', capabilities: nativeCaps(), ...over,
 });
}

/** A missing wake: the 55 ms off the CPU has no wake evidence, so it is one unknown interval. blocked_ns and runnable_ns are absent. */
export function missingWakeView(over: Partial<ProfileView> = {}): ProfileView {
 return baseView({
  method: 'native_offcpu', units: 'nanoseconds', native_domain: { host_id: 'host-1', boot_id: 'boot-1' },
  frames: NATIVE_FRAMES, stacks: NATIVE_STACKS,
  intervals: [interval('unknown_offcpu', 0, 55, 0, { reason: 'coverage_unmeasured' })],
  unknown_ns: '55000000', capabilities: nativeCaps(), ...over,
 });
}

/** A browser that cannot sample ordinary pages: an unsupported capability and nothing observed. */
export function browserUnsupportedView(status: 'unsupported' | 'denied' | 'error' = 'unsupported', over: Partial<ProfileView> = {}): ProfileView {
 return baseView({
  method: 'runtime_cpu', units: 'samples', completeness: 'partial', reasons: ['no_observations_in_window'],
  capabilities: [capability('runtime_cpu', { runtime: 'browser', version: 'safari-17', build: 'webkit', os: 'macos', arch: 'arm64', status, reason: status === 'unsupported' ? 'self_profiling_unavailable' : status === 'denied' ? 'document_policy_denied' : 'probe_failed', coverage: { frames: 'none', threads: 'none', workers: 'none', tasks: 'none' } })], ...over,
 });
}

const lossNative = (): NativeLoss[] => [
 { at_ns: mono(25), cpu: 2, count: '12', reason: 'records_lost' },
 { at_ns: mono(60), cpu: 2, count: '0', reason: 'throttled', throttle_event_id: '7', throttle_stream_id: '9' },
];
/** Loss and truncation: records lost on a CPU, a throttle, a loss report, a truncated profile and a long gap between samples. */
export function lossView(over: Partial<ProfileView> = {}): ProfileView {
 return nativeCpuView({
  samples: [nativeSample(0, 0), nativeSample(10, 0), nativeSample(20, 0), nativeSample(30, 0), nativeSample(500, 0)],
  native_loss: lossNative(), loss_count: '12', truncated: true, completeness: 'partial', reasons: ['coverage_incomplete'],
  loss: [{ source: '4'.repeat(32), producer: '5'.repeat(32), producer_epoch: '6'.repeat(32), start_ns: String(T0 + 25n * MS), end_ns: String(T0 + 60n * MS), signal: 'profile', reason: 'ring_overflow', count: '12', last_ack: null, queue_bytes: '4096', queue_records: '3' }],
  ...over,
 });
}

export function responseOf(view: ProfileView, over: Partial<ProfileResponse> = {}): ProfileResponse {
 const partial = view.completeness === 'partial' || view.truncated;
 const reason = partial ? (view.reasons[0] ?? 'profile_partial') : undefined;
 const state = partial ? 'incomplete' : 'ready';
 return {
  org: ORG, project: PROJECT, profile: PROFILE, state, ...(reason === undefined ? {} : { reason }), partial, view,
  sections: [{ name: 'profile', state, ...(reason === undefined ? {} : { reason }) }], ...over,
 };
}
export function notAvailable(): ProfileResponse {
 return { org: ORG, project: PROJECT, profile: PROFILE, state: 'not_available', reason: 'profile_service_not_wired', partial: false, sections: [{ name: 'profile', state: 'not_available', reason: 'profile_service_not_wired' }] };
}
