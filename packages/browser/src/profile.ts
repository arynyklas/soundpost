// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Browser JS Self-Profiling supplement (method `browser_js_self_profile`).
//
// Off unless startProfile() is called. Feature detection is by actually constructing the W3C `Profiler`, never by browser version.
// Real Chrome 156 throws NotAllowedError ("JS profiling is disabled by Document Policy") when the `js-profiling` Document-Policy is absent;
// NotSupportedError (the spec's other refusal) is treated the same. Other DOMExceptions are permission_denied.
// Expected failures (API absent, Document-Policy `js-profiling` missing, owner conflict, bad options, timeouts) are returned as a
// capability status+reason with zero samples; nothing here throws into the application and nothing is imported from the replay code.
// Frames are code identities only: origin-relative script path (never a query, fragment or absolute URL), a conservative-regex function
// name, or the `external` placeholder. No arguments, locals, source text, thread names or error values exist in the trace to begin with.

import type {Client} from "./index.ts";
import {profileWire} from "./profile_wire.ts";

export const profileReasons = [
 "ok", "profiler_owned", "isolate_scope_mismatch", "monitoring_tool_ids_occupied", "document_policy_missing", "permission_denied", "invalid_options",
 "inspector_unavailable", "profiler_api_unavailable", "sys_monitoring_unavailable", "js_self_profiling_unavailable", "free_threaded_unqualified", "runtime_unsupported",
 "inspector_timeout", "inspector_error", "profiler_state_lost", "stop_timeout", "sampler_failed",
] as const;
export type ProfileReason = typeof profileReasons[number];
export type ProfileStatus = "supported" | "denied" | "unsupported" | "error";
export type ProfileCoverageLevel = "complete" | "partial" | "none" | "unknown";
export interface ProfileOptions {
 /** Hard-bounded run length, integer 1..60000. The profiler stops itself when it elapses. */
 readonly durationMs: number;
 /** Requested sample interval in microseconds, 1000..1_000_000 (default 10_000). The browser may grant another; the report states what it actually delivered. */
 readonly intervalUs?: number;
 /** Declared isolate scope; a mismatch with the actual global (Window vs WorkerGlobalScope) is refused. */
 readonly scope?: "main" | "worker";
 /** Page origin used to reduce script URLs to origin-relative paths (default: the global's own origin). Never echoed in the report. */
 readonly origin?: string;
 /** Also record `long_task` entries (duration and start only) as separate non-profile metric entries. */
 readonly longTasks?: boolean;
 /** Upper bound of retained samples and of the browser's sample buffer, 1..8192 (default 8192). */
 readonly maxSamples?: number;
}
export interface ProfileClockDomain {readonly host: string; readonly boot: string; readonly runtime: string}
export interface ProfileCapability {
 readonly id: string; readonly runtime: string; readonly version: string; readonly build: string; readonly os: string; readonly arch: string;
 readonly signal: "profile_chunk"; readonly method: "browser_js_self_profile"; readonly status: ProfileStatus; readonly reason: ProfileReason;
 readonly coverage: {readonly frames: ProfileCoverageLevel; readonly threads: ProfileCoverageLevel; readonly workers: ProfileCoverageLevel; readonly tasks: ProfileCoverageLevel};
 readonly clock_domain: ProfileClockDomain; readonly expires_ns: string;
}
export interface ProfileFrame {readonly module_id: string; readonly function: string; readonly artifact_id: string; readonly line: number; readonly column: number; readonly offset: "0"; readonly reason: "" | "not_captured"}
export interface ProfileSample {readonly at_us: string; readonly stack: number; readonly count: "1"; readonly thread: string}
export interface ProfileLongTask {readonly method: "long_task"; readonly profile: false; readonly signal: "metric"; readonly unit: "milliseconds"; readonly duration_ms: number; readonly start_ms: number}
export interface ProfileLoss {readonly reason: "truncated" | "sample_gap" | "foreign_state" | "timeout_cleanup"; readonly count: string}
export interface ProfileReport {
 readonly version: 1; readonly method: "browser_js_self_profile"; readonly profile: true; readonly units: "samples"; readonly time_delta_unit: null;
 readonly capability: ProfileCapability;
 readonly interval: {readonly requested_us: number; readonly achieved_us: number | null};
 readonly requested: Readonly<Record<string, unknown>>;
 readonly clock: {readonly domain: ProfileClockDomain; readonly uncertainty_ns: string; readonly source: string; readonly wall_start_ns: string; readonly wall_end_ns: string};
 readonly scope: Readonly<Record<string, unknown>>;
 readonly stack_order: "leaf_first";
 readonly frames: readonly ProfileFrame[]; readonly stacks: readonly {readonly frames: readonly number[]}[]; readonly samples: readonly ProfileSample[];
 readonly sample_count: number; readonly truncated: boolean; readonly losses: readonly ProfileLoss[]; readonly non_profile: readonly ProfileLongTask[];
 readonly ack: {readonly status: "not_available" | "obtained" | "failed"; readonly reason?: string; readonly cursors?: readonly string[]};
 readonly stopped_by: "caller" | "duration" | "client_close" | "timeout_cleanup" | "not_started";
}
export interface ProfileHandle {
 /** Idempotent and bounded. Resolves (never rejects) with the finished report; the profile lease is always released. */
 stop(): Promise<ProfileReport>;
}
export interface ProfilerApi {startProfile(options: ProfileOptions): Promise<ProfileHandle>}
/** Everything the profiler touches. The real browser values come from globalEnv(); tests inject fakes (bun has no DOM). */
export interface ProfilerEnv {
 readonly Profiler: unknown;
 readonly PerformanceObserver: unknown;
 readonly scope: "main" | "worker" | "unknown";
 readonly origin: () => string | undefined;
 readonly userAgent: () => string | undefined;
 readonly userAgentData: () => unknown;
 readonly visibility: () => "visible" | "hidden" | undefined;
 readonly onVisibilityChange: (listener: () => void) => () => void;
 readonly isDOMException: (error: unknown) => boolean;
 /** performance.now(): DOMHighResTimeStamp milliseconds since the time origin (the clock of the trace timestamps). */
 readonly now: () => number;
 readonly wallNs: () => string;
 readonly randomBytes: (length: number) => Uint8Array;
 readonly setTimeout: (callback: () => void, ms: number) => unknown;
 readonly clearTimeout: (handle: unknown) => void;
 /** Object carrying the process-global lease under a well-known symbol (the real global in production). */
 readonly leaseHost: object;
 readonly stopTimeoutMs?: number;
}

const METHOD = "browser_js_self_profile" as const;
const LEASE_KEY = Symbol.for("soundpost.profile.lease.browser_js_self_profile");
const DEFAULT_INTERVAL_US = 10_000, MAX_SAMPLES = 8192, MAX_FRAMES = 4096, MAX_STACKS = 4096, MAX_DEPTH = 128, MAX_LONG_TASKS = 256;
const STOP_TIMEOUT_MS = 5000, IDENTITY_TIMEOUT_MS = 250, CAPABILITY_TTL_NS = 3600n * 1_000_000_000n;
const UNCERTAINTY_NS = "18446744073709551615";
const CLOCK_SOURCE = "performance.now() DOMHighResTimeStamp (milliseconds since the browser time origin) from the JS Self-Profiling trace; sample offsets are relative to the first sample and are never converted to wall time";
const PATH = /^[A-Za-z0-9_.+-]+(?:\/[A-Za-z0-9_.+-]+)*$/;
const SAFE_FUNCTION = /^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*){0,3}$/;
const VERSION = "\\d+(?:\\.\\d+){0,3}";

interface Valid {readonly durationMs: number; readonly intervalUs: number; readonly maxSamples: number; readonly scope: "main" | "worker" | undefined; readonly origin: string | undefined; readonly longTasks: boolean}
interface Identity {readonly name: string; readonly version: string; readonly token: string; readonly os: string; readonly arch: string}
interface Mapped {
 readonly frames: ProfileFrame[]; readonly stacks: {frames: number[]}[]; readonly samples: ProfileSample[];
 readonly idle: number; readonly dropped: number; readonly deepSamples: number; readonly achievedUs: number | null; readonly missingSamples: number;
}

function validate(options: unknown): Valid | undefined {
 try {
  if (typeof options !== "object" || options === null) return undefined;
  const durationMs: unknown = Reflect.get(options, "durationMs"), intervalUs: unknown = Reflect.get(options, "intervalUs"), maxSamples: unknown = Reflect.get(options, "maxSamples");
  const scope: unknown = Reflect.get(options, "scope"), origin: unknown = Reflect.get(options, "origin"), longTasks: unknown = Reflect.get(options, "longTasks");
  if (typeof durationMs !== "number" || !Number.isInteger(durationMs) || durationMs < 1 || durationMs > 60000) return undefined;
  if (intervalUs !== undefined && (typeof intervalUs !== "number" || !Number.isInteger(intervalUs) || intervalUs < 1000 || intervalUs > 1_000_000)) return undefined;
  if (maxSamples !== undefined && (typeof maxSamples !== "number" || !Number.isInteger(maxSamples) || maxSamples < 1 || maxSamples > MAX_SAMPLES)) return undefined;
  if (scope !== undefined && scope !== "main" && scope !== "worker") return undefined;
  if (longTasks !== undefined && typeof longTasks !== "boolean") return undefined;
  if (origin !== undefined) {
   if (typeof origin !== "string") return undefined;
   const parsed = new URL(origin);
   if ((parsed.protocol !== "https:" && parsed.protocol !== "http:") || parsed.origin !== origin) return undefined;
  }
  return {durationMs, intervalUs: intervalUs ?? DEFAULT_INTERVAL_US, maxSamples: maxSamples ?? MAX_SAMPLES, scope, origin, longTasks: longTasks === true};
 } catch { return undefined; }
}
const settle = <T>(promise: Promise<T>, fallback: T): Promise<T> => promise.then(value => value, () => fallback);
const hex = (env: ProfilerEnv): string => Array.from(env.randomBytes(16), byte => byte.toString(16).padStart(2, "0")).join("");
const safeCall = <T>(fn: () => T): T | undefined => { try { return fn(); } catch { return undefined; } };

function uaIdentity(userAgent: string | undefined): {name: string; version: string; os: string; arch: string} {
 const ua = typeof userAgent === "string" && userAgent.length <= 1024 ? userAgent : "";
 const match = (name: string, pattern: string): {name: string; version: string} | undefined => { const m = new RegExp(pattern + "(" + VERSION + ")(?=[\\s;)]|$)").exec(ua); return m?.[1] ? {name, version: m[1]} : undefined; };
 const found = match("Edge", "\\bEdg(?:e|A|iOS)?\\/") ?? match("Firefox", "\\bFirefox\\/") ?? match("Chrome", "\\bChrome\\/") ?? match("Safari", "\\bVersion\\/(?=" + VERSION + "[^]*\\bSafari\\/)");
 const os = /Android/.test(ua) ? "android" : /iPhone|iPad|iPod/.test(ua) ? "ios" : /CrOS/.test(ua) ? "chromeos" : /Windows/.test(ua) ? "windows" : /Macintosh|Mac OS X/.test(ua) ? "macos" : /Linux|X11/.test(ua) ? "linux" : "unknown";
 const arch = /\b(?:x86_64|x64|Win64|WOW64|amd64)\b/i.test(ua) ? "x86_64" : /\b(?:aarch64|arm64)\b/i.test(ua) ? "arm64" : "unknown";
 return {name: found?.name ?? "unknown", version: found?.version ?? "unknown", os, arch};
}
const platformOs = (platform: unknown): string | undefined => {
 if (typeof platform !== "string") return undefined;
 const known: Record<string, string> = {windows: "windows", macos: "macos", linux: "linux", android: "android", ios: "ios", "chrome os": "chromeos", chromeos: "chromeos"};
 return known[platform.toLowerCase()];
};
async function identify(env: ProfilerEnv): Promise<Identity> {
 let {name, version, os, arch} = uaIdentity(safeCall(env.userAgent));
 const data = safeCall(env.userAgentData);
 if (typeof data === "object" && data !== null) {
  os = platformOs(safeCall(() => Reflect.get(data, "platform"))) ?? os;
  const lookup = safeCall(() => Reflect.get(data, "getHighEntropyValues"));
  if (typeof lookup === "function") {
   let timer: unknown;
   const values: unknown = await Promise.race([
    settle((async () => Reflect.apply(lookup, data, [["architecture", "bitness", "fullVersionList"]]))(), undefined),
    new Promise<undefined>(resolve => { timer = env.setTimeout(() => resolve(undefined), IDENTITY_TIMEOUT_MS); }),
   ]);
   env.clearTimeout(timer);
   if (typeof values === "object" && values !== null) {
    const list: unknown = Reflect.get(values, "fullVersionList");
    const brands: Record<string, string> = {"Google Chrome": "Chrome", "Microsoft Edge": "Edge", Chromium: "Chromium"};
    let best: {name: string; version: string; rank: number} | undefined;
    if (Array.isArray(list)) for (const entry of list.slice(0, 16) as unknown[]) {
     const brand: unknown = typeof entry === "object" && entry !== null ? Reflect.get(entry, "brand") : undefined, v: unknown = typeof entry === "object" && entry !== null ? Reflect.get(entry, "version") : undefined;
     const mapped = typeof brand === "string" ? brands[brand] : undefined;
     if (mapped === undefined || typeof v !== "string" || !new RegExp("^" + VERSION + "$").test(v)) continue;
     const rank = mapped === "Chromium" ? 0 : 1;
     if (!best || rank > best.rank) best = {name: mapped, version: v, rank};
    }
    if (best) {name = best.name; version = best.version;}
    const architecture: unknown = Reflect.get(values, "architecture"), bitness: unknown = Reflect.get(values, "bitness");
    if (architecture === "x86") arch = bitness === "64" ? "x86_64" : bitness === "32" ? "x86" : arch;
    else if (architecture === "arm") arch = bitness === "64" ? "arm64" : bitness === "32" ? "arm" : arch;
   }
  }
 }
 return {name, version, token: version === "unknown" || name === "unknown" ? "unknown" : `${name}/${version}`, os, arch};
}

function scriptPath(url: unknown, origin: string | undefined): string | undefined {
 if (typeof url !== "string" || origin === undefined || origin === "null" || url.length > 2048 || /[?#\\]/.test(url)) return undefined;
 const parsed = safeCall(() => new URL(url));
 if (!parsed || parsed.origin !== origin || parsed.username !== "" || parsed.password !== "") return undefined;
 const path = parsed.pathname.slice(1);
 return path.length > 0 && path.length <= 256 && PATH.test(path) ? path : undefined;
}

type ReadOnly = Readonly<Record<string, unknown>>;
const record = (value: unknown): ReadOnly | undefined => typeof value === "object" && value !== null && !Array.isArray(value) ? value as ReadOnly : undefined;
const index = (value: unknown, length: number): number | undefined => value === undefined || value === null ? undefined : (typeof value === "number" && Number.isInteger(value) && value >= 0 && value < length ? value : Number.NaN);

/** Maps an untrusted ProfilerTrace; undefined = structurally malformed (the whole profile fails, nothing is partially mapped). */
function mapTrace(trace: unknown, origin: string | undefined, limit: number, thread: string, intervalMs: number): Mapped | undefined {
 const t = record(trace);
 if (!t) return undefined;
 const resources: unknown = t.resources, rawFrames: unknown = t.frames, rawStacks: unknown = t.stacks, rawSamples: unknown = t.samples;
 if (!Array.isArray(resources) || !Array.isArray(rawFrames) || !Array.isArray(rawStacks) || !Array.isArray(rawSamples)) return undefined;
 const paths = resources.map(resource => scriptPath(resource, origin));
 interface TraceFrame {readonly key: string; readonly frame: ProfileFrame}
 const frameInfo: TraceFrame[] = [];
 for (const raw of rawFrames as unknown[]) {
  const f = record(raw);
  if (!f) return undefined;
  const resource = f.resourceId === undefined || f.resourceId === null ? undefined : index(f.resourceId, resources.length);
  if (resource !== undefined && Number.isNaN(resource)) return undefined;
  const path = resource === undefined ? undefined : paths[resource];
  let frame: ProfileFrame;
  if (path === undefined) frame = {module_id: "external", function: "", artifact_id: "", line: 0, column: 0, offset: "0", reason: "not_captured"};
  else {
   const name: unknown = f.name, safe = typeof name === "string" && name.length <= 128 && SAFE_FUNCTION.test(name);
   const num = (value: unknown): number => typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 4294967295 ? value : 0;
   frame = {module_id: path, function: safe ? name : "", artifact_id: path, line: num(f.line), column: num(f.column), offset: "0", reason: safe ? "" : "not_captured"};
  }
  frameInfo.push({key: JSON.stringify(frame), frame});
 }
 const byKey = new Map(frameInfo.map(info => [info.key, info.frame] as const));
 const parents: (number | undefined)[] = [], leafFrames: number[] = [];
 for (const raw of rawStacks as unknown[]) {
  const s = record(raw);
  if (!s) return undefined;
  const parent = index(s.parentId, rawStacks.length), frame = index(s.frameId, rawFrames.length);
  if ((parent !== undefined && Number.isNaN(parent)) || frame === undefined || Number.isNaN(frame)) return undefined;
  parents.push(parent); leafFrames.push(frame);
 }
 const stackIds: (number | undefined)[] = [], times: number[] = [];
 for (const raw of rawSamples as unknown[]) {
  const s = record(raw);
  if (!s || typeof s.timestamp !== "number" || !Number.isFinite(s.timestamp)) return undefined;
  const stack = index(s.stackId, rawStacks.length);
  if (stack !== undefined && Number.isNaN(stack)) return undefined;
  stackIds.push(stack); times.push(s.timestamp);
 }
 const base = times[0] ?? 0;
 if (times.some(time => time < base)) return undefined;
 const frames: ProfileFrame[] = [], stacks: {frames: number[]}[] = [], samples: ProfileSample[] = [];
 const frameIndex = new Map<string, number>(), stackIndex = new Map<string, number>();
 const memo = new Map<number, {stack: number; deep: boolean} | null>();
 let idle = 0, dropped = 0, deepSamples = 0;
 const chain = (leaf: number): number[] | undefined => {
  const out: number[] = [];
  let current: number | undefined = leaf;
  for (let steps = 0; current !== undefined; steps++) {
   if (steps > rawStacks.length) return undefined; // a parent cycle: corrupt trace
   out.push(leafFrames[current]!); current = parents[current];
  }
  return out;
 };
 for (let i = 0; i < stackIds.length; i++) {
  const leaf = stackIds[i];
  if (leaf === undefined) { idle++; continue; }
  if (samples.length >= limit) { dropped++; continue; }
  let entry = memo.get(leaf);
  if (entry === undefined) {
   const walked = chain(leaf);
   if (!walked) return undefined;
   // Leaf-first, placeholder runs collapsed, root-most frames cut at the 128-frame cap.
   const keys: string[] = [];
   for (const traceFrame of walked) { const info = frameInfo[traceFrame]!; if (info.frame.module_id === "external" && keys[keys.length - 1] === info.key) continue; keys.push(info.key); }
   const deep = keys.length > MAX_DEPTH;
   if (deep) keys.length = MAX_DEPTH;
   const fresh = keys.filter((key, position) => !frameIndex.has(key) && keys.indexOf(key) === position);
   if (frames.length + fresh.length > MAX_FRAMES) entry = null;
   else {
    for (const key of fresh) { frameIndex.set(key, frames.length); frames.push(byKey.get(key)!); }
    const ids = keys.map(key => frameIndex.get(key)!), joined = ids.join(",");
    let stack = stackIndex.get(joined);
    if (stack === undefined) {
     if (stacks.length >= MAX_STACKS) entry = null;
     else { stack = stacks.length; stacks.push({frames: ids}); stackIndex.set(joined, stack); entry = {stack, deep}; }
    } else entry = {stack, deep};
   }
   memo.set(leaf, entry ?? null);
  }
  if (entry === null || entry === undefined) { dropped++; continue; }
  if (entry.deep) deepSamples++;
  samples.push({at_us: String(Math.round((times[i]! - base) * 1000)), stack: entry.stack, count: "1", thread});
 }
 const gaps: number[] = [];
 for (let i = 1; i < times.length; i++) gaps.push(times[i]! - times[i - 1]!);
 const sorted = [...gaps].sort((a, b) => a - b), mid = sorted.length >> 1;
 const median = sorted.length === 0 ? undefined : sorted.length % 2 === 1 ? sorted[mid]! : (sorted[mid - 1]! + sorted[mid]!) / 2;
 let missingSamples = 0;
 for (const gap of gaps) if (gap > 2 * intervalMs) missingSamples += Math.max(0, Math.round(gap / intervalMs) - 1);
 return {frames, stacks, samples, idle, dropped, deepSamples, achievedUs: median === undefined ? null : Math.round(median * 1000), missingSamples};
}

/** `deliver`, when given, receives every finished report exactly once (a refusal at start, or the single finish of a run: caller stop, duration
 * timer or stop timeout). It runs after the profile lease is released, and an exception from it never reaches the application. */
export function createProfiler(env: ProfilerEnv, deliver?: (report: ProfileReport) => void): ProfilerApi {
 const stopTimeoutMs = env.stopTimeoutMs ?? STOP_TIMEOUT_MS;
 const hand = (report: ProfileReport): void => { if (deliver === undefined) return; try { deliver(report); } catch { /* delivery failures are the delivery layer's to count; the application never sees them */ } };
 interface Frame {
  status: ProfileStatus; reason: ProfileReason; wallStart: string; wallEnd: string; identity: Identity; requestedUs: number; requested: Record<string, unknown>; scope: Record<string, unknown>;
  stoppedBy: ProfileReport["stopped_by"]; mapped?: Mapped; truncated?: boolean; losses?: ProfileLoss[]; nonProfile?: ProfileLongTask[];
 }
 const assemble = (f: Frame): ProfileReport => {
  const domain = {host: hex(env), boot: hex(env), runtime: hex(env)};
  const supported = f.status === "supported", none = "none" as const;
  const m = f.mapped;
  return {
   version: 1, method: METHOD, profile: true, units: "samples", time_delta_unit: null,
   capability: {
    id: hex(env), runtime: f.identity.token, version: f.identity.version, build: f.identity.token, os: f.identity.os, arch: f.identity.arch, signal: "profile_chunk", method: METHOD, status: f.status, reason: f.reason,
    coverage: supported ? {frames: "partial", threads: "partial", workers: none, tasks: none} : {frames: none, threads: none, workers: none, tasks: none}, clock_domain: domain, expires_ns: String(BigInt(f.wallStart) + CAPABILITY_TTL_NS),
   },
   interval: {requested_us: f.requestedUs, achieved_us: m?.achievedUs ?? null}, requested: f.requested,
   clock: {domain, uncertainty_ns: UNCERTAINTY_NS, source: CLOCK_SOURCE, wall_start_ns: f.wallStart, wall_end_ns: f.wallEnd}, scope: f.scope, stack_order: "leaf_first",
   frames: m?.frames ?? [], stacks: m?.stacks ?? [], samples: m?.samples ?? [], sample_count: m?.samples.length ?? 0, truncated: f.truncated ?? false, losses: f.losses ?? [], non_profile: f.nonProfile ?? [],
   ack: {status: "not_available"}, stopped_by: f.stoppedBy,
  };
 };
 const refusal = async (status: ProfileStatus, reason: ProfileReason, identity: Promise<Identity>, requestedUs: number, requested: Record<string, unknown>): Promise<ProfileHandle> => {
  const wall = env.wallNs(), who = await identity;
  const report = assemble({status, reason, wallStart: wall, wallEnd: wall, identity: who, requestedUs, requested, scope: {isolate: env.scope, runtime: {name: who.name, version: who.version}}, stoppedBy: "not_started"});
  hand(report);
  return {stop: () => Promise.resolve(report)};
 };

 return {async startProfile(raw: ProfileOptions): Promise<ProfileHandle> {
  const identity = identify(env);
  const options = validate(raw);
  if (!options) {
   const requested: unknown = safeCall(() => Reflect.get(raw as object, "intervalUs"));
   return refusal("denied", "invalid_options", identity, typeof requested === "number" && Number.isInteger(requested) && requested >= 1000 && requested <= 1_000_000 ? requested : DEFAULT_INTERVAL_US, {});
  }
  const requested = {duration_ms: options.durationMs, interval_us: options.intervalUs, max_samples: options.maxSamples, scope: options.scope ?? null, long_tasks: options.longTasks};
  if (options.scope !== undefined && options.scope !== env.scope) return refusal("denied", "isolate_scope_mismatch", identity, options.intervalUs, requested);
  const ctor = env.Profiler;
  if (typeof ctor !== "function") return refusal("unsupported", "js_self_profiling_unavailable", identity, options.intervalUs, requested);
  // The lease is taken synchronously (before any await) so two racing starts cannot both own the profiler.
  if (Reflect.get(env.leaseHost, LEASE_KEY) !== undefined) return refusal("denied", "profiler_owned", identity, options.intervalUs, requested);
  const token = {};
  Reflect.defineProperty(env.leaseHost, LEASE_KEY, {value: token, configurable: true, writable: true, enumerable: false});
  const release = (): void => { if (Reflect.get(env.leaseHost, LEASE_KEY) === token) Reflect.deleteProperty(env.leaseHost, LEASE_KEY); };

  let profiler: object;
  try {
   profiler = Reflect.construct(ctor, [{sampleInterval: options.intervalUs / 1000, maxBufferSize: options.maxSamples}]) as object;
  } catch (error) {
   release();
   if (env.isDOMException(error)) {
    const name: unknown = safeCall(() => Reflect.get(error as object, "name"));
    return refusal("denied", name === "NotAllowedError" || name === "NotSupportedError" ? "document_policy_missing" : "permission_denied", identity, options.intervalUs, requested);
   }
   return refusal("error", "sampler_failed", identity, options.intervalUs, requested);
  }

  const wallStart = env.wallNs(), startedAt = env.now();
  const grantedMs = safeCall(() => Reflect.get(profiler, "sampleInterval"));
  const effectiveMs = typeof grantedMs === "number" && Number.isFinite(grantedMs) && grantedMs > 0 ? grantedMs : options.intervalUs / 1000;
  const visibility = {start: env.visibility() ?? "unknown", changed: false};
  let bufferFull = false, finished: Promise<ProfileReport> | undefined;
  const onFull = (): void => { bufferFull = true; };
  safeCall(() => Reflect.apply(Reflect.get(profiler, "addEventListener"), profiler, ["samplebufferfull", onFull]));
  const unsubscribeVisibility = safeCall(() => env.onVisibilityChange(() => { visibility.changed = true; }));

  const longTasks: ProfileLongTask[] = [];
  let longTaskState: "not_requested" | "observed" | "unsupported" = "not_requested", longTasksDropped = 0, observer: object | undefined;
  const collect = (entries: unknown): void => {
   if (!Array.isArray(entries)) return;
   for (const entry of entries as unknown[]) {
    const e = record(entry);
    const duration = e && safeCall(() => Reflect.get(e, "duration")), start = e && safeCall(() => Reflect.get(e, "startTime"));
    if (!e || safeCall(() => Reflect.get(e, "entryType")) !== "longtask" || typeof duration !== "number" || !Number.isFinite(duration) || duration < 0 || typeof start !== "number" || !Number.isFinite(start)) continue;
    if (longTasks.length >= MAX_LONG_TASKS) { longTasksDropped++; continue; }
    longTasks.push({method: "long_task", profile: false, signal: "metric", unit: "milliseconds", duration_ms: Math.round(duration * 10) / 10, start_ms: Math.round((start - startedAt) * 10) / 10});
   }
  };
  if (options.longTasks) {
   longTaskState = "unsupported";
   const Observer = env.PerformanceObserver;
   const supportedTypes: unknown = typeof Observer === "function" ? safeCall(() => Reflect.get(Observer, "supportedEntryTypes")) : undefined;
   if (typeof Observer === "function" && Array.isArray(supportedTypes) && supportedTypes.includes("longtask")) {
    try {
     observer = Reflect.construct(Observer, [(list: unknown) => collect(safeCall(() => Reflect.apply(Reflect.get(list as object, "getEntries"), list, [])))]) as object;
     Reflect.apply(Reflect.get(observer, "observe"), observer, [{type: "longtask"}]);
     longTaskState = "observed";
    } catch { safeCall(() => Reflect.apply(Reflect.get(observer as object, "disconnect"), observer, [])); observer = undefined; longTaskState = "unsupported"; }
   }
  }

  const cleanup = (): void => {
   if (observer) {
    const o = observer; observer = undefined;
    collect(safeCall(() => Reflect.apply(Reflect.get(o, "takeRecords"), o, [])));
    safeCall(() => Reflect.apply(Reflect.get(o, "disconnect"), o, []));
   }
   safeCall(() => Reflect.apply(Reflect.get(profiler, "removeEventListener"), profiler, ["samplebufferfull", onFull]));
   safeCall(() => unsubscribeVisibility?.());
   release();
  };
  const finish = (stoppedBy: "caller" | "duration"): Promise<ProfileReport> => finished ??= (async (): Promise<ProfileReport> => {
   env.clearTimeout(durationTimer);
   let outcome: {kind: "trace"; trace: unknown} | {kind: "timeout"} | {kind: "failed"};
   let stopTimer: unknown;
   let wallEnd = wallStart, who: Identity = {name: "unknown", version: "unknown", token: "unknown", os: "unknown", arch: "unknown"};
   try {
    const stopping = (async () => Reflect.apply(Reflect.get(profiler, "stop"), profiler, []) as unknown)().then((trace): typeof outcome => ({kind: "trace", trace}), (): typeof outcome => ({kind: "failed"}));
    const timeout = new Promise<typeof outcome>(resolve => { stopTimer = env.setTimeout(() => resolve({kind: "timeout"}), stopTimeoutMs); });
    outcome = await Promise.race([stopping, timeout]);
   } catch { outcome = {kind: "failed"}; } finally { env.clearTimeout(stopTimer); cleanup(); }
   try { wallEnd = env.wallNs(); who = await identity; } catch { /* keep the unknown identity */ }
   const visibilityEnd = safeCall(() => env.visibility()) ?? "unknown";
   const scope: Record<string, unknown> = {
    isolate: env.scope, thread: env.scope, runtime: {name: who.name, version: who.version}, visibility: {start: visibility.start, end: visibilityEnd, changed: visibility.changed},
    granted_interval_us: typeof grantedMs === "number" && Number.isFinite(grantedMs) && grantedMs > 0 ? Math.round(grantedMs * 1000) : null,
    idle_samples: 0, stack_depth_truncated_samples: 0, buffer_full: bufferFull, long_tasks: longTaskState, long_tasks_dropped: longTasksDropped,
   };
   const base = {wallStart, wallEnd, identity: who, requestedUs: options.intervalUs, requested, scope, stoppedBy, nonProfile: longTasks};
   if (outcome.kind === "timeout") return assemble({...base, status: "error", reason: "stop_timeout", stoppedBy: "timeout_cleanup", losses: [{reason: "timeout_cleanup", count: "1"}]});
   const mapped = outcome.kind === "trace" ? safeCall(() => mapTrace(outcome.trace, options.origin ?? safeCall(env.origin), options.maxSamples, env.scope, effectiveMs)) : undefined;
   if (!mapped) return assemble({...base, status: "error", reason: "sampler_failed"});
   scope.idle_samples = mapped.idle; scope.stack_depth_truncated_samples = mapped.deepSamples;
   const losses: ProfileLoss[] = [];
   const truncatedCount = mapped.dropped + (bufferFull ? 1 : 0); // lower bound: the browser never reports how many samples it discarded
   if (truncatedCount > 0) losses.push({reason: "truncated", count: String(truncatedCount)});
   if (mapped.missingSamples > 0 || visibility.changed || visibility.start === "hidden" || visibilityEnd === "hidden") losses.push({reason: "sample_gap", count: String(mapped.missingSamples)});
   return assemble({...base, status: "supported", reason: "ok", mapped, truncated: truncatedCount > 0 || mapped.deepSamples > 0, losses});
  })().then(report => { hand(report); return report; });
  const durationTimer = env.setTimeout(() => { void finish("duration"); }, options.durationMs);
  return {stop: () => finish("caller")};
 }};
}

/** The real browser/worker globals, read at call time (never at import time). */
export function globalProfilerEnv(): ProfilerEnv {
 const g: object = globalThis;
 const document: unknown = Reflect.get(g, "document");
 const workerScope: unknown = Reflect.get(g, "WorkerGlobalScope");
 const nav: unknown = Reflect.get(g, "navigator");
 const read = (target: unknown, key: string): unknown => (typeof target === "object" && target !== null ? Reflect.get(target, key) : undefined);
 return {
  Profiler: Reflect.get(g, "Profiler"), PerformanceObserver: Reflect.get(g, "PerformanceObserver"),
  scope: typeof workerScope === "function" && g instanceof workerScope ? "worker" : typeof document === "object" && document !== null && Reflect.get(g, "window") === g ? "main" : "unknown",
  origin: () => { const origin = read(read(g, "location"), "origin"); return typeof origin === "string" ? origin : undefined; },
  userAgent: () => { const ua = read(nav, "userAgent"); return typeof ua === "string" ? ua : undefined; },
  userAgentData: () => read(nav, "userAgentData"),
  visibility: () => { const state = read(document, "visibilityState"); return state === "visible" || state === "hidden" ? state : undefined; },
  onVisibilityChange: listener => {
   if (typeof document !== "object" || document === null) return () => {};
   const doc = document as Document;
   doc.addEventListener("visibilitychange", listener);
   return () => doc.removeEventListener("visibilitychange", listener);
  },
  isDOMException: error => (typeof DOMException === "function" && error instanceof DOMException) || (typeof error === "object" && error !== null && Reflect.get(error, Symbol.toStringTag) === "DOMException"),
  now: () => performance.now(), wallNs: () => String(BigInt(Date.now()) * 1_000_000n), randomBytes: length => crypto.getRandomValues(new Uint8Array(length)),
  setTimeout: (callback, ms) => setTimeout(callback, ms), clearTimeout: handle => clearTimeout(handle as number), leaseHost: g,
 };
}

/** Starts one bounded JS Self-Profiling run on the calling global. Never throws: refusals are reports with a status and reason. */
export function startProfile(options: ProfileOptions): Promise<ProfileHandle> { return createProfiler(globalProfilerEnv()).startProfile(options); }

const processIds = new WeakMap<Client, string>();
function randomId(): string { for (;;) { const id = Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, "0")).join(""); if (id !== "0".repeat(32)) return id; } }

/** Maps a finished report to wire records and enqueues them on `client`. Returns true only when everything was queued. */
export function submitProfile(client: Client, report: ProfileReport): boolean {
 let queued: boolean;
 try { const wire = profileWire(report, {process: processIds.get(client) ?? (processIds.set(client, randomId()), processIds.get(client)!), id: randomId}); queued = client.captureProfile(wire.capability, wire.chunks); }
 catch { client.profileFailed(); queued = false; }
 // Samples the profiler dropped from this run are a recorded loss whether or not the retained part was queued.
 try {
  let truncated = 0n; for (const loss of report.losses) if (loss.reason === "truncated") truncated += BigInt(loss.count);
  if (truncated > 0n) client.captureProfileLoss(truncated, BigInt(report.clock.wall_end_ns) >= BigInt(report.clock.wall_start_ns) ? report.clock.wall_end_ns : report.clock.wall_start_ns);
 } catch { client.profileFailed(); }
 return queued;
}

/** Starts one bounded JS Self-Profiling run whose finished report (including a refusal) is delivered through `client`'s queue:
 * the capability truth record always, the profile chunk(s) only when the sampler genuinely ran. Requires `deploymentProfiles: true`
 * and a source policy that lists profile_chunk and capability; otherwise nothing is enqueued and the drop is counted in diagnostics(). */
export function startClientProfile(client: Client, options: ProfileOptions): Promise<ProfileHandle> { return createProfiler(globalProfilerEnv(), report => { submitProfile(client, report); }).startProfile(options); }
