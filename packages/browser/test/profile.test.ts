// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Every Profiler, PerformanceObserver, clock, timer, visibility and user-agent object below is a FAKE built inside this test file
// (bun has no DOM and no JS Self-Profiling API). The fake traces follow the W3C ProfilerTrace shape; the real-browser behaviour is
// qualified separately by fixtures/sdk/profiles/browser.spec.ts in real Chrome.
import {test, expect} from "bun:test";
import {createProfiler, profileReasons, type ProfileOptions, type ProfileReport, type ProfilerApi, type ProfilerEnv} from "../src/profile.ts";
import {parseSafeRecord} from "../../core/src/wire.ts";

const LEASE_KEY = Symbol.for("soundpost.profile.lease.browser_js_self_profile");
const CHROME_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36";
const FIREFOX_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:144.0) Gecko/20100101 Firefox/144.0";
const SAFARI_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15";
const ORIGIN = "https://soundpost.test";
// Module-load check: importing profile.ts must not have installed any global state.
const leaseAtImport = Reflect.get(globalThis, LEASE_KEY);

interface Trace {resources: unknown; frames: unknown; stacks: unknown; samples: unknown}
class FakeTimers {
 now = 0; private next = 1; readonly queue = new Map<number, {at: number; fn: () => void}>();
 set = (fn: () => void, ms: number): number => { const id = this.next++; this.queue.set(id, {at: this.now + ms, fn}); return id; };
 clear = (handle: unknown): void => { this.queue.delete(handle as number); };
 get pending(): number { return this.queue.size; }
 delays(): number[] { return [...this.queue.values()].map(entry => entry.at - this.now).sort((a, b) => a - b); }
 async advance(ms: number): Promise<void> {
  const target = this.now + ms;
  for (;;) {
   const due = [...this.queue.entries()].filter(([, entry]) => entry.at <= target).sort((a, b) => a[1].at - b[1].at)[0];
   if (!due) break;
   this.now = due[1].at; this.queue.delete(due[0]); due[1].fn(); await flush();
  }
  this.now = target;
 }
}
const flush = async (): Promise<void> => { for (let i = 0; i < 20; i++) await Promise.resolve(); };
class DOMError extends Error {constructor(readonly domName: string) { super(domName); this.name = domName; }}

interface Harness {
 env: ProfilerEnv; timers: FakeTimers; api: ProfilerApi;
 trace: Trace | undefined; ctorError: unknown; stopMode: "resolve" | "hang" | "reject"; grantedMs: number | undefined;
 profilers: FakeProfiler[]; observers: FakeObserver[]; clock: {value: number}; visibility: {value: "visible" | "hidden" | undefined; listeners: Set<() => void>};
 longTaskSupported: boolean; ua: string; uaData: unknown; hasProfiler: boolean; hasObserver: boolean; scope: "main" | "worker" | "unknown"; origin: string | undefined;
 setVisibility(value: "visible" | "hidden"): void;
}
class FakeProfiler {
 stopCalls = 0; readonly listeners = new Map<string, Set<() => void>>(); readonly sampleInterval: number;
 constructor(readonly options: {sampleInterval: number; maxBufferSize: number}, private readonly h: Harness) {
  if (h.ctorError !== undefined) throw h.ctorError;
  this.sampleInterval = h.grantedMs ?? options.sampleInterval; h.profilers.push(this);
 }
 addEventListener(type: string, listener: () => void): void { (this.listeners.get(type) ?? this.listeners.set(type, new Set()).get(type)!).add(listener); }
 removeEventListener(type: string, listener: () => void): void { this.listeners.get(type)?.delete(listener); }
 emit(type: string): void { for (const listener of [...(this.listeners.get(type) ?? [])]) listener(); }
 listenerCount(): number { return [...this.listeners.values()].reduce((sum, set) => sum + set.size, 0); }
 stop(): Promise<unknown> {
  this.stopCalls++;
  if (this.h.stopMode === "hang") return new Promise(() => {});
  if (this.h.stopMode === "reject") return Promise.reject(new DOMError("InvalidStateError"));
  return Promise.resolve(this.h.trace ?? {resources: [], frames: [], stacks: [], samples: []});
 }
}
class FakeObserver {
 static supportedEntryTypes: string[] = [];
 observed: unknown[] = []; disconnected = false; queued: unknown[] = [];
 constructor(readonly callback: (list: {getEntries(): unknown[]}) => void, h?: Harness) { void h; }
 observe(options: unknown): void { this.observed.push(options); }
 disconnect(): void { this.disconnected = true; }
 takeRecords(): unknown[] { const rest = this.queued; this.queued = []; return rest; }
 deliver(entries: unknown[]): void { this.callback({getEntries: () => entries}); }
}
function harness(over: Partial<Pick<Harness, "ua" | "uaData" | "hasProfiler" | "hasObserver" | "scope" | "origin" | "longTaskSupported">> = {}, stopTimeoutMs = 1000, host: object = {}): Harness {
 const h: Harness = {
  timers: new FakeTimers(), trace: undefined, ctorError: undefined, stopMode: "resolve", grantedMs: undefined, profilers: [], observers: [], clock: {value: 1000},
  visibility: {value: "visible", listeners: new Set()}, longTaskSupported: true, ua: CHROME_UA, uaData: undefined, hasProfiler: true, hasObserver: true, scope: "main", origin: ORIGIN,
  setVisibility(value) { h.visibility.value = value; for (const listener of [...h.visibility.listeners]) listener(); },
  ...over,
 } as Harness;
 let counter = 0;
 const Profiler = function (this: unknown, options: {sampleInterval: number; maxBufferSize: number}) { return new FakeProfiler(options, h); } as unknown;
 const Observer = class extends FakeObserver {
  static override get supportedEntryTypes(): string[] { return h.longTaskSupported ? ["longtask"] : []; }
  constructor(callback: (list: {getEntries(): unknown[]}) => void) { super(callback); h.observers.push(this); }
 };
 h.env = {
  get Profiler() { return h.hasProfiler ? Profiler : undefined; },
  get PerformanceObserver() { return h.hasObserver ? Observer : undefined; },
  get scope() { return h.scope; }, origin: () => h.origin, userAgent: () => h.ua, userAgentData: () => h.uaData, visibility: () => h.visibility.value,
  onVisibilityChange: listener => { h.visibility.listeners.add(listener); return () => { h.visibility.listeners.delete(listener); }; },
  isDOMException: error => error instanceof DOMError, now: () => h.clock.value, wallNs: () => "1700000000000000000",
  randomBytes: length => { counter++; return Uint8Array.from({length}, (_, i) => (counter * 17 + i * 3 + 1) % 255 + 1); },
  setTimeout: h.timers.set, clearTimeout: h.timers.clear, leaseHost: host, stopTimeoutMs,
 };
 h.api = createProfiler(h.env);
 return h;
}
const run = async (h: Harness, options: ProfileOptions, trace?: Trace): Promise<ProfileReport> => {
 const handle = await h.api.startProfile(options); h.trace = trace; return handle.stop();
};
const withFrames = (report: ProfileReport, stack: number): string[] => report.stacks[stack]!.frames.map(index => {
 const f = report.frames[index]!; return `${f.module_id}#${f.function}@${f.line}:${f.column}${f.reason ? "!" + f.reason : ""}`;
});
const keys = ["version", "method", "profile", "units", "time_delta_unit", "capability", "interval", "requested", "clock", "scope", "stack_order", "frames", "stacks", "samples", "sample_count", "truncated", "losses", "non_profile", "ack", "stopped_by"];
function expectEmptyRefusal(report: ProfileReport, status: string, reason: string): void {
 expect(Object.keys(report).sort()).toEqual([...keys].sort());
 expect(report.capability.status).toBe(status); expect(report.capability.reason).toBe(reason);
 expect(report.frames).toEqual([]); expect(report.stacks).toEqual([]); expect(report.samples).toEqual([]); expect(report.sample_count).toBe(0);
 expect(report.non_profile).toEqual([]); expect(report.stopped_by).toBe("not_started"); expect(report.profile).toBe(true);
 expect(report.capability.coverage).toEqual({frames: "none", threads: "none", workers: "none", tasks: "none"});
}

// A realistic ProfilerTrace: first-party named functions, an anonymous function, a query/fragment-carrying script, a cross-origin CDN
// script, other-port origin, a native frame (no resource), absolute-path-like and URL-like function names, plus an idle sample.
function realisticTrace(): Trace {
 return {
  resources: [`${ORIGIN}/assets/app.js`, `${ORIGIN}/assets/app.js?token=CANARY_QUERY_1`, "https://cdn.example.com/lib/vendor.js", `${ORIGIN}/assets/chunk.js#CANARY_FRAG`, `${ORIGIN}/a b/c.js`, `${ORIGIN}/`, `${ORIGIN}:8443/assets/x.js`],
  frames: [
   {name: "busyLoop", resourceId: 0, line: 10, column: 5}, {name: "outer", resourceId: 0, line: 20, column: 3}, {name: "", resourceId: 0, line: 30, column: 7},
   {name: "/home/CANARY_USER/secret.js", resourceId: 0, line: 4, column: 1}, {name: "C:\\Users\\CANARY_USER\\x", resourceId: 0, line: 5, column: 1},
   {name: "https://evil.example/CANARY_NAME.js:12:1", resourceId: 0, line: 6, column: 1}, {name: "vendorFn", resourceId: 2, line: 1, column: 1},
   {name: "queryFn", resourceId: 1, line: 2, column: 2}, {name: "fragFn", resourceId: 3, line: 3, column: 3}, {name: "Array.map"},
   {name: "handler.run", resourceId: 0, line: 40, column: 9}, {name: "spaced", resourceId: 4, line: 1, column: 1}, {name: "docFn", resourceId: 5, line: 1, column: 1}, {name: "portFn", resourceId: 6, line: 1, column: 1},
  ],
  stacks: [
   {frameId: 1}, {parentId: 0, frameId: 0}, {parentId: 1, frameId: 6}, {parentId: 2, frameId: 9}, {parentId: 0, frameId: 3}, {parentId: 4, frameId: 4}, {parentId: 5, frameId: 5},
   {parentId: 0, frameId: 7}, {parentId: 0, frameId: 8}, {parentId: 0, frameId: 2}, {parentId: 0, frameId: 10}, {frameId: 11}, {frameId: 12}, {frameId: 13},
  ],
  samples: [
   {timestamp: 2000, stackId: 1}, {timestamp: 2010.5, stackId: 3}, {timestamp: 2021}, {timestamp: 2031.5, stackId: 6}, {timestamp: 2042, stackId: 7}, {timestamp: 2052.5, stackId: 8},
   {timestamp: 2063, stackId: 9}, {timestamp: 2073.5, stackId: 10}, {timestamp: 2084, stackId: 11}, {timestamp: 2094.5, stackId: 12}, {timestamp: 2105, stackId: 13}, {timestamp: 2115.5, stackId: 1},
  ],
 };
}

test("importing the module installs nothing globally", () => { expect(leaseAtImport).toBeUndefined(); });

for (const [row, ua, runtime] of [["Firefox", FIREFOX_UA, "Firefox/144.0"], ["Safari", SAFARI_UA, "Safari/26.0"]] as const) {
 test(`${row}: no Profiler constructor -> unsupported js_self_profiling_unavailable, zero samples, engine identified from the user agent`, async () => {
  const h = harness({ua, hasProfiler: false});
  const handle = await h.api.startProfile({durationMs: 1000});
  const report = await handle.stop();
  expectEmptyRefusal(report, "unsupported", "js_self_profiling_unavailable");
  expect(report.capability.runtime).toBe(runtime);
  expect(report.capability.os).toBe("macos");
  expect(h.profilers.length).toBe(0); expect(h.timers.pending).toBe(0); expect(h.observers.length).toBe(0);
  expect(await handle.stop()).toBe(report);
  expect(Reflect.get(h.env.leaseHost, LEASE_KEY)).toBeUndefined();
 });
}

test("a Profiler that is not constructible (wrong typeof) is unsupported, never supported by version", async () => {
 const h = harness({ua: CHROME_UA}); Object.defineProperty(h.env, "Profiler", {value: {not: "a function"}});
 expectEmptyRefusal(await run(h, {durationMs: 100}), "unsupported", "js_self_profiling_unavailable");
});

for (const name of ["NotAllowedError", "NotSupportedError"]) test(`constructor throwing ${name} (Document-Policy js-profiling absent; NotAllowedError is what real Chrome 156 throws) -> denied document_policy_missing with zero samples, lease released`, async () => {
 const h = harness(); h.ctorError = new DOMError(name);
 const report = await run(h, {durationMs: 100}, realisticTrace());
 expectEmptyRefusal(report, "denied", "document_policy_missing");
 expect(h.timers.pending).toBe(0); expect(h.observers.length).toBe(0); expect(h.visibility.listeners.size).toBe(0);
 h.ctorError = undefined;
 expect((await run(h, {durationMs: 100})).capability.status).toBe("supported");
});

for (const name of ["SecurityError", "AbortError", "DataCloneError"]) {
 test(`constructor throwing DOMException ${name} -> denied permission_denied`, async () => {
  const h = harness(); h.ctorError = new DOMError(name);
  expectEmptyRefusal(await run(h, {durationMs: 100}), "denied", "permission_denied");
 });
}
for (const [row, thrown] of [["RangeError", new RangeError("CANARY_MESSAGE sampleInterval")], ["string", "CANARY_STRING"], ["number", 0]] as const) {
 test(`constructor throwing a non-DOMException (${row}) -> error sampler_failed, message never copied`, async () => {
  const h = harness(); h.ctorError = thrown;
  const report = await run(h, {durationMs: 100});
  expectEmptyRefusal(report, "error", "sampler_failed");
  expect(JSON.stringify(report)).not.toContain("CANARY");
 });
}

test("maps a realistic trace to frames/stacks/samples with leaf-first stacks and every privacy rule", async () => {
 const h = harness();
 const report = await run(h, {durationMs: 5000, intervalUs: 10000}, realisticTrace());
 expect(report.capability.status).toBe("supported"); expect(report.capability.reason).toBe("ok");
 expect(report.stack_order).toBe("leaf_first"); expect(report.units).toBe("samples"); expect(report.time_delta_unit).toBeNull();
 // 12 trace samples, one idle (no stackId): 11 real samples, idle counted in scope only.
 expect(report.sample_count).toBe(11); expect(report.samples.length).toBe(11); expect(report.scope.idle_samples).toBe(1);
 const stackOf = (sample: number): string[] => withFrames(report, report.samples[sample]!.stack);
 const external = "external#@0:0!not_captured";
 expect(stackOf(0)).toEqual(["assets/app.js#busyLoop@10:5", "assets/app.js#outer@20:3"]);
 // native Array.map + cross-origin vendorFn are two consecutive external frames: collapsed to one placeholder; the rest stays.
 expect(stackOf(1)).toEqual([external, "assets/app.js#busyLoop@10:5", "assets/app.js#outer@20:3"]);
 // absolute-path-like / Windows-path-like / URL-like function names are rejected: empty function + not_captured, location kept.
 expect(stackOf(2)).toEqual(["assets/app.js#@6:1!not_captured", "assets/app.js#@5:1!not_captured", "assets/app.js#@4:1!not_captured", "assets/app.js#outer@20:3"]);
 expect(stackOf(3)).toEqual([external, "assets/app.js#outer@20:3"]); // query string script
 expect(stackOf(4)).toEqual([external, "assets/app.js#outer@20:3"]); // fragment script
 expect(stackOf(5)).toEqual(["assets/app.js#@30:7!not_captured", "assets/app.js#outer@20:3"]); // anonymous function
 expect(stackOf(6)).toEqual(["assets/app.js#handler.run@40:9", "assets/app.js#outer@20:3"]); // dotted safe name
 expect(stackOf(7)).toEqual([external]); // path with a space is not a safe path
 expect(stackOf(8)).toEqual([external]); // the document itself has no script path
 expect(stackOf(9)).toEqual([external]); // other port = other origin
 // one placeholder frame is shared; frames are deduplicated.
 expect(report.frames.filter(f => f.module_id === "external").length).toBe(1);
 expect(new Set(report.frames.map(f => JSON.stringify(f))).size).toBe(report.frames.length);
 for (const f of report.frames) { expect(f.offset).toBe("0"); expect(f.artifact_id === "" || f.artifact_id === f.module_id).toBe(true); }
 const wire = JSON.stringify(report);
 for (const secret of ["CANARY", "token=", "cdn.example.com", "evil.example", "https://", "http://", "?", "#CANARY", "/home/", "Users"]) expect(wire).not.toContain(secret);
 for (const sample of report.samples) { expect(sample.count).toBe("1"); expect(sample.thread).toBe("main"); expect(sample.at_us).toMatch(/^(0|[1-9][0-9]*)$/); }
 // offsets are relative to the first sample (engine clock, ms -> us), never wall time.
 expect(report.samples.map(s => s.at_us).slice(0, 4)).toEqual(["0", "10500", "31500", "42000"]);
 for (const stack of report.stacks) for (const index of stack.frames) expect(index).toBeLessThan(report.frames.length);
});

test("achieved interval comes from the returned timestamps, not from the request or the grant; no CPU unit anywhere", async () => {
 const h = harness(); h.grantedMs = 10;
 const samples = [1000, 1016, 1032, 1048.5, 1064].map(timestamp => ({timestamp, stackId: 0}));
 const report = await run(h, {durationMs: 1000, intervalUs: 10000}, {resources: [`${ORIGIN}/a.js`], frames: [{name: "work", resourceId: 0, line: 1, column: 1}], stacks: [{frameId: 0}], samples});
 expect(report.interval.requested_us).toBe(10000);
 expect(report.interval.achieved_us).toBe(16000); // median of gaps 16000,16000,16500,15500
 expect(report.scope.granted_interval_us).toBe(10000);
 expect(JSON.stringify(report).toLowerCase()).not.toMatch(/cpu|nanosecond/);
 expect(report.units).toBe("samples");
 expect(report.clock.source).toContain("DOMHighResTimeStamp");
 expect(report.clock.uncertainty_ns).toBe("18446744073709551615");
 expect(report.clock.domain).toEqual(report.capability.clock_domain);
 for (const id of Object.values(report.clock.domain)) expect(id).toMatch(/^[0-9a-f]{32}$/);
 expect(new Set(Object.values(report.clock.domain)).size).toBe(3);
});

test("fewer than two samples: achieved interval is null, not assumed", async () => {
 const h = harness();
 const report = await run(h, {durationMs: 1000}, {resources: [], frames: [{name: "work"}], stacks: [{frameId: 0}], samples: [{timestamp: 5, stackId: 0}]});
 expect(report.interval.achieved_us).toBeNull(); expect(report.sample_count).toBe(1);
});

test("requested options reach the Profiler: interval in ms, bounded buffer from maxSamples; defaults 10 ms / 8192", async () => {
 const a = harness(); await run(a, {durationMs: 100, intervalUs: 4500, maxSamples: 300});
 expect(a.profilers[0]!.options).toEqual({sampleInterval: 4.5, maxBufferSize: 300});
 const b = harness(); const report = await run(b, {durationMs: 100});
 expect(b.profilers[0]!.options).toEqual({sampleInterval: 10, maxBufferSize: 8192});
 expect(report.requested).toEqual({duration_ms: 100, interval_us: 10000, max_samples: 8192, scope: null, long_tasks: false});
});

test("invalid options are denied invalid_options before any Profiler exists", async () => {
 const cases: unknown[] = [{}, {durationMs: 0}, {durationMs: 60001}, {durationMs: 1.5}, {durationMs: Number.NaN}, {durationMs: "100"}, {durationMs: 100, intervalUs: 999}, {durationMs: 100, intervalUs: 1_000_001}, {durationMs: 100, intervalUs: 1500.5},
  {durationMs: 100, maxSamples: 0}, {durationMs: 100, maxSamples: 8193}, {durationMs: 100, origin: "not an origin"}, {durationMs: 100, origin: "ftp://soundpost.test"}, {durationMs: 100, origin: "https://soundpost.test/path"},
  {durationMs: 100, scope: "iframe"}, {durationMs: 100, longTasks: "yes"}, null, "x"];
 for (const options of cases) {
  const h = harness();
  const report = await (await h.api.startProfile(options as ProfileOptions)).stop();
  expectEmptyRefusal(report, "denied", "invalid_options");
  expect(h.profilers.length).toBe(0); expect(Reflect.get(h.env.leaseHost, LEASE_KEY)).toBeUndefined(); expect(h.timers.pending).toBe(0);
 }
});

test("range boundaries are accepted exactly", async () => {
 for (const options of [{durationMs: 1}, {durationMs: 60000, intervalUs: 1000, maxSamples: 1}, {durationMs: 60000, intervalUs: 1_000_000, maxSamples: 8192}] as ProfileOptions[]) {
  const h = harness(); expect((await run(h, options)).capability.status).toBe("supported");
 }
});

test("owner conflict: a second start (even from a duplicate module copy) is denied profiler_owned and cannot release the owner's lease", async () => {
 const host = {}; const a = harness({}, 1000, host); const b = harness({}, 1000, host);
 const first = await a.api.startProfile({durationMs: 5000});
 const refused = await b.api.startProfile({durationMs: 5000});
 expectEmptyRefusal(await refused.stop(), "denied", "profiler_owned");
 expect(b.profilers.length).toBe(0); expect(a.profilers.length).toBe(1);
 const again = await b.api.startProfile({durationMs: 100});
 expectEmptyRefusal(await again.stop(), "denied", "profiler_owned"); // refused handle's stop did not release the owner
 const ok = await first.stop();
 expect(ok.capability.status).toBe("supported");
 expect((await (await b.api.startProfile({durationMs: 100})).stop()).capability.status).toBe("supported");
});

test("concurrent starts racing in the same tick: exactly one owner", async () => {
 const host = {}; const a = harness({}, 1000, host);
 const [x, y] = await Promise.all([a.api.startProfile({durationMs: 100}), a.api.startProfile({durationMs: 100})]);
 const reports = await Promise.all([x.stop(), y.stop()]);
 expect(reports.map(r => r.capability.reason).sort()).toEqual(["ok", "profiler_owned"]);
 expect(a.profilers.length).toBe(1);
});

test("isolate scope mismatch: declared worker on a window global (and the inverse) is denied without constructing", async () => {
 const w = harness({scope: "main"}); expectEmptyRefusal(await run(w, {durationMs: 100, scope: "worker"}), "denied", "isolate_scope_mismatch");
 const v = harness({scope: "worker"}); expectEmptyRefusal(await run(v, {durationMs: 100, scope: "main"}), "denied", "isolate_scope_mismatch");
 const u = harness({scope: "unknown"}); expectEmptyRefusal(await run(u, {durationMs: 100, scope: "main"}), "denied", "isolate_scope_mismatch");
 expect(w.profilers.length + v.profilers.length + u.profilers.length).toBe(0);
 const ok = harness({scope: "worker"}); const report = await run(ok, {durationMs: 100, scope: "worker"}, {resources: [], frames: [{name: "w"}], stacks: [{frameId: 0}], samples: [{timestamp: 1, stackId: 0}]});
 expect(report.capability.status).toBe("supported"); expect(report.scope.isolate).toBe("worker"); expect(report.samples[0]!.thread).toBe("worker");
 expect(Reflect.get(ok.env.leaseHost, LEASE_KEY)).toBeUndefined();
});

test("stop is idempotent: concurrent and later calls share one report and the Profiler is stopped once", async () => {
 const h = harness(); const handle = await h.api.startProfile({durationMs: 5000});
 h.trace = realisticTrace();
 const [a, b] = await Promise.all([handle.stop(), handle.stop()]);
 expect(a).toBe(b); expect(await handle.stop()).toBe(a); expect(h.profilers[0]!.stopCalls).toBe(1);
 expect(a.stopped_by).toBe("caller"); expect(h.timers.pending).toBe(0); expect(h.profilers[0]!.listenerCount()).toBe(0);
 expect(Reflect.get(h.env.leaseHost, LEASE_KEY)).toBeUndefined();
});

test("auto-stop after durationMs by timer; a later stop() returns the same finished report", async () => {
 const h = harness(); const handle = await h.api.startProfile({durationMs: 750}); h.trace = realisticTrace();
 expect(h.timers.delays()).toEqual([750]); expect(h.profilers[0]!.stopCalls).toBe(0);
 await h.timers.advance(749); expect(h.profilers[0]!.stopCalls).toBe(0);
 await h.timers.advance(1); expect(h.profilers[0]!.stopCalls).toBe(1);
 const report = await handle.stop(); expect(report.stopped_by).toBe("duration"); expect(report.sample_count).toBe(11);
 expect(h.profilers[0]!.stopCalls).toBe(1); expect(h.timers.pending).toBe(0); expect(Reflect.get(h.env.leaseHost, LEASE_KEY)).toBeUndefined();
});

test("Profiler.stop() hang: bounded by its own timeout -> error stop_timeout, no samples, timeout_cleanup loss, lease released, nothing pending", async () => {
 const h = harness({}, 1000); h.stopMode = "hang"; h.trace = realisticTrace();
 const handle = await h.api.startProfile({durationMs: 5000, longTasks: true});
 const pending = handle.stop(); await flush();
 expect(h.timers.delays()).toEqual([1000]); // only the stop timeout; the duration timer is gone
 await h.timers.advance(1000);
 const report = await pending;
 expect(report.capability.status).toBe("error"); expect(report.capability.reason).toBe("stop_timeout");
 expect(report.samples).toEqual([]); expect(report.frames).toEqual([]); expect(report.sample_count).toBe(0);
 expect(report.stopped_by).toBe("timeout_cleanup"); expect(report.losses.map(l => l.reason)).toEqual(["timeout_cleanup"]);
 expect(h.timers.pending).toBe(0); expect(h.observers[0]!.disconnected).toBe(true); expect(h.visibility.listeners.size).toBe(0);
 expect(Reflect.get(h.env.leaseHost, LEASE_KEY)).toBeUndefined();
 expect(await handle.stop()).toBe(report);
 h.stopMode = "resolve"; expect((await run(h, {durationMs: 100})).capability.status).toBe("supported");
});

test("Profiler.stop() rejecting -> error sampler_failed, lease released", async () => {
 const h = harness(); h.stopMode = "reject";
 const report = await run(h, {durationMs: 100}, realisticTrace());
 expect(report.capability.status).toBe("error"); expect(report.capability.reason).toBe("sampler_failed"); expect(report.sample_count).toBe(0); expect(report.samples).toEqual([]);
 expect(report.stopped_by).toBe("caller"); expect(Reflect.get(h.env.leaseHost, LEASE_KEY)).toBeUndefined();
});

test("malformed traces are sampler_failed with zero samples, never partially mapped", async () => {
 const bad: Record<string, Trace> = {
  notArray: {resources: [], frames: [], stacks: [], samples: "x"},
  cycle: {resources: [], frames: [{name: "a"}, {name: "b"}], stacks: [{parentId: 1, frameId: 0}, {parentId: 0, frameId: 1}], samples: [{timestamp: 1, stackId: 0}]},
  badStack: {resources: [], frames: [{name: "a"}], stacks: [{frameId: 0}], samples: [{timestamp: 1, stackId: 3}]},
  badFrame: {resources: [], frames: [{name: "a"}], stacks: [{frameId: 7}], samples: [{timestamp: 1, stackId: 0}]},
  badTime: {resources: [], frames: [{name: "a"}], stacks: [{frameId: 0}], samples: [{timestamp: Number.NaN, stackId: 0}]},
  badResource: {resources: [], frames: [{name: "a", resourceId: 4}], stacks: [{frameId: 0}], samples: [{timestamp: 1, stackId: 0}]},
 };
 for (const [row, trace] of Object.entries(bad)) {
  const h = harness(); const report = await run(h, {durationMs: 100}, trace);
  expect(report.capability.status, row).toBe("error"); expect(report.capability.reason, row).toBe("sampler_failed");
  expect(report.samples, row).toEqual([]); expect(report.frames, row).toEqual([]); expect(report.sample_count, row).toBe(0);
  expect(Reflect.get(h.env.leaseHost, LEASE_KEY), row).toBeUndefined();
 }
 const h = harness(); h.trace = undefined; Object.defineProperty(h, "trace", {get() { throw new Error("CANARY_TRACE_GETTER"); }});
 expect((await (await h.api.startProfile({durationMs: 100})).stop()).capability.reason).toBe("sampler_failed");
});

test("stacks deeper than 128 keep the leaf-most 128 frames and say so", async () => {
 const h = harness(); const frames = Array.from({length: 200}, (_, i) => ({name: `f${i}`, resourceId: 0, line: i + 1, column: 1}));
 const stacks = frames.map((_, i) => i === 0 ? {frameId: 0} : {parentId: i - 1, frameId: i});
 const report = await run(h, {durationMs: 100}, {resources: [`${ORIGIN}/deep.js`], frames, stacks, samples: [{timestamp: 1, stackId: 199}]});
 const names = withFrames(report, 0);
 expect(names.length).toBe(128); expect(names[0]).toBe("deep.js#f199@200:1"); expect(names[127]).toBe("deep.js#f72@73:1");
 expect(report.truncated).toBe(true); expect(report.scope.stack_depth_truncated_samples).toBe(1);
});

test("frame cap 4096: samples needing more distinct frames are dropped and counted as truncated", async () => {
 const h = harness(); const n = 5000;
 const frames = Array.from({length: n}, (_, i) => ({name: `fn${i}`, resourceId: 0, line: i + 1, column: 1}));
 const report = await run(h, {durationMs: 100}, {resources: [`${ORIGIN}/many.js`], frames, stacks: frames.map((_, i) => ({frameId: i})), samples: frames.map((_, i) => ({timestamp: i, stackId: i}))});
 expect(report.frames.length).toBe(4096); expect(report.stacks.length).toBe(4096); expect(report.sample_count).toBe(4096); expect(report.truncated).toBe(true);
 expect(report.losses).toEqual([{reason: "truncated", count: "904"}]);
});

test("a trace longer than maxSamples is cut at maxSamples with a truncated loss", async () => {
 const h = harness(); const samples = Array.from({length: 10}, (_, i) => ({timestamp: i * 10, stackId: 0}));
 const report = await run(h, {durationMs: 100, maxSamples: 4}, {resources: [], frames: [{name: "a"}], stacks: [{frameId: 0}], samples});
 expect(report.sample_count).toBe(4); expect(report.samples.length).toBe(4); expect(report.truncated).toBe(true); expect(report.losses).toEqual([{reason: "truncated", count: "6"}]);
});

test("samplebufferfull marks the report truncated with a truncated loss; listener removed", async () => {
 const h = harness(); const handle = await h.api.startProfile({durationMs: 5000});
 expect(h.profilers[0]!.listenerCount()).toBe(1);
 h.profilers[0]!.emit("samplebufferfull"); h.trace = realisticTrace();
 const report = await handle.stop();
 expect(report.truncated).toBe(true); expect(report.losses.map(l => l.reason)).toEqual(["truncated"]); expect(h.profilers[0]!.listenerCount()).toBe(0);
});

test("a regular run reports no truncation and no sample_gap", async () => {
 const h = harness(); const report = await run(h, {durationMs: 5000}, realisticTrace());
 expect(report.truncated).toBe(false); expect(report.losses).toEqual([]); expect(report.scope.visibility).toEqual({start: "visible", end: "visible", changed: false});
});

test("sample gaps are measured against the granted interval (not the request) and reported as sample_gap", async () => {
 const h = harness(); h.grantedMs = 16;
 const timestamps = [1000, 1016, 1051, 1067, 1083];
 const report = await run(h, {durationMs: 5000, intervalUs: 10000}, {resources: [], frames: [{name: "a"}], stacks: [{frameId: 0}], samples: timestamps.map(timestamp => ({timestamp, stackId: 0}))});
 expect(report.losses).toEqual([{reason: "sample_gap", count: "1"}]); // 35 ms gap at a 16 ms grant: 1 missing sample (a 10 ms request would say 3)
 expect(report.scope.granted_interval_us).toBe(16000);
 const exact = harness(); exact.grantedMs = 16;
 const none = await run(exact, {durationMs: 5000, intervalUs: 10000}, {resources: [], frames: [{name: "a"}], stacks: [{frameId: 0}], samples: [1000, 1016, 1048, 1064].map(timestamp => ({timestamp, stackId: 0}))});
 expect(none.losses).toEqual([]); // 32 ms == 2x grant is within tolerance
});

test("visibility change during the run is recorded and is a sample_gap loss even without a measurable timestamp gap", async () => {
 const h = harness(); const handle = await h.api.startProfile({durationMs: 5000});
 h.setVisibility("hidden"); h.setVisibility("visible");
 h.trace = {resources: [], frames: [{name: "a"}], stacks: [{frameId: 0}], samples: [1000, 1010, 1020].map(timestamp => ({timestamp, stackId: 0}))};
 const report = await handle.stop();
 expect(report.scope.visibility).toEqual({start: "visible", end: "visible", changed: true});
 expect(report.losses.map(l => l.reason)).toEqual(["sample_gap"]);
 expect(h.visibility.listeners.size).toBe(0);
 const hidden = harness(); hidden.visibility.value = "hidden";
 const r2 = await run(hidden, {durationMs: 100}, {resources: [], frames: [{name: "a"}], stacks: [{frameId: 0}], samples: [{timestamp: 1, stackId: 0}]});
 expect(r2.scope.visibility).toEqual({start: "hidden", end: "hidden", changed: false}); expect(r2.losses.map(l => l.reason)).toEqual(["sample_gap"]);
});

test("coverage honesty and absent ACK: JS frames partial, threads partial, workers/tasks none", async () => {
 const h = harness(); const report = await run(h, {durationMs: 100}, realisticTrace());
 expect(report.capability.coverage).toEqual({frames: "partial", threads: "partial", workers: "none", tasks: "none"});
 expect(report.ack).toEqual({status: "not_available"}); expect(report.capability.signal).toBe("profile_chunk"); expect(report.method).toBe("browser_js_self_profile");
 expect(report.capability.expires_ns).toBe("1700003600000000000"); expect(report.clock.wall_start_ns).toBe("1700000000000000000");
});

test("script paths use the page origin by default and an explicit origin option; other origins become the placeholder", async () => {
 const trace = {resources: [`${ORIGIN}/a.js`, "https://app.example/b.js"], frames: [{name: "one", resourceId: 0, line: 1, column: 1}, {name: "two", resourceId: 1, line: 2, column: 2}], stacks: [{frameId: 0}, {frameId: 1}], samples: [{timestamp: 1, stackId: 0}, {timestamp: 2, stackId: 1}]};
 const a = harness(); const byDefault = await run(a, {durationMs: 100}, trace);
 expect(withFrames(byDefault, 0)).toEqual(["a.js#one@1:1"]); expect(withFrames(byDefault, 1)).toEqual(["external#@0:0!not_captured"]);
 const b = harness({origin: undefined}); const explicit = await run(b, {durationMs: 100, origin: "https://app.example"}, trace);
 expect(withFrames(explicit, 0)).toEqual(["external#@0:0!not_captured"]); expect(withFrames(explicit, 1)).toEqual(["b.js#two@2:2"]);
 expect(JSON.stringify(explicit)).not.toContain("app.example");
 const c = harness({origin: undefined}); const none = await run(c, {durationMs: 100}, trace);
 expect(none.frames.every(f => f.module_id === "external")).toBe(true); // no known origin: nothing may be called first-party
 const d = harness({origin: "null"}); const opaque = await run(d, {durationMs: 100}, trace);
 expect(opaque.frames.every(f => f.module_id === "external")).toBe(true);
});

test("long tasks: separate non_profile metric entries with only duration/start, bounded, never in samples; observer disconnected", async () => {
 const h = harness(); const handle = await h.api.startProfile({durationMs: 5000, longTasks: true});
 expect(h.observers.length).toBe(1); expect(h.observers[0]!.observed).toEqual([{type: "longtask"}]);
 const task = (i: number, extra: Record<string, unknown> = {}): Record<string, unknown> => ({entryType: "longtask", name: "self", startTime: 1500.4 + i, duration: 120.25, attribution: [{name: "unknown", containerSrc: "https://x.example/CANARY_SRC", containerId: "CANARY_ID", containerName: "CANARY_NAME"}], ...extra});
 h.observers[0]!.deliver([task(0)]);
 h.observers[0]!.deliver([{entryType: "paint", name: "CANARY_PAINT", startTime: 1, duration: 100}, task(1, {duration: Number.NaN})]);
 h.observers[0]!.deliver(Array.from({length: 299}, (_, i) => task(i + 2)));
 h.observers[0]!.queued = [task(1000)];
 h.trace = realisticTrace();
 const report = await handle.stop();
 expect(report.non_profile.length).toBe(256);
 expect(report.non_profile[0]).toEqual({method: "long_task", profile: false, signal: "metric", unit: "milliseconds", duration_ms: 120.3, start_ms: 500.4});
 for (const entry of report.non_profile) expect(Object.keys(entry).sort()).toEqual(["duration_ms", "method", "profile", "signal", "start_ms", "unit"]);
 expect(report.scope.long_tasks).toBe("observed"); expect(report.scope.long_tasks_dropped).toBe(45); // 300 delivered + 1 queued = 301 valid entries, 256 kept; the paint entry and the NaN duration are ignored, not counted
 expect(JSON.stringify(report)).not.toMatch(/CANARY_(SRC|ID|NAME|PAINT)/);
 expect(report.sample_count).toBe(11); expect(report.samples.every(s => "stack" in s && !("duration_ms" in s))).toBe(true);
 expect(h.observers[0]!.disconnected).toBe(true);
});

test("long tasks not requested: no observer is created; unsupported entry type is reported, profile unaffected", async () => {
 const a = harness(); const off = await run(a, {durationMs: 100}, realisticTrace());
 expect(a.observers.length).toBe(0); expect(off.scope.long_tasks).toBe("not_requested"); expect(off.non_profile).toEqual([]);
 const b = harness({longTaskSupported: false}); const unsupported = await run(b, {durationMs: 100, longTasks: true}, realisticTrace());
 expect(unsupported.scope.long_tasks).toBe("unsupported"); expect(b.observers.length).toBe(0); expect(unsupported.sample_count).toBe(11);
 const c = harness({hasObserver: false}); const missing = await run(c, {durationMs: 100, longTasks: true}, realisticTrace());
 expect(missing.scope.long_tasks).toBe("unsupported"); expect(missing.capability.status).toBe("supported");
});

test("browser identity: high-entropy brands give an exact build token; fallbacks reduce the user agent; hostile input becomes unknown", async () => {
 const entropy = {platform: "Linux", brands: [{brand: "Chromium", version: "156"}], getHighEntropyValues: async (hints: string[]) => {
  expect(hints.sort()).toEqual(["architecture", "bitness", "fullVersionList"]);
  return {fullVersionList: [{brand: "Not A(Brand", version: "99.0.0.0"}, {brand: "Chromium", version: "156.0.8078.80"}, {brand: "Google Chrome", version: "156.0.8078.80"}], architecture: "x86", bitness: "64", platform: "Linux"};
 }};
 const a = harness({uaData: entropy}); const exact = await run(a, {durationMs: 100});
 expect(exact.capability).toMatchObject({runtime: "Chrome/156.0.8078.80", version: "156.0.8078.80", build: "Chrome/156.0.8078.80", os: "linux", arch: "x86_64"});
 expect(exact.scope.runtime).toEqual({name: "Chrome", version: "156.0.8078.80"});
 const b = harness(); const reduced = await run(b, {durationMs: 100});
 expect(reduced.capability).toMatchObject({runtime: "Chrome/156.0.0.0", version: "156.0.0.0", os: "linux", arch: "x86_64"});
 const hostile = harness({ua: "Mozilla/5.0 CANARY_UA (C:\\Users\\CANARY) Chrome/1x2<script>"}); const unknown = await run(hostile, {durationMs: 100});
 expect(unknown.capability).toMatchObject({runtime: "unknown", version: "unknown", build: "unknown", os: "unknown", arch: "unknown"}); expect(JSON.stringify(unknown)).not.toContain("CANARY");
 const edge = harness({uaData: {platform: "Windows", getHighEntropyValues: async () => ({fullVersionList: [{brand: "Chromium", version: "156.0.1.2"}, {brand: "Microsoft Edge", version: "156.0.1.2"}], architecture: "arm", bitness: "64"})}});
 expect((await run(edge, {durationMs: 100})).capability).toMatchObject({runtime: "Edge/156.0.1.2", os: "windows", arch: "arm64"});
 const throwing = harness({uaData: {platform: "Linux", getHighEntropyValues: async () => { throw new DOMError("NotAllowedError"); }}});
 expect((await run(throwing, {durationMs: 100})).capability.runtime).toBe("Chrome/156.0.0.0");
});

test("a high-entropy lookup that never settles cannot hold the profile open: bounded fallback to the user agent token", async () => {
 const h = harness({uaData: {platform: "Linux", getHighEntropyValues: () => new Promise(() => {})}});
 const handle = await h.api.startProfile({durationMs: 5000});
 const pending = handle.stop(); await flush(); await h.timers.advance(1000);
 const report = await pending;
 expect(report.capability.runtime).toBe("Chrome/156.0.0.0"); expect(report.capability.status).toBe("supported"); expect(h.timers.pending).toBe(0);
});

test("capability payload from every report kind passes core parseSafeRecord for a capability record; reasons are the closed set", async () => {
 const make = async (): Promise<ProfileReport[]> => {
  const reports: ProfileReport[] = [];
  const ok = harness(); reports.push(await run(ok, {durationMs: 100}, realisticTrace()));
  const fx = harness({ua: FIREFOX_UA, hasProfiler: false}); reports.push(await run(fx, {durationMs: 100}));
  const pol = harness(); pol.ctorError = new DOMError("NotSupportedError"); reports.push(await run(pol, {durationMs: 100}));
  const bad = harness(); reports.push(await run(bad, {durationMs: -1}));
  const err = harness(); err.stopMode = "hang"; const handle = await err.api.startProfile({durationMs: 100}); const pending = handle.stop(); await flush(); await err.timers.advance(1000); reports.push(await pending);
  return reports;
 };
 for (const report of await make()) {
  const {id, ...payload} = report.capability;
  const record = parseSafeRecord(JSON.stringify({id, kind: "capability", observed_at_ns: report.clock.wall_start_ns, policy_revision: "1", payload}));
  expect(record.kind).toBe("capability"); expect(record.payload.reason).toBe(report.capability.reason);
  expect(profileReasons as readonly string[]).toContain(report.capability.reason);
  for (const key of ["runtime", "version", "build", "os", "arch", "method", "reason"]) expect(String(record.payload[key])).toMatch(/^[A-Za-z0-9_.:/<>+ $-]+$/);
  expect(report.capability.id).toMatch(/^[0-9a-f]{32}$/);
 }
});

test("script URLs with user info are placeholders; function names over 128 chars are rejected, exactly 128 accepted", async () => {
 const h = harness(); const long = "a".repeat(128), tooLong = "a".repeat(129);
 const report = await run(h, {durationMs: 100}, {
  resources: [`https://user:pw@soundpost.test/a.js`, `${ORIGIN}/b.js`],
  frames: [{name: "credentialed", resourceId: 0, line: 1, column: 1}, {name: long, resourceId: 1, line: 2, column: 2}, {name: tooLong, resourceId: 1, line: 3, column: 3}],
  stacks: [{frameId: 0}, {frameId: 1}, {frameId: 2}], samples: [0, 1, 2].map(i => ({timestamp: i, stackId: i})),
 });
 expect(withFrames(report, 0)).toEqual(["external#@0:0!not_captured"]);
 expect(withFrames(report, 1)).toEqual([`b.js#${long}@2:2`]);
 expect(withFrames(report, 2)).toEqual(["b.js#@3:3!not_captured"]);
 expect(JSON.stringify(report)).not.toMatch(/user|pw@/);
});

test("depth boundary: exactly 128 frames is complete, 129 is cut to 128 and flagged", async () => {
 const make = (n: number): Trace => {
  const frames = Array.from({length: n}, (_, i) => ({name: `f${i}`, resourceId: 0, line: i + 1, column: 1}));
  return {resources: [`${ORIGIN}/d.js`], frames, stacks: frames.map((_, i) => i === 0 ? {frameId: 0} : {parentId: i - 1, frameId: i}), samples: [{timestamp: 1, stackId: n - 1}]};
 };
 const a = await run(harness(), {durationMs: 100}, make(128));
 expect(a.stacks[0]!.frames.length).toBe(128); expect(a.truncated).toBe(false); expect(a.scope.stack_depth_truncated_samples).toBe(0);
 const b = await run(harness(), {durationMs: 100}, make(129));
 expect(b.stacks[0]!.frames.length).toBe(128); expect(b.truncated).toBe(true); expect(b.scope.stack_depth_truncated_samples).toBe(1);
});

test("a lease that was replaced by someone else while running is left alone on release", async () => {
 const host: Record<symbol, unknown> = {}; const h = harness({}, 1000, host);
 const handle = await h.api.startProfile({durationMs: 5000});
 const foreign = {foreign: true}; host[LEASE_KEY] = foreign;
 await handle.stop();
 expect(host[LEASE_KEY]).toBe(foreign);
});

test("samples that go backwards in time are a malformed trace, never negative offsets", async () => {
 const h = harness();
 const report = await run(h, {durationMs: 100}, {resources: [], frames: [{name: "a"}], stacks: [{frameId: 0}], samples: [{timestamp: 100, stackId: 0}, {timestamp: 90, stackId: 0}]});
 expect(report.capability.status).toBe("error"); expect(report.capability.reason).toBe("sampler_failed"); expect(report.samples).toEqual([]);
});

test("reports are plain JSON: survive a JSON round trip unchanged", async () => {
 const h = harness(); const report = await run(h, {durationMs: 100, longTasks: true}, realisticTrace());
 expect(JSON.parse(JSON.stringify(report))).toEqual(report);
});
