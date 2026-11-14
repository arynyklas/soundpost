// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Real-browser rows for the JS Self-Profiling supplement (packages/browser/src/profile.ts bundled for the browser, no fakes).
// The page is served from a fake https origin through page.route with (or without) the `Document-Policy: js-profiling` header.
import {test, expect, type Browser, type Page} from "@playwright/test";
import {execFileSync} from "node:child_process";
import {mkdtempSync, readFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join, resolve} from "node:path";

const root = resolve(__dirname, "../../..");
const bundleDir = mkdtempSync(join(tmpdir(), "soundpost-profile-"));
const bun = process.env.SOUNDPOST_BUN ?? "bun";
execFileSync(bun, ["build", join(root, "packages/browser/src/profile.ts"), "--outdir", bundleDir, "--target=browser", "--format=esm"], {stdio: "pipe"});
const html = readFileSync(join(root, "fixtures/sdk/profiles/browser.html"), "utf8");
const origin = "https://soundpost.test";
// Named first-party functions the busy loop runs through; a script reached through a query string; a cross-origin script.
const workload = `function innerSpin(ms) { const end = performance.now() + ms; let x = 0; while (performance.now() < end) { x = (x + Math.sqrt(x + 1)) % 1000003; } return x; }
function outerWork(ms) { return innerSpin(ms); }
window.runWorkload = function (ms) { return outerWork(ms); };
`;
const queryScript = "window.queryWork = function queryWork(ms) { const end = performance.now() + ms; while (performance.now() < end) { Math.sqrt(end); } };\n";
const vendorScript = "window.vendorWork = function vendorWork(ms) { const end = performance.now() + ms; while (performance.now() < end) { Math.sqrt(end); } };\n";
const workerScript = `import {startProfile} from "/profile.js";
self.onmessage = async () => {
 const handle = await startProfile({durationMs: 5000, intervalUs: 5000, scope: "worker"});
 const end = performance.now() + 150; let x = 0; while (performance.now() < end) { x = (x + Math.sqrt(x + 1)) % 1000003; }
 self.postMessage(await handle.stop());
};
`;

interface Report {
 capability: {runtime: string; version: string; build: string; os: string; arch: string; status: string; reason: string; coverage: Record<string, string>; clock_domain: Record<string, string>; id: string; expires_ns: string};
 interval: {requested_us: number; achieved_us: number | null}; clock: {source: string; uncertainty_ns: string};
 scope: Record<string, unknown>; frames: {module_id: string; function: string; artifact_id: string; line: number; column: number; reason: string}[]; stacks: {frames: number[]}[];
 samples: {at_us: string; stack: number; count: string; thread: string}[]; sample_count: number; truncated: boolean; losses: {reason: string; count: string}[];
 non_profile: Record<string, unknown>[]; stopped_by: string; units: string; time_delta_unit: null; stack_order: string;
}
const evidence: Record<string, unknown> = {};

async function open(page: Page, options: {policy: boolean; init?: string} = {policy: true}): Promise<string[]> {
 const errors: string[] = [];
 page.on("pageerror", error => errors.push(error.message));
 if (options.init) await page.addInitScript(options.init);
 await page.route("https://**/*", async route => {
  const url = new URL(route.request().url());
  const js = {contentType: "text/javascript"};
  if (url.origin === origin && url.pathname === "/") return route.fulfill({contentType: "text/html", body: html, headers: options.policy ? {"Document-Policy": "js-profiling"} : {}});
  if (url.origin === origin && url.pathname === "/profile.js") return route.fulfill({...js, body: readFileSync(join(bundleDir, "profile.js"), "utf8")});
  if (url.origin === origin && url.pathname === "/assets/workload.js") return route.fulfill({...js, body: workload});
  if (url.origin === origin && url.pathname === "/assets/query.js") return route.fulfill({...js, body: queryScript});
  if (url.origin === origin && url.pathname === "/worker.js") return route.fulfill({...js, body: workerScript, headers: options.policy ? {"Document-Policy": "js-profiling"} : {}});
  if (url.origin === "https://cdn.soundpost.test" && url.pathname === "/vendor.js") return route.fulfill({...js, body: vendorScript});
  return route.fulfill({status: 404, body: ""});
 });
 await page.goto(`${origin}/`);
 await page.waitForFunction(() => Reflect.get(window, "__ready") === true);
 return errors;
}
const identity = async (page: Page, browser: Browser): Promise<Record<string, string>> => ({chrome: browser.version(), userAgent: await page.evaluate(() => navigator.userAgent), hasProfiler: String(await page.evaluate(() => typeof Reflect.get(window, "Profiler")))});

test("with the Document-Policy header: genuine samples from a real busy loop, safe frames, long_task separate, no CPU unit", async ({page, browser}) => {
 const errors = await open(page);
 const report: Report = await page.evaluate(async () => {
  const handle = await Reflect.get(window, "__startProfile")({durationMs: 5000, intervalUs: 5000, longTasks: true, origin: location.origin});
  // Mixed workload run as a real timer task (a CDP-evaluated call is not a scheduler task and is never a long task): first-party named
  // functions (200 ms), a query-string script and a cross-origin script.
  await new Promise<void>(resolve => setTimeout(() => { Reflect.get(window, "runWorkload")(200); Reflect.get(window, "queryWork")(60); Reflect.get(window, "vendorWork")(60); resolve(); }, 0));
  await new Promise(resolve => setTimeout(resolve, 150));
  return handle.stop();
 });
 const wire = JSON.stringify(report);
 const named = new Set(report.frames.filter(f => f.module_id === "assets/workload.js").map(f => f.function));
 const leafInner = report.samples.filter(s => report.frames[report.stacks[s.stack]!.frames[0]!]?.function === "innerSpin");
 const inner = leafInner.length ? report.stacks[leafInner[0]!.stack]!.frames.map(i => report.frames[i]!.function) : [];
 evidence.with_header = {...await identity(page, browser), status: report.capability.status, reason: report.capability.reason, runtime: report.capability.runtime, os: report.capability.os, arch: report.capability.arch,
  sample_count: report.sample_count, requested_us: report.interval.requested_us, achieved_us: report.interval.achieved_us, granted_us: report.scope.granted_interval_us, idle_samples: report.scope.idle_samples,
  frames: report.frames.length, stacks: report.stacks.length, losses: report.losses, truncated: report.truncated, long_tasks: report.non_profile.length, long_task_max_ms: Math.max(0, ...report.non_profile.map(e => Number(e.duration_ms))), coverage: report.capability.coverage,
  named_first_party: [...named].sort(), frame_modules: [...new Set(report.frames.map(f => f.module_id))].sort(), frame_list: report.frames.map(f => `${f.module_id}#${f.function}@${f.line}:${f.column}`), inner_stack: inner, visibility: report.scope.visibility, stopped_by: report.stopped_by};
 expect(errors).toEqual([]);
 expect(report.capability.status).toBe("supported"); expect(report.capability.reason).toBe("ok");
 expect(report.capability.runtime).toMatch(new RegExp("^(Chrome|Chromium|Edge)/" + browser.version().replaceAll(".", "\\.") + "$")); // brand token from userAgentData (Playwright's emulated metadata lists only "Chromium") plus the version of the build that was launched
 expect(report.sample_count).toBeGreaterThan(0); expect(report.samples.length).toBe(report.sample_count);
 expect(named.has("innerSpin")).toBe(true); expect(named.has("outerWork")).toBe(true);
 expect(inner.slice(0, 2)).toEqual(["innerSpin", "outerWork"]); // leaf-first
 // profile.js: the profiler's own start-up frames are legitimately sampled (first-party script, origin-relative path).
 for (const f of report.frames) { expect(["external", "assets/workload.js", "profile.js"]).toContain(f.module_id); expect(f.artifact_id).toBe(f.module_id === "external" ? "" : f.module_id); }
 expect(report.frames.some(f => f.module_id === "external")).toBe(true);
 expect(report.frames.some(f => f.function === "queryWork" || f.function === "vendorWork")).toBe(false); // query-string and cross-origin scripts are placeholders
 for (const secret of ["CANARY", "token=", "https://", "http://", "soundpost.test", "cdn."]) expect(wire).not.toContain(secret);
 expect(wire.toLowerCase()).not.toMatch(/cpu|nanosecond/);
 expect(report.units).toBe("samples"); expect(report.time_delta_unit).toBeNull(); expect(report.stack_order).toBe("leaf_first");
 expect(typeof report.interval.achieved_us).toBe("number"); expect(report.interval.achieved_us).toBeGreaterThan(0); expect(report.interval.requested_us).toBe(5000);
 expect(report.capability.coverage).toEqual({frames: "partial", threads: "partial", workers: "none", tasks: "none"});
 expect(report.clock.source).toContain("DOMHighResTimeStamp"); expect(report.clock.uncertainty_ns).toBe("18446744073709551615");
 expect(report.non_profile.length).toBeGreaterThan(0);
 for (const entry of report.non_profile) { expect(Object.keys(entry).sort()).toEqual(["duration_ms", "method", "profile", "signal", "start_ms", "unit"]); expect(entry.method).toBe("long_task"); expect(entry.signal).toBe("metric"); }
 expect(Math.max(...report.non_profile.map(e => Number(e.duration_ms)))).toBeGreaterThanOrEqual(50);
 expect(report.scope.long_tasks).toBe("observed");
 expect(JSON.parse(wire)).toEqual(report);
});

test("without the Document-Policy header: truthful refusal, zero samples", async ({page, browser}) => {
 const errors = await open(page, {policy: false});
 const probe = await page.evaluate(() => { try { new (Reflect.get(window, "Profiler"))({sampleInterval: 10, maxBufferSize: 100}); return {constructed: true}; } catch (error) { const e = error as DOMException; return {constructed: false, name: e.name, domException: e instanceof DOMException, message: e.message}; } });
 const report: Report = await page.evaluate(async () => (await Reflect.get(window, "__startProfile")({durationMs: 1000})).stop());
 evidence.without_header = {...await identity(page, browser), constructor_error: probe, status: report.capability.status, reason: report.capability.reason, runtime: report.capability.runtime, sample_count: report.sample_count, coverage: report.capability.coverage};
 expect(errors).toEqual([]);
 // Observed in Chrome 156: the constructor throws a DOMException named NotAllowedError ("JS profiling is disabled by Document Policy").
 expect(probe).toMatchObject({constructed: false, name: "NotAllowedError", domException: true});
 expect(report.capability.status).toBe("denied"); expect(report.capability.reason).toBe("document_policy_missing");
 expect(report.sample_count).toBe(0); expect(report.samples).toEqual([]); expect(report.frames).toEqual([]); expect(report.stacks).toEqual([]); expect(report.stopped_by).toBe("not_started");
});

test("Profiler removed (Firefox/Safari emulation): unsupported, zero samples, the page keeps running", async ({page, browser}) => {
 const errors = await open(page, {policy: true, init: "delete window.Profiler;"});
 const result = await page.evaluate(async () => {
  const handle = await Reflect.get(window, "__startProfile")({durationMs: 1000});
  const sum = Reflect.get(window, "runWorkload")(20); // application code still runs
  return {report: await handle.stop(), ran: typeof sum === "number"};
 });
 const report = result.report as Report;
 evidence.profiler_removed = {...await identity(page, browser), status: report.capability.status, reason: report.capability.reason, sample_count: report.sample_count};
 expect(errors).toEqual([]); expect(result.ran).toBe(true);
 expect(report.capability.status).toBe("unsupported"); expect(report.capability.reason).toBe("js_self_profiling_unavailable");
 expect(report.sample_count).toBe(0); expect(report.samples).toEqual([]); expect(report.frames).toEqual([]); expect(report.stopped_by).toBe("not_started");
});

test("second concurrent start is denied profiler_owned and does not disturb the owner; the lease frees after stop", async ({page, browser}) => {
 const errors = await open(page);
 const result = await page.evaluate(async () => {
  const start = Reflect.get(window, "__startProfile");
  const first = await start({durationMs: 5000, intervalUs: 5000});
  const second = await (await start({durationMs: 1000})).stop();
  await new Promise<void>(resolve => setTimeout(() => { Reflect.get(window, "runWorkload")(100); resolve(); }, 0));
  const owner = await first.stop();
  const third = await (await start({durationMs: 1000, intervalUs: 5000})).stop();
  return {second, owner, third};
 });
 evidence.concurrent_start = {...await identity(page, browser), second: [result.second.capability.status, result.second.capability.reason], owner: [result.owner.capability.status, result.owner.sample_count], after_stop: [result.third.capability.status, result.third.capability.reason]};
 expect(errors).toEqual([]);
 expect(result.second.capability.status).toBe("denied"); expect(result.second.capability.reason).toBe("profiler_owned"); expect(result.second.sample_count).toBe(0);
 expect(result.owner.capability.status).toBe("supported"); expect(result.owner.sample_count).toBeGreaterThan(0);
 expect(result.third.capability.status).toBe("supported");
});

test("declared worker scope on the main thread is denied isolate_scope_mismatch; auto-stop after durationMs", async ({page, browser}) => {
 const errors = await open(page);
 const result = await page.evaluate(async () => {
  const start = Reflect.get(window, "__startProfile");
  const mismatch = await (await start({durationMs: 1000, scope: "worker"})).stop();
  const handle = await start({durationMs: 120, intervalUs: 5000, scope: "main"});
  await new Promise<void>(resolve => setTimeout(() => { Reflect.get(window, "runWorkload")(60); resolve(); }, 0));
  await new Promise(resolve => setTimeout(resolve, 400));
  const auto = await handle.stop();
  return {mismatch, auto};
 });
 evidence.scope_and_duration = {...await identity(page, browser), mismatch: [result.mismatch.capability.status, result.mismatch.capability.reason], auto_stopped_by: result.auto.stopped_by, auto_samples: result.auto.sample_count};
 expect(errors).toEqual([]);
 expect(result.mismatch.capability.status).toBe("denied"); expect(result.mismatch.capability.reason).toBe("isolate_scope_mismatch");
 expect(result.auto.stopped_by).toBe("duration"); expect(result.auto.capability.status).toBe("supported");
});

test("dedicated worker: Chrome 156 does not expose Profiler in workers, so a worker start is unsupported with worker scope and zero samples", async ({page, browser}) => {
 const errors = await open(page);
 const report: Report = await page.evaluate(() => new Promise<Report>((resolve, reject) => {
  const worker = new Worker("/worker.js", {type: "module"});
  worker.onmessage = event => { worker.terminate(); resolve(event.data as Report); };
  worker.onerror = event => { worker.terminate(); reject(new Error("worker error " + event.message)); };
  worker.postMessage(1);
 }));
 evidence.worker = {...await identity(page, browser), status: report.capability.status, reason: report.capability.reason, sample_count: report.sample_count, isolate: report.scope.isolate, coverage: report.capability.coverage};
 expect(errors).toEqual([]);
 // Observed: `Profiler` is not defined in a dedicated worker (even under the Document-Policy header) and the declared worker scope matches the global.
 expect(report.scope.isolate).toBe("worker");
 expect(report.capability.status).toBe("unsupported"); expect(report.capability.reason).toBe("js_self_profiling_unavailable");
 expect(report.sample_count).toBe(0); expect(report.samples).toEqual([]); expect(report.frames).toEqual([]);
});

test.afterAll(() => { console.log("SOUNDPOST_PROFILE_EVIDENCE " + JSON.stringify(evidence)); });
