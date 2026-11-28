// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// 03.09-W3: the recorder's cost per MutationObserver batch in a real browser against the design 13 budget (p95 <= 5 ms per batch).
// The page's MutationObserver is wrapped BEFORE the recorder loads so every callback the recorder registers is timed with
// performance.now() around the recorder's own handler (the work the recorder adds to the main thread per batch). The workload is
// deterministic: BATCHES bursts of a fixed mix (insert, rewrite text, attribute churn, remove) at three burst sizes, on the canary
// page with replay consent given. The measured numbers are printed as one JSON line (`MUTATION_BATCH_P95 {...}`) and attached to the
// test result; the budget is asserted, never edited here.
import {test, expect, type Page} from "@playwright/test";
import {execFileSync} from "node:child_process";
import {mkdtempSync, readFileSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join, resolve} from "node:path";

const root = resolve(__dirname, "../../..");
const bundleDir = mkdtempSync(join(tmpdir(), "soundpost-replay-batch-"));
const bun = process.env.SOUNDPOST_BUN ?? "bun";
execFileSync(bun, ["build", join(root, "packages/browser/src/replay/recorder.ts"), join(root, "packages/browser/src/replay/stream.ts"), "--outdir", bundleDir, "--target=browser", "--format=esm"], {stdio: "pipe"});
const html = readFileSync(join(root, "fixtures/sdk/replay/canaries.html"), "utf8");
const origin = "http://soundpost.test";
const BUDGET_P95_MS = 5;
const BATCHES = 60;
const SIZES = [10, 100, 400];

const timing = `
 window.__batchMs = [];
 // The recorder schedules the slices of an id-space checkpoint it prepares between callbacks as zero-delay timers (its event flush is 1 s, its cadence 30 s): each zero-delay task is timed, so the work moved out of the callback is measured too.
 window.__sliceMs = [];
 const nativeSetTimeout = window.setTimeout.bind(window);
 window.setTimeout = (callback, delay, ...rest) => typeof callback !== "function" || delay !== 0 ? nativeSetTimeout(callback, delay, ...rest) : nativeSetTimeout((...args) => { const t0 = performance.now(); try { return callback(...args); } finally { window.__sliceMs.push(performance.now() - t0); } }, 0, ...rest);
 const Native = window.MutationObserver;
 window.MutationObserver = class extends Native {
  constructor(callback) { super((records, observer) => { const t0 = performance.now(); try { callback(records, observer); } finally { window.__batchMs.push(performance.now() - t0); } }); }
 };`;

async function open(page: Page): Promise<void> {
 await page.addInitScript(timing);
 await page.route(`${origin}/**`, async route => {
  const path = new URL(route.request().url()).pathname;
  if (path === "/") return route.fulfill({contentType: "text/html", body: html});
  if (path === "/recorder.js" || path === "/stream.js") return route.fulfill({contentType: "text/javascript", body: readFileSync(join(bundleDir, path.slice(1)), "utf8")});
  return route.fulfill({status: 404, body: ""});
 });
 await page.goto(`${origin}/`);
 await page.waitForFunction(() => Reflect.get(window, "__ready") === true);
}

const quantile = (sorted: number[], q: number): number => sorted[Math.min(sorted.length - 1, Math.ceil(q * sorted.length) - 1)]!;

test("recorder p95 per mutation batch stays within the 5 ms budget", async ({page}) => {
 await open(page);
 await page.evaluate(() => Reflect.get(window, "__replay").setConsent(true));
 // SOUNDPOST_BATCH_CPUPROFILE=FILE additionally writes the page's V8 CPU profile of the whole run (summarize it with
 // fixtures/sdk/cpuprofile-summary.mjs); profiling perturbs timing, so the budget numbers come from unprofiled runs.
 const profilePath = process.env.SOUNDPOST_BATCH_CPUPROFILE;
 const cdp = profilePath ? await page.context().newCDPSession(page) : undefined;
 if (cdp) { await cdp.send("Profiler.enable"); await cdp.send("Profiler.setSamplingInterval", {interval: 100}); await cdp.send("Profiler.start"); }
 const rows: Array<{burst_nodes: number; batches: number; p50_ms: number; p95_ms: number; p99_ms: number; max_ms: number; chunks: number; checkpoints: number; gaps: number; slices: number; slice_max_ms: number}> = [];
 // What the recorder emitted: one JSON text per chunk (the page keeps them in __chunks). A checkpoint is a chunk that is its own checkpoint_sequence.
 const emitted = async (): Promise<{chunks: number; checkpoints: number; gaps: number}> => page.evaluate(() => {
  const all = (Reflect.get(window, "__chunks") as string[]).map(text => JSON.parse(text) as {sequence: string; checkpoint_sequence: string; gap: boolean});
  return {chunks: all.length, checkpoints: all.filter(chunk => chunk.sequence === chunk.checkpoint_sequence).length, gaps: all.filter(chunk => chunk.gap).length};
 });
 for (const size of SIZES) {
  await page.evaluate(() => { (Reflect.get(window, "__batchMs") as number[]).length = 0; (Reflect.get(window, "__sliceMs") as number[]).length = 0; });
  const emittedBefore = await emitted(), rowStart = Date.now();
  for (let batch = 0; batch < BATCHES; batch++) {
   await page.evaluate(count => {
    const burst = document.getElementById("burst")!;
    for (let i = 0; i < count; i++) {
     const node = document.createElement(i % 2 ? "p" : "span");
     node.className = "b" + (i % 7); node.setAttribute("data-i", String(i)); node.textContent = "t" + i;
     burst.appendChild(node);
     if (i % 3 === 0) node.firstChild!.textContent = "r" + i;
     if (i % 5 === 0) burst.removeChild(node);
    }
    if (burst.childNodes.length > 1500) burst.textContent = "";
   }, size);
   await page.waitForTimeout(25); // let the observer deliver this batch before the next burst
  }
  const durations = (await page.evaluate(() => Reflect.get(window, "__batchMs") as number[])).slice().sort((a, b) => a - b);
  const sliceMs = await page.evaluate(() => Reflect.get(window, "__sliceMs") as number[]);
  expect(durations.length).toBeGreaterThanOrEqual(BATCHES);
  const emittedAfter = await emitted(), seconds = (Date.now() - rowStart) / 1000;
  const row = {burst_nodes: size, batches: durations.length, p50_ms: +quantile(durations, 0.5).toFixed(3), p95_ms: +quantile(durations, 0.95).toFixed(3), p99_ms: +quantile(durations, 0.99).toFixed(3), max_ms: +durations.at(-1)!.toFixed(3), chunks: emittedAfter.chunks - emittedBefore.chunks, checkpoints: emittedAfter.checkpoints - emittedBefore.checkpoints, gaps: emittedAfter.gaps - emittedBefore.gaps, slices: sliceMs.length, slice_max_ms: +Math.max(0, ...sliceMs).toFixed(3)};
  rows.push(row);
  console.log("MUTATION_BATCH_ROW " + JSON.stringify(row));
  // Design (soundpost-design.md:162): a checkpoint is due every 30 s or after a gap. A burst that makes the page's list larger than one chunk
  // can hold (128 KiB) is a gap the recorder declares itself (rows report `gaps`); nothing else here is, so apart from the checkpoints the clock owes
  // (and the few a long-lived tree's id space or a declared gap may add: fewer than one per 20 batches) every batch is a delta.
  expect(row.checkpoints, `burst of ${size} nodes: checkpoints in ${seconds.toFixed(1)} s`).toBeLessThanOrEqual(Math.floor(seconds / 30) + Math.floor(BATCHES / 20));
 }
 if (cdp && profilePath) writeFileSync(profilePath, JSON.stringify((await cdp.send("Profiler.stop")).profile));
 // engine: the browser type that actually ran ("chromium", "firefox", "webkit"), so a harness row built for one engine is never satisfied by another's report.
 const report = JSON.stringify({budget_p95_ms: BUDGET_P95_MS, engine: page.context().browser()?.browserType().name(), browser: page.context().browser()?.version(), rows});
 console.log("MUTATION_BATCH_P95 " + report);
 await test.info().attach("mutation-batch-p95.json", {body: report, contentType: "application/json"});
 for (const row of rows) expect(row.p95_ms, `burst of ${row.burst_nodes} nodes`).toBeLessThanOrEqual(BUDGET_P95_MS);
});

// The same budget through the production consumer: the page bundles the REAL `startReplay` (packages/browser/src/replay.ts) over a REAL core client (mutation-batch-prod.ts) whose transport is an in-page
// ledger, so each timed observer callback includes the recorder AND core's serialisation and validation of the chunk it emits. Same canary page, same bursts, same timing wrapper, same budget.
const prodDir = mkdtempSync(join(tmpdir(), "soundpost-replay-batch-prod-"));
execFileSync(bun, ["build", join(root, "fixtures/sdk/replay/mutation-batch-prod.ts"), "--outdir", prodDir, "--target=browser", "--format=esm"], {stdio: "pipe"});
const prodHtml = html.replace(/<script type="module">[\s\S]*?<\/script>/, '<script type="module" src="/prod.js"></script>');
/** The client's queue is drained through the in-page ledger this often (outside any timed callback), as a real page's own flush would. */
const FLUSH_EVERY = 10;

async function openProd(page: Page): Promise<void> {
 await page.addInitScript(timing);
 await page.route(`${origin}/**`, async route => {
  const path = new URL(route.request().url()).pathname;
  if (path === "/") return route.fulfill({contentType: "text/html", body: prodHtml});
  if (path === "/prod.js") return route.fulfill({contentType: "text/javascript", body: readFileSync(join(prodDir, "mutation-batch-prod.js"), "utf8")});
  return route.fulfill({status: 404, body: ""});
 });
 await page.goto(`${origin}/`);
 await page.waitForFunction(() => Reflect.get(window, "__ready") === true);
}

test("recorder p95 per mutation batch through the production consumer stays within the 5 ms budget", async ({page}) => {
 await openProd(page);
 await page.evaluate(() => Reflect.get(window, "__replay").setConsent(true));
 const rows: Array<{burst_nodes: number; batches: number; p50_ms: number; p95_ms: number; p99_ms: number; max_ms: number; chunks: number; checkpoints: number; gaps: number; slices: number; slice_max_ms: number}> = [];
 const emitted = async (): Promise<{chunks: number; checkpoints: number; gaps: number}> => page.evaluate(() => Reflect.get(window, "__counts")() as {chunks: number; checkpoints: number; gaps: number});
 for (const size of SIZES) {
  await page.evaluate(() => { (Reflect.get(window, "__batchMs") as number[]).length = 0; (Reflect.get(window, "__sliceMs") as number[]).length = 0; });
  const emittedBefore = await emitted(), rowStart = Date.now();
  for (let batch = 0; batch < BATCHES; batch++) {
   await page.evaluate(count => {
    const burst = document.getElementById("burst")!;
    for (let i = 0; i < count; i++) {
     const node = document.createElement(i % 2 ? "p" : "span");
     node.className = "b" + (i % 7); node.setAttribute("data-i", String(i)); node.textContent = "t" + i;
     burst.appendChild(node);
     if (i % 3 === 0) node.firstChild!.textContent = "r" + i;
     if (i % 5 === 0) burst.removeChild(node);
    }
    if (burst.childNodes.length > 1500) burst.textContent = "";
   }, size);
   await page.waitForTimeout(25); // let the observer deliver this batch before the next burst
   if (batch % FLUSH_EVERY === FLUSH_EVERY - 1) await page.evaluate(() => Reflect.get(window, "__flush")() as Promise<unknown>);
  }
  const durations = (await page.evaluate(() => Reflect.get(window, "__batchMs") as number[])).slice().sort((a, b) => a - b);
  const sliceMs = await page.evaluate(() => Reflect.get(window, "__sliceMs") as number[]);
  expect(durations.length).toBeGreaterThanOrEqual(BATCHES);
  const emittedAfter = await emitted(), seconds = (Date.now() - rowStart) / 1000;
  const row = {burst_nodes: size, batches: durations.length, p50_ms: +quantile(durations, 0.5).toFixed(3), p95_ms: +quantile(durations, 0.95).toFixed(3), p99_ms: +quantile(durations, 0.99).toFixed(3), max_ms: +durations.at(-1)!.toFixed(3), chunks: emittedAfter.chunks - emittedBefore.chunks, checkpoints: emittedAfter.checkpoints - emittedBefore.checkpoints, gaps: emittedAfter.gaps - emittedBefore.gaps, slices: sliceMs.length, slice_max_ms: +Math.max(0, ...sliceMs).toFixed(3)};
  rows.push(row);
  console.log("MUTATION_BATCH_ROW_PROD " + JSON.stringify(row));
  expect(row.checkpoints, `burst of ${size} nodes: checkpoints in ${seconds.toFixed(1)} s`).toBeLessThanOrEqual(Math.floor(seconds / 30) + Math.floor(BATCHES / 20));
 }
 // Every chunk reached core's queue and left through the ledger: nothing was refused, so what was timed is the whole production path and not a recorder that dropped its output.
 const flushed = await page.evaluate(() => Reflect.get(window, "__flush")() as Promise<{pending: number; lost: number; receipts: number}>);
 const diagnostics = await page.evaluate(() => Reflect.get(window, "__diagnostics")() as Record<string, number>);
 expect(flushed, "queue drained").toMatchObject({pending: 0, lost: 0});
 expect(diagnostics.batches, "batches the ledger accepted").toBeGreaterThan(0);
 expect(Object.keys(diagnostics).filter(key => key !== "batches"), "client diagnostics (losses, refusals)").toEqual([]);
 const report = JSON.stringify({budget_p95_ms: BUDGET_P95_MS, consumer: "startReplay+core client", engine: page.context().browser()?.browserType().name(), browser: page.context().browser()?.version(), rows});
 console.log("MUTATION_BATCH_P95_PROD " + report);
 await test.info().attach("mutation-batch-p95-prod.json", {body: report, contentType: "application/json"});
 for (const row of rows) expect(row.p95_ms, `burst of ${row.burst_nodes} nodes`).toBeLessThanOrEqual(BUDGET_P95_MS);
});
