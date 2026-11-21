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
 const rows: Array<{burst_nodes: number; batches: number; p50_ms: number; p95_ms: number; p99_ms: number; max_ms: number; chunks: number; checkpoints: number; gaps: number}> = [];
 // What the recorder emitted: one JSON text per chunk (the page keeps them in __chunks). A checkpoint is a chunk that is its own checkpoint_sequence.
 const emitted = async (): Promise<{chunks: number; checkpoints: number; gaps: number}> => page.evaluate(() => {
  const all = (Reflect.get(window, "__chunks") as string[]).map(text => JSON.parse(text) as {sequence: string; checkpoint_sequence: string; gap: boolean});
  return {chunks: all.length, checkpoints: all.filter(chunk => chunk.sequence === chunk.checkpoint_sequence).length, gaps: all.filter(chunk => chunk.gap).length};
 });
 for (const size of SIZES) {
  await page.evaluate(() => { (Reflect.get(window, "__batchMs") as number[]).length = 0; });
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
  expect(durations.length).toBeGreaterThanOrEqual(BATCHES);
  const emittedAfter = await emitted(), seconds = (Date.now() - rowStart) / 1000;
  const row = {burst_nodes: size, batches: durations.length, p50_ms: +quantile(durations, 0.5).toFixed(3), p95_ms: +quantile(durations, 0.95).toFixed(3), p99_ms: +quantile(durations, 0.99).toFixed(3), max_ms: +durations.at(-1)!.toFixed(3), chunks: emittedAfter.chunks - emittedBefore.chunks, checkpoints: emittedAfter.checkpoints - emittedBefore.checkpoints, gaps: emittedAfter.gaps - emittedBefore.gaps};
  rows.push(row);
  console.log("MUTATION_BATCH_ROW " + JSON.stringify(row));
  // Design (soundpost-design.md:162): a checkpoint is due every 30 s or after a gap. A burst that makes the page's list larger than one chunk
  // can hold (128 KiB) is a gap the recorder declares itself (rows report `gaps`); nothing else here is, so apart from the checkpoints the clock owes
  // (and the few a long-lived tree's id space or a declared gap may add: fewer than one per 20 batches) every batch is a delta.
  expect(row.checkpoints, `burst of ${size} nodes: checkpoints in ${seconds.toFixed(1)} s`).toBeLessThanOrEqual(Math.floor(seconds / 30) + Math.floor(BATCHES / 20));
 }
 if (cdp && profilePath) writeFileSync(profilePath, JSON.stringify((await cdp.send("Profiler.stop")).profile));
 const report = JSON.stringify({budget_p95_ms: BUDGET_P95_MS, browser: page.context().browser()?.version(), rows});
 console.log("MUTATION_BATCH_P95 " + report);
 await test.info().attach("mutation-batch-p95.json", {body: report, contentType: "application/json"});
 for (const row of rows) expect(row.p95_ms, `burst of ${row.burst_nodes} nodes`).toBeLessThanOrEqual(BUDGET_P95_MS);
});
