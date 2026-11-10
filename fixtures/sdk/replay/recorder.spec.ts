// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {test, expect, type Page} from "@playwright/test";
import {execFileSync} from "node:child_process";
import {mkdtempSync, readFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join, resolve} from "node:path";
import {gunzipSync} from "node:zlib";

const root = resolve(__dirname, "../../..");
const bundleDir = mkdtempSync(join(tmpdir(), "soundpost-replay-"));
const bun = process.env.SOUNDPOST_BUN ?? "bun";
execFileSync(bun, ["build", join(root, "packages/browser/src/replay/recorder.ts"), join(root, "packages/browser/src/replay/stream.ts"), "--outdir", bundleDir, "--target=browser", "--format=esm"], {stdio: "pipe"});
const html = readFileSync(join(root, "fixtures/sdk/replay/canaries.html"), "utf8");
const origin = "http://soundpost.test";
interface Node {tag: string; class: string; text: string}
interface Event {kind: string; x: number; y: number}
const secrets = [/canary/i, /918273645/, /5550100999/, /2001-02-03/, /#123456/];

async function open(page: Page, init?: string): Promise<{console: string[]; errors: string[]}> {
 const seen = {console: [] as string[], errors: [] as string[]};
 page.on("console", message => seen.console.push(message.text()));
 page.on("pageerror", error => seen.errors.push(error.message));
 if (init) await page.addInitScript(init);
 await page.route(`${origin}/**`, async route => {
  const path = new URL(route.request().url()).pathname;
  if (path === "/") return route.fulfill({contentType: "text/html", body: html});
  if (path === "/recorder.js" || path === "/stream.js") return route.fulfill({contentType: "text/javascript", body: readFileSync(join(bundleDir, path.slice(1)), "utf8")});
  return route.fulfill({status: 404, body: ""});
 });
 await page.goto(`${origin}/`);
 await page.waitForFunction(() => Reflect.get(window, "__ready") === true);
 return seen;
}
const chunksOf = (page: Page): Promise<string[]> => page.evaluate(() => Reflect.get(window, "__chunks") as string[]);

test("pre-buffer canaries: nothing from the page survives into chunks, queue bytes, compressed transport or diagnostics", async ({page}) => {
 const seen = await open(page);
 await page.evaluate(() => Reflect.get(window, "__replay").setConsent(true));
 // Real user-like activity: typing, editing, clicking, clipboard, resize and a 900-record mutation burst with different-length secrets.
 await page.fill("#i-text", "CANARY_TYPED_INPUT_" + "x".repeat(37));
 await page.fill("#i-area", "CANARY_TYPED_AREA");
 await page.click("#editable"); await page.keyboard.type("CANARY_TYPED_EDITABLE_WWWWW");
 await page.click("#button");
 await page.evaluate(() => { document.execCommand("copy"); });
 await page.evaluate(() => {
  const burst = document.getElementById("burst")!;
  for (let i = 0; i < 900; i++) {
   const node = document.createElement(i % 2 ? "p" : "span");
   node.id = "CANARY_BURST_ID_" + i; node.className = "CANARY_BURST_CLASS_" + "q".repeat(i % 17); node.setAttribute("data-secret", "CANARY_BURST_DATA_" + i);
   node.textContent = "CANARY_BURST_TEXT_" + "z".repeat(i % 29);
   burst.appendChild(node);
   if (i % 3 === 0) node.firstChild!.textContent = "CANARY_BURST_REWRITE_" + "y".repeat(i % 11);
   if (i % 5 === 0) burst.removeChild(node);
  }
 });
 await page.waitForTimeout(1500); // event flush interval (1s)
 await page.setViewportSize({width: 700, height: 500}); await page.mouse.click(30, 30); await page.waitForTimeout(1500);
 const queue = await chunksOf(page);
 expect(queue.length).toBeGreaterThan(1);
 const wire = queue.join("\n");
 for (const pattern of secrets) expect(wire).not.toMatch(pattern);
 const compressed = await page.evaluate(async text => {
  const stream = new Blob([text]).stream().pipeThrough(new CompressionStream("gzip"));
  const bytes = new Uint8Array(await new Response(stream).arrayBuffer());
  return Array.from(bytes);
 }, wire);
 const compressedBuffer = Buffer.from(compressed);
 for (const pattern of secrets) expect(compressedBuffer.toString("latin1")).not.toMatch(pattern);
 expect(gunzipSync(compressedBuffer).toString("utf8")).toBe(wire);
 // Diagnostics: the page's own single console.log is the only canary anywhere; no trap fired, no page error.
 expect(seen.console.filter(line => /canary/i.test(line))).toEqual(["CANARY_CONSOLE_ARGUMENT_EEEEEEEE"]);
 expect(seen.errors).toEqual([]);
 expect(await page.evaluate(() => Reflect.get(window, "__traps"))).toBe(0);
 const chunks = queue.map(line => JSON.parse(line));
 const nodes = chunks.flatMap(chunk => chunk.nodes);
 for (const node of nodes) { expect(Object.keys(node).sort()).toEqual(["class", "id", "parent", "pres", "rect", "tag", "text"]); expect(["", "[masked]"]).toContain(node.text); expect(node.rect.x % 8).toBe(0); expect(Math.abs(node.rect.w)).toBeLessThanOrEqual(32768); }
 const first = chunks[0];
 const inputs = first.nodes.filter((node: Node) => node.tag === "input");
 expect(inputs.length).toBeGreaterThanOrEqual(15); // 14 input types + the open-shadow input
 expect(new Set(inputs.map((node: Node) => `${node.tag}|${node.class}|${node.text}`)).size).toBe(1);
 expect(first.nodes.filter((node: Node) => node.class === "masked").length).toBeGreaterThanOrEqual(5); // editable, textarea, select, video, iframe
 expect(chunks.some(chunk => chunk.events.some((event: Event) => event.kind === "mutation"))).toBe(true);
 expect(chunks.some(chunk => chunk.events.some((event: Event) => event.kind === "pointer" && event.x % 8 === 0 && event.y % 8 === 0))).toBe(true);
 for (const chunk of chunks) expect(JSON.stringify(chunk).length).toBeLessThanOrEqual(131072);
});

test("capture stays off without deployment opt-in even with consent", async ({page}) => {
 await open(page, "window.__deployment = false;");
 await page.evaluate(() => Reflect.get(window, "__replay").setConsent(true));
 await page.evaluate(() => { document.getElementById("burst")!.textContent = "CANARY_NO_CAPTURE"; });
 await page.mouse.click(30, 30); await page.waitForTimeout(1500);
 expect(await chunksOf(page)).toEqual([]);
});

test("consent revocation: disconnects at once, destroys pending replay state, no sends after, resume carries a gap", async ({page}) => {
 await open(page);
 await page.evaluate(() => Reflect.get(window, "__replay").setConsent(true));
 const acked = (await chunksOf(page)).length;
 expect(acked).toBeGreaterThan(0);
 // Queue pointer/scroll activity (pending, flushed only after 1s) then revoke synchronously inside the same task.
 const pendingAfterRevoke = await page.evaluate(() => {
  document.body.dispatchEvent(new PointerEvent("pointerdown", {clientX: 100, clientY: 100, bubbles: true}));
  window.dispatchEvent(new Event("scroll"));
  Reflect.get(window, "__replay").setConsent(false);
  document.getElementById("burst")!.textContent = "CANARY_AFTER_REVOKE";
  return {pending: Reflect.get(window, "__stream").pending as number, revoked: Reflect.get(window, "__revoked") as number};
 });
 expect(pendingAfterRevoke).toEqual({pending: 0, revoked: 1});
 await page.mouse.click(40, 40); await page.setViewportSize({width: 640, height: 480});
 await page.waitForTimeout(2500);
 const after = await chunksOf(page);
 expect(after).toHaveLength(acked); // no replay send after revocation; ACKed history is neither recalled nor altered
 expect(after.join("\n")).not.toMatch(/AFTER_REVOKE/);
 await page.evaluate(() => Reflect.get(window, "__replay").setConsent(true));
 const resumed = JSON.parse((await chunksOf(page)).at(-1)!);
 expect(resumed.gap).toBe(true);
 expect(resumed.checkpoint_sequence).toBe(resumed.sequence);
 expect((await chunksOf(page)).join("\n")).not.toMatch(/canary/i);
});
