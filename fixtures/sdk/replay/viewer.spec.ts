// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {test, expect, type Frame, type Page} from "@playwright/test";
import {execFileSync} from "node:child_process";
import {mkdtempSync, readFileSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join, resolve} from "node:path";

/*
 * Real-browser proof for the replay viewer. Every row counts what the browser actually did: requests of the
 * page and the sandboxed frame, navigations, dialogs, console errors (CSP violations are reported there) and
 * messages the frame posts back that are not viewer status. Nothing is assumed from the code.
 */
const root = resolve(__dirname, "../../..");
const bun = process.env.SOUNDPOST_BUN ?? "bun";
const dir = mkdtempSync(join(tmpdir(), "soundpost-viewer-"));
const origin = "http://soundpost.test";
const viewerSource = join(root, "packages/replay-viewer/src/index.ts").replaceAll("\\", "/");

writeFileSync(join(dir, "frame-entry.ts"), `import {attachFrameBridge} from ${JSON.stringify(viewerSource)};
attachFrameBridge(window, document.getElementById("replay") as HTMLElement, {onStatus: status => window.parent.postMessage({soundpost: "status", status}, "*")});
`);
// Control: the renderer's tree builder alone, handed hostile typed nodes (decoding bypassed), with NO CSP at all.
writeFileSync(join(dir, "direct-entry.ts"), `import {renderTree} from ${JSON.stringify(viewerSource)};
window.addEventListener("message", event => { if (event.source === window.parent) document.getElementById("replay")!.append(renderTree(document, event.data.nodes)); });
window.parent.postMessage({soundpost: "status", status: "loading"}, "*");
`);
const build = (entry: string, out: string, target: string, format: string): void => { execFileSync(bun, ["build", join(dir, entry), "--outfile", join(dir, out), `--target=${target}`, `--format=${format}`], {stdio: "pipe"}); };
build("frame-entry.ts", "frame.js", "browser", "iife");
build("direct-entry.ts", "direct.js", "browser", "iife");
execFileSync(bun, ["build", viewerSource, "--outfile", join(dir, "helper.cjs"), "--target=node", "--format=cjs"], {stdio: "pipe"});
const helper = require(join(dir, "helper.cjs")) as {VIEWER_STYLE: string; VIEWER_SANDBOX: string; viewerCsp: (script: string, style: string) => string};
const template = readFileSync(join(root, "fixtures/sdk/replay/viewer.html"), "utf8");
const fill = (script: string): string => template.replace("/*__VIEWER_STYLE__*/", () => helper.VIEWER_STYLE).replace("/*__VIEWER_SCRIPT__*/", () => script);
const frameScript = readFileSync(join(dir, "frame.js"), "utf8"), directScript = readFileSync(join(dir, "direct.js"), "utf8");
const frameHtml = fill(frameScript), directHtml = fill(directScript);
const csp = helper.viewerCsp(frameScript, helper.VIEWER_STYLE);

/** The deliberately vulnerable renderer used only to prove the counters can see an attack. */
const vulnerableHtml = `<!doctype html><body><div id="replay"></div><script>
addEventListener("message", e => { if (e.source === parent) document.getElementById("replay").innerHTML = e.data.html; });
parent.postMessage({soundpost: "status", status: "loading"}, "*");
</script></body>`;
const hostHtml = `<!doctype html><body><iframe id="f" sandbox="${helper.VIEWER_SANDBOX}" src="/frame.html"></iframe><script>
window.__messages = [];
addEventListener("message", e => { if (e.source === document.getElementById("f").contentWindow) window.__messages.push(e.data); });
const toBytes = b64 => Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
window.__sendChunk = b64 => document.getElementById("f").contentWindow.postMessage({soundpost: "replay", item: {kind: "chunk", bytes: toBytes(b64)}}, "*");
window.__sendItem = item => document.getElementById("f").contentWindow.postMessage({soundpost: "replay", item}, "*");
window.__sendRaw = data => document.getElementById("f").contentWindow.postMessage(data, "*");
window.__fromSibling = spec => {
  const message = spec.b64 !== undefined
    ? "{soundpost: 'replay', item: {kind: 'chunk', bytes: Uint8Array.from(atob(" + JSON.stringify(spec.b64) + "), c => c.charCodeAt(0)).buffer}}"
    : JSON.stringify({soundpost: "replay", item: spec.item}).replace(/</g, "\\u003c");
  const sibling = document.createElement("iframe");
  sibling.setAttribute("sandbox", "allow-scripts");
  sibling.srcdoc = "<script>parent.frames[0].postMessage(" + message + ", '*');<" + "/script>";
  document.body.appendChild(sibling);
};
</script></body>`;

interface VectorChunk {wire?: string; go: {verdict: string}}
const vectors = JSON.parse(readFileSync(join(root, "fixtures/sdk/replay/chain-vectors.json"), "utf8")) as {chunks: Record<string, VectorChunk>};
const b64 = (name: string): string => Buffer.from(vectors.chunks[name]!.wire!, "utf8").toString("base64");
const forbidden = /evil\.test|soundpost\.test\/(pwn|probe)|PWN/;

type Variant = "production" | "control" | "vulnerable";
interface Seen { requests: string[]; served: string[]; failed: {url: string; error: string}[]; navigations: string[]; dialogs: string[]; consoleErrors: string[]; pageErrors: string[]; popups: number; websockets: number }

async function open(page: Page, variant: Variant): Promise<{seen: Seen; frame: () => Frame; messages: () => Promise<{soundpost?: string; status?: string}[]>}> {
 const seen: Seen = {requests: [], served: [], failed: [], navigations: [], dialogs: [], consoleErrors: [], pageErrors: [], popups: 0, websockets: 0};
 page.on("request", request => seen.requests.push(request.url()));
 page.on("framenavigated", frame => seen.navigations.push(frame.url()));
 page.on("dialog", dialog => { seen.dialogs.push(dialog.message()); void dialog.dismiss(); });
 page.on("console", message => { if (message.type() === "error" || message.type() === "warning") seen.consoleErrors.push(message.text()); });
 page.on("pageerror", error => seen.pageErrors.push(error.message));
 page.on("popup", () => { seen.popups++; });
 page.on("websocket", () => { seen.websockets++; });
 page.on("requestfailed", request => seen.failed.push({url: request.url(), error: request.failure()?.errorText ?? ""}));
 await page.route(`${origin}/**`, async route => {
  const path = new URL(route.request().url()).pathname;
  if (path === "/" || path === "/frame.html") seen.served.push(path);
  if (path === "/") return route.fulfill({contentType: "text/html", body: hostHtml});
  if (path === "/frame.html") {
   if (variant === "production") return route.fulfill({contentType: "text/html", headers: {"Content-Security-Policy": csp}, body: frameHtml});
   return route.fulfill({contentType: "text/html", body: variant === "control" ? directHtml : vulnerableHtml});
  }
  seen.served.push(path); // only requests that survive CSP and sandbox reach this handler
  return route.fulfill({status: 200, contentType: "text/plain", body: "reached"});
 });
 await page.goto(`${origin}/`);
 await page.waitForFunction(() => (Reflect.get(window, "__messages") as {status?: string}[]).some(message => message.status === "loading"));
 const frame = (): Frame => page.frames().find(candidate => candidate.url().endsWith("/frame.html"))!;
 const messages = (): Promise<{soundpost?: string; status?: string}[]> => page.evaluate(() => Reflect.get(window, "__messages") as {soundpost?: string; status?: string}[]);
 return {seen, frame, messages};
}
const send = (page: Page, name: string): Promise<void> => page.evaluate(value => Reflect.get(window, "__sendChunk")(value), b64(name));
const sendItem = (page: Page, item: object): Promise<void> => page.evaluate(value => Reflect.get(window, "__sendItem")(value), item);
const waitState = (frame: Frame, state: string): Promise<unknown> => frame.waitForFunction(wanted => document.querySelector("[data-replay-root]")?.getAttribute("data-state") === wanted, state);

interface Snapshot { state: string | null; tree: string; timeline: string[]; interactions: string[]; opaque: number; elements: string[]; attributes: string[]; html: string }
const snapshot = (frame: Frame): Promise<Snapshot> => frame.evaluate(() => {
 const rootEl = document.querySelector("[data-replay-root]");
 const lines = (selector: string): string[] => Array.from(document.querySelectorAll(`${selector} > li`), item => item.textContent ?? "");
 const summarize = (el: Element): string => {
  const own = el.getAttribute("data-tag") ?? "?";
  const text = Array.from(el.children).filter(child => child.hasAttribute("data-masked")).map(child => child.textContent).join("");
  const kids = Array.from(el.children).filter(child => child.hasAttribute("data-tag")).map(summarize);
  return own + (text === "" ? "" : ":" + text) + (kids.length > 0 ? "[" + kids.join(",") + "]" : "");
 };
 const tree = document.querySelector("[data-replay-tree]");
 const everything = Array.from(document.body.querySelectorAll("*"));
 return {
  state: rootEl?.getAttribute("data-state") ?? null,
  tree: tree === null ? "" : Array.from(tree.children).filter(child => child.hasAttribute("data-tag")).map(summarize).join("|"),
  timeline: lines("[data-replay-timeline]"), interactions: lines("[data-replay-interactions]"),
  opaque: document.querySelectorAll("[data-opaque]").length,
  elements: Array.from(new Set(everything.filter(el => el.tagName !== "SCRIPT").map(el => el.tagName.toLowerCase()))),
  attributes: Array.from(new Set(everything.filter(el => el.tagName !== "SCRIPT").flatMap(el => el.getAttributeNames()))),
  html: document.getElementById("replay")?.innerHTML ?? "",
 };
});
const ELEMENTS = ["div", "span", "p", "section", "ol", "li"];
const ATTRIBUTES = ["id", "data-replay-root", "data-state", "data-replay-status", "role", "data-replay-tree", "inert", "data-tag", "data-opaque", "data-masked", "data-replay-timeline", "data-replay-interactions", "data-kind", "data-sequence"];

const hostileNodes = [
 {id: "1", parent: "0", tag: "img src=x onerror=parent.postMessage('PWN','*')", class: "\"><svg onload=parent.postMessage('PWN','*')>", text: "<img src='http://soundpost.test/pwn-text.png'>"},
 {id: "2", parent: "1", tag: "script", class: "masked", text: "javascript:parent.postMessage('PWN','*')"},
 {id: "3", parent: "1", tag: "a", class: "", text: "[masked]"},
 {id: "4", parent: "3", tag: "iframe", class: "", text: "url(http://evil.test/css)"},
 {id: "5", parent: "4", tag: "input", class: "", text: "[masked]"},
 {id: "6", parent: "6", tag: "div", class: "", text: ""},
 {id: "7", parent: "8", tag: "div", class: "", text: ""},
 {id: "8", parent: "7", tag: "div", class: "", text: ""},
 {id: "9", parent: "1", tag: "style", class: "", text: "@import url(http://evil.test/x.css)"},
];

test.describe("replay viewer in a real browser", () => {
 test("no network: malicious tag, class, text, URL, CSS and script payloads cause zero requests, script runs and navigations under the production CSP and sandbox", async ({page}) => {
  const {seen, frame, messages} = await open(page, "production");
  expect(seen.requests).toEqual([`${origin}/`, `${origin}/frame.html`]);
  expect(seen.served).toEqual(["/", "/frame.html"]); // host page and frame only: nothing else was fetched to boot the viewer
  // The policy is actually enforced here, by observation: the frame cannot fetch, load images or reach its parent.
  const probe = await frame().evaluate(async () => {
   const fetched = await fetch("http://soundpost.test/probe-fetch").then(() => "loaded", () => "blocked");
   const imaged = await new Promise<string>(resolveImage => { const image = new Image(); image.onload = () => resolveImage("loaded"); image.onerror = () => resolveImage("blocked"); image.src = "http://soundpost.test/probe-img"; });
   let parentAccess = "reachable";
   try { void (window.parent.document.title); } catch { parentAccess = "blocked"; }
   let storage = "reachable";
   try { void localStorage.length; } catch { storage = "blocked"; }
   return {fetched, imaged, parentAccess, storage, origin: window.origin, cookie: (() => { try { return document.cookie; } catch { return "blocked"; } })()};
  });
  expect(probe).toMatchObject({fetched: "blocked", imaged: "blocked", parentAccess: "blocked", storage: "blocked", origin: "null"});
  // The browser attempted the probe image but CSP blocked it before the network: the route never served it.
  expect(seen.failed.filter(failure => failure.url.endsWith("/probe-img")).map(failure => failure.error)).toEqual(["csp"]); // Playwright's errorText for a request blocked by Content-Security-Policy
  expect(seen.served).toEqual(["/", "/frame.html"]);
  // From here on, not even a blocked attempt may happen: every request the browser starts is counted.
  const baseline = {requests: [...seen.requests], navigations: [...seen.navigations]};
  seen.consoleErrors.length = 0;
  // Hostile wire chunks: every Go-invalid vector (unknown fields, img/html tags, secret text/class, rect/pres) plus raw payload chunks.
  const hostileWires = Object.entries(vectors.chunks).filter(([, entry]) => entry.go.verdict !== "valid" && entry.wire !== undefined).map(([name]) => name);
  expect(hostileWires.length).toBeGreaterThanOrEqual(18);
  await send(page, "c1");
  await waitState(frame(), "ready");
  for (const name of hostileWires) await send(page, name);
  const payloadChunk = (mutate: (chunk: Record<string, unknown>) => void): string => { const chunk = JSON.parse(vectors.chunks["c1"]!.wire!) as Record<string, unknown>; mutate(chunk); return Buffer.from(JSON.stringify(chunk), "utf8").toString("base64"); };
  const rawPayloads = [
   payloadChunk(chunk => { chunk["nodes"] = hostileNodes; }),
   payloadChunk(chunk => { chunk["html"] = "<img src=http://soundpost.test/pwn-html.png onerror=parent.postMessage('PWN','*')>"; }),
   payloadChunk(chunk => { chunk["recorder_version"] = "1<script>parent.postMessage('PWN','*')</script>"; }),
   payloadChunk(chunk => { chunk["clock"] = {style: "background:url(http://evil.test/bg)", href: "javascript:parent.postMessage('PWN','*')"}; }),
  ];
  for (const payload of rawPayloads) await page.evaluate(value => Reflect.get(window, "__sendChunk")(value), payload);
  // Messages that are not well-formed items (bytes that are not bytes, a bare string) are ignored by the bridge.
  await page.evaluate(() => Reflect.get(window, "__sendRaw")({soundpost: "replay", item: {kind: "chunk", bytes: "<img src=http://evil.test/bytes>"}}));
  await page.evaluate(() => Reflect.get(window, "__sendRaw")("<img src=http://evil.test/string>"));
  await waitState(frame(), "unsupported"); // unknown recorder versions were among the hostile chunks; no checkpoint has recovered since
  await page.waitForTimeout(500);
  const during = await snapshot(frame());
  // A control item with a hostile reason is a protocol violation: the view stops and clears.
  await sendItem(page, {kind: "gap", reason: "<img src=http://evil.test/x>", from: "2", through: "3"});
  await waitState(frame(), "error");
  const shown = await snapshot(frame());
  // Observed counters: nothing but the original two requests, no navigation, no dialog, no script-visible side effect, no CSP violation.
  expect(seen.requests).toEqual(baseline.requests);
  expect(seen.requests.slice(baseline.requests.length).filter(url => forbidden.test(url))).toEqual([]);
  expect(seen.navigations).toEqual(baseline.navigations);
  expect(seen.dialogs).toEqual([]);
  expect(seen.popups).toBe(0);
  expect(seen.websockets).toBe(0);
  expect(seen.pageErrors).toEqual([]);
  expect(seen.consoleErrors.filter(text => /content security policy|refused|violat/i.test(text))).toEqual([]);
  expect((await messages()).filter(message => message.soundpost !== "status")).toEqual([]);
  // The DOM is only fixed first-party elements and the hostile strings are nowhere in it, while the chain was broken and after the view stopped.
  for (const view of [during, shown]) {
   expect(view.elements.filter(name => !ELEMENTS.includes(name))).toEqual([]);
   expect(view.attributes.filter(name => !ATTRIBUTES.includes(name))).toEqual([]);
   expect(view.html).not.toMatch(forbidden);
   expect(view.html).not.toMatch(/<img|<script|<iframe|<a |href|src=|style=|onerror/i);
  }
  expect(during.tree).toBe("div[p[span:[masked]]]"); // the one valid checkpoint, dimmed by the gap state, is all that was ever shown
  expect(during.timeline.filter(line => line.startsWith("gap")).length).toBe(1);
  expect(shown.tree).toBe("");
 });

 test("no network: the renderer alone is inert even when decoding is bypassed and no CSP applies (control rows)", async ({page}) => {
  const {seen, frame, messages} = await open(page, "control");
  const baseline = seen.requests.length;
  await page.evaluate(nodes => Reflect.get(window, "__sendRaw")({nodes}), hostileNodes);
  await frame().waitForSelector("[data-replay-tree]");
  await page.waitForTimeout(500);
  const shown = await snapshot(frame());
  expect(seen.requests.length).toBe(baseline);
  expect(seen.dialogs).toEqual([]);
  expect(seen.pageErrors).toEqual([]);
  expect((await messages()).filter(message => message.soundpost !== "status")).toEqual([]);
  expect(shown.elements.filter(name => !ELEMENTS.includes(name))).toEqual([]);
  expect(shown.attributes.filter(name => !ATTRIBUTES.includes(name))).toEqual([]);
  expect(shown.html).not.toMatch(/<img|<script|<iframe|<a |href|src=|style=|onerror|evil\.test|PWN/i);
  expect(shown.tree).toBe("masked[masked:[opaque],masked:[masked][masked[input:[masked]]],masked]");
  expect(shown.tree).toContain("input:[masked]");
  expect(shown.opaque).toBeGreaterThanOrEqual(1);
 });

 test("no network: messages from any window other than the parent are ignored", async ({page}) => {
  const {seen, frame} = await open(page, "production");
  // A sibling frame (not the parent) tries to feed the viewer a checkpoint and then a deletion.
  await page.evaluate(value => Reflect.get(window, "__fromSibling")(value), {b64: b64("c1")});
  await page.evaluate(() => Reflect.get(window, "__fromSibling")({item: {kind: "revoke", reason: "deleted"}}));
  await page.waitForTimeout(600);
  const ignored = await snapshot(frame());
  expect(ignored.state).toBe("loading");
  expect(ignored.tree).toBe("");
  // The parent still drives the same view afterwards, so the frame was alive and listening the whole time.
  await send(page, "c1");
  await waitState(frame(), "ready");
  expect((await snapshot(frame())).tree).toBe("div[p[span:[masked]]]");
  expect(seen.requests.filter(url => !url.endsWith("/") && !url.endsWith("/frame.html"))).toEqual([]);
 });

 test("no network: a vulnerable innerHTML renderer is caught by the same counters (the detection is not vacuous)", async ({page}) => {
  const {seen, messages} = await open(page, "vulnerable");
  const baseline = seen.requests.length;
  await page.evaluate(() => Reflect.get(window, "__sendRaw")({html: "<img src='http://soundpost.test/pwn-vulnerable.png' onerror=\"parent.postMessage('PWN','*')\">"}));
  await expect.poll(async () => (await messages()).filter(message => message.soundpost !== "status").length).toBeGreaterThan(0);
  expect(seen.requests.length).toBeGreaterThan(baseline);
  expect(seen.requests.some(url => url.includes("pwn-vulnerable"))).toBe(true);
 });

 test("gap recovery: a missing chunk is a visible gap, no delta applies across it and the next checkpoint resumes", async ({page}) => {
  const {seen, frame, messages} = await open(page, "production");
  await send(page, "c1"); await waitState(frame(), "ready");
  await send(page, "d2"); await frame().waitForFunction(() => document.querySelectorAll("[data-replay-interactions] > li").length === 1);
  await send(page, "d4"); // chunk 3 never arrives
  await waitState(frame(), "gap");
  const inGap = await snapshot(frame());
  expect(inGap.timeline.some(line => /^gap 3-4 missing_chunk$/.test(line))).toBe(true);
  expect(inGap.interactions).toEqual(["pointer 64,-8"]); // d4's resize never applied
  await send(page, "c5"); await waitState(frame(), "ready");
  await send(page, "d6");
  await frame().waitForFunction(() => document.querySelectorAll("[data-replay-interactions] > li").length === 2);
  const recovered = await snapshot(frame());
  expect(recovered.timeline).toEqual(["checkpoint 1", "delta 2", "gap 3-4 missing_chunk", "checkpoint 5", "delta 6"]);
  expect(recovered.interactions).toEqual(["pointer 64,-8", "pointer 8,8"]);
  expect(recovered.tree).toBe("section[canvas:[opaque]]");
  expect(recovered.opaque).toBe(1);
  // A duplicate and a stale (already superseded) delta change nothing.
  await send(page, "d6"); await send(page, "d3_altered_previous");
  await page.waitForTimeout(300);
  expect((await snapshot(frame())).interactions).toEqual(["pointer 64,-8", "pointer 8,8"]);
  expect((await messages()).filter(message => message.soundpost === "status").map(message => message.status)).toEqual(["loading", "ready", "gap", "ready"]);
  expect(seen.requests.length).toBe(2);
 });

 test("gap recovery: an altered chain link rejects and the honest delta after it still cannot apply until a checkpoint", async ({page}) => {
  const {frame} = await open(page, "production");
  for (const name of ["c1", "d2", "d3_altered_previous", "d3"]) await send(page, name);
  await waitState(frame(), "gap");
  await page.waitForTimeout(300);
  const broken = await snapshot(frame());
  expect(broken.interactions).toEqual(["pointer 64,-8"]); // neither the altered delta nor the honest d3 (mutation + scroll) applied
  expect(broken.timeline.filter(line => line.startsWith("gap"))).toEqual(["gap 3 hash_mismatch"]);
  await send(page, "c5");
  await waitState(frame(), "ready");
  const resumed = await snapshot(frame());
  expect(resumed.timeline).toEqual(["checkpoint 1", "delta 2", "gap 3-4 hash_mismatch", "checkpoint 5"]);
  expect(resumed.tree).toBe("section[canvas:[opaque]]");
 });

 test("gap recovery: deltas arriving after a gap and before the next checkpoint never apply", async ({page}) => {
  const {frame} = await open(page, "production");
  await send(page, "c1"); await send(page, "d2");
  await frame().waitForFunction(() => document.querySelectorAll("[data-replay-interactions] > li").length === 1);
  await send(page, "d4"); await send(page, "d6"); // 3 is missing, and d6 depends on a checkpoint that never came
  await waitState(frame(), "gap");
  await page.waitForTimeout(300);
  const open_ = await snapshot(frame());
  expect(open_.interactions).toEqual(["pointer 64,-8"]); // neither d4's resize nor d6's pointer
  expect(open_.timeline.filter(line => line.startsWith("delta"))).toEqual(["delta 2"]);
  await send(page, "c8");
  await waitState(frame(), "ready");
  await send(page, "d9");
  await frame().waitForFunction(() => document.querySelectorAll("[data-replay-interactions] > li").length === 2);
  const resumed = await snapshot(frame());
  expect(resumed.timeline).toEqual(["checkpoint 1", "delta 2", "gap 3-7 missing_chunk", "checkpoint 8", "delta 9"]);
  expect(resumed.interactions).toEqual(["pointer 64,-8", "pointer 24,24"]);
  expect(resumed.tree).toBe("div[input:[masked]]");
 });

 test("gap recovery: interaction order is reconstructed across checkpoint and deltas", async ({page}) => {
  const {frame} = await open(page, "production");
  for (const name of ["c1", "d2", "d3", "d4"]) await send(page, name);
  await frame().waitForFunction(() => document.querySelectorAll("[data-replay-interactions] > li").length === 4);
  const shown = await snapshot(frame());
  expect(shown.interactions).toEqual(["pointer 64,-8", "mutation 0,0", "scroll 0,480", "resize 1280,720"]);
  expect(shown.tree).toBe("div[p[span:[masked],button:[masked]]]");
  expect(shown.state).toBe("ready");
 });

 test("revoked stream: a revocation stops and clears rendering and nothing sent afterwards is applied", async ({page}) => {
  const {seen, frame, messages} = await open(page, "production");
  await send(page, "c1"); await send(page, "d2");
  await frame().waitForFunction(() => document.querySelectorAll("[data-replay-tree] [data-tag]").length > 0 && document.querySelectorAll("[data-replay-interactions] > li").length === 1);
  await sendItem(page, {kind: "revoke", reason: "authority_revoked"});
  await waitState(frame(), "error");
  const revoked = await snapshot(frame());
  expect(revoked.tree).toBe("");
  expect(revoked.interactions).toEqual([]);
  expect(revoked.timeline).toEqual([]);
  expect(revoked.html).not.toContain("[masked]");
  expect(revoked.html).not.toContain("data-tag");
  // The host keeps sending (an unauthorized continuation attempt): the frame no longer listens and renders nothing.
  for (const name of ["d3", "c5", "d6", "c8"]) await send(page, name);
  await page.waitForTimeout(500);
  const after = await snapshot(frame());
  expect(after.tree).toBe("");
  expect(after.interactions).toEqual([]);
  expect(after.state).toBe("error");
  expect(seen.requests.length).toBe(2);
  expect((await messages()).filter(message => message.soundpost === "status").map(message => message.status)).toEqual(["loading", "ready", "error"]);
 });

 test("revoked stream: deletion ends the view the same way", async ({page}) => {
  const {frame} = await open(page, "production");
  await send(page, "c1");
  await waitState(frame(), "ready");
  await sendItem(page, {kind: "revoke", reason: "deleted"});
  await waitState(frame(), "error");
  const shown = await snapshot(frame());
  expect(shown.tree).toBe("");
  expect(shown.html).not.toContain("[masked]");
 });
});
