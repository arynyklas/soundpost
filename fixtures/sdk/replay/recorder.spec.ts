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
// The production viewer's tree renderer, bundled alone (one entry keeps the output name render.js), so the placeholder is checked on the recorder's own output.
execFileSync(bun, ["build", join(root, "packages/replay-viewer/src/render.ts"), "--outdir", bundleDir, "--target=browser", "--format=esm"], {stdio: "pipe"});
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
  if (path === "/recorder.js" || path === "/stream.js" || path === "/render.js") return route.fulfill({contentType: "text/javascript", body: readFileSync(join(bundleDir, path.slice(1)), "utf8")});
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
 // The browser itself logs "Failed to load resource: ... canary.invalid" (WebKit) for the page's own canary URLs; that is the engine reporting the page's request, not output of the recorder.
 expect(seen.console.filter(line => /canary/i.test(line) && !/^Failed to load resource/.test(line))).toEqual(["CANARY_CONSOLE_ARGUMENT_EEEEEEEE"]);
 expect(seen.errors).toEqual([]);
 expect(await page.evaluate(() => Reflect.get(window, "__traps"))).toBe(0);
 const chunks = queue.map(line => JSON.parse(line));
 const nodes = chunks.flatMap(chunk => chunk.nodes);
 for (const node of nodes) { expect(Object.keys(node).sort()).toEqual(["class", "id", "parent", "tag", "text"]); expect(["", "[masked]"]).toContain(node.text); expect(["div", "span", "p", "button", "input", "section", "canvas", "masked"]).toContain(node.tag); }
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

test("closed shadow roots attached while capture is active are opaque (roots attached before capture starts are a documented limitation)", async ({page}) => {
 await open(page);
 await page.evaluate(() => Reflect.get(window, "__replay").setConsent(true));
 await page.evaluate(() => {
  const host = document.createElement("div"); host.id = "late-closed-host";
  host.attachShadow({mode: "closed"}).innerHTML = "<p>CANARY_LATE_CLOSED_SHADOW_TEXT</p>";
  const light = document.createElement("p"); light.textContent = "CANARY_LATE_CLOSED_LIGHT_CHILD"; host.appendChild(light);
  const open = document.createElement("div"); open.attachShadow({mode: "open"}).innerHTML = "<span>CANARY_LATE_OPEN_SHADOW_TEXT</span>";
  document.getElementById("burst")!.append(host, open);
 });
 await page.waitForTimeout(1500);
 const queue = await chunksOf(page);
 for (const pattern of secrets) expect(queue.join("\n")).not.toMatch(pattern);
 const delta = queue.map(line => JSON.parse(line)).filter(chunk => chunk.sequence !== chunk.checkpoint_sequence && chunk.nodes.length > 0);
 expect(delta.length).toBeGreaterThan(0);
 const nodes = delta.flatMap(chunk => chunk.nodes) as Array<Node & {id: string; parent: string}>;
 // The batch holds the new closed host (opaque: tag and class masked) and then the open host. No node hangs below the closed host.
 const opaque = nodes.filter(node => node.tag === "masked" && node.class === "masked");
 expect(opaque.length).toBeGreaterThan(0);
 for (const node of opaque) expect(nodes.some(other => other.parent === node.id)).toBe(false);
 // The open host's shadow content IS walked (masked text) under it, so the opaque node above is the closed host, not the open one.
 expect(nodes.filter(node => node.tag === "span" || node.tag === "p").length).toBeGreaterThan(0);
});

test("a closed shadow root attached BEFORE capture started: its canary never reaches a chunk, its host is the closed-shadow mark and the viewer shows the explicit placeholder", async ({page}) => {
 await open(page);
 // The page really hides the root (shadowRoot is null, no light child): nothing here could ever be read, only inferred from the platform's own answers.
 const facts = await page.evaluate(() => { const host = document.getElementById("pre-closed")!; return {rootHidden: host.shadowRoot === null, boxed: host.offsetWidth > 0 && host.offsetHeight > 0, light: host.childNodes.length}; });
 expect(facts).toEqual({rootHidden: true, boxed: true, light: 0});
 await page.evaluate(() => Reflect.get(window, "__replay").setConsent(true));
 await page.waitForTimeout(1500);
 const queue = await chunksOf(page);
 expect(queue.length).toBeGreaterThan(0);
 for (const pattern of [...secrets, /PREEXISTING/i, /CLOSED_SHADOW/i]) expect(queue.join("\n")).not.toMatch(pattern);
 const first = JSON.parse(queue[0]!) as {nodes: Array<Node & {id: string; parent: string}>};
 // The mark is an opaque node (class masked) carrying the constant mask: no other cause of opacity produces that shape, and only the one pre-existing component qualifies.
 const marks = first.nodes.filter(node => node.tag === "masked" && node.class === "masked" && node.text === "[masked]");
 expect(marks).toHaveLength(1);
 expect(first.nodes.some(node => node.parent === marks[0]!.id)).toBe(false);
 // The production renderer draws that record as the explicit placeholder and nothing inside it.
 const shown = await page.evaluate(async nodes => {
  const {renderTree} = await import("/render.js");
  const tree = renderTree(document, nodes);
  return Array.from(tree.querySelectorAll("[data-opaque=\"closed-shadow\"]"), element => element.textContent);
 }, first.nodes);
 expect(shown).toEqual(["[opaque: closed shadow root not observable]"]);
});
test("late start (D100): a recorder started after the page loaded says so, its first checkpoint is gap-marked and the viewer shows the banner", async ({page}) => {
 await open(page); // the recorder module runs after the document was parsed: not the supported install (a classic script first in <head>)
 await page.evaluate(() => Reflect.get(window, "__replay").setConsent(true));
 await page.waitForTimeout(500);
 const reason = await page.evaluate(() => Reflect.get(window, "__replay").lateStart());
 expect(["document_ready_state", "body_content_present"]).toContain(reason);
 const queue = await chunksOf(page);
 expect(JSON.parse(queue[0]!).gap).toBe(true);
 // The production viewer over the recorder's own chunks (the module comes from the served bundle: a runtime-selected page module, not a build-time import).
 const banner = await page.evaluate(async chunks => {
  const {renderReplay} = await import("/render.js");
  const host = document.createElement("div"), encoder = new TextEncoder();
  const items = async function* () { for (const text of chunks) yield {kind: "chunk" as const, bytes: encoder.encode(text)}; };
  await renderReplay(host, items()).done;
  return Array.from(host.querySelectorAll("[data-kind=\"late-start\"]"), element => element.textContent);
 }, queue);
 expect(banner).toEqual(["Recording started after the page had loaded: pre-existing closed shadow roots may be unobservable."]);
});

// The recorder answers an append from the page's children and a child-list record's `nextSibling`, never from `addedNodes`/`removedNodes`. Fake pages encode what the platform reports; this runs seeded random
// histories of every kind of child-list operation (append, fragment append, last child removal, removal of any child, insertion, replacement, move, replaceChildren, prepend, remove(), textContent, character data) on the real
// DOM of each engine, plays the recorder's deltas through the production viewer, and compares what it shows with what a fresh checkpoint of the same page shows.
test("random DOM histories in a real browser: the viewer shows after the recorder's deltas what a fresh checkpoint of the page shows", async ({page}) => {
 await open(page);
 await page.evaluate(() => Reflect.get(window, "__replay").setConsent(true));
 let deltas = 0;
 for (const seed of [1, 2, 3, 4, 5, 6, 7, 8]) {
  const verdict = await page.evaluate(async seed => {
   const {renderReplay} = await import("/render.js");
   const chunks = Reflect.get(window, "__chunks") as string[];
   const from = chunks.length - 1; // the checkpoint the recorder made when it (re)started: the history of this seed begins there
   let s = seed >>> 0;
   const rnd = () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 2 ** 32; };
   const root = document.getElementById("burst")!;
   const tags = ["div", "p", "span", "section", "button", "my-widget", "select", "input"];
   const make = (depth = 0): Element => {
    const element = document.createElement(tags[Math.floor(rnd() * tags.length)]!);
    if (depth < 2 && element.tagName !== "INPUT") for (let count = Math.floor(rnd() * 3); count > 0; count--) element.append(rnd() < 0.3 ? document.createTextNode("t") : make(depth + 1));
    return element;
   };
   const pick = (): Element => { const all = [root, ...Array.from(root.querySelectorAll("*"))]; return all[Math.floor(rnd() * all.length)]!; };
   const child = (parent: Element): ChildNode | null => parent.childNodes[Math.floor(rnd() * parent.childNodes.length)] ?? null;
   for (let batch = 0; batch < 40; batch++) {
    for (let operations = 1 + Math.floor(rnd() * 5); operations > 0; operations--) {
     const roll = rnd(), parent = pick();
     try {
      if (roll < 0.22) parent.appendChild(make());
      else if (roll < 0.30) { const fragment = document.createDocumentFragment(); fragment.append(make(), make(), document.createTextNode("f")); parent.appendChild(fragment); }
      else if (roll < 0.40 && parent.lastChild) parent.removeChild(parent.lastChild);
      else if (roll < 0.48 && parent.firstChild) parent.removeChild(child(parent)!);
      else if (roll < 0.55 && parent.firstChild) parent.insertBefore(make(), child(parent));
      else if (roll < 0.61 && parent.firstChild) parent.replaceChild(make(), child(parent)!);
      else if (roll < 0.69) { const moved = pick(); if (moved !== root) parent.appendChild(moved); }
      else if (roll < 0.73) parent.textContent = rnd() < 0.5 ? "" : "x";
      else if (roll < 0.77) parent.replaceChildren(make(), make());
      else if (roll < 0.81) parent.prepend(make());
      else if (roll < 0.85 && parent !== root) parent.remove();
      else if (roll < 0.90) { const text = Array.from(parent.childNodes).find(node => node.nodeType === 3); if (text) text.nodeValue = "changed" + batch; }
      else if (roll < 0.94 && parent.lastChild) { parent.removeChild(parent.lastChild); parent.appendChild(make()); parent.appendChild(make()); }
      else parent.setAttribute("data-n", String(batch));
     } catch { /* a hierarchy error (a node moved into itself) changes nothing */ }
    }
    await new Promise(resolve => setTimeout(resolve, 0)); // the observer delivers this batch
   }
   const summarize = (element: Element): string => {
    const own = Array.from(element.children).filter(item => item.hasAttribute("data-masked")).map(item => item.textContent).join("");
    const kids = Array.from(element.children).filter(item => item.hasAttribute("data-tag")).map(summarize);
    return (element.getAttribute("data-tag") ?? "?") + (own === "" ? "" : ":" + own) + (kids.length > 0 ? "[" + kids.join(",") + "]" : "");
   };
   const encoder = new TextEncoder();
   const shown = async (texts: string[]): Promise<{tree: string; status: string}> => {
    const host = document.createElement("div");
    const items = async function* () { for (const text of texts) yield {kind: "chunk" as const, bytes: encoder.encode(text)}; };
    const handle = renderReplay(host, items());
    await handle.done;
    const tree = host.querySelector("[data-replay-tree]")!;
    return {tree: Array.from(tree.children).filter(item => item.hasAttribute("data-tag")).map(summarize).join("|"), status: handle.status()};
   };
   const after = await shown(chunks.slice(from));
   const delta = chunks.slice(from).filter(text => { const chunk = JSON.parse(text) as {sequence: string; checkpoint_sequence: string}; return chunk.sequence !== chunk.checkpoint_sequence; }).length;
   // A fresh checkpoint of the page as it is now: consent off and on again starts the recorder over, and its first chunk is a full snapshot.
   const replay = Reflect.get(window, "__replay") as {setConsent(on: boolean): void};
   replay.setConsent(false); replay.setConsent(true);
   const fresh = await shown([chunks.at(-1)!]);
   return {after: after.tree, fresh: fresh.tree, status: after.status, delta};
  }, seed);
  expect(["ready", "gap"], `seed ${seed}: a recording resumed after revoked consent starts with a gap-marked checkpoint`).toContain(verdict.status);
  expect(verdict.after, `seed ${seed}`).toBe(verdict.fresh);
  expect(verdict.after.length, `seed ${seed}: the page shows something`).toBeGreaterThan(20);
  deltas += verdict.delta;
 }
 expect(deltas).toBeGreaterThan(100);
});

// Firefox reports `replaceChildren(...)` as ONE child-list record with nextSibling null, whatever was inserted before or reordered among the children the replay holds; Chromium and WebKit report an
// "inside" record there. Every engine must show, after the recorder's deltas, exactly what a fresh checkpoint of the page shows.
test("replaceChildren shapes in a real browser (new node first or in the middle, reorders, drops, pure append): the viewer shows what a fresh checkpoint shows", async ({page}) => {
 await open(page);
 await page.evaluate(() => Reflect.get(window, "__replay").setConsent(true));
 const verdicts = await page.evaluate(async () => {
  const {renderReplay} = await import("/render.js");
  const chunks = Reflect.get(window, "__chunks") as string[];
  const replay = Reflect.get(window, "__replay") as {setConsent(on: boolean): void};
  const encoder = new TextEncoder();
  const summarize = (element: Element): string => {
   const own = Array.from(element.children).filter(item => item.hasAttribute("data-masked")).map(item => item.textContent).join("");
   const kids = Array.from(element.children).filter(item => item.hasAttribute("data-tag")).map(summarize);
   return (element.getAttribute("data-tag") ?? "?") + (own === "" ? "" : ":" + own) + (kids.length > 0 ? "[" + kids.join(",") + "]" : "");
  };
  const shown = async (texts: string[]): Promise<string> => {
   const host = document.createElement("div");
   const items = async function* () { for (const text of texts) yield {kind: "chunk" as const, bytes: encoder.encode(text)}; };
   await renderReplay(host, items()).done;
   return Array.from(host.querySelector("[data-replay-tree]")!.children).filter(item => item.hasAttribute("data-tag")).map(summarize).join("|");
  };
  const tick = () => new Promise(resolve => setTimeout(resolve, 0));
  const restart = async () => { replay.setConsent(false); replay.setConsent(true); await tick(); };
  const shapes: Record<string, (kids: Element[], fresh: () => Element) => (Element | string)[]> = {
   "new first": (kids, fresh) => [fresh(), ...kids],
   "new in the middle": (kids, fresh) => [kids[0]!, kids[1]!, fresh(), ...kids.slice(2)],
   "reverse": kids => [...kids].reverse(),
   "swap the first two": kids => [kids[1]!, kids[0]!, ...kids.slice(2)],
   "new first and reorder": (kids, fresh) => [fresh(), kids[3]!, kids[0]!, kids[1]!, kids[2]!, kids[4]!],
   "drop the first": kids => kids.slice(1),
   "drop the last and add a new one first": (kids, fresh) => [fresh(), ...kids.slice(0, -1)],
   "pure append of a new node": (kids, fresh) => [...kids, fresh()],
   "text first": kids => ["text", ...kids],
  };
  const out: {shape: string; after: string; fresh: string; chunks: number}[] = [];
  for (const [shape, order] of Object.entries(shapes)) {
   const box = document.createElement("div");
   for (const name of ["div", "p", "section", "button", "span"]) box.append(document.createElement(name));
   document.getElementById("burst")!.append(box);
   await tick(); await restart();
   const from = chunks.length - 1;
   const kids = Array.from(box.children);
   box.replaceChildren(...order(kids, () => document.createElement("input")).map(item => typeof item === "string" ? document.createTextNode(item) : item));
   await tick();
   const after = await shown(chunks.slice(from));
   const count = chunks.length - from;
   await restart();
   out.push({shape, after, fresh: await shown([chunks.at(-1)!]), chunks: count});
   box.remove(); await tick();
  }
  return out;
 });
 for (const verdict of verdicts) {
  expect(verdict.chunks, `${verdict.shape}: the change was recorded`).toBeGreaterThan(1);
  expect(verdict.after, verdict.shape).toBe(verdict.fresh);
 }
});
