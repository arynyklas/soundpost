// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {afterAll, beforeAll, describe, expect, setDefaultTimeout, test} from "bun:test";
import {BidiConnection, callFunction} from "../firefox/bidi.ts";
import {launchFirefox, type FirefoxProcess} from "../firefox/launch.ts";
import {ATTRIBUTES, ELEMENTS, b64, csp, directHtml, forbidden, frameHtml, hostHtml, hostileNodes, hostilePayloads, hostileWireNames, vulnerableHtml} from "./viewer-fixture.ts";

/*
 * 03.08-C10: the replay viewer's inertness rows (the same rows, documents and hostile material as viewer.spec.ts) on a stock Firefox.
 * Playwright cannot run them there: its BiDi frame evaluation is an `eval`, which the viewer's production CSP refuses, and `bypassCSP`
 * would defeat the thing under test. This driver talks WebDriver BiDi itself (../firefox/bidi.ts) and uses `script.callFunction` with
 * function declarations, which needs no eval: the probes run in the sandboxed frame's own realm under the production policy.
 *
 * Counters are the browser's own: `network.beforeRequestSent` for every request of the tab and its frames (a request blocked by CSP
 * never reaches the network layer, so it never appears there), `network.fetchError`, `browsingContext.navigationStarted`, user prompts,
 * new top-level contexts (popups) and `log.entryAdded` (Firefox reports CSP violations there, as errors of type "javascript"). Like
 * viewer.spec.ts's page.route, the pages live at http://soundpost.test: Firefox is pointed (through its own proxy preferences) at a loopback
 * server that answers for that host only (the production frame with its real `Content-Security-Policy` header) and counts every path it
 * is asked for; any other host (evil.test) is refused and recorded, so an escaped request can both succeed and be seen.
 *
 *   SOUNDPOST_FIREFOX=/path/to/firefox bun test fixtures/sdk/replay/viewer-firefox.test.ts
 * (SOUNDPOST_FIREFOX_ENV="LD_LIBRARY_PATH=..." adds environment for a host without system GTK.) Without SOUNDPOST_FIREFOX the rows are skipped, not passed.
 * Real wall-clock waits are deliberate here: this drives a real browser (state is polled until a named condition holds) and the "nothing
 * happened" rows must give the page real time to do something unwanted, exactly as viewer.spec.ts's waitForTimeout does.
 */
const binary = process.env.SOUNDPOST_FIREFOX;
const suite = binary === undefined || binary === "" ? describe.skip : describe;

type Variant = "production" | "control" | "vulnerable";
setDefaultTimeout(60000);
interface Seen { requests: string[]; served: string[]; failed: {url: string; error: string}[]; navigations: string[]; dialogs: string[]; consoleErrors: string[]; pageErrors: string[]; popups: number; websockets: number; cspMessages: string[] }
interface Snapshot { state: string | null; tree: string; timeline: string[]; interactions: string[]; opaque: number; elements: string[]; attributes: string[]; html: string }
interface Tab {
 readonly seen: Seen;
 readonly frame: () => Promise<string>;
 inTab<T>(fn: (...args: never[]) => unknown, ...args: unknown[]): Promise<T>;
 inFrame<T>(fn: (...args: never[]) => unknown, ...args: unknown[]): Promise<T>;
 messages(): Promise<{soundpost?: string; status?: string}[]>;
 close(): Promise<void>;
}

let firefox: FirefoxProcess;
let connection: BidiConnection;
const sleep = (ms: number): Promise<void> => new Promise(resolve => setTimeout(resolve, ms));
const parseEnv = (text: string | undefined): Record<string, string> => Object.fromEntries((text ?? "").split(/\s+/).filter(Boolean).map(pair => [pair.slice(0, pair.indexOf("=")), pair.slice(pair.indexOf("=") + 1)]));

const origin = "http://soundpost.test";
const PIXEL = Uint8Array.from(atob("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="), char => char.charCodeAt(0));
/** The row being run: the proxy answers for it and records what it was asked. Rows run one after the other. */
let current: {readonly variant: Variant; readonly seen: Seen} | undefined;
let proxy: ReturnType<typeof Bun.serve>;
function startProxy(): ReturnType<typeof Bun.serve> {
 return Bun.serve({port: 0, hostname: "127.0.0.1", fetch(request) {
  const row = current;
  const host = (request.headers.get("host") ?? "").toLowerCase(), path = new URL(request.url).pathname;
  if (host !== "soundpost.test") { row?.seen.served.push(`${host}${path}`); return new Response("refused", {status: 502}); }
  row?.seen.served.push(path);
  if (path === "/") return new Response(hostHtml, {headers: {"content-type": "text/html"}});
  if (path === "/frame.html") {
   if (row?.variant === "production") return new Response(frameHtml, {headers: {"content-type": "text/html", "content-security-policy": csp}});
   return new Response(row?.variant === "control" ? directHtml : vulnerableHtml, {headers: {"content-type": "text/html"}});
  }
  // A real image, so an image probe that CSP does not stop reads "loaded", not "blocked by being undecodable".
  if (path.endsWith("/probe-img")) return new Response(PIXEL, {headers: {"content-type": "image/png"}});
  return new Response("reached", {headers: {"content-type": "text/plain"}}); // only requests that survive CSP and sandbox reach here
 }});
}

/** Opens a fresh tab for one row and counts everything that tab and its frames do. */
async function open(variant: Variant): Promise<Tab & {origin: string}> {
 const seen: Seen = {requests: [], served: [], failed: [], navigations: [], dialogs: [], consoleErrors: [], pageErrors: [], popups: 0, websockets: 0, cspMessages: []};
 current = {variant, seen};
 const created = await connection.send<{context: string}>("browsingContext.create", {type: "tab"});
 const tab = created.context;
 const members = new Set<string>([tab]);
 const off = [
  connection.on("browsingContext.contextCreated", params => {
   const context = String(params["context"]), parent = params["parent"];
   if (typeof parent === "string") { if (members.has(parent)) members.add(context); }
   else if (context !== tab && !members.has(context)) seen.popups++;
  }),
  connection.on("network.beforeRequestSent", params => {
   if (!members.has(String(params["context"]))) return;
   const url = String((params["request"] as {url: string}).url);
   seen.requests.push(url);
   if (/^wss?:/.test(url)) seen.websockets++;
  }),
  connection.on("network.fetchError", params => { if (members.has(String(params["context"]))) seen.failed.push({url: String((params["request"] as {url: string}).url), error: String(params["errorText"])}); }),
  connection.on("browsingContext.navigationStarted", params => { if (members.has(String(params["context"]))) seen.navigations.push(String(params["url"])); }),
  connection.on("browsingContext.userPromptOpened", params => {
   if (!members.has(String(params["context"]))) return;
   seen.dialogs.push(String(params["message"]));
   void connection.send("browsingContext.handleUserPrompt", {context: String(params["context"]), accept: false}).catch(() => undefined);
  }),
  connection.on("log.entryAdded", params => {
   const source = params["source"] as {context?: string} | undefined;
   if (source?.context === undefined || !members.has(source.context)) return;
   const level = String(params["level"]), text = String(params["text"]);
   if (level !== "error" && level !== "warn") return;
   seen.consoleErrors.push(text);
   if (/^Content-Security-Policy:/.test(text)) seen.cspMessages.push(text);
   else if (params["type"] === "javascript") seen.pageErrors.push(text); // an uncaught exception or script error, as Playwright's pageerror
  }),
 ];
 await connection.send("browsingContext.navigate", {context: tab, url: `${origin}/`, wait: "complete"});
 const frame = async (): Promise<string> => {
  const tree = await connection.send<{contexts: {children?: {context: string; url: string}[]}[]}>("browsingContext.getTree", {root: tab});
  const child = tree.contexts[0]?.children?.find(entry => entry.url.endsWith("/frame.html"));
  if (child === undefined) throw new Error("the viewer frame is not in the tab");
  return child.context;
 };
 const handle: Tab & {origin: string} = {
  seen, origin, frame,
  inTab: <T>(fn: (...args: never[]) => unknown, ...args: unknown[]) => callFunction<T>(connection, {context: tab}, fn, ...args),
  inFrame: async <T>(fn: (...args: never[]) => unknown, ...args: unknown[]) => callFunction<T>(connection, {context: await frame()}, fn, ...args),
  messages: () => callFunction<{soundpost?: string; status?: string}[]>(connection, {context: tab}, () => (window as unknown as {__messages: {soundpost?: string; status?: string}[]}).__messages),
  async close() { for (const stop of off) stop(); await connection.send("browsingContext.close", {context: tab}).catch(() => undefined); current = undefined; },
 };
 await waitFor(async () => (await handle.messages()).some(message => message.status === "loading"), "the viewer frame to report loading");
 return handle;
}

async function waitFor(predicate: () => Promise<boolean>, what: string, timeoutMs = 15000): Promise<void> {
 const deadline = Date.now() + timeoutMs;
 for (;;) {
  if (await predicate().catch(() => false)) return;
  if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
  await sleep(25);
 }
}
const send = (tab: Tab, name: string): Promise<void> => tab.inTab<void>((value: string) => (window as unknown as {__sendChunk: (value: string) => void}).__sendChunk(value), b64(name));
const sendPayload = (tab: Tab, payload: string): Promise<void> => tab.inTab<void>((value: string) => (window as unknown as {__sendChunk: (value: string) => void}).__sendChunk(value), payload);
const sendRaw = (tab: Tab, data: unknown): Promise<void> => tab.inTab<void>((value: unknown) => (window as unknown as {__sendRaw: (value: unknown) => void}).__sendRaw(value), data);
const sendItem = (tab: Tab, item: object): Promise<void> => tab.inTab<void>((value: object) => (window as unknown as {__sendItem: (value: object) => void}).__sendItem(value), item);
const waitState = (tab: Tab, state: string): Promise<void> => waitFor(async () => (await tab.inFrame<boolean>((wanted: string) => document.querySelector("[data-replay-root]")?.getAttribute("data-state") === wanted, state)) === true, `viewer state ${state}`);
const waitInteractions = (tab: Tab, count: number): Promise<void> => waitFor(async () => (await tab.inFrame<number>(() => document.querySelectorAll("[data-replay-interactions] > li").length)) === count, `${count} interactions`);
const snapshot = (tab: Tab): Promise<Snapshot> => tab.inFrame<Snapshot>(() => {
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

beforeAll(async () => {
 if (binary === undefined || binary === "") return;
 proxy = startProxy();
 // Everything http goes to the loopback server (no direct fallback, no exceptions), so soundpost.test and evil.test are reachable only through it.
 const prefs = {"network.proxy.type": 1, "network.proxy.http": "127.0.0.1", "network.proxy.http_port": proxy.port ?? 0, "network.proxy.no_proxies_on": "", "network.proxy.failover_direct": false};
 firefox = await launchFirefox({binary, env: parseEnv(process.env["SOUNDPOST_FIREFOX_ENV"]), prefs});
 connection = firefox.connection;
 await connection.send("session.subscribe", {events: ["network", "browsingContext", "log"]});
});
afterAll(async () => { if (firefox !== undefined) await firefox.stop(); proxy?.stop(true); });

async function withTab(variant: Variant, run: (tab: Tab & {origin: string}) => Promise<void>): Promise<void> {
 const tab = await open(variant);
 try { await run(tab); } finally { await tab.close(); }
}

suite("replay viewer in stock Firefox (own WebDriver BiDi driver)", () => {
 test("the browser is the pinned stock Firefox 144", () => {
  expect(firefox.version.startsWith("144.")).toBe(true);
 });

 test("no network: malicious tag, class, text, URL, CSS and script payloads cause zero requests, script runs and navigations under the production CSP and sandbox", async () => {
  await withTab("production", async tab => {
   const {seen, origin} = tab;
   expect(seen.requests).toEqual([`${origin}/`, `${origin}/frame.html`]);
   expect(seen.served).toEqual(["/", "/frame.html"]); // host page and frame only: nothing else was fetched to boot the viewer
   // The policy is actually enforced here, by observation: the frame cannot fetch, load images, eval or reach its parent.
   const probe = await tab.inFrame<{fetched: string; imaged: string; evaled: string; parentAccess: string; storage: string; origin: string}>(async () => {
    // A probe that neither loads nor fails within 5 s reports "pending": a policy that lets it through to a slow host must not read as blocked.
    const fetched = await fetch("http://soundpost.test/probe-fetch", {signal: AbortSignal.timeout(5000)}).then(() => "loaded", error => (error instanceof DOMException && error.name === "TimeoutError" ? "pending" : "blocked"));
    const imaged = await new Promise<string>(resolveImage => { const image = new Image(); image.onload = () => resolveImage("loaded"); image.onerror = () => resolveImage("blocked"); setTimeout(() => resolveImage("pending"), 5000); image.src = "http://soundpost.test/probe-img"; });
    let evaled = "allowed";
    try { (0, eval)("1"); } catch { evaled = "blocked"; }
    let parentAccess = "reachable";
    try { void (window.parent.document.title); } catch { parentAccess = "blocked"; }
    let storage = "reachable";
    try { void localStorage.length; } catch { storage = "blocked"; }
    return {fetched, imaged, evaled, parentAccess, storage, origin: window.origin};
   });
   expect(probe).toMatchObject({fetched: "blocked", imaged: "blocked", evaled: "blocked", parentAccess: "blocked", storage: "blocked", origin: "null"});
   // The browser attempted the probes and CSP stopped them before the network: each one is a reported violation naming its directive and URL,
   // and none of them is a request (the Chromium row reads Playwright's `csp` failure text; Firefox reports violations in its console log).
   await waitFor(async () => seen.cspMessages.length >= 3, "the CSP violation reports of the three probes");
   expect(seen.cspMessages.some(text => text.includes("(connect-src) at http://soundpost.test/probe-fetch"))).toBe(true);
   expect(seen.cspMessages.some(text => text.includes("(img-src) at http://soundpost.test/probe-img"))).toBe(true);
   expect(seen.cspMessages.some(text => text.includes("JavaScript eval (script-src)"))).toBe(true);
   expect(seen.requests).toEqual([`${origin}/`, `${origin}/frame.html`]);
   expect(seen.failed).toEqual([]);
   expect(seen.served).toEqual(["/", "/frame.html"]);
   // From here on, not even a blocked attempt may happen: every request the browser starts is counted, and every CSP report.
   const baseline = {requests: [...seen.requests], navigations: [...seen.navigations]};
   seen.consoleErrors.length = 0; seen.cspMessages.length = 0;
   // Hostile wire chunks: every Go-invalid vector (unknown fields, img/html tags, secret text/class, rect/pres) plus raw payload chunks.
   const hostileWires = hostileWireNames();
   expect(hostileWires.length).toBeGreaterThanOrEqual(18);
   await send(tab, "c1");
   await waitState(tab, "ready");
   for (const name of hostileWires) await send(tab, name);
   for (const payload of hostilePayloads()) await sendPayload(tab, payload);
   // Messages that are not well-formed items (bytes that are not bytes, a bare string) are ignored by the bridge.
   await sendRaw(tab, {soundpost: "replay", item: {kind: "chunk", bytes: "<img src=http://evil.test/bytes>"}});
   await sendRaw(tab, "<img src=http://evil.test/string>");
   await waitState(tab, "unsupported"); // unknown recorder versions were among the hostile chunks; no checkpoint has recovered since
   await sleep(500);
   const during = await snapshot(tab);
   // A control item with a hostile reason is a protocol violation: the view stops and clears.
   await sendItem(tab, {kind: "gap", reason: "<img src=http://evil.test/x>", from: "2", through: "3"});
   await waitState(tab, "error");
   const shown = await snapshot(tab);
   // Observed counters: nothing but the original two requests, no navigation, no dialog, no script-visible side effect, no CSP violation.
   expect(seen.requests).toEqual(baseline.requests);
   expect(seen.requests.slice(baseline.requests.length).filter(url => forbidden.test(url))).toEqual([]);
   expect(seen.navigations).toEqual(baseline.navigations);
   expect(seen.dialogs).toEqual([]);
   expect(seen.popups).toBe(0);
   expect(seen.websockets).toBe(0);
   expect(seen.pageErrors).toEqual([]);
   expect(seen.failed).toEqual([]);
   expect(seen.cspMessages).toEqual([]);
   expect(seen.consoleErrors.filter(text => /content[- ]security[- ]policy|refused|violat/i.test(text))).toEqual([]);
   expect((await tab.messages()).filter(message => message.soundpost !== "status")).toEqual([]);
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
 });

 test("no network: the renderer alone is inert even when decoding is bypassed and no CSP applies (control rows)", async () => {
  await withTab("control", async tab => {
   const {seen} = tab;
   const baseline = seen.requests.length;
   await sendRaw(tab, {nodes: hostileNodes});
   await waitFor(async () => (await tab.inFrame<boolean>(() => document.querySelector("[data-replay-tree]") !== null)) === true, "the control tree");
   await sleep(500);
   const shown = await snapshot(tab);
   expect(seen.requests.length).toBe(baseline);
   expect(seen.dialogs).toEqual([]);
   expect(seen.pageErrors).toEqual([]);
   expect((await tab.messages()).filter(message => message.soundpost !== "status")).toEqual([]);
   expect(shown.elements.filter(name => !ELEMENTS.includes(name))).toEqual([]);
   expect(shown.attributes.filter(name => !ATTRIBUTES.includes(name))).toEqual([]);
   expect(shown.html).not.toMatch(/<img|<script|<iframe|<a |href|src=|style=|onerror|evil\.test|PWN/i);
   expect(shown.tree).toBe("masked[masked:[opaque],masked:[masked][masked[input:[masked]]],masked]");
   expect(shown.tree).toContain("input:[masked]");
   expect(shown.opaque).toBeGreaterThanOrEqual(1);
  });
 });

 test("no network: messages from any window other than the parent are ignored", async () => {
  await withTab("production", async tab => {
   const {seen} = tab;
   // A sibling frame (not the parent) tries to feed the viewer a checkpoint and then a deletion.
   await tab.inTab<void>((value: unknown) => (window as unknown as {__fromSibling: (value: unknown) => void}).__fromSibling(value), {b64: b64("c1")});
   await tab.inTab<void>((value: unknown) => (window as unknown as {__fromSibling: (value: unknown) => void}).__fromSibling(value), {item: {kind: "revoke", reason: "deleted"}});
   await sleep(600);
   const ignored = await snapshot(tab);
   expect(ignored.state).toBe("loading");
   expect(ignored.tree).toBe("");
   // The parent still drives the same view afterwards, so the frame was alive and listening the whole time.
   await send(tab, "c1");
   await waitState(tab, "ready");
   expect((await snapshot(tab)).tree).toBe("div[p[span:[masked]]]");
   expect(seen.requests.filter(url => !url.endsWith("/") && !url.endsWith("/frame.html"))).toEqual([]);
  });
 });

 test("no network: a vulnerable innerHTML renderer is caught by the same counters (the detection is not vacuous)", async () => {
  await withTab("vulnerable", async tab => {
   const {seen} = tab;
   const baseline = seen.requests.length;
   await sendRaw(tab, {html: "<img src='http://soundpost.test/pwn-vulnerable.png' onerror=\"parent.postMessage('PWN','*')\">"});
   await waitFor(async () => (await tab.messages()).filter(message => message.soundpost !== "status").length > 0, "the vulnerable renderer's PWN message");
   expect(seen.requests.length).toBeGreaterThan(baseline);
   expect(seen.requests.some(url => url.includes("pwn-vulnerable"))).toBe(true);
  });
 });

 test("gap recovery: a missing chunk is a visible gap, no delta applies across it and the next checkpoint resumes", async () => {
  await withTab("production", async tab => {
   const {seen} = tab;
   await send(tab, "c1"); await waitState(tab, "ready");
   await send(tab, "d2"); await waitInteractions(tab, 1);
   await send(tab, "d4"); // chunk 3 never arrives
   await waitState(tab, "gap");
   const inGap = await snapshot(tab);
   expect(inGap.timeline.some(line => /^gap 3-4 missing_chunk$/.test(line))).toBe(true);
   expect(inGap.interactions).toEqual(["pointer 64,-8"]); // d4's resize never applied
   await send(tab, "c5"); await waitState(tab, "ready");
   await send(tab, "d6");
   await waitInteractions(tab, 2);
   const recovered = await snapshot(tab);
   expect(recovered.timeline).toEqual(["checkpoint 1", "delta 2", "gap 3-4 missing_chunk", "checkpoint 5", "delta 6"]);
   expect(recovered.interactions).toEqual(["pointer 64,-8", "pointer 8,8"]);
   expect(recovered.tree).toBe("section[canvas:[opaque]]");
   expect(recovered.opaque).toBe(1);
   // A duplicate and a stale (already superseded) delta change nothing.
   await send(tab, "d6"); await send(tab, "d3_altered_previous");
   await sleep(300);
   expect((await snapshot(tab)).interactions).toEqual(["pointer 64,-8", "pointer 8,8"]);
   expect((await tab.messages()).filter(message => message.soundpost === "status").map(message => message.status)).toEqual(["loading", "ready", "gap", "ready"]);
   expect(seen.requests.length).toBe(2);
  });
 });

 test("gap recovery: an altered chain link rejects and the honest delta after it still cannot apply until a checkpoint", async () => {
  await withTab("production", async tab => {
   for (const name of ["c1", "d2", "d3_altered_previous", "d3"]) await send(tab, name);
   await waitState(tab, "gap");
   await sleep(300);
   const broken = await snapshot(tab);
   expect(broken.interactions).toEqual(["pointer 64,-8"]); // neither the altered delta nor the honest d3 (mutation + scroll) applied
   expect(broken.timeline.filter(line => line.startsWith("gap"))).toEqual(["gap 3 hash_mismatch"]);
   await send(tab, "c5");
   await waitState(tab, "ready");
   const resumed = await snapshot(tab);
   expect(resumed.timeline).toEqual(["checkpoint 1", "delta 2", "gap 3-4 hash_mismatch", "checkpoint 5"]);
   expect(resumed.tree).toBe("section[canvas:[opaque]]");
  });
 });

 test("gap recovery: deltas arriving after a gap and before the next checkpoint never apply", async () => {
  await withTab("production", async tab => {
   await send(tab, "c1"); await send(tab, "d2");
   await waitInteractions(tab, 1);
   await send(tab, "d4"); await send(tab, "d6"); // 3 is missing, and d6 depends on a checkpoint that never came
   await waitState(tab, "gap");
   await sleep(300);
   const open_ = await snapshot(tab);
   expect(open_.interactions).toEqual(["pointer 64,-8"]); // neither d4's resize nor d6's pointer
   expect(open_.timeline.filter(line => line.startsWith("delta"))).toEqual(["delta 2"]);
   await send(tab, "c8");
   await waitState(tab, "ready");
   await send(tab, "d9");
   await waitInteractions(tab, 2);
   const resumed = await snapshot(tab);
   expect(resumed.timeline).toEqual(["checkpoint 1", "delta 2", "gap 3-7 missing_chunk", "checkpoint 8", "delta 9"]);
   expect(resumed.interactions).toEqual(["pointer 64,-8", "pointer 24,24"]);
   expect(resumed.tree).toBe("div[input:[masked]]");
  });
 });

 test("gap recovery: interaction order is reconstructed across checkpoint and deltas", async () => {
  await withTab("production", async tab => {
   for (const name of ["c1", "d2", "d3", "d4"]) await send(tab, name);
   await waitInteractions(tab, 4);
   const shown = await snapshot(tab);
   expect(shown.interactions).toEqual(["pointer 64,-8", "mutation 0,0", "scroll 0,480", "resize 1280,720"]);
   expect(shown.tree).toBe("div[p[span:[masked],button:[masked]]]");
   expect(shown.state).toBe("ready");
  });
 });

 test("revoked stream: a revocation stops and clears rendering and nothing sent afterwards is applied", async () => {
  await withTab("production", async tab => {
   const {seen} = tab;
   await send(tab, "c1"); await send(tab, "d2");
   await waitFor(async () => (await tab.inFrame<boolean>(() => document.querySelectorAll("[data-replay-tree] [data-tag]").length > 0 && document.querySelectorAll("[data-replay-interactions] > li").length === 1)) === true, "the first interaction");
   await sendItem(tab, {kind: "revoke", reason: "authority_revoked"});
   await waitState(tab, "error");
   const revoked = await snapshot(tab);
   expect(revoked.tree).toBe("");
   expect(revoked.interactions).toEqual([]);
   expect(revoked.timeline).toEqual([]);
   expect(revoked.html).not.toContain("[masked]");
   expect(revoked.html).not.toContain("data-tag");
   // The host keeps sending (an unauthorized continuation attempt): the frame no longer listens and renders nothing.
   for (const name of ["d3", "c5", "d6", "c8"]) await send(tab, name);
   await sleep(500);
   const after = await snapshot(tab);
   expect(after.tree).toBe("");
   expect(after.interactions).toEqual([]);
   expect(after.state).toBe("error");
   expect(seen.requests.length).toBe(2);
   expect((await tab.messages()).filter(message => message.soundpost === "status").map(message => message.status)).toEqual(["loading", "ready", "error"]);
  });
 });

 test("revoked stream: deletion ends the view the same way", async () => {
  await withTab("production", async tab => {
   await send(tab, "c1");
   await waitState(tab, "ready");
   await sendItem(tab, {kind: "revoke", reason: "deleted"});
   await waitState(tab, "error");
   const shown = await snapshot(tab);
   expect(shown.tree).toBe("");
   expect(shown.html).not.toContain("[masked]");
  });
 });
});
