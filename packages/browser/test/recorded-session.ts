// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Deterministic recording sessions driven through the REAL recorder (src/replay/recorder.ts) over a scripted fake DOM.
// The wire strings it returns are exactly what the recorder hands to its emit callback (compact JSON.stringify); they are the
// golden fixtures of fixtures/replays/recorder, which the Go validator and the Go chain reader consume.
import {createRecorder} from "../src/replay/recorder.ts";
import type {DomAccessors, ReplayConfig, ReplayTimers} from "../src/replay/types.ts";

export const SESSION_SECRETS = ["SECRET-TEXT-IN-DIV", "SECRET-TYPED-PASSWORD", "SECRET-TEXTAREA-BODY", "SECRET-IFRAME-DOCUMENT", "SECRET-LATE-MUTATION-TEXT", "SECRET-CLASS-NAME", "SECRET-ID-ATTRIBUTE"] as const;

interface Fake { t: number; name: string; kids: Fake[]; parent: Fake | null; secret?: string }
function node(name: string, ...kids: Fake[]): Fake { const out: Fake = {t: 1, name, kids, parent: null}; for (const kid of kids) kid.parent = out; return out; }
function text(secret: string): Fake { return {t: 3, name: "#text", kids: [], parent: null, secret}; }
function append(parent: Fake, child: Fake): void { child.parent = parent; parent.kids.push(child); }

/** One scripted page: the structure covers every recorder branch (text mask, input mask, opaque widgets, skipped code, generic tags). */
function page() {
 const button = node("button", text(SESSION_SECRETS[0]));
 const section = node("section", node("span", text(SESSION_SECRETS[4])));
 const body = node("body",
  node("div", text(SESSION_SECRETS[0]), node("p", text(SESSION_SECRETS[0])), node("input")),
  button, section,
  node("my-widget", text(SESSION_SECRETS[5])),
  node("svg", node("text", text(SESSION_SECRETS[6]))),
  node("textarea", text(SESSION_SECRETS[2])),
  node("iframe", text(SESSION_SECRETS[3])),
  node("canvas"),
  node("script", text("script-source")));
 const html = node("html", node("head", node("title", text("title-text"))), body);
 const document: Fake = {t: 9, name: "#document", kids: [html], parent: null}; html.parent = document;
 return {document, html, button, section};
}

interface TimerEntry { id: number; ms: number; callback: () => void; live: boolean }
function timers(): ReplayTimers & { fire(ms: number): void } {
 const entries: TimerEntry[] = []; let next = 1;
 return {
  set: (callback, ms) => { const id = next++; entries.push({id, ms, callback, live: true}); return id; },
  clear: handle => { for (const entry of entries) if (entry.id === handle) entry.live = false; },
  fire(ms) {
   for (const entry of entries.filter(item => item.live && item.ms === ms)) { entry.live = false; entry.callback(); }
   entries.splice(0, entries.length, ...entries.filter(item => item.live));
  },
 };
}

export const FLUSH_MS = 1000, CHECKPOINT_MS = 30000;
const IDS = {
 session: {replay: "11111111111111111111111111111111", session: "22222222222222222222222222222222"},
 recovery: {replay: "66666666666666666666666666666666", session: "77777777777777777777777777777777"},
} as const;

export type SessionName = keyof typeof IDS;
export const SESSION_NAMES: readonly SessionName[] = ["session", "recovery"];

/** A scripted page plus every seam the recorder needs, all driven by hand: events, mutation records and timers. */
export function scriptedPage(ids: {readonly replay: string; readonly session: string} = IDS.session, revision = "1") {
 const {document, html, button, section} = page();
 const dom: DomAccessors = {
  nodeType: n => (n as Fake).t, firstChild: n => (n as Fake).kids[0] ?? null,
  nextSibling: n => { const parent = (n as Fake).parent; return parent === null ? null : parent.kids[parent.kids.indexOf(n as Fake) + 1] ?? null; },
  parentNode: n => (n as Fake).parent, localName: n => (n as Fake).name, openShadowRoot: () => null, editable: () => false,
  mutationTarget: record => (record as {target: object}).target, eventTarget: event => (event as {target: object}).target,
  clientX: event => (event as {x: number}).x, clientY: event => (event as {y: number}).y,
 };
 let observe: ((records: readonly object[]) => void) | undefined;
 class Observer { constructor(callback: (records: readonly object[]) => void) { observe = callback; } observe(): void {} disconnect(): void {} }
 const listeners = new Map<string, (event: object) => void>();
 const clock = timers();
 let tick = 0;
 const config: Omit<ReplayConfig, "projectPolicy" | "deploymentOptIn"> = {
  root: document, replayId: ids.replay, sessionId: ids.session, capturePolicyRevision: revision,
  domain: {host: "33333333333333333333333333333333", boot: "44444444444444444444444444444444", runtime: "55555555555555555555555555555555"},
  clock: () => ({wall_ns: String(1_700_000_000_000_000_000n + BigInt(tick) * 1_000_000n), mono_ns: String(5_000_000_000n + BigInt(++tick) * 1_000n), uncertainty_ns: "1000"}),
  dom, observer: Observer, viewport: () => ({w: 1280, h: 720, x: 0, y: 96}),
  eventTarget: {addEventListener: (type, listener) => { listeners.set(type, listener); }, removeEventListener: () => {}},
  timers: clock,
 };
 return {
  config, fire: clock.fire,
  /** Page events reach the recorder only while it listens (consent given and policy open); otherwise they go nowhere, as in a browser. */
  pointer: (on: "button" | "html", x: number, y: number) => listeners.get("pointerdown")?.({target: on === "button" ? button : html, x, y}),
  scroll: () => listeners.get("scroll")?.({}), resize: () => listeners.get("resize")?.({}),
  /** A text-only addition under <section>: the recorder re-reads that subtree. */
  grow: (secret?: string) => { append(section, secret === undefined ? node("p") : node("p", text(secret))); observe!([{target: section}]); },
 };
}

/** Records `name` and returns the wire JSON of every chunk the recorder emitted, in order. `delivered` marks chunks the sink refused. */
export function recordSession(name: SessionName): {wire: string[]; delivered: boolean[]} {
 const stage = scriptedPage(IDS[name]);
 const wire: string[] = [], delivered: boolean[] = [];
 let refuse = false;
 const recorder = createRecorder({...stage.config, projectPolicy: true, deploymentOptIn: true}, chunk => { wire.push(JSON.stringify(chunk)); delivered.push(!refuse); return refuse ? "rejected" : "accepted"; });
 recorder.setConsent(true); // chunk 1: checkpoint
 if (name === "recovery") {
  // A refused delta leaves a counted hole; the recorder heals it with a gap-marked checkpoint.
  refuse = true;
  stage.pointer("button", 123, 45);
  stage.fire(FLUSH_MS); // chunk 2: pointer delta (refused)
  refuse = false;
  stage.fire(FLUSH_MS); // chunk 3: gap checkpoint (loss 1, gap true)
  stage.scroll();
  stage.fire(FLUSH_MS); // chunk 4: scroll delta on the healed checkpoint
  recorder.close();
  return {wire, delivered};
 }
 stage.pointer("button", 123, 45);
 stage.scroll();
 stage.resize();
 stage.fire(FLUSH_MS); // chunk 2: pointer, scroll, resize
 stage.grow(SESSION_SECRETS[4]); // chunk 3: mutation subtree
 stage.pointer("html", 7, 9);
 stage.fire(FLUSH_MS); // chunk 4: pointer
 stage.fire(CHECKPOINT_MS); // chunk 5: second checkpoint
 stage.grow(); // chunk 6: mutation on checkpoint 5
 recorder.close();
 return {wire, delivered};
}
