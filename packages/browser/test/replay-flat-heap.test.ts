// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// A recorded batch must not leave one object per node for the garbage collector: Firefox charged its minor collections (a full nursery of node objects and id
// strings) to the observer callback, which is where the 400-node batch p95 went over its 5 ms budget (03.07 / 03.09). Counted on the engine's own heap.
import {test, expect} from "bun:test";
import {heapStats} from "bun:jsc";
import {createRecorder} from "../src/replay/recorder.ts";
import type {DomAccessors, ReplayChunk} from "../src/replay/types.ts";
import {scriptedPage} from "./recorded-session.ts";

interface Fake { t: number; name: string; kids: Fake[]; parent: Fake | null }
const fake = (name: string, ...kids: Fake[]): Fake => { const out: Fake = {t: 1, name, kids, parent: null}; for (const kid of kids) kid.parent = out; return out; };
function wideDom(): DomAccessors {
 return {
  nodeType: n => (n as Fake).t, firstChild: n => (n as Fake).kids[0] ?? null,
  nextSibling: n => { const parent = (n as Fake).parent; return parent === null ? null : parent.kids[parent.kids.indexOf(n as Fake) + 1] ?? null; },
  lastChild: n => (n as Fake).kids.at(-1) ?? null,
  previousSibling: n => { const parent = (n as Fake).parent; return parent === null ? null : parent.kids[parent.kids.indexOf(n as Fake) - 1] ?? null; },
  parentNode: n => (n as Fake).parent, localName: n => (n as Fake).name, openShadowRoot: () => null, editable: () => false,
  mutationTarget: record => (record as {target: object}).target, recordKind: () => "other", eventTarget: () => null, clientX: () => 0, clientY: () => 0,
 };
}
const objects = (): number => { Bun.gc(true); return (heapStats().objectTypeCounts as Record<string, number>)["Object"] ?? 0; };

test("a chunk of 1,500 nodes keeps no node object until a consumer reads them", () => {
 const body = fake("body");
 for (let i = 0; i < 1500; i++) { const p = fake(i % 2 ? "p" : "span"); p.parent = body; body.kids.push(p); }
 const html = fake("html", body);
 const document: Fake = {t: 9, name: "#document", kids: [html], parent: null}; html.parent = document;
 const base = scriptedPage();
 const chunks: ReplayChunk[] = [];
 const recorder = createRecorder({...base.config, root: document, dom: wideDom(), projectPolicy: true, deploymentOptIn: true}, chunk => { chunks.push(chunk); return "accepted"; });
 const before = objects();
 recorder.setConsent(true);
 const created = objects(), during = created - before;
 expect(chunks).toHaveLength(1);
 expect(during).toBeLessThan(300); // the chunk and its small parts; per-node objects would add 1,502
 const nodes = chunks[0]!.nodes; // the first read makes the objects, once
 expect(nodes).toHaveLength(1502);
 expect(chunks[0]!.nodes).toBe(nodes);
 expect(objects() - created).toBeGreaterThan(1500); // exactly what the read made: one object per node
});
