// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {test, expect} from "bun:test";
import {readFileSync} from "node:fs";
import {config} from "./fixture.ts";
import {Client} from "../src/client.ts";

const golden = JSON.parse(readFileSync(new URL("../../../fixtures/replays/recorder/session/01.json", import.meta.url), "utf8")) as Record<string, unknown> & {nodes: Record<string, unknown>[]};
const kinds = (client: Client): string[] => client.bufferedRecords().map(line => (JSON.parse(line) as {kind: string}).kind);

test("the core client enqueues exactly the chunks the real recorder emits and refuses anything outside the closed schema", () => {
 const client = new Client({...config(), deploymentReplay: true});
 expect(client.captureReplay(golden)).toBe(true);
 expect(kinds(client)).toEqual(["replay_chunk"]);
 // The former recorder shapes: node geometry, a wider tag, any extra field.
 const withRect = {...golden, nodes: golden.nodes.map(node => ({...node, rect: {x: 0, y: 0, w: 8, h: 8}}))};
 const withTag = {...golden, nodes: golden.nodes.map(node => ({...node, tag: "html"}))};
 const withHtml = {...golden, html: "<b>typed</b>"};
 for (const bad of [withRect, withTag, withHtml]) expect(client.captureReplay(bad)).toBe(false);
 expect(client.captureReplay({...golden, clock: null})).toBe(false);
 expect(kinds(client)).toEqual(["replay_chunk"]);
 expect(client.diagnostics().invalid_replay_record).toBe(4);
});

test("replay chunks need the policy's replay flag AND the deployment's opt-in", () => {
 const denied = new Client(config());
 expect(denied.captureReplay(golden)).toBe(false);
 expect(denied.bufferedRecords()).toEqual([]);
});

test("discardUnsentReplay destroys only queued replay chunks", () => {
 const client = new Client({...config(), deploymentReplay: true});
 client.captureException(Error("kept"));
 client.captureReplay(golden); client.captureReplay({...golden, sequence: "2"});
 expect(kinds(client)).toEqual(["error", "replay_chunk", "replay_chunk"]);
 expect(client.discardUnsentReplay()).toBe(2);
 expect(kinds(client)).toEqual(["error"]);
 expect(client.discardUnsentReplay()).toBe(0);
 expect(client.diagnostics().replay_chunks_discarded).toBe(2);
});
