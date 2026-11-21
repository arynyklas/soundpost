// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Cross-language wire contract of the replay recorder. The chunks below are produced by the real recorder; the golden
// files in fixtures/replays/recorder are what internal/replays (ValidateChunk, ChunkHash, the chain reader) consumes in
// fixtures/replays/recorder/recorder_test.go. This file is the generator check: the recorder's output must be
// byte-identical to the committed fixtures. After an intentional recorder or protocol change regenerate with
//
//   SOUNDPOST_UPDATE_RECORDER_FIXTURES=1 bun test packages/browser/test/replay-wire.test.ts
import {test, expect} from "bun:test";
import {existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync} from "node:fs";
import {join} from "node:path";
import {createHash} from "node:crypto";
import {SESSION_NAMES, SESSION_SECRETS, recordSession, type SessionName} from "./recorded-session.ts";
import {canonicalJSON} from "../src/replay/policy.ts";

const ROOT = join(import.meta.dir, "..", "..", "..", "fixtures", "replays", "recorder");
const UPDATE = process.env.SOUNDPOST_UPDATE_RECORDER_FIXTURES === "1";
const file = (index: number): string => String(index + 1).padStart(2, "0") + ".json";

// The closed Go schema (internal/model ReplayChunk, MaskedNode, MaskedEvent, TraceClock; internal/replays vocabularies).
const CHUNK_KEYS = ["capture_policy_revision", "checkpoint_hash", "checkpoint_sequence", "clock", "events", "gap", "loss", "nodes", "previous_hash", "recorder_version", "replay_id", "sequence", "session_id"];
const CLOCK_KEYS = ["domain", "mono_ns", "uncertainty_ns", "wall_ns"];
const NODE_KEYS = ["class", "id", "parent", "tag", "text"];
const EVENT_KEYS = ["at_ns", "kind", "node", "x", "y"];
const TAGS = ["div", "span", "p", "button", "input", "section", "canvas", "masked"];
const KINDS = ["pointer", "scroll", "resize", "mutation", "checkpoint", "gap"];

interface Wire { [key: string]: unknown }
const keys = (value: unknown): string[] => Object.keys(value as object).sort();

function assertClosed(chunk: Wire): void {
 expect(keys(chunk)).toEqual(CHUNK_KEYS);
 expect(keys(chunk.clock)).toEqual(CLOCK_KEYS);
 expect(keys((chunk.clock as Wire).domain)).toEqual(["boot", "host", "runtime"]);
 for (const node of chunk.nodes as Wire[]) {
  expect(keys(node)).toEqual(NODE_KEYS);
  expect(TAGS).toContain(node.tag as string);
  expect(["", "masked"]).toContain(node.class as string);
  expect(["", "[masked]"]).toContain(node.text as string);
  expect(node.id).toMatch(/^[1-9][0-9]*$/);
  expect(node.parent).toMatch(/^(0|[1-9][0-9]*)$/);
 }
 for (const event of chunk.events as Wire[]) {
  expect(keys(event)).toEqual(EVENT_KEYS);
  expect(KINDS).toContain(event.kind as string);
  expect(Number.isInteger(event.x)).toBe(true);
  expect(Number.isInteger(event.y)).toBe(true);
 }
 for (const key of ["sequence", "checkpoint_sequence", "loss", "capture_policy_revision"]) expect(chunk[key]).toMatch(/^(0|[1-9][0-9]*)$/);
 expect(chunk.previous_hash).toMatch(/^[0-9a-f]{64}$/);
 expect(chunk.checkpoint_hash).toMatch(/^[0-9a-f]{64}$/);
 expect(typeof chunk.gap).toBe("boolean");
}

for (const name of SESSION_NAMES) {
 test(`${name}: the real recorder emits exactly the Go closed schema, masked, with an unbroken canonical-JSON hash chain`, () => {
  const {wire} = recordSession(name);
  expect(wire.length).toBeGreaterThanOrEqual(4);
  const chunks = wire.map(line => JSON.parse(line) as Wire);
  for (const chunk of chunks) assertClosed(chunk);
  // Go's MaskedEvent.at_ns is a MonoNano: events carry the chunk clock's monotonic reading, never wall time.
  for (const chunk of chunks) for (const event of chunk.events as Wire[]) { expect(BigInt(event.at_ns as string)).toBeGreaterThan(0n); expect(BigInt(event.at_ns as string)).toBeLessThanOrEqual(BigInt((chunk.clock as Wire).mono_ns as string)); }
  // Node ids are per chunk and restart at every checkpoint (the server admits ids up to 2^31 only).
  if (name === "session") expect((chunks[4]!.nodes as Wire[])[0]!.id).toBe("1");
  // No raw page text, value, class or id ever leaves the browser.
  const everything = wire.join("\n");
  for (const secret of SESSION_SECRETS) expect(everything).not.toContain(secret);
  expect(everything).not.toMatch(/"(rect|pres|html|attributes|css|url|value)"/);
  // The chain hash is SHA-256 over canonical JSON (what Go's replays.ChunkHash computes).
  for (let index = 1; index < chunks.length; index++) expect(chunks[index]!.previous_hash).toBe(createHash("sha256").update(canonicalJSON(chunks[index - 1])).digest("hex"));
 });

 test(`${name}: committed fixtures are byte-identical to what the recorder emits now`, () => {
  const {wire, delivered} = recordSession(name);
  const dir = join(ROOT, name);
  const manifest = JSON.stringify({scenario: name, chunks: wire.map((_, index) => file(index)), undelivered: wire.flatMap((_, index) => (delivered[index] ? [] : [file(index)]))}, null, 1) + "\n";
  if (UPDATE) {
   rmSync(dir, {recursive: true, force: true});
   mkdirSync(dir, {recursive: true});
   wire.forEach((line, index) => writeFileSync(join(dir, file(index)), line + "\n"));
   writeFileSync(join(dir, "manifest.json"), manifest);
  }
  expect(existsSync(dir)).toBe(true);
  expect(readdirSync(dir).sort()).toEqual([...wire.map((_, index) => file(index)), "manifest.json"].sort());
  wire.forEach((line, index) => expect(readFileSync(join(dir, file(index)), "utf8")).toBe(line + "\n"));
  expect(readFileSync(join(dir, "manifest.json"), "utf8")).toBe(manifest);
 });
}

test("every fixture scenario directory is generated here (no stale scenario)", () => {
 const names: readonly SessionName[] = SESSION_NAMES;
 expect(readdirSync(ROOT).filter(entry => !entry.includes(".")).sort()).toEqual([...names].sort());
});

test("createRecorder refuses identifiers and revisions the server would refuse", async () => {
 const {scriptedPage} = await import("./recorded-session.ts");
 const {createRecorder} = await import("../src/replay/recorder.ts");
 const base = scriptedPage().config;
 const make = (over: Record<string, unknown>) => createRecorder({...base, ...over, projectPolicy: true, deploymentOptIn: true}, () => "accepted");
 expect(() => make({})).not.toThrow();
 expect(() => make({replayId: "0".repeat(32)})).toThrow();
 expect(() => make({sessionId: "ABCDEF".repeat(5) + "AB"})).toThrow();
 expect(() => make({domain: {host: "host0001", boot: "d".repeat(32), runtime: "e".repeat(32)}})).toThrow();
 expect(() => make({capturePolicyRevision: "0"})).toThrow();
 expect(() => make({capturePolicyRevision: "01"})).toThrow();
});
