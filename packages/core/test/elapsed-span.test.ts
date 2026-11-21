// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// 10.17#13: an interval that already happened (a browser Long Task) is delivered as an ordinary root span of an allowlisted operation:
// the same queue, policy switch, sampling and loss counters as every span, no new record kind and nothing else on the wire.
import {test, expect} from "bun:test";
import {Client} from "../src/client.ts";
import {captureElapsedSpan, spanRefusal} from "../src/elapsed_span.ts";
import {config, signed} from "./fixture.ts";
import {canonical} from "../src/policy.ts";
import {createTraceClock} from "../src/tracing.ts";
import type {MetadataContext} from "../src/types.ts";

const mono = 5_000_000_000n, wall = "1700000000000000000";
function context(): MetadataContext {
 const clock = createTraceClock(() => mono, () => wall);
 return {clockDomain: clock.domain, current: () => undefined, run: (_context, callback) => callback(), jobCurrent: () => undefined, runJob: (_context, callback) => callback(), clock, close() {}};
}
function settings(traces = true, operations = ["long_task", "other"]) {
 const base = config();
 return {...base, operations, policy: signed(canonical({version: 1, org: base.org, project: base.project, source: base.source, revision: "1", expires_ns: "9223372036854775807", errors: true, logs: false, replay: false, bodies: false, traces, jobs: false})), deploymentTraces: true, clockNs: () => wall};
}
const spans = (client: Client) => client.bufferedRecords().map(line => JSON.parse(line) as {kind: string; observed_at_ns: string; payload: Record<string, unknown>}).filter(row => row.kind === "span");

test("an elapsed interval is one root span: exact monotonic start and end, wall time aligned to the same clock, status ok, no parent, no dependency", () => {
 const client = new Client(settings(), undefined, undefined, context());
 expect(captureElapsedSpan(client, "long_task", 4_800_000_000n, 4_850_000_000n)).toBe(true);
 const [row] = spans(client);
 expect(spans(client)).toHaveLength(1);
 const span = row!.payload as {operation: string; span_kind: string; status: string; parent_id: string | null; dependency_alias: string; start: {mono_ns: string; wall_ns: string}; end: {mono_ns: string; wall_ns: string}; trace_id: string; span_id: string; links: unknown[]};
 expect(span).toMatchObject({operation: "long_task", span_kind: "internal", status: "ok", parent_id: null, dependency_alias: "", links: []});
 expect(span.start.mono_ns).toBe("4800000000"); expect(span.end.mono_ns).toBe("4850000000");
 // now is mono 5.0 s = wall 1.7e18; 200 ms earlier is 200 ms earlier on the wall clock too.
 expect(span.start.wall_ns).toBe("1699999999800000000"); expect(span.end.wall_ns).toBe("1699999999850000000");
 expect(span.trace_id).toMatch(/^[0-9a-f]{32}$/); expect(span.span_id).toMatch(/^[0-9a-f]{16}$/);
 expect(row!.observed_at_ns).toBe(span.start.wall_ns);
});

test("every interval is its own root trace (a Long Task has no request to hang under)", () => {
 const client = new Client(settings(), undefined, undefined, context());
 for (let i = 0n; i < 3n; i++) expect(captureElapsedSpan(client, "long_task", 4_000_000_000n + i * 100_000_000n, 4_060_000_000n + i * 100_000_000n)).toBe(true);
 expect(new Set(spans(client).map(row => row.payload.trace_id)).size).toBe(3);
});

test("an operation outside the allowlist is refused (and the client can say so beforehand), never queued", () => {
 const client = new Client(settings(true, ["other"]), undefined, undefined, context());
 expect(spanRefusal(client, "long_task")).toBe("unregistered_operation");
 expect(captureElapsedSpan(client, "long_task", 4_800_000_000n, 4_850_000_000n)).toBe(false);
 expect(spans(client)).toHaveLength(0);
});

test("the signed policy's trace switch decides: off means nothing is queued, and the client says why beforehand", () => {
 const off = new Client(settings(false), undefined, undefined, context()), on = new Client(settings(), undefined, undefined, context());
 expect(spanRefusal(off, "long_task")).toBe("policy"); expect(spanRefusal(on, "long_task")).toBeUndefined();
 expect(captureElapsedSpan(off, "long_task", 4_800_000_000n, 4_850_000_000n)).toBe(false);
 expect(spans(off)).toHaveLength(0);
});

test("a reversed interval is refused, counted as invalid_clock and never queued", () => {
 const client = new Client(settings(), undefined, undefined, context());
 expect(captureElapsedSpan(client, "long_task", 4_850_000_000n, 4_800_000_000n)).toBe(false);
 expect(spans(client)).toHaveLength(0);
 expect(client.diagnostics().invalid_clock).toBe(1);
});

test("an interval that cannot have happened is refused and counted, never queued: ending in the future, starting before the clock's epoch, not a bigint", () => {
 const client = new Client(settings(), undefined, undefined, context());
 const impossible: [unknown, unknown][] = [
  [4_900_000_000n, mono + 1n], // ends after now
  [mono + 1n, mono + 2n], // wholly in the future
  [-1n, 1_000n], // starts before the monotonic epoch
  ["4800000000", "4850000000"], // decimal text is not an interval (the API takes bigint)
  [4_800_000_000, 4_850_000_000], // a number is not either
  [undefined, undefined],
 ];
 for (const [start, end] of impossible) expect(captureElapsedSpan(client, "long_task", start as bigint, end as bigint)).toBe(false);
 expect(spans(client)).toHaveLength(0);
 expect(client.diagnostics().invalid_clock).toBe(impossible.length);
});

test("the edges of a possible interval are admitted: it may start at the epoch, have zero length and end exactly now", () => {
 const client = new Client(settings(), undefined, undefined, context());
 expect(captureElapsedSpan(client, "long_task", 0n, 1_000n)).toBe(true);
 expect(captureElapsedSpan(client, "long_task", 4_000_000_000n, 4_000_000_000n)).toBe(true);
 expect(captureElapsedSpan(client, "long_task", 4_999_000_000n, mono)).toBe(true);
 expect(spans(client)).toHaveLength(3);
 expect(client.diagnostics().invalid_clock).toBeUndefined();
});

test("refusals that are not about the interval (allowlist, policy switch, closed client) are not counted as a bad clock", async () => {
 const unregistered = new Client(settings(true, ["other"]), undefined, undefined, context()), off = new Client(settings(false), undefined, undefined, context());
 expect(captureElapsedSpan(unregistered, "long_task", 4_850_000_000n, 4_800_000_000n)).toBe(false);
 expect(captureElapsedSpan(off, "long_task", 4_850_000_000n, 4_800_000_000n)).toBe(false);
 expect(unregistered.diagnostics().invalid_clock).toBeUndefined(); expect(off.diagnostics().invalid_clock).toBeUndefined();
});

test("the trace sampling budget applies: probability zero queues nothing and counts the drop", () => {
 const client = new Client({...settings(), traceSampleProbability: "0000000000000000"}, undefined, undefined, context());
 expect(captureElapsedSpan(client, "long_task", 4_800_000_000n, 4_850_000_000n)).toBe(false);
 expect(spans(client)).toHaveLength(0);
 expect(client.diagnostics().trace_sampled_out).toBe(1);
});

test("a closed client takes nothing and never throws", async () => {
 const client = new Client(settings(), undefined, undefined, context());
 await client.close();
 expect(captureElapsedSpan(client, "long_task", 4_800_000_000n, 4_850_000_000n)).toBe(false);
 expect(captureElapsedSpan(client, undefined as unknown as string, 1n, 2n)).toBe(false);
});
