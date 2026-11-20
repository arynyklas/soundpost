// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// 10.17#13: an interval that already happened (a browser Long Task) delivered as one root span of an allowlisted operation on the client's ordinary span
// path. This is its own entry (`@soundpost/core/elapsed`) and nothing in the core entry imports it: the browser core bundle sits on its 40 KiB gzip
// budget, and only the profile entry (which delivers Long Tasks) pays for these bytes. It reads the span recorder's public fields; it adds no record kind.
import type {Client} from "./client.ts";
import {randomHex, sampleTraceDecision, type TraceClock} from "./tracing.ts";

const MAX_U64 = 18446744073709551615n;

/** Why captureElapsedSpan can queue nothing whatever the interval: the operation is not in the allowlist, or the signed policy / deployment does not allow traces ("policy"). Undefined when it can. */
export function spanRefusal(client: Client, operation: string): "unregistered_operation" | "policy" | undefined {
  return client.spans.operations.has(operation) ? client.policy.decision.traces ? undefined : "policy" : "unregistered_operation";
}

/**
 * Enqueues one finished interval as a root span of `operation`: explicit monotonic start and end on the client's clock, wall times derived from the same instant, kind
 * internal, status ok, no parent, no dependency. The allowlist, the signed-policy trace switch, the sampling budget, the queue bounds, the receipts and the loss counters are
 * those of a span begun and ended in place. An interval that cannot have happened (not bigints, reversed, ending in the future, starting before the clock's epoch, or whose wall
 * time would not be a valid timestamp) is counted as `invalid_clock` and refused, exactly like a span whose clock readings are impossible. Never throws; false when nothing was queued.
 */
export function captureElapsedSpan(client: Client, operation: string, startMono: bigint, endMono: bigint): boolean {
  const recorder = client.spans;
  try {
    if (!recorder.operations.has(operation) || !recorder.enabled()) return false;
    let clock: TraceClock, now: bigint, offset: bigint;
    try { clock = recorder.context.clock(); now = BigInt(clock.mono_ns); offset = BigInt(clock.wall_ns) - now; } catch { recorder.loss("invalid_clock"); return false; }
    if (typeof startMono !== "bigint" || typeof endMono !== "bigint" || startMono < 0n || endMono < startMono || endMono > now || startMono + offset < 0n || endMono + offset > MAX_U64) { recorder.loss("invalid_clock"); return false; }
    if (!sampleTraceDecision(recorder.probability)) { recorder.loss("trace_sampled_out"); return false; }
    const at = (mono: bigint): TraceClock => ({...clock, wall_ns: String(mono + offset), mono_ns: String(mono)});
    recorder.emit({trace_id: randomHex(16), span_id: randomHex(8), parent_id: null, span_kind: "internal", operation, start: at(startMono), end: at(endMono), status: "ok", dependency_alias: "", links: [], sample_probability: recorder.probability, sample_decision: "keep"});
    return true;
  } catch { return false; }
}
