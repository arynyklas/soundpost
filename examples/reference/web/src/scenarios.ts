// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Diagnostic scenarios driven by drive.mjs. Each one uses its OWN client, so nothing here can change what the order
// page's client has queued or acknowledged. No page content, note text or chunk content is returned.
import {init, ReplayStream} from "@soundpost/browser";
import type {ReplayChunk} from "@soundpost/browser";
import {sdkConfig} from "./config.ts";
import type {PublicConfig} from "./config.ts";

export interface ProfileOutcome {
  readonly status: string;
  readonly reason: string;
  readonly sampleCount: number;
  readonly stoppedBy: string;
  readonly profilesPolicyAllowed: boolean;
  readonly flush: {readonly pending: number; readonly lost: number; readonly receipts: number};
  readonly bufferedRecords: number;
  readonly diagnostics: Readonly<Record<string, number>>;
}

// The profile is delivered by the SDK itself: client.startProfile hands the finished report (a refusal included) to this client's queue.
export async function profileFor(raw: PublicConfig, durationMs: number): Promise<ProfileOutcome> {
  const client = init(sdkConfig(raw, {deploymentProfiles: true}));
  try {
    const handle = await client.startProfile({durationMs: 5000, intervalUs: 10_000, scope: "main"});
    const end = performance.now() + durationMs;
    let spin = 0;
    while (performance.now() < end) spin = (spin + Math.sqrt(spin + 1)) % 1000003;
    const report = await handle.stop();
    const flush = await client.flush(10000);
    return {
      status: report.capability.status, reason: report.capability.reason, sampleCount: report.sample_count, stoppedBy: report.stopped_by,
      profilesPolicyAllowed: client.policyDecision.profiles,
      flush: {pending: flush.pending, lost: flush.lost, receipts: flush.receipts.length},
      bufferedRecords: client.bufferedRecords().length, diagnostics: client.diagnostics(),
    };
  } finally {
    await client.close();
  }
}

export interface ReplayOutcome {
  readonly replayPolicyAllowed: boolean;
  readonly chunksEmitted: number;
  readonly chunksRejectedByStream: number;
  readonly flush: {readonly pending: number; readonly lost: number; readonly receipts: number};
  readonly bufferedRecords: number;
  readonly diagnostics: Readonly<Record<string, number>>;
}

function randomId(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), value => value.toString(16).padStart(2, "0")).join("");
}

function policyRevision(raw: PublicConfig): string {
  const payload: unknown = JSON.parse(atob(raw.policy.payload.replace(/-/g, "+").replace(/_/g, "/")));
  if (payload && typeof payload === "object" && "revision" in payload && typeof payload.revision === "string") return payload.revision;
  throw Error("policy_revision_missing");
}

export async function replayFor(raw: PublicConfig): Promise<ReplayOutcome> {
  const client = init(sdkConfig(raw, {deploymentReplay: true}));
  const stream = new ReplayStream(256);
  let emitted = 0, rejected = 0;
  try {
    const recorder = client.startReplay({
      root: document.documentElement,
      replayId: randomId(), sessionId: randomId(), capturePolicyRevision: policyRevision(raw),
      domain: {host: randomId().slice(0, 8), boot: randomId().slice(0, 8), runtime: randomId().slice(0, 8)},
      clock: () => ({wall_ns: String(BigInt(Date.now()) * 1000000n), mono_ns: String(BigInt(Math.round(performance.now() * 1e6))), uncertainty_ns: "1000000"}),
      viewport: () => ({w: innerWidth, h: innerHeight, x: scrollX, y: scrollY}),
    }, (chunk: ReplayChunk) => {
      emitted++;
      const outcome = stream.push(chunk);
      if (outcome === "rejected") rejected++;
      return outcome;
    });
    client.setReplayConsent(true);
    // A real interaction after consent: the recorder sees structure only.
    document.getElementById("note")?.dispatchEvent(new MouseEvent("click", {bubbles: true, clientX: 40, clientY: 40}));
    const settled = Promise.withResolvers<void>();
    setTimeout(settled.resolve, 400);
    await settled.promise;
    recorder.setConsent(false);
    const report = await client.flush(10000);
    return {
      replayPolicyAllowed: client.policyDecision.replay,
      chunksEmitted: emitted, chunksRejectedByStream: rejected,
      flush: {pending: report.pending, lost: report.lost, receipts: report.receipts.length},
      bufferedRecords: client.bufferedRecords().length, diagnostics: client.diagnostics(),
    };
  } finally {
    stream.close();
    await client.close();
  }
}
