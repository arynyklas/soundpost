// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Diagnostic scenarios driven by drive.mjs. Each one uses its OWN client, so nothing here can change what the order
// page's client has queued or acknowledged. No page content, note text or chunk content is returned.
import {init} from "@soundpost/browser";
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
  /** Replay chunks the client had queued (and not yet sent) when the scenario finished recording. */
  readonly queuedBeforeFlush: number;
  readonly flush: {readonly pending: number; readonly lost: number; readonly receipts: number};
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

/** One recording in its own client: started before the driver's real input, finished (flushed, then consent revoked) after it. */
export interface ReplaySession {
  finish(): Promise<ReplayOutcome>;
}

// The replay is delivered by the SDK itself: client.startReplay hands every chunk to this client's queue, and the closed
// masked schema is the server's own, so nothing here converts or filters. `emitted` counts the local tap only.
export function replayFor(raw: PublicConfig): ReplaySession {
  const client = init(sdkConfig(raw, {deploymentReplay: true}));
  let emitted = 0;
  const recorder = client.startReplay({
    root: document.documentElement,
    replayId: randomId(), sessionId: randomId(), capturePolicyRevision: policyRevision(raw),
    domain: {host: randomId(), boot: randomId(), runtime: randomId()},
    clock: () => ({wall_ns: String(BigInt(Date.now()) * 1000000n), mono_ns: String(BigInt(Math.round(performance.now() * 1e6))), uncertainty_ns: "1000000"}),
    viewport: () => ({w: innerWidth, h: innerHeight, x: scrollX, y: scrollY}),
  }, () => { emitted++; });
  client.setReplayConsent(true);
  return {
    async finish() {
      try {
        // Everything the recorder produced is queued by now; measure that before the flush drains the queue.
        const queued = client.bufferedRecords().length;
        const report = await client.flush(10000);
        recorder.setConsent(false);
        return {
          replayPolicyAllowed: client.policyDecision.replay,
          chunksEmitted: emitted, queuedBeforeFlush: queued,
          flush: {pending: report.pending, lost: report.lost, receipts: report.receipts.length},
          diagnostics: client.diagnostics(),
        };
      } finally {
        await client.close();
      }
    },
  };
}
