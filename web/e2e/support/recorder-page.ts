// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// The page side of the real-recorder e2e: the REAL browser SDK (packages/browser) with its REAL replay recorder over this page's own DOM.
// Bundled by support/recorder.ts (bun build) and served next to a page of canary text; the SDK delivers every chunk itself, over its own
// HTTPS transport, to the ingest route of the real server. Nothing here converts, filters or builds a chunk.
import {init} from "../../../packages/browser/src/index.ts";
import type {Client, Config} from "../../../packages/browser/src/index.ts";
import {setReplayConsent, startReplay} from "../../../packages/browser/src/replay.ts";
import type {ReplayRecorder} from "../../../packages/browser/src/replay.ts";

interface PublicConfig {
  readonly org: string; readonly project: string; readonly source: string; readonly credential: string; readonly build: string; readonly endpoint: string;
  readonly policy: Config["policy"]; readonly trusted_keys: Readonly<Record<string, string>>; readonly resource: Config["resource"]; readonly descriptor: NonNullable<Config["descriptor"]>;
}
interface Outcome {
  readonly replayPolicyAllowed: boolean; readonly chunksEmitted: number; readonly queuedBeforeFlush: number;
  readonly flush: {readonly pending: number; readonly lost: number; readonly receipts: number}; readonly diagnostics: Readonly<Record<string, number>>;
}

function base64url(value: string): Uint8Array {
  return Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), character => character.charCodeAt(0));
}
function randomId(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), value => value.toString(16).padStart(2, "0")).join("");
}
function policyRevision(raw: PublicConfig): string {
  const payload: unknown = JSON.parse(atob(raw.policy.payload.replace(/-/g, "+").replace(/_/g, "/")));
  if (payload && typeof payload === "object" && "revision" in payload && typeof payload.revision === "string") return payload.revision;
  throw Error("policy_revision_missing");
}

let client: Client | undefined;
let recorder: ReplayRecorder | undefined;
let emitted = 0;
const api = {
  /** Starts recording this page in a fresh client and returns the replay's IDs. */
  start(raw: PublicConfig): {replay: string; session: string} {
    if (client) throw Error("already_started");
    const trustedKeys = Object.fromEntries(Object.entries(raw.trusted_keys).map(([id, value]) => [id, base64url(value)]));
    client = init({org: raw.org, project: raw.project, source: raw.source, credential: raw.credential, build: raw.build, endpoint: raw.endpoint, policy: raw.policy, trustedKeys, resource: raw.resource, descriptor: raw.descriptor, deploymentReplay: true});
    const ids = {replay: randomId(), session: randomId()};
    recorder = startReplay(client, {
      root: document.documentElement, replayId: ids.replay, sessionId: ids.session, capturePolicyRevision: policyRevision(raw),
      domain: {host: randomId(), boot: randomId(), runtime: randomId()},
      clock: () => ({wall_ns: String(BigInt(Date.now()) * 1000000n), mono_ns: String(BigInt(Math.round(performance.now() * 1e6))), uncertainty_ns: "1000000"}),
      viewport: () => ({w: innerWidth, h: innerHeight, x: scrollX, y: scrollY}),
    }, () => { emitted++; });
    setReplayConsent(client, true);
    return ids;
  },
  /** Flushes the queue through the SDK's own delivery, revokes consent and closes the client. */
  async finish(): Promise<Outcome> {
    if (!client || !recorder) throw Error("not_started");
    try {
      const queuedBeforeFlush = client.bufferedRecords().length;
      const report = await client.flush(15000);
      recorder.setConsent(false);
      return {replayPolicyAllowed: client.policyDecision.replay, chunksEmitted: emitted, queuedBeforeFlush, flush: {pending: report.pending, lost: report.lost, receipts: report.receipts.length}, diagnostics: client.diagnostics()};
    } finally {
      await client.close();
    }
  },
};
Reflect.set(window, "__soundpost", api);
Reflect.set(window, "__ready", true);
