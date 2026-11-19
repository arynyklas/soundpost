// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// The page side of the browser profiler capability e2e: the REAL browser SDK (packages/browser) with its REAL JS Self-Profiling supplement
// (startClientProfile) on an ORDINARY page, in whatever engine loads it. Bundled by support/browser_profile.ts (bun build) and served next to a
// page that runs a named busy loop. The SDK probes its own engine (it constructs the W3C `Profiler`, never a version check), builds the capability
// record and any profile chunk, and delivers them itself over its own HTTPS transport to the ingest route of the real server. Nothing here
// builds, converts, filters or fakes a record or a capability answer; this file only reports what the SDK said, to the test.
import {init} from "../../../packages/browser/src/index.ts";
import type {Config} from "../../../packages/browser/src/index.ts";
import {startClientProfile} from "../../../packages/browser/src/profile.ts";

interface PublicConfig {
  readonly org: string; readonly project: string; readonly source: string; readonly credential: string; readonly build: string; readonly endpoint: string;
  readonly policy: Config["policy"]; readonly trusted_keys: Readonly<Record<string, string>>; readonly resource: Config["resource"]; readonly descriptor: NonNullable<Config["descriptor"]>;
}
export interface ProfileOutcome {
  /** `typeof window.Profiler` read in this engine, before the SDK ran: what the engine itself exposes. */
  readonly profilerGlobal: string;
  readonly userAgent: string;
  readonly status: string; readonly reason: string; readonly runtime: string; readonly version: string; readonly os: string; readonly arch: string;
  readonly coverage: Readonly<Record<string, string>>;
  readonly sampleCount: number; readonly stoppedBy: string; readonly intervalAchievedUs: number | null;
  readonly ack: {readonly status: string; readonly reason?: string; readonly cursors?: number};
  readonly frameFunctions: readonly string[];
  readonly workMs: number;
  readonly diagnostics: Readonly<Record<string, number>>;
}

function base64url(value: string): Uint8Array {
  return Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), character => character.charCodeAt(0));
}

/** Named first-party functions the busy loop runs through, so a supported engine's samples carry frames the profile page can show. */
function e2eInnerSpin(ms: number): number {
  const end = performance.now() + ms; let x = 0;
  while (performance.now() < end) x = (x + Math.sqrt(x + 1)) % 1000003;
  return x;
}
function e2eBrowserHotLoop(ms: number): number {
  const end = performance.now() + ms; let total = 0;
  while (performance.now() < end) total += e2eInnerSpin(5);
  return total;
}

let started = false;
const api = {
  /** One bounded profile run of this page's own busy loop through the SDK, delivered by the SDK, then its report summarized for the test. */
  async run(raw: PublicConfig, workMs: number): Promise<ProfileOutcome> {
    if (started) throw Error("already_started");
    started = true;
    const trustedKeys = Object.fromEntries(Object.entries(raw.trusted_keys).map(([id, value]) => [id, base64url(value)]));
    const client = init({org: raw.org, project: raw.project, source: raw.source, credential: raw.credential, build: raw.build, endpoint: raw.endpoint, policy: raw.policy, trustedKeys, resource: raw.resource, descriptor: raw.descriptor, deploymentProfiles: true});
    const profilerGlobal = typeof Reflect.get(window, "Profiler");
    try {
      const handle = await startClientProfile(client, {durationMs: 10_000, intervalUs: 1000, scope: "main"});
      e2eBrowserHotLoop(workMs);
      const report = await handle.stop();
      await client.flush(15_000);
      const functions = [...new Set(report.frames.map(frame => frame.function))].slice(0, 64);
      const ack = report.ack;
      return {
        profilerGlobal, userAgent: navigator.userAgent,
        status: report.capability.status, reason: report.capability.reason, runtime: report.capability.runtime, version: report.capability.version, os: report.capability.os, arch: report.capability.arch,
        coverage: {...report.capability.coverage}, sampleCount: report.sample_count, stoppedBy: report.stopped_by, intervalAchievedUs: report.interval.achieved_us,
        ack: ack.status === "obtained" ? {status: ack.status, cursors: ack.cursors.length} : ack.status === "failed" ? {status: ack.status, reason: ack.reason} : {status: ack.status, ...(ack.reason === undefined ? {} : {reason: ack.reason})},
        frameFunctions: functions, workMs, diagnostics: client.diagnostics(),
      };
    } finally {
      await client.close();
    }
  },
};
Reflect.set(window, "__soundpostProfile", api);
Reflect.set(window, "__ready", true);
