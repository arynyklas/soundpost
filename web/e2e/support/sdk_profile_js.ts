// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Drives the real Node or Bun SDK's profile supplement against the live product: one bounded runtime_engine_samples profile of a named hot loop,
// stopped, handed to the client's own delivery and flushed over its own HTTPS transport (durable receipts required).
//   node --experimental-transform-types sdk_profile_js.ts node      |      bun sdk_profile_js.ts bun
// Configuration: SOUNDPOST_SDK_CONFIG (the file web/e2e/support/real.ts sdkConfig writes). Prints one JSON line.
import {readFileSync} from 'node:fs';
import {dirname, resolve} from 'node:path';
import {setTimeout as sleep} from 'node:timers/promises';
import {fileURLToPath, pathToFileURL} from 'node:url';

interface Chunk {readonly payload?: {readonly profile_id?: string; readonly units?: string}}
interface Client {captureProfile(capability: unknown, chunks: readonly Chunk[]): unknown; flush(timeoutMs: number): Promise<{readonly pending: number; readonly lost: number}>; close(): Promise<void>}
interface Report {readonly sample_count: number; readonly method: string; readonly units: string; readonly ack: {readonly status: string; readonly reason?: string}; readonly scope: {readonly runtime: {readonly name: string}}}
interface Handle {readonly active: boolean; readonly capability: {readonly status: string; readonly reason: string}; stop(): Promise<Report>}
interface Sdk {init(config: unknown): Client; startProfile(options: unknown): Promise<Handle>}

const root = dirname(fileURLToPath(import.meta.url));
const runtime = process.argv[2];
if (runtime !== 'node' && runtime !== 'bun') throw new Error(`sdk_profile_js: runtime must be node or bun, got ${String(runtime)}`);
// A dynamic import on purpose: the module is the Node SDK or the Bun SDK, chosen by argv, and only one of them can run in a given runtime.
const sdk = await import(pathToFileURL(resolve(root, `../../../packages/${runtime}/src/index.ts`)).href) as Sdk;

function base64url(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
}
function e2e_hot_loop_js(milliseconds: number): number {
  const end = performance.now() + milliseconds;
  let total = 0;
  while (performance.now() < end) {
    for (let i = 0; i < 2000; i++) total += i * i;
  }
  return total;
}

async function main(): Promise<void> {
  const raw = JSON.parse(readFileSync(process.env.SOUNDPOST_SDK_CONFIG ?? '', 'utf8')) as Record<string, unknown> & {trusted_keys: Record<string, string>};
  const client = sdk.init({
    org: raw.org, project: raw.project, source: raw.source, credential: raw.credential, build: raw.build, endpoint: raw.endpoint,
    policy: raw.policy, trustedKeys: Object.fromEntries(Object.entries(raw.trusted_keys).map(([id, key]) => [id, base64url(key)])),
    resource: raw.resource, descriptor: raw.descriptor, deploymentProfiles: true,
  });
  try {
    // The lease hands its wire records to the client's own capture path and flushes them itself when it stops; the spy only observes what it hands over.
    const handed: {capability: unknown; chunks: readonly Chunk[]}[] = [];
    const capture = client.captureProfile.bind(client);
    client.captureProfile = (capability, chunks) => { handed.push({capability, chunks}); return capture(capability, chunks); };
    const handle = await sdk.startProfile({durationMs: 30_000, intervalUs: 1000, projectRoot: root, client});
    if (!handle.active || handle.capability.status !== 'supported') throw new Error(`profile_did_not_start: ${handle.capability.status}/${handle.capability.reason}`);
    e2e_hot_loop_js(600);
    await sleep(200);
    const report = await handle.stop();
    if (report.sample_count < 20) throw new Error(`too_few_samples: ${report.sample_count}`);
    if (report.ack.status !== 'obtained' || handed.length !== 1 || handed[0]?.chunks.length === 0) throw new Error(`sdk_did_not_deliver_profile: ${JSON.stringify(report.ack)}`);
    const flushed = await client.flush(30_000);
    if (flushed.pending !== 0 || flushed.lost !== 0) throw new Error('durable_delivery_incomplete');
    const first = handed[0]?.chunks[0]?.payload;
    console.log(JSON.stringify({profile: first?.profile_id, samples: report.sample_count, chunks: handed[0]?.chunks.length, method: report.method, units: first?.units ?? report.units, runtime: report.scope.runtime.name}));
  } finally {
    await client.close();
  }
}

try {
  await main();
} catch (e) {
  console.error(`sdk_profile_js_failed: ${e instanceof Error ? e.message : String(e)}`.slice(0, 400));
  process.exit(1);
}
