// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Drives the real Node or Bun SDK's job API (packages/core/src/jobs.ts through client.withJobAttempt) against the live product: one run whose first attempt
// throws (a failed attempt with the captured error as its cause) and whose retry succeeds. Everything is delivered by the SDK's own HTTPS transport and
// verified by durable receipts. The TypeScript twin of sdk_job_retry.py.
//   node --experimental-transform-types sdk_job_js.ts node      |      bun sdk_job_js.ts bun
// Configuration: SOUNDPOST_SDK_CONFIG (the file web/e2e/support/real.ts sdkConfig writes), SOUNDPOST_SDK_JOB (the job ID). Prints one JSON line.
import {randomBytes} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {dirname, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';

interface Record_ {readonly kind: string; readonly id: string; readonly payload: Record<string, unknown>}
interface FlushReport {readonly pending: number; readonly lost: number; readonly receipts: readonly unknown[]}
interface Client {
  readonly policyDecision: {readonly jobs: boolean; readonly errors: boolean};
  withJobAttempt<T>(job: string, runId: string, ordinal: number, callback: () => Promise<T>): Promise<T>;
  bufferedRecords(): readonly string[];
  flush(timeoutMs: number): Promise<FlushReport>;
  close(): Promise<void>;
}
interface Sdk {init(config: unknown): Client}

const root = dirname(fileURLToPath(import.meta.url));
const runtime = process.argv[2];
if (runtime !== 'node' && runtime !== 'bun') throw new Error(`sdk_job_js: runtime must be node or bun, got ${String(runtime)}`);
// A dynamic import on purpose: the module is the Node SDK or the Bun SDK, chosen by argv, and only one of them can run in a given runtime.
const sdk = await import(pathToFileURL(resolve(root, `../../../packages/${runtime}/src/index.ts`)).href) as Sdk;

function base64url(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
}

async function main(): Promise<void> {
  const raw = JSON.parse(readFileSync(process.env.SOUNDPOST_SDK_CONFIG ?? '', 'utf8')) as Record<string, unknown> & {trusted_keys: Record<string, string>};
  const job = process.env.SOUNDPOST_SDK_JOB ?? '';
  const client = sdk.init({
    org: raw.org, project: raw.project, source: raw.source, credential: raw.credential, build: raw.build, endpoint: raw.endpoint,
    policy: raw.policy, trustedKeys: Object.fromEntries(Object.entries(raw.trusted_keys).map(([id, key]) => [id, base64url(key)])),
    resource: raw.resource, descriptor: raw.descriptor, jobRegistry: {'e2e.task': job},
  });
  try {
    if (!(client.policyDecision.jobs && client.policyDecision.errors)) throw new Error('signed_job_and_error_permissions_required');
    const run = randomBytes(16).toString('hex');
    try {
      await client.withJobAttempt('e2e.task', run, 1, async () => { throw new Error('e2e task failed'); });
    } catch (e) {
      if (!(e instanceof Error) || e.message !== 'e2e task failed') throw e;
    }
    await client.withJobAttempt('e2e.task', run, 2, async () => undefined);
    const records = client.bufferedRecords().map((value) => JSON.parse(value) as Record_);
    const events = records.filter((r) => r.kind === 'job_attempt').map((r) => r.payload);
    const errors = records.filter((r) => r.kind === 'error');
    if (events.map((e) => e.state).join(',') !== 'started,failed,started,succeeded' || errors.length !== 1 || events[1]?.cause_error !== errors[0]?.id) throw new Error('sdk_attempt_history_changed');
    const report = await client.flush(20_000);
    if (report.pending !== 0 || report.lost !== 0 || report.receipts.length === 0) throw new Error('durable_delivery_incomplete');
    console.log(JSON.stringify({run, failed_attempt: events[0]?.attempt_id, retry_attempt: events[2]?.attempt_id, error: errors[0]?.id, events: events.length}));
  } finally {
    await client.close();
  }
}

try {
  await main();
} catch (e) {
  console.error(`sdk_job_js_failed: ${e instanceof Error ? e.message : String(e)}`.slice(0, 1600));
  process.exit(1);
}
