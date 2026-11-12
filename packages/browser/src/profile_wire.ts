// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Maps a finished ProfileReport onto the wire records the server's profile reader assembles (internal/profiles): one `capability` record,
// plus, only when the sampler genuinely ran (status "supported"), one or more `profile_chunk` records that name that capability by id and
// carry the same clock domain. A refused or failed run is the capability truth record alone: never a chunk, never samples.
//
// Everything on the wire already exists in the report (code identities: origin-relative script path, a conservative-regex function name or
// `external`; relative sample offsets; counts). Line and column are NOT sent (the closed server frame has no such field) and long-task
// entries are not sent (they are metrics, not profile samples). Nothing here reads a URL, an argument or a local.
import type {CapabilityInput, ProfileInput} from "@soundpost/core/types";
import type {ProfileReport} from "./profile.ts";

/** Payload budget per chunk. The queue refuses a record over 262,144 bytes (resource included) and a batch over 1 MiB, so a larger profile is split. */
const CHUNK_BYTES = 180_000;
const THREADS: Readonly<Record<string, string>> = {main: "1", worker: "2"};
const MAX_UINT64 = 18446744073709551615n;

export interface ProfileWire {readonly capability: CapabilityInput; readonly chunks: readonly ProfileInput[]}
export interface WireIds {readonly process: string; readonly id: () => string}
type Frame = {module_id: string; function: string; artifact_id: string; offset: "0"; reason: string};
type Stack = {frames: number[]};
type Sample = {at_ns: string; stack: number; count: "1"; thread: string};
interface Chunk {frames: Frame[]; stacks: Stack[]; samples: Sample[]; frameIndex: Map<number, number>; stackIndex: Map<number, number>; bytes: number}
const fresh = (): Chunk => ({frames: [], stacks: [], samples: [], frameIndex: new Map(), stackIndex: new Map(), bytes: 0});
const size = (value: unknown): number => JSON.stringify(value).length + 1; // all content is ASCII by the profiler's own regexes, so length is bytes

export function profileWire(report: ProfileReport, ids: WireIds): ProfileWire {
 const c = report.capability;
 const wallStart = report.clock.wall_start_ns;
 const wallEnd = BigInt(report.clock.wall_end_ns) >= BigInt(wallStart) ? report.clock.wall_end_ns : wallStart;
 const capability: CapabilityInput = {
  kind: "capability", id: c.id, observed_at_ns: wallEnd,
  payload: {
   runtime: c.runtime, version: c.version, build: c.build, os: c.os, arch: c.arch, signal: c.signal, method: c.method, status: c.status, reason: c.reason,
   coverage: {frames: c.coverage.frames, threads: c.coverage.threads, workers: c.coverage.workers, tasks: c.coverage.tasks},
   clock_domain: {host: c.clock_domain.host, boot: c.clock_domain.boot, runtime: c.clock_domain.runtime}, expires_ns: c.expires_ns,
  },
 };
 if (c.status !== "supported") return {capability, chunks: []};

 let lost = 0n;
 for (const loss of report.losses) lost += BigInt(loss.count);
 if (lost > MAX_UINT64) lost = MAX_UINT64;
 const profile = ids.id();
 const chunks: Chunk[] = [];
 let current = fresh();
 const add = (sample: ProfileReport["samples"][number]): void => {
  const stack = report.stacks[sample.stack]!;
  const newFrames = [...new Set(stack.frames)].filter(index => !current.frameIndex.has(index));
  const wireFrames: Frame[] = newFrames.map(index => {
   const f = report.frames[index]!;
   return {module_id: f.module_id, function: f.function, artifact_id: f.artifact_id, offset: f.offset, reason: f.reason};
  });
  const known = current.stackIndex.has(sample.stack);
  const wireSample = (local: number): Sample => ({at_ns: (BigInt(sample.at_us) * 1000n).toString(), stack: local, count: "1", thread: THREADS[sample.thread] ?? "0"});
  const cost = wireFrames.reduce((n, f) => n + size(f), 0) + (known ? 0 : size({frames: stack.frames}) + 8) + size(wireSample(0));
  if (current.samples.length > 0 && current.bytes + cost > CHUNK_BYTES) { chunks.push(current); current = fresh(); return add(sample); }
  const localFrames = (): void => { for (const [i, index] of newFrames.entries()) { current.frameIndex.set(index, current.frames.length); current.frames.push(wireFrames[i]!); } };
  let local = current.stackIndex.get(sample.stack);
  if (local === undefined) {
   localFrames();
   local = current.stacks.length;
   current.stacks.push({frames: stack.frames.map(index => current.frameIndex.get(index)!)});
   current.stackIndex.set(sample.stack, local);
  }
  current.samples.push(wireSample(local));
  current.bytes += cost;
 };
 for (const sample of report.samples) add(sample);
 chunks.push(current);

 const mono = "0"; // sample offsets are relative to the first sample; the unbounded uncertainty states that no wall alignment is claimed
 const out = chunks.map((chunk, position): ProfileInput => ({
  kind: "profile_chunk", id: ids.id(), observed_at_ns: wallEnd,
  payload: {
   profile_id: profile, process_id: ids.process, capability_id: c.id, method: "runtime_cpu", units: "samples", start_ns: wallStart, end_ns: wallEnd,
   clock: {wall_ns: wallStart, mono_ns: mono, domain: {host: report.clock.domain.host, boot: report.clock.domain.boot, runtime: report.clock.domain.runtime}, uncertainty_ns: report.clock.uncertainty_ns},
   frames: chunk.frames, stacks: chunk.stacks, samples: chunk.samples, intervals: [],
   loss: (position === 0 ? lost : 0n).toString(), truncated: position === 0 && report.truncated,
  },
 }));
 return {capability, chunks: out};
}
