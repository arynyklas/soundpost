// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Merge of qualification runs into fixtures/sdk/qualification.json (used by fixtures/sdk/qualify.mjs; pure, no I/O).
//
// One run of qualify.mjs observes one Node (the one it runs under), one Bun, one Python and one Chrome on one host. The manifest needs
// several runs (Node 22.21.1, Node 24.11.0, ...), so a run is a sealed record of its own and the manifest is built by merging them:
//   - a run carries its source stamp (go run ./build source-digest of the tree it ran against), its host and a digest over all of it;
//   - every merged row is bound to {run digest, runtime, host id, source stamp};
//   - a run whose source stamp is not the one the manifest is built for is refused, and so is the whole batch (nothing half merged);
//   - rows are keyed by id, so a rerun replaces exactly the rows it produced (newest recorded_at wins, never the order of the arguments);
//   - rows recorded before binding existed, or against an older source, are kept apart in `retired_evidence`, never claimed.
import {createHash} from "node:crypto";

export const RUN_SCHEMA="soundpost-qualify-run/1";
export const EVIDENCE_SCHEMA=2;
const HEX64=/^[0-9a-f]{64}$/;
const FROZEN={Node:{runtime:"node",method:"runtime_engine_samples"},Bun:{runtime:"bun",method:"runtime_engine_samples"},CPython:{runtime:"cpython",method:"python_monitoring+python_wall_samples"}};
const PLATFORMS=["linux","darwin","win32"];

export const MEANING="Rows record what the real runtime fixtures OBSERVED (exit code 0 plus their own assertions), not a release qualification. Each row is bound to the run that produced it (`run`: run digest, runtime, host id, source stamp); `observed` is valid only for the exact runtime version/platform in the row and for the source stamp of this manifest. Frozen dependency/runtime/browser targets elsewhere in this manifest keep their own status (not_run unless stated); `target_coverage` says which frozen target has an observed row. Rows recorded without a run binding or against another source are in `retired_evidence`, never claimed. Nothing here is a `passed` row for an unlisted combination.";

export class MergeError extends Error{constructor(message){super(message);this.name="MergeError";}}
const refuse=message=>{throw new MergeError(message);};
const sha256=text=>createHash("sha256").update(text).digest("hex");

/** JSON with sorted keys: the same value always has the same text, whatever the producer's key order. */
export function canonical(value){
 if(Array.isArray(value))return "["+value.map(item=>canonical(item)).join(",")+"]";
 if(value&&typeof value==="object")return "{"+Object.keys(value).filter(key=>value[key]!==undefined).sort().map(key=>JSON.stringify(key)+":"+canonical(value[key])).join(",")+"}";
 return JSON.stringify(value)??"null";
}

const HOST_FIELDS=["hostname","platform","release","arch","cpu_model","logical_cpus","total_memory_mib"];
const hostId=host=>sha256(canonical(Object.fromEntries(HOST_FIELDS.map(key=>[key,host[key]])))).slice(0,16);

/** The host a run was observed on: its identifying facts and an id derived from them. */
export function makeHost(machine){
 const host=Object.fromEntries(HOST_FIELDS.map(key=>[key,machine[key]??null]));
 return {id:hostId(host),...host};
}

/** Seals a run body: the digest covers every other field, so a stamp, a host or a row cannot be edited afterwards. */
export function sealRun(body){
 const {run_digest:_,...rest}=body;
 return {...rest,run_digest:sha256(canonical(rest))};
}

const runtimeKey=row=>row.version?`${row.runtime}-${row.version}`:row.runtime;
const short=run=>String(run.run_digest).slice(0,12);

/** Checks one run record on its own: schema, digest, host id and the Node version its node rows claim. */
export function verifyRun(run){
 if(!run||typeof run!=="object"||run.schema!==RUN_SCHEMA)refuse(`not a ${RUN_SCHEMA} run record`);
 if(!HEX64.test(run.run_digest??""))refuse("run record has no run_digest");
 const {run_digest,...rest}=run;
 if(sha256(canonical(rest))!==run_digest)refuse(`run ${short(run)}: its digest does not match its content (the run was edited after it was sealed)`);
 if(!HEX64.test(run.source_sha256??""))refuse(`run ${short(run)}: no 64-hex source stamp`);
 if(!run.host||run.host.id!==hostId(run.host))refuse(`run ${short(run)}: host id does not match the host it describes`);
 if(!Array.isArray(run.rows)||!Array.isArray(run.unqualified))refuse(`run ${short(run)}: rows and unqualified must be arrays`);
 const seen=new Set();
 for(const row of run.rows){
  if(!row||typeof row.id!=="string"||typeof row.runtime!=="string"||typeof row.status!=="string")refuse(`run ${short(run)}: a row without id, runtime and status`);
  if(seen.has(row.id))refuse(`run ${short(run)}: row ${row.id} twice`);
  seen.add(row.id);
  if(row.runtime==="node"&&row.version!==run.runtimes?.node)refuse(`run ${short(run)}: node row ${row.id} is ${row.version}, the run's Node is ${run.runtimes?.node}`);
 }
}

const bind=(row,run)=>({...row,run:{digest:run.run_digest,runtime:runtimeKey(row),host_id:run.host.id,source_sha256:run.source_sha256}});
const stripV=version=>String(version??"").replace(/^v/,"");

/** Notes that follow from the merged rows alone: which frozen targets and platforms have no observed row. */
function derivedNotes(manifest,rows){
 const observed=rows.filter(row=>row.status==="observed"),notes=[],coverage=[];
 for(const target of manifest.runtime_targets??[]){
  const frozen=FROZEN[target.name];
  if(!frozen)continue;
  const hit=observed.find(row=>row.runtime===frozen.runtime&&stripV(row.version)===target.version);
  coverage.push({target:`${target.name} ${target.version}`,observed_row:hit?.id??null});
  if(!hit)notes.push({row:`${frozen.runtime}-${target.version}-${frozen.method}`,reason:`no observed ${target.name} ${target.version} row is merged into this manifest: the frozen target keeps its status; only an observed row of exactly this version counts, a different patch level does not.`});
 }
 for(const [name,frozen] of Object.entries(FROZEN))for(const platform of PLATFORMS){
  if(!observed.some(row=>row.runtime===frozen.runtime&&row.platform===platform))notes.push({row:`${frozen.runtime}-${platform}-${frozen.method}`,reason:`no observed ${name} row on ${platform} is merged into this manifest.`});
 }
 return {notes,coverage};
}

/**
 * Merges sealed runs into a manifest and returns the new manifest (the input is not modified).
 * sourceStamp is the stamp of the tree the manifest is built for. Any run with another stamp refuses the whole merge.
 */
export function mergeRuns(manifest,runs,{sourceSha256,now=new Date().toISOString()}){
 if(!HEX64.test(sourceSha256??""))refuse("the manifest's source stamp must be a 64-hex source digest");
 const byDigest=new Map();
 runs.forEach((run,index)=>{
  verifyRun(run);
  if(run.source_sha256!==sourceSha256)refuse(`run ${short(run)} (${run.host.hostname}, recorded ${run.recorded_at}) carries source stamp ${run.source_sha256}, the manifest is built for ${sourceSha256}: refused, nothing was merged`);
  if(!byDigest.has(run.run_digest))byDigest.set(run.run_digest,{run,index});
 });
 // Newest observation last; the position on the command line only breaks a tie.
 const incoming=[...byDigest.values()].sort((a,b)=>String(a.run.recorded_at).localeCompare(String(b.run.recorded_at))||a.index-b.index).map(entry=>entry.run);

 const out=structuredClone(manifest),prev=out.measured_evidence;
 const retired=[...(prev?.retired_evidence??[])];
 let rows=[],keptRuns=[],overhead;
 if(prev?.schema===EVIDENCE_SCHEMA&&prev.source_sha256===sourceSha256){
  rows=prev.runtime_supplement_rows??[];keptRuns=prev.runs??[];overhead=prev.overhead;
 }else if(prev){
  const reason=prev.schema===EVIDENCE_SCHEMA?"source_stamp_changed":"no_run_binding";
  const from=prev.schema===EVIDENCE_SCHEMA?{source_sha256:prev.source_sha256}:{};
  for(const row of prev.runtime_supplement_rows??[])retired.push({reason,...from,row});
  if(prev.overhead?.source)retired.push({reason,...from,overhead:prev.overhead});
 }
 const known=new Set();
 const retiredUnique=retired.filter(entry=>{const key=canonical(entry);return known.has(key)?false:(known.add(key),true);});

 const byId=new Map(rows.map(row=>[row.id,row]));
 for(const run of incoming){
  for(const row of run.rows)byId.set(row.id,bind(row,run));
  keptRuns=keptRuns.filter(entry=>entry.run_digest!==run.run_digest);
  keptRuns.push({run_digest:run.run_digest,recorded_at:run.recorded_at,source_sha256:run.source_sha256,host:run.host,runtimes:run.runtimes,command:run.command,unqualified:run.unqualified});
  if(run.overhead?.source)overhead={...run.overhead,run:{digest:run.run_digest,host_id:run.host.id,source_sha256:run.source_sha256}};
 }
 const merged=[...byId.values()].sort((a,b)=>a.id.localeCompare(b.id));
 // A run that no row (and not the overhead) refers to any more has been replaced entirely.
 const referenced=new Set(merged.map(row=>row.run.digest));
 if(overhead?.run)referenced.add(overhead.run.digest);
 keptRuns=keptRuns.filter(entry=>referenced.has(entry.run_digest)).sort((a,b)=>String(a.recorded_at).localeCompare(String(b.recorded_at))||a.run_digest.localeCompare(b.run_digest));
 for(const entry of keptRuns)entry.row_ids=merged.filter(row=>row.run.digest===entry.run_digest).map(row=>row.id);

 // Notes: those the kept runs recorded (the newest run's wording wins), minus those an observed row of the same runtime answers,
 // plus those that follow from the merged rows.
 const notes=new Map();
 for(const entry of keptRuns)for(const note of entry.unqualified){
  if(note.kind?.startsWith("runtime:")&&merged.some(row=>row.status==="observed"&&row.runtime===note.kind.slice("runtime:".length)))continue;
  notes.set(note.row,note);
 }
 const {notes:derived,coverage}=derivedNotes(out,merged);
 for(const note of derived)notes.set(note.row,note);

 out.measured_evidence={
  schema:EVIDENCE_SCHEMA,
  source_sha256:sourceSha256,
  recorded_at:now,
  tool:"fixtures/sdk/qualify.mjs",
  meaning:MEANING,
  runs:keptRuns,
  runtime_supplement_rows:merged,
  overhead:overhead??{not_run:"pass --overhead <result.json> produced by `node fixtures/sdk/overhead.mjs --out result.json`"},
  target_coverage:coverage,
  unqualified_rows:[...notes.values()].map(({row,reason})=>({row,reason})),
  retired_evidence:retiredUnique,
 };
 return out;
}
