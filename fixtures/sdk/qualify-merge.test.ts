// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// The qualification manifest is built from several runs (one Node per run). Each row is bound to its runtime, host and run digest, a run
// built against another source is refused, and a rerun replaces only the rows it produced.
// Run: bun test fixtures/sdk/qualify-merge.test.ts
import {describe,expect,test} from "bun:test";
// @ts-ignore: plain ES module next to the tool
import {EVIDENCE_SCHEMA,MergeError,RUN_SCHEMA,makeHost,mergeRuns,sealRun,verifyRun} from "./qualify-merge.mjs";

const SRC_A="a".repeat(64),SRC_B="b".repeat(64);
const hostOf=(hostname="the Debian 12 (6.1) lab VM")=>makeHost({platform:"linux",release:"6.1.0-54-amd64",arch:"x64",cpu_model:"vCPU",logical_cpus:8,total_memory_mib:15000,hostname});
const nodeRow=(version:string,over:Record<string,unknown>={})=>({id:`node-${version}-linux-x64-runtime_engine_samples`,runtime:"node",version,platform:"linux",arch:"x64",method:"runtime_engine_samples",exit_code:0,duration_ms:1000,status:"observed",evidence:{ok:true},...over});
const bunRow=(over:Record<string,unknown>={})=>({id:"bun-1.3.14-linux-x64-runtime_engine_samples",runtime:"bun",version:"1.3.14",platform:"linux",arch:"x64",method:"runtime_engine_samples",exit_code:0,duration_ms:900,status:"observed",evidence:{ok:true},...over});
const NOTES=[{row:"edge-142",reason:"not run on this machine."},{row:"node-runtime_engine_samples",reason:"skipped by --skip",kind:"runtime:node"}];
function run(node:string,{source=SRC_A,at="2026-11-19T10:00:00.000Z",host=hostOf(),rows,overhead}:{source?:string;at?:string;host?:object;rows?:unknown[];overhead?:unknown}={}){
 return sealRun({schema:RUN_SCHEMA,tool:"fixtures/sdk/qualify.mjs",recorded_at:at,source_sha256:source,host,runtimes:{node:`v${node}`,bun:"1.3.14",python:null},command:`node fixtures/sdk/qualify.mjs --run-out ${node}.json`,
  rows:rows??[nodeRow(`v${node}`),bunRow()],overhead:overhead??{not_run:"pass --overhead"},unqualified:NOTES});
}
const manifest=()=>({schema_version:1,status:"not_run",runtime_targets:[
 {name:"CPython",version:"3.12.12",qualification:"not_run"},{name:"CPython",version:"3.13.9",qualification:"not_run"},{name:"CPython",version:"3.14.0",qualification:"not_run"},
 {name:"Node",version:"22.21.1",qualification:"not_run"},{name:"Node",version:"24.11.0",qualification:"not_run"},{name:"Bun",version:"1.3.14",qualification:"not_run"}],
 measured_evidence:{schema:1,runtime_supplement_rows:[{id:"node-v22.23.4-win32-x64-runtime_engine_samples",runtime:"node",version:"v22.23.4",platform:"win32",status:"observed"}],overhead:{source:"fixtures/sdk/overhead.mjs",rows:{}},unqualified_rows:[{row:"stale",reason:"old"}]},
 observed_rows:[{id:"keep-me"}]});
const rowIds=(m:any)=>m.measured_evidence.runtime_supplement_rows.map((r:any)=>r.id);
const rowOf=(m:any,id:string)=>m.measured_evidence.runtime_supplement_rows.find((r:any)=>r.id===id);
const noteRows=(m:any)=>m.measured_evidence.unqualified_rows.map((r:any)=>r.row);
const merge=(m:any,runs:unknown[],source=SRC_A)=>mergeRuns(m,runs,{sourceSha256:source,now:"2026-11-19T12:00:00.000Z"});

describe("a run built against another source is refused",()=>{
 test("(a) a row whose run carries another source digest is not accepted",()=>{
  const m=manifest();
  expect(()=>merge(m,[run("22.21.1",{source:SRC_B})])).toThrow(MergeError);
  expect(()=>merge(m,[run("22.21.1",{source:SRC_B})])).toThrow(/source/);
  expect(m.measured_evidence.schema).toBe(1);// the input manifest is never modified
 });
 test("one stale run in a batch refuses the whole batch, nothing is half merged",()=>{
  expect(()=>merge(manifest(),[run("22.21.1"),run("24.11.0",{source:SRC_B})])).toThrow(/source/);
 });
 test("the stamp cannot be edited into the run: the run digest covers it",()=>{
  const r=run("22.21.1",{source:SRC_B});
  const forged={...r,source_sha256:SRC_A};
  expect(()=>merge(manifest(),[forged])).toThrow(/digest/);
 });
 test("a row edited after the run was sealed is refused, and a node row must carry the run's own Node version",()=>{
  const r=run("22.21.1");
  r.rows[0].status="failed";
  expect(()=>merge(manifest(),[r])).toThrow(/digest/);
  const lying=sealRun({...run("22.21.1"),rows:[nodeRow("v24.11.0"),bunRow()]});
  expect(()=>merge(manifest(),[lying])).toThrow(/node/i);
  expect(()=>verifyRun({...run("22.21.1"),schema:"x"})).toThrow(MergeError);
  expect(()=>merge(manifest(),[run("22.21.1")],"not-a-digest")).toThrow(MergeError);
 });
});

describe("two runs merge into both rows",()=>{
 test("(b) Node 22.21.1 and Node 24.11.0 runs give both rows, each bound to runtime, host and run digest",()=>{
  const r22=run("22.21.1",{at:"2026-11-19T10:00:00.000Z"}),r24=run("24.11.0",{at:"2026-11-19T10:05:00.000Z",host:hostOf("a second Debian 12 (6.1) lab VM")});
  const m=merge(manifest(),[r22,r24]);
  expect(rowIds(m)).toEqual(expect.arrayContaining(["node-v22.21.1-linux-x64-runtime_engine_samples","node-v24.11.0-linux-x64-runtime_engine_samples","bun-1.3.14-linux-x64-runtime_engine_samples"]));
  const a=rowOf(m,"node-v22.21.1-linux-x64-runtime_engine_samples"),b=rowOf(m,"node-v24.11.0-linux-x64-runtime_engine_samples");
  expect(a.run).toEqual({digest:r22.run_digest,runtime:"node-v22.21.1",host_id:r22.host.id,source_sha256:SRC_A});
  expect(b.run).toEqual({digest:r24.run_digest,runtime:"node-v24.11.0",host_id:r24.host.id,source_sha256:SRC_A});
  expect(r22.host.id).not.toBe(r24.host.id);
  expect(m.measured_evidence.schema).toBe(EVIDENCE_SCHEMA);
  expect(m.measured_evidence.source_sha256).toBe(SRC_A);
  expect(m.measured_evidence.runs.map((r:any)=>r.run_digest)).toEqual(expect.arrayContaining([r22.run_digest,r24.run_digest]));
  expect(m.measured_evidence.runs.find((r:any)=>r.run_digest===r22.run_digest).host.hostname).toBe("the Debian 12 (6.1) lab VM");
  // frozen target rows and the hand-entered observed rows are never touched
  expect(m.runtime_targets).toEqual(manifest().runtime_targets);
  expect(m.observed_rows).toEqual([{id:"keep-me"}]);
 });
 test("the order of the runs on the command line does not decide which observation is newest",()=>{
  const r22=run("22.21.1",{at:"2026-11-19T10:00:00.000Z",rows:[nodeRow("v22.21.1"),bunRow({duration_ms:111})]}),r24=run("24.11.0",{at:"2026-11-19T10:05:00.000Z",rows:[nodeRow("v24.11.0"),bunRow({duration_ms:222})]});
  expect(rowOf(merge(manifest(),[r22,r24]),bunRow().id).duration_ms).toBe(222);
  expect(rowOf(merge(manifest(),[r24,r22]),bunRow().id).duration_ms).toBe(222);
 });
 test("the frozen targets are reported as covered only by an observed row of exactly that version",()=>{
  const only22=merge(manifest(),[run("22.21.1")]);
  expect(noteRows(only22)).toContain("node-24.11.0-runtime_engine_samples");
  expect(noteRows(only22)).not.toContain("node-22.21.1-runtime_engine_samples");
  expect(only22.measured_evidence.target_coverage).toEqual(expect.arrayContaining([{target:"Node 22.21.1",observed_row:"node-v22.21.1-linux-x64-runtime_engine_samples"},{target:"Node 24.11.0",observed_row:null}]));
  const both=merge(only22,[run("24.11.0",{at:"2026-11-19T10:05:00.000Z"})]);
  expect(noteRows(both)).not.toContain("node-24.11.0-runtime_engine_samples");
  expect(both.measured_evidence.target_coverage).toEqual(expect.arrayContaining([{target:"Node 24.11.0",observed_row:"node-v24.11.0-linux-x64-runtime_engine_samples"}]));
  // a different patch level never stands in for the frozen one
  expect(noteRows(merge(manifest(),[run("22.23.4")]))).toContain("node-22.21.1-runtime_engine_samples");
  // the frozen runtime_targets keep their own status
  expect(both.runtime_targets.every((t:any)=>t.qualification==="not_run")).toBe(true);
 });
 test("notes a merged observation satisfies are dropped, platform notes follow the rows, static notes stay once",()=>{
  const m=merge(manifest(),[run("22.21.1"),run("24.11.0",{at:"2026-11-19T10:05:00.000Z"})]);
  const rows=noteRows(m);
  expect(rows).not.toContain("node-runtime_engine_samples");// "skipped" is satisfied by an observed node row
  expect(rows).not.toContain("stale");// the old derived notes are regenerated, never carried
  expect(rows.filter((r:string)=>r==="edge-142")).toHaveLength(1);
  expect(rows).not.toContain("node-linux-runtime_engine_samples");
  expect(rows).toContain("node-darwin-runtime_engine_samples");
  expect(rows).toContain("node-win32-runtime_engine_samples");
 });
 test("merging the same run again changes nothing but the merge time",()=>{
  const r=run("22.21.1");
  const once=merge(manifest(),[r]),twice=merge(once,[r]);
  expect(twice).toEqual(once);
 });
});

describe("a rerun replaces only its rows",()=>{
 test("(c) rerunning Node 22.21.1 replaces the Node 22.21.1 row and leaves the Node 24.11.0 row and its run alone",()=>{
  const r22=run("22.21.1",{at:"2026-11-19T10:00:00.000Z"}),r24=run("24.11.0",{at:"2026-11-19T10:05:00.000Z"});
  const first=merge(manifest(),[r22,r24]);
  const before24=JSON.stringify(rowOf(first,"node-v24.11.0-linux-x64-runtime_engine_samples"));
  const r22b=run("22.21.1",{at:"2026-11-19T11:00:00.000Z",rows:[nodeRow("v22.21.1",{duration_ms:4242}),bunRow({duration_ms:333})]});
  const second=merge(first,[r22b]);
  const a=rowOf(second,"node-v22.21.1-linux-x64-runtime_engine_samples");
  expect(a.duration_ms).toBe(4242);
  expect(a.run.digest).toBe(r22b.run_digest);
  expect(JSON.stringify(rowOf(second,"node-v24.11.0-linux-x64-runtime_engine_samples"))).toBe(before24);
  expect(second.measured_evidence.runs.map((r:any)=>r.run_digest)).toContain(r24.run_digest);
  expect(second.measured_evidence.runs.map((r:any)=>r.run_digest)).not.toContain(r22.run_digest);// no row refers to the replaced run any more
  expect(rowIds(second).filter((id:string)=>id.startsWith("node-v22"))).toHaveLength(1);
 });
 test("a rerun that skips Node replaces nothing of it",()=>{
  const first=merge(manifest(),[run("22.21.1"),run("24.11.0",{at:"2026-11-19T10:05:00.000Z"})]);
  const bunOnly=run("22.21.1",{at:"2026-11-19T11:00:00.000Z",rows:[bunRow({duration_ms:5})]});
  const second=merge(first,[bunOnly]);
  expect(rowOf(second,"node-v22.21.1-linux-x64-runtime_engine_samples")).toEqual(rowOf(first,"node-v22.21.1-linux-x64-runtime_engine_samples"));
  expect(rowOf(second,bunRow().id).duration_ms).toBe(5);
 });
 test("a failing rerun replaces an observed row: the newest observation is the one on record",()=>{
  const first=merge(manifest(),[run("22.21.1")]);
  const bad=run("22.21.1",{at:"2026-11-19T11:00:00.000Z",rows:[nodeRow("v22.21.1",{status:"failed",exit_code:1})]});
  const second=merge(first,[bad]);
  expect(rowOf(second,"node-v22.21.1-linux-x64-runtime_engine_samples").status).toBe("failed");
  expect(noteRows(second)).toContain("node-22.21.1-runtime_engine_samples");
 });
 test("overhead is replaced only by a run that supplies one",()=>{
  const withOverhead=run("22.21.1",{overhead:{source:"fixtures/sdk/overhead.mjs",recorded_at:"t",rows:{x:1}}});
  const first=merge(manifest(),[withOverhead]);
  expect(first.measured_evidence.overhead.rows).toEqual({x:1});
  expect(first.measured_evidence.overhead.run.digest).toBe(withOverhead.run_digest);
  const second=merge(first,[run("24.11.0",{at:"2026-11-19T10:05:00.000Z"})]);
  expect(second.measured_evidence.overhead).toEqual(first.measured_evidence.overhead);
 });
});

describe("what was recorded before rows were bound to a run is kept apart, never claimed",()=>{
 test("schema 1 rows and overhead move to retired_evidence with their reason",()=>{
  const m=merge(manifest(),[run("22.21.1")]);
  expect(rowIds(m)).not.toContain("node-v22.23.4-win32-x64-runtime_engine_samples");
  const retired=m.measured_evidence.retired_evidence;
  expect(retired.map((e:any)=>e.reason)).toEqual(["no_run_binding","no_run_binding"]);
  expect(retired[0].row.id).toBe("node-v22.23.4-win32-x64-runtime_engine_samples");
  expect(retired[1].overhead.source).toBe("fixtures/sdk/overhead.mjs");
  expect(merge(m,[run("22.21.1")]).measured_evidence.retired_evidence).toEqual(retired);// retiring is not repeated
 });
 test("rows of a manifest stamped with an older source are retired when the tree changed",()=>{
  const old=merge(manifest(),[run("22.21.1")]);
  const now=merge(old,[run("22.21.1",{source:SRC_B,at:"2026-11-19T13:00:00.000Z"})],SRC_B);
  expect(now.measured_evidence.source_sha256).toBe(SRC_B);
  expect(now.measured_evidence.retired_evidence.filter((e:any)=>e.reason==="source_stamp_changed").map((e:any)=>e.row.id)).toContain("bun-1.3.14-linux-x64-runtime_engine_samples");
  expect(rowIds(now).every((id:string)=>rowOf(now,id).run.source_sha256===SRC_B)).toBe(true);
 });
});
