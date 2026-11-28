// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// D31 canary (lane 4 wave 25). installServe decides whether a Response body is held in memory from the first line of Bun.inspect(response): "Response (N bytes)" or
// "Response (N.NN KB|MB|GB)" for a held body, "Response (0 KB)" for a stream, a used or touched body, a null body and Response.error(). That text is a debugging format, not an API:
// if a Bun release changes it, the probe silently classifies every body one way (a buffered body would be wrapped and lose Bun's native send, or a stream would be released
// as held and its span would end at return). serve-probe.test.ts compares the lease with the same regular expression it uses, so it cannot see the format move; this file
// pins the text itself, one body kind at a time, and names the runtime when it drifts. A failure here means: re-derive D31 for this Bun (l4w21-evidence/bun) before shipping.
import {test,expect} from "bun:test";
import {bufferedSummary} from "../src/serve.ts";
type Inspect=(value:unknown,options?:object)=>string;
const options=Object.freeze({depth:0,colors:false});
const encoder=new TextEncoder();
const stream=():ReadableStream<Uint8Array>=>new ReadableStream({pull(controller){controller.enqueue(encoder.encode("chunk"));controller.close();}},{highWaterMark:0});
const form=():FormData=>{const data=new FormData();data.set("a","1");return data;};
const touched=():Response=>{const response=new Response("hello");void response.body;return response;};
const used=():Response=>{const response=new Response("hello");void response.arrayBuffer().catch(()=>undefined);return response;};
type Case={name:string;make:()=>Response;held:boolean;size?:RegExp};
/** `size` is the exact size text where Bun's count is deterministic; the others are only required to be a size in the documented shapes. */
const cases:Case[]=[
 {name:"ascii string",make:()=>new Response("hello"),held:true,size:/^5 bytes$/},
 {name:"non-latin1 string",make:()=>new Response("héllo ✓"),held:true,size:/^10 bytes$/},
 {name:"Uint8Array",make:()=>new Response(new Uint8Array(7)),held:true,size:/^7 bytes$/},
 {name:"ArrayBuffer",make:()=>new Response(new ArrayBuffer(9)),held:true,size:/^9 bytes$/},
 {name:"Blob",make:()=>new Response(new Blob(["blob"])),held:true,size:/^4 bytes$/},
 {name:"URLSearchParams",make:()=>new Response(new URLSearchParams("a=1")),held:true,size:/^3 bytes$/},
 {name:"FormData",make:()=>new Response(form()),held:true},
 {name:"5000 bytes",make:()=>new Response("x".repeat(5000)),held:true,size:/^(?:4\.8\d?|5\.0+) KB$/},
 {name:"3 MB",make:()=>new Response("x".repeat(3e6)),held:true,size:/^(?:2\.8\d?|3\.0+) MB$/},
 {name:"Bun.file",make:()=>new Response(Bun.file(import.meta.path)),held:true,size:/^\d+\.\d+ KB$/},
 {name:"null body",make:()=>new Response(null),held:false},
 {name:"empty string",make:()=>new Response(""),held:false},
 {name:"ReadableStream",make:()=>new Response(stream()),held:false},
 {name:"body touched",make:touched,held:false},
 {name:"body used",make:used,held:false},
 {name:"Response.error()",make:()=>Response.error(),held:false},
];

/** What is wrong with the way `inspect` formats the Response bodies D31 relies on; empty when the format still has the shape the probe was derived from. */
export function canaryProblems(inspect:Inspect):string[]{
 const problems:string[]=[];
 for(const row of cases){
  const line=inspect(row.make(),options).split("\n",1)[0]!,match=/^Response \((.*)\)(?: \{)?$/.exec(line);
  if(match===null){problems.push(`${row.name}: first line ${JSON.stringify(line)} is not "Response (<size>)"`);continue;}
  const size=match[1]!;
  if(!/^(?:\d+ bytes|\d+\.\d+ (?:KB|MB|GB|TB)|0 KB)$/.test(size))problems.push(`${row.name}: size ${JSON.stringify(size)} is not N bytes, N.NN KB|MB|GB|TB or 0 KB`);
  if(row.size!==undefined&&!row.size.test(size))problems.push(`${row.name}: size ${JSON.stringify(size)} != ${row.size}`);
  if(row.held&&!bufferedSummary.test(line))problems.push(`${row.name}: a held body no longer matches the probe: ${JSON.stringify(line)}`);
  if(!row.held&&bufferedSummary.test(line))problems.push(`${row.name}: a body that is not held matches the probe: ${JSON.stringify(line)}`);
  if(!row.held&&size!=="0 KB")problems.push(`${row.name}: expected "0 KB", got ${JSON.stringify(size)}`);
 }
 return problems;
}
test(`D31 canary: Bun ${Bun.version} still reports a held body as "Response (N bytes | N.NN KB|MB|GB)" and every other body as "Response (0 KB)"`,()=>{
 expect(canaryProblems(Bun.inspect as Inspect),`Bun ${Bun.version} changed the Response summary D31 relies on; re-derive the probe (packages/bun/src/serve.ts)`).toEqual([]);
});
test("the canary notices each way the summary can drift",()=>{
 const real=Bun.inspect as Inspect;
 const drifts:Array<[string,Inspect]>=[
  ["lower-case unit",(value,option)=>real(value,option).replace(/^Response \((\d+) bytes\)/,"Response ($1 b)")],
  ["brackets",(value,option)=>real(value,option).replace(/^Response \((.*?)\)/,"Response [$1]")],
  ["no size",(value,option)=>real(value,option).replace(/^Response \(.*?\)/,"Response")],
  ["kibibytes",(value,option)=>real(value,option).replace(/ KB\)/,"KiB)")],
  ["stream reported as held",(value,option)=>real(value,option).replace(/^Response \(0 KB\)/,"Response (5 bytes)")],
  ["held reported as empty",(value,option)=>real(value,option).replace(/^Response \(\d+ bytes\)/,"Response (0 KB)")],
  ["size on the next line",(value,option)=>real(value,option).replace(/^(Response) \((.*?)\) \{/,"$1 {\n  size: $2")],
 ];
 for(const [name,drifted] of drifts)expect(canaryProblems(drifted).length,name).toBeGreaterThan(0);
});
test("the probe accepts exactly the documented held shapes",()=>{
 for(const held of ["Response (0 bytes)","Response (5 bytes) {","Response (4.88 KB)","Response (5.0 KB) {","Response (3.00 MB)","Response (1.25 GB)","Response (2.00 TB)"])expect(bufferedSummary.test(held),held).toBe(true);
 for(const other of ["Response (0 KB)","Response (0 KB) {","Response ()","Response (5 B)","Response [5 bytes]","Response (5 KB)","Response (5.0 kb)"," Response (5 bytes)","response (5 bytes)"])expect(bufferedSummary.test(other),other).toBe(false);
});
