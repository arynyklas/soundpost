// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Pins D31 for installServe over a broad corpus (lane 4 wave 21): whatever Bun reports for the body of a Response decides what the lease does with it. A body Bun reports as
// held in memory is handed back unchanged and its span ends at return; every other body that can be read is wrapped and its span ends when it completes. The corpus (body kind x
// body state x init) is the one the cheaper-probe candidates were judged against (estimate, clone, clone+estimate: none exact in Bun 1.3.14, see l4w21-evidence/bun).
import {test,expect} from "bun:test";
import {init} from "../src/index.ts";
import {installServe} from "../src/serve.ts";
import {config,signed} from "../../core/test/fixture.ts";
import {canonical} from "../../core/src/policy.ts";
function settings(){const base=config();return {...base,operations:["request"],dependencies:[],policy:signed(canonical({version:1,org:base.org,project:base.project,source:base.source,revision:"1",expires_ns:"9223372036854775807",errors:true,logs:true,replay:false,bodies:false,traces:true,jobs:false}))};}
const summary=/^Response \((?:\d+ bytes|\d+\.\d+ (?:KB|MB|GB|TB))\)/;
/** The D31 ground truth: what Bun reports about the body of a Response. */
const truth=(response:Response):boolean=>summary.test(Bun.inspect(response,{depth:0,colors:false}));
const spanStatuses=(client:ReturnType<typeof init>):string[]=>client.bufferedRecords().map(text=>JSON.parse(text)).filter(record=>record.kind==="span").map(record=>record.payload.status);
const encoder=new TextEncoder();
const form=():FormData=>{const data=new FormData();data.set("a","1");return data;};
const stream=():ReadableStream<Uint8Array>=>new ReadableStream({pull(controller){controller.enqueue(encoder.encode("chunk"));controller.close();}},{highWaterMark:0});
const bodies:Array<[string,()=>BodyInit|null]>=[
 ["null",()=>null],["empty string",()=>""],["ascii",()=>"hello"],["non-latin1",()=>"héllo wörld ✓"],["5000 bytes",()=>"x".repeat(5000)],["70000 bytes",()=>"x".repeat(70000)],["3 MB",()=>"x".repeat(3e6)],
 ["Uint8Array",()=>new Uint8Array(7)],["ArrayBuffer",()=>new ArrayBuffer(9)],["DataView",()=>new DataView(new ArrayBuffer(3))],["Blob",()=>new Blob(["blob"])],["FormData",form],["URLSearchParams",()=>new URLSearchParams("a=1&b=2")],
 ["Bun.file",()=>Bun.file(import.meta.path)],["ReadableStream",stream],["async generator",()=>(async function*(){yield "chunk";})() as never],
];
type Shape=[string,(make:()=>Response)=>Promise<Response>];
const states:Shape[]=[
 ["fresh",async make=>make()],
 ["body touched",async make=>{const response=make();void response.body;return response;}],
 ["body used",async make=>{const response=make();await response.arrayBuffer().catch(()=>undefined);return response;}],
 ["body locked",async make=>{const response=make();response.body?.getReader();return response;}],
 ["cloned",async make=>{const response=make();response.clone();return response;}],
];
const inits:Array<[string,ResponseInit]>=[["plain",{}],["status text",{statusText:"Hello"}],["30 headers",{headers:Object.fromEntries(Array.from({length:30},(_,i)=>["x-h"+i,"v".repeat(40)]))}],["500",{status:500}],["json header",{headers:{"content-type":"application/json"}}]];

test("D31 over the corpus: a body Bun reports as held is returned unchanged with its span ended; a readable stream-like body is wrapped and ends its span on completion",async()=>{
 const client=init(settings());let held=0,wrapped=0;
 try{
  for(const [bodyName,body] of bodies)for(const [stateName,state] of states)for(const [initName,responseInit] of inits){
   const make=()=>{try{return new Response(body(),responseInit);}catch{return new Response(null,responseInit);}};
   const label=`${bodyName} / ${stateName} / ${initName}`;
   const reference=await state(make),expected=truth(reference);
   const readable=!expected&&reference.status!==0&&reference.body!==null&&!reference.body.locked;
   const subject=await state(make),lease=installServe(client,{operation:"request"}),before=spanStatuses(client).length;
   try{
    const returned=lease.handler(()=>subject)(new Request("https://fixture.invalid"),undefined as never) as Response;
    if(expected){
     held++;
     expect(returned,label+": handed back unchanged").toBe(subject);
     expect(spanStatuses(client).slice(before),label+": span ended at return").toEqual([subject.status>=400?"error":"ok"]);
    }else if(readable){
     wrapped++;
     expect(returned,label+": wrapped").not.toBe(subject);
     expect(spanStatuses(client).slice(before),label+": span open until the body completes").toEqual([]);
     await returned.arrayBuffer();
     expect(spanStatuses(client).slice(before),label+": span ended on completion").toEqual([subject.status>=400?"error":"ok"]);
    }
   }finally{lease.close();}
  }
  expect(held).toBeGreaterThan(40);expect(wrapped).toBeGreaterThan(20);
 }finally{await client.close();}
},120000);

test("through Bun.serve a buffered body is still sent natively with its Content-Length, and a touched or streamed body still completes with its span",async()=>{
 const client=init(settings()),lease=installServe(client,{operation:"request"});
 const app=Bun.serve({hostname:"127.0.0.1",port:0,fetch:lease.handler(request=>{
  const path=new URL(request.url).pathname;
  if(path==="/json")return Response.json({a:1});
  if(path==="/text")return new Response("hello");
  if(path==="/utf16")return new Response("héllo ✓");
  if(path==="/bytes")return new Response(new Uint8Array(11));
  if(path==="/touched"){const touched=new Response("hello");void touched.body;return touched;}
  return new Response(stream());
 })});
 try{
  for(const [path,length] of [["/json","7"],["/text","5"],["/bytes","11"]] as const){
   const response=await fetch(new URL(path,app.url)),body=await response.arrayBuffer();
   expect(response.headers.get("content-length"),path).toBe(length);expect(response.headers.get("transfer-encoding"),path).toBeNull();expect(body.byteLength,path).toBe(Number(length));
  }
  const utf16=await fetch(new URL("/utf16",app.url));expect(utf16.headers.get("transfer-encoding"),"/utf16").toBeNull();expect(await utf16.text()).toBe("héllo ✓");
  for(const path of ["/stream","/touched"]){const response=await fetch(new URL(path,app.url));expect(await response.text(),path).toMatch(/^(chunk|hello)$/);}
  expect(spanStatuses(client)).toEqual(["ok","ok","ok","ok","ok","ok"]);
 }finally{lease.close();await app.stop(true);await client.close();}
},30000);
