// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {test,expect} from "bun:test";
import {createServer,request as nativeRequest,type Server,type ClientRequest,type IncomingMessage,type ServerResponse} from "node:http";
import {once,EventEmitter} from "node:events";
import {createRequire} from "node:module";
import {init,type Client} from "../src/index.ts";
import {installHttp} from "../src/http.ts";
import {installFetch} from "../src/fetch.ts";
import {installPg} from "../src/pg.ts";
import {installExpress} from "../src/express.ts";
import {serializeWorkerContext,withWorkerContext} from "../src/workers.ts";
import {config,signed} from "../../core/test/fixture.ts";
function settings(){const base=config();return {...base,operations:["request","dependency","query","parent","child"],dependencies:["fixture-http","fixture-pg"],policy:signed(JSON.stringify({version:1,org:base.org,project:base.project,source:base.source,revision:"1",expires_ns:"9223372036854775807",errors:true,logs:true,replay:false,bodies:false,traces:true,jobs:false},Object.keys({version:0,org:0,project:0,source:0,revision:0,expires_ns:0,errors:0,logs:0,replay:0,bodies:0,traces:0,jobs:0}).sort()))};}
function spans(client:Client){return client.bufferedRecords().map(s=>JSON.parse(s)).filter(s=>s.kind==="span").map(s=>s.payload);}
async function listening(server:Server){server.listen(0,"127.0.0.1");await once(server,"listening");const address=server.address();if(!address||typeof address==="string")throw Error("fixture address missing");return `http://127.0.0.1:${address.port}`;}
const require=createRequire(import.meta.url);
test("per-client async scopes preserve parallel siblings, explicit worker parent, and unrelated roots",async()=>{
 const a=init(settings()),b=init(settings());let root:string|undefined;
 await a.withSpan("parent",async()=>{root=a.traceContext()!.spanId;expect(b.traceContext()).toBeUndefined();const envelope=serializeWorkerContext(a.traceContext()!);expect(Object.keys(envelope).sort()).not.toContain("project");await Promise.all([a.withSpan("child",async()=>{await Promise.resolve();expect(a.traceContext()!.spanId).not.toBe(root);}),withWorkerContext(b,envelope,()=>b.withSpan("child",async()=>{await Promise.resolve();}))]);expect(a.traceContext()!.spanId).toBe(root);});
 expect(a.traceContext()).toBeUndefined();expect(b.traceContext()).toBeUndefined();expect(spans(a).find(s=>s.operation==="child").parent_id).toBe(root);expect(spans(b)[0].parent_id).toBe(root);
 let gets=0;const forged=Object.defineProperty({version:1},"trace_id",{get(){gets++;throw Error("CANARY_GETTER");}});await expect(withWorkerContext(a,forged,async()=>1)).rejects.toThrow();expect(gets).toBe(0);
 await expect(withWorkerContext(a,{...serializeWorkerContext({traceId:"1".repeat(32),spanId:"2".repeat(16),sampled:true,probability:"3ff0000000000000",clockDomain:{host:"3".repeat(32),boot:"4".repeat(32),runtime:"5".repeat(32)}}),credential:"CANARY_AUTHORITY"},async()=>1)).rejects.toThrow();await a.close();await b.close();
});
test("HTTP streaming and fetch propagation retain status, body, fanout and pre-buffer privacy",async()=>{
 const client=init(settings());let traceparent:string|undefined;const dependency=createServer((req,res)=>{traceparent=typeof req.headers.traceparent==="string"?req.headers.traceparent:undefined;res.writeHead(207);res.write("first");queueMicrotask(()=>res.end("second"));});const dependencyOrigin=await listening(dependency);
 const outbound=installFetch(client,{operation:"dependency",origins:[{origin:dependencyOrigin,dependency:"fixture-http"}]});const http=installHttp(client,{operation:"request"});const server=createServer(http.listener(async(_req,res)=>{const replies=await Promise.all([outbound.fetch(dependencyOrigin+"/CANARY_URL?secret=CANARY_QUERY",{headers:{"x-canary":"CANARY_HEADER"}}),outbound.fetch(dependencyOrigin+"/fanout")]);res.writeHead(replies[0]!.status);res.write(await replies[0]!.text());res.end(await replies[1]!.text());}));const origin=await listening(server);
 try{const response=await fetch(origin+"/CANARY_REQUEST");expect(response.status).toBe(207);expect(await response.text()).toBe("firstsecondfirstsecond");expect(traceparent).toMatch(/^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/);const rows=spans(client);expect(rows.filter(s=>s.span_kind==="client")).toHaveLength(2);expect(rows.filter(s=>s.span_kind==="client").every(s=>s.parent_id===rows.find(s=>s.span_kind==="server").span_id)).toBe(true);expect(JSON.stringify({records:client.bufferedRecords(),diagnostics:client.diagnostics()})).not.toContain("CANARY");expect(()=>installFetch(client,{operation:"dependency",origins:[]})).toThrow();outbound.close();expect(()=>outbound.fetch(dependencyOrigin)).toThrow();}finally{http.close();outbound.close();server.closeAllConnections();server.close();dependency.closeAllConnections();dependency.close();await client.close();}
});
test("HTTP listener synchronous exceptions retain exact thrown identity",async()=>{const client=init(settings()),lease=installHttp(client,{operation:"request"}),error=new Error("CANARY_SYNC");const listener=lease.listener(()=>{throw error;});try{let caught:unknown;try{listener({headers:{},on(){return this;}} as never,{on(){return this;}} as never);}catch(observed){caught=observed;}expect(caught).toBe(error);}finally{lease.close();await client.close();}});
test("Express5 and pg8 actual applications retain promise failure, query rows and callback return semantics",async()=>{
 const database=process.env.SOUNDPOST_FIXTURE_DATABASE_URL;if(!database)throw Error("qualification requires SOUNDPOST_FIXTURE_DATABASE_URL (PostgreSQL16)");const express=require("express") as ()=>any;const {Pool}=require("pg") as {Pool:new(options:unknown)=>any};const pool=new Pool({connectionString:database});const client=init(settings()),pg=installPg(client,{operation:"query",dependency:"fixture-pg"}),routes=installExpress(client),app=express();const expected=new Error("CANARY_EXPRESS_MESSAGE");app.get("/ok",routes.handler("request",async(_req:any,res:any)=>{const result=await pg.query(pool,"SELECT $1::integer AS answer /* CANARY_SQL */",[42]);res.status(201).json(result.rows);}));app.get("/failure",routes.handler("request",async()=>{throw expected;}));app.use((error:unknown,_req:any,res:any,_next:any)=>res.status(error===expected?503:500).end("application-error"));const server=createServer(app),origin=await listening(server);
 try{const ok=await fetch(origin+"/ok?CANARY_URL");expect(ok.status).toBe(201);expect(await ok.json()).toEqual([{answer:42}]);expect((await fetch(origin+"/failure")).status).toBe(503);expect(spans(client).find(s=>s.operation==="query").dependency_alias).toBe("fixture-pg");const gate=Promise.withResolvers<any>();const returned=pg.query(pool,"SELECT 7 AS answer",(error:unknown,result:any)=>error?gate.reject(error):gate.resolve(result));expect(returned).toBeUndefined();const rows=await gate.promise;expect(rows.rows).toEqual([{answer:7}]);expect(JSON.stringify({records:client.bufferedRecords(),diagnostics:client.diagnostics()})).not.toContain("CANARY");}finally{server.closeAllConnections();server.close();routes.close();pg.close();await pool.end();await client.close();}
});
test("native HTTP client preserves ClientRequest and callback receiver through body completion",async()=>{
 const client=init(settings()),server=createServer((_request,response)=>{response.writeHead(202);response.write("one");queueMicrotask(()=>response.end("two"));}),origin=await listening(server),lease=installHttp(client,{operation:"dependency",origins:[{origin,dependency:"fixture-http"}]}),gate=Promise.withResolvers<string>();let request:ClientRequest;
 try{request=lease.request(origin+"/CANARY_HTTP_PATH",{},function(this:ClientRequest,response){expect(this).toBe(request);expect(response.statusCode).toBe(202);const parts:Buffer[]=[];response.on("data",part=>parts.push(part));response.once("end",()=>gate.resolve(Buffer.concat(parts).toString()));response.once("error",gate.reject);});request.once("error",gate.reject);const closed=once(request,"close");request.end();expect(await gate.promise).toBe("onetwo");await closed;expect(spans(client)).toHaveLength(1);expect(spans(client)[0].span_kind).toBe("client");expect(spans(client)[0].status).toBe("ok");expect(JSON.stringify(client.bufferedRecords())).not.toContain("CANARY");}finally{lease.close();server.closeAllConnections();server.close();await client.close();}
});
test("HTTP transport failure remains application-owned while recording an error span",async()=>{
 const client=init(settings()),server=createServer((_request,response)=>response.destroy()),origin=await listening(server),lease=installHttp(client,{operation:"dependency",origins:[{origin,dependency:"fixture-http"}]}),failure=Promise.withResolvers<Error>();let call:ClientRequest|undefined;
 try{call=lease.request(origin);call.once("error",failure.resolve);expect(call.listenerCount("error")).toBe(1);call.end();await failure.promise;const records=client.bufferedRecords().map(text=>JSON.parse(text));expect(records.some(record=>record.kind==="error")).toBe(true);expect(records.find(record=>record.kind==="span").payload.status).toBe("error");}
 finally{call?.destroy();lease.close();server.closeAllConnections();server.close();await client.close();}
});
test("fetch forwards non-enumerable own data options and never runs init accessors",async()=>{
 for(const origin of ["https://allowed.example","https://unregistered.example"]){
  const client=init(settings());let seen:RequestInit|undefined;const lease=installFetch(client,{operation:"dependency",origins:[{origin:"https://allowed.example",dependency:"fixture-http"}],fetch:async(_input,options)=>{seen=options;return new Response("ok");}});
  try{const controller=new AbortController(),hidden:RequestInit={};Object.defineProperty(hidden,"method",{value:"POST",enumerable:false,configurable:true,writable:true});Object.defineProperty(hidden,"headers",{value:{"x-app":"kept"},enumerable:false,configurable:true,writable:true});Object.defineProperty(hidden,"signal",{value:controller.signal,enumerable:false,configurable:true,writable:true});
   const marker=Symbol("application-marker");Object.defineProperty(hidden,marker,{value:1,enumerable:false,configurable:true,writable:true});await lease.fetch(origin+"/x",hidden);expect(seen!.method).toBe("POST");expect(Object.getOwnPropertyDescriptor(seen!,"method")?.enumerable).toBe(false);expect(Object.getOwnPropertyDescriptor(seen!,"signal")?.enumerable).toBe(false);expect((seen as unknown as Record<symbol,unknown>)[marker]).toBe(1);expect(seen!.signal).toBe(controller.signal);expect(new Headers(seen!.headers).get("x-app")).toBe("kept");
   let reads=0;const accessor:RequestInit={};Object.defineProperty(accessor,"headers",{get(){reads++;return {"x-app":"kept"};},enumerable:false,configurable:true});await lease.fetch(origin+"/x",accessor);expect(seen).toBe(accessor);expect(reads).toBe(0);
  }finally{lease.close();await client.close();}
 }
});
test("HTTP wrapper keeps application headers for Headers, array and object inputs",async()=>{
 const seen:Record<string,string|string[]|undefined>[]=[];const server=createServer((request,response)=>{seen.push({...request.headers});response.end("ok");});
 server.listen(0,"127.0.0.1");await once(server,"listening");const address=server.address();if(!address||typeof address==="string")throw Error("fixture address missing");const registered=`http://127.0.0.1:${address.port}`,unregistered=`http://localhost:${address.port}`;
 const call=(target:(input:string,options:Record<string,unknown>)=>import("node:http").ClientRequest,origin:string,headers:unknown)=>new Promise<string>((resolve,reject)=>{try{const request=target(origin,{headers});request.once("error",error=>resolve("error:"+(error as {code?:string}).code));request.once("response",response=>{response.resume();response.once("end",()=>resolve("ok"));});request.end();}catch(error){resolve("throw:"+(error as {code?:string}).code);}});
 const inputs:[string,()=>unknown][]=[["headers",()=>new Headers({"x-app":"kept",authorization:"Bearer a"})],["array",()=>["x-app","kept","authorization","Bearer a"]],["object",()=>({"x-app":"kept",authorization:"Bearer a"})]];
 const client=init(settings()),lease=installHttp(client,{operation:"dependency",origins:[{origin:registered,dependency:"fixture-http"}]});
 try{for(const [name,make] of inputs){
   // Unregistered origin: byte-identical outcome to the runtime's own http.request.
   const nativeOutcome=await call((input,options)=>nativeRequest(input,options as never),unregistered,make());const nativeHeaders=seen.pop();
   const wrappedOutcome=await call((input,options)=>lease.request(input,options as never),unregistered,make());const wrappedHeaders=seen.pop();
   expect(wrappedOutcome,name).toBe(nativeOutcome);expect(wrappedHeaders?.["x-app"],name).toBe(nativeHeaders?.["x-app"]);expect(wrappedHeaders?.authorization,name).toBe(nativeHeaders?.authorization);expect(wrappedHeaders?.traceparent,name).toBeUndefined();
   // Registered origin: application headers survive and propagation is added.
   expect(await call((input,options)=>lease.request(input,options as never),registered,make()),name).toBe("ok");const observed=seen.pop()!;expect(observed["x-app"],name).toBe("kept");expect(observed.authorization,name).toBe("Bearer a");expect(observed.traceparent,name).toMatch(/^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/);
  }}finally{lease.close();server.closeAllConnections();server.close();await client.close();}
});
// The server listener ends a request's span from the response `close` (status from writableFinished and the status code) or the request `aborted`: no `finish` listener, cancellation on a lost connection, `incomplete` on lease close.
test("HTTP server listener ends the span from one close listener with the right status",async()=>{
 const client=init(settings()),lease=installHttp(client,{operation:"request"});
 const seen:Record<string,number[]>={},closed:PromiseWithResolvers<void>[]=[];
 const route=(label:string,request:IncomingMessage,response:ServerResponse)=>{
  seen[label]=[response.listenerCount("finish"),response.listenerCount("close"),request.listenerCount("aborted")];
  // The lease's listeners were added first, so when this one runs the span has ended. A lost connection is awaited through the request's `aborted` (Bun's node:http emits no response `close` for it).
  if(label==="wrapped"){const gate=Promise.withResolvers<void>();closed.push(gate);if(request.url==="/hang")request.once("aborted",gate.resolve);else response.once("close",gate.resolve);}
  if(request.url==="/ok")response.end("fine");
  else if(request.url==="/fail"){response.statusCode=500;response.end("failed");}
  else response.write("partial");// /hang: headers and a first chunk, never finished
 };
 const plain=createServer((request,response)=>route("plain",request,response)),wrapped=createServer(lease.listener((request,response)=>route("wrapped",request,response)));
 const plainOrigin=await listening(plain),wrappedOrigin=await listening(wrapped);
 try{
  expect(await (await fetch(plainOrigin+"/ok")).text()).toBe("fine");
  expect(await (await fetch(wrappedOrigin+"/ok")).text()).toBe("fine");
  expect(seen.wrapped![0],"finish listeners").toBe(seen.plain![0]);
  expect(seen.wrapped![1],"close listeners").toBe(seen.plain![1]!+1);
  expect(seen.wrapped![2],"aborted listeners").toBe(seen.plain![2]!+1);
  await closed[0]!.promise;expect(spans(client).map(s=>s.status)).toEqual(["ok"]);
  expect((await fetch(wrappedOrigin+"/fail")).status).toBe(500);
  await closed[1]!.promise;expect(spans(client).map(s=>s.status)).toEqual(["ok","error"]);
  // A connection lost before the response finished is cancelled, not ok.
  const headers=Promise.withResolvers<IncomingMessage>(),call=nativeRequest(wrappedOrigin+"/hang",headers.resolve);call.on("error",()=>{});call.end();
  const incoming=await headers.promise;incoming.on("error",()=>{});incoming.destroy();call.destroy();
  await closed[2]!.promise;expect(spans(client).map(s=>s.status)).toEqual(["ok","error","cancelled"]);
  // Closing the lease ends an in-flight request's span as incomplete and detaches the listener.
  const held=Promise.withResolvers<IncomingMessage>(),second=nativeRequest(wrappedOrigin+"/hang",held.resolve);second.on("error",()=>{});second.end();
  const reply=await held.promise;reply.on("error",()=>{});
  expect(spans(client).length).toBe(3);
  lease.close();
  expect(spans(client).map(s=>s.status)).toEqual(["ok","error","cancelled","incomplete"]);
  reply.destroy();second.destroy();
 }finally{lease.close();plain.closeAllConnections();wrapped.closeAllConnections();plain.close();wrapped.close();await client.close();}
},30000);
// The listener is two closures and two plain listeners that are never removed (cost work): this pins what that must not change. One close and one aborted listener per request,
// the first event decides the status, and every later event (and a lease close after the span ended) is a no-op.
test("HTTP server listener: the first event decides the span status, later events change nothing, and each request holds exactly one close and one aborted listener",()=>{
 const client=init(settings()),lease=installHttp(client,{operation:"request"});
 const pair=(finished:boolean,status:number)=>{const request=new EventEmitter() as EventEmitter&{rawHeaders:string[];headers:Record<string,string>},response=new EventEmitter() as EventEmitter&{writableFinished:boolean;statusCode:number};request.rawHeaders=[];request.headers={};response.writableFinished=finished;response.statusCode=status;return {request,response};};
 const run=(label:string,finished:boolean,status:number,drive:(request:EventEmitter,response:EventEmitter)=>void)=>{
  const {request,response}=pair(finished,status),before=spans(client).length;let counts:number[]=[];
  lease.listener((_request,_response)=>{counts=[response.listenerCount("close"),request.listenerCount("aborted"),response.listenerCount("finish")];})(request as never,response as never);
  expect(counts,label+" listeners while the handler runs").toEqual([1,1,0]);
  expect(spans(client).length,label+" open").toBe(before);drive(request,response);
  expect(response.listenerCount("close"),label+" no removal").toBe(1);
  return spans(client).slice(before).map(s=>s.status);
 };
 try{
  expect(run("finished ok",true,200,(_q,s)=>{s.emit("close");s.emit("close");_q.emit("aborted");})).toEqual(["ok"]);
  expect(run("finished 500",true,500,(_q,s)=>{s.emit("close");})).toEqual(["error"]);
  expect(run("unfinished close",false,200,(_q,s)=>{s.emit("close");})).toEqual(["cancelled"]);
  expect(run("aborted first",false,200,(q,s)=>{q.emit("aborted");s.emit("close");q.emit("aborted");})).toEqual(["cancelled"]);
  // A lease closed while a request is in flight ends its span incomplete; the request's own later close is then ignored.
  const flying=pair(false,200);let started=false;lease.listener(()=>{started=true;})(flying.request as never,flying.response as never);expect(started).toBe(true);
  const before=spans(client).length;lease.close();expect(spans(client).slice(before).map(s=>s.status)).toEqual(["incomplete"]);
  flying.response.emit("close");flying.request.emit("aborted");expect(spans(client).length).toBe(before+1);
 }finally{lease.close();}
 // A handler that throws gets its span ended as error exactly once, the same error object is rethrown, and its response's later close is ignored.
 const second=installHttp(client,{operation:"request"}),thrown=new Error("CANARY_THROWN"),failing=pair(true,200),count=spans(client).length;
 try{
  let caught:unknown;try{second.listener(()=>{throw thrown;})(failing.request as never,failing.response as never);}catch(error){caught=error;}
  expect(caught).toBe(thrown);failing.response.emit("close");failing.request.emit("aborted");
  expect(spans(client).slice(count).map(s=>s.status)).toEqual(["error"]);
 }finally{second.close();}
});
