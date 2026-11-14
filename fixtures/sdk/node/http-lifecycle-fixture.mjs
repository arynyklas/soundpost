// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import {createServer,IncomingMessage} from "node:http";
import {once} from "node:events";
import {config,signed} from "../../../packages/core/test/fixture.ts";
import {canonical} from "../../../packages/core/src/policy.ts";
export async function exerciseHttpLifecycle(init,installHttp,runtime) {
 const base=config(),settings={...base,operations:["http.call"],dependencies:["dependency"],policy:signed(canonical({version:1,org:base.org,project:base.project,source:base.source,revision:"1",expires_ns:"9223372036854775807",errors:true,logs:false,replay:false,bodies:false,traces:true,jobs:false}))},client=init(settings),release=Promise.withResolvers(),abortReceived=Promise.withResolvers();
 const server=createServer((request,response)=>{if(request.url==="/disconnect"){response.destroy();return;}if(request.url==="/abort"){abortReceived.resolve();return;}response.writeHead(202);response.write("one");if(request.url==="/stream")release.promise.then(()=>response.end("two"));else response.end("two");});server.listen(0,"127.0.0.1");await once(server,"listening");const origin=`http://127.0.0.1:${server.address().port}`,lease=installHttp(client,{operation:"http.call",origins:[{origin,dependency:"dependency"}]}),requests=[];
 const spans=()=>client.bufferedRecords().map(text=>JSON.parse(text)).filter(record=>record.kind==="span").map(record=>record.payload);
 try {
  const headers=Promise.withResolvers(),body=Promise.withResolvers();let call;
  call=lease.request(origin+"/stream",{agent:false},function(response){assert.equal(this,call);assert.equal(response.statusCode,202);const chunks=[];response.on("data",part=>chunks.push(part));response.once("error",body.reject);response.once("end",()=>body.resolve(Buffer.concat(chunks).toString()));headers.resolve();});requests.push(call);call.on("error",body.reject);call.end();await headers.promise;assert.equal(spans().length,0,"headers are not completed response bodies");release.resolve();assert.equal(await body.promise,"onetwo");assert.equal(spans().at(-1).status,"ok");
  // No response consumer is registered: instrumentation must not defeat native auto-discard.
  const discarded=lease.request(origin+"/discard",{agent:false});requests.push(discarded);const discardedClose=once(discarded,"close");discarded.end();await discardedClose;const incoming=Object.getOwnPropertyDescriptor(discarded,"res")?.value;assert.ok(incoming instanceof IncomingMessage);if(!incoming.readableEnded)await once(incoming,"end");assert.equal(spans().at(-1).status,"ok");
  const failed=lease.request(origin+"/disconnect",{agent:false});requests.push(failed);const error=Promise.withResolvers();let observed=0;failed.on("error",value=>{observed++;error.resolve(value);});assert.equal(failed.listenerCount("error"),1,"only the application consumes errors");failed.end();await error.promise;assert.equal(observed,1);assert.equal(spans().at(-1).status,"error");assert.ok(client.bufferedRecords().some(text=>JSON.parse(text).kind==="error"));failed.destroy();
  const controller=new AbortController(),cancelled=lease.request(origin+"/abort",{agent:false,signal:controller.signal});requests.push(cancelled);const terminal=Promise.withResolvers();cancelled.on("error",terminal.resolve);cancelled.once("abort",terminal.resolve);cancelled.once("close",terminal.resolve);cancelled.end();await abortReceived.promise;controller.abort();await terminal.promise;assert.equal(spans().at(-1).status,"cancelled");
  console.log(JSON.stringify({fixture:"actual_http_lifecycle",runtime,stream:"ok",unobserved_body_native_discard:true,application_error_ownership:true,cancellation:"cancelled",qualification:"this_exact_runtime_only"}));
 }finally{release.resolve();for(const request of requests)request.destroy();lease.close();server.closeAllConnections();server.close();await client.close();}
}
