// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {test,expect} from "bun:test";
import {createServer,type IncomingMessage} from "node:http";
import {connect} from "node:net";
import {parsePropagation,requestPropagation} from "../src/workers.ts";

const TRACE="a".repeat(32),SPAN="b".repeat(16),PROBABILITY="3ff0000000000000",DOMAIN=["1","2","3"].map(c=>c.repeat(32));
const traceparent=(sampled=true):string=>"00-"+TRACE+"-"+SPAN+(sampled?"-01":"-00");
const companion="v1."+PROBABILITY+"."+DOMAIN.join(".");

/** Writes the header lines exactly as given (so repeats and casing reach Node's own parser) and reports what both readers conclude on the server. */
async function observe(headers:readonly string[]):Promise<{raw:unknown;viaHeaders:unknown}>{
 return new Promise((resolve,reject)=>{
  const server=createServer((req:IncomingMessage,res)=>{
   const raw=requestPropagation(req);
   // `headers` is read only after requestPropagation ran, so the answer above cannot have relied on it.
   const viaHeaders=parsePropagation(req.headers.traceparent,req.headers["x-soundpost-context"]);
   res.end("ok");
   resolve({raw,viaHeaders});
  });
  server.listen(0,"127.0.0.1",()=>{
   const address=server.address();if(address===null||typeof address==="string"){reject(Error("no port"));return;}
   const socket=connect(address.port,"127.0.0.1",()=>{
    let lines="GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n";
    for(let index=0;index<headers.length;index+=2)lines+=headers[index]+": "+headers[index+1]+"\r\n";
    socket.write(lines+"\r\n");
   });
   socket.on("error",reject);socket.on("close",()=>server.close());socket.resume();
  });
 });
}

test("raw-header propagation reads exactly what the parsed headers would, for every casing and repeat",async()=>{
 const cases:readonly (readonly string[])[]=[
  [],
  ["traceparent",traceparent(),"x-soundpost-context",companion],
  ["TraceParent",traceparent(false),"X-SoundPost-Context",companion],
  ["traceparent",traceparent()],
  ["x-soundpost-context",companion],
  ["traceparent",traceparent(),"traceparent",traceparent()],
  ["x-soundpost-context",companion,"X-Soundpost-Context",companion],
  ["traceparent","00-"+TRACE+"-"+SPAN+"-07","x-soundpost-context",companion],
  ["traceparent",traceparent(),"x-soundpost-context","v2.nonsense"],
  ["traceparent","  "+traceparent()+"  ","x-soundpost-context",companion],
  ["x-other","1","traceparent",traceparent(),"x-trailing","2","x-soundpost-context",companion],
 ];
 for(const headers of cases){
  const seen=await observe(headers);
  expect(seen.raw,JSON.stringify(headers)).toEqual(seen.viaHeaders);
 }
 const accepted=await observe(["traceparent",traceparent(),"x-soundpost-context",companion]);
 expect(accepted.raw).toMatchObject({traceId:TRACE,spanId:SPAN,sampled:true,probability:PROBABILITY});
 const repeated=await observe(["traceparent",traceparent(),"traceparent",traceparent(),"x-soundpost-context",companion]);
 expect(repeated.raw).toBeUndefined();
});

test("raw-header propagation does not build the lazy headers object",()=>{
 const request={rawHeaders:["traceparent",traceparent(),"x-soundpost-context",companion],get headers():never{throw Error("headers must not be materialized");}};
 expect(requestPropagation(request as unknown as IncomingMessage)).toMatchObject({traceId:TRACE,spanId:SPAN});
 expect(requestPropagation({rawHeaders:["host","x"],get headers():never{throw Error("headers must not be materialized");}} as unknown as IncomingMessage)).toBeUndefined();
});

test("a request without a raw header list falls back to the parsed headers",()=>{
 const request={headers:{traceparent:traceparent(),"x-soundpost-context":companion}};
 expect(requestPropagation(request as unknown as IncomingMessage)).toMatchObject({traceId:TRACE,spanId:SPAN});
});
