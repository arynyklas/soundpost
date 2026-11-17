// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Server capture cost, wave 22 (see packages/core/test/gc-pressure.test.ts): what the HTTP server adapter leaves for the collector per request. A Set insert and delete per request
// churns V8's ordered hash table (allocate, rehash, shrink), so the requests in flight are tracked through a linked list instead; this pins that, and that the list keeps
// everything the set did: the in-flight limit, the order a closing lease ends spans in, and exactly-once settlement.
import {test,expect} from "bun:test";
import {EventEmitter} from "node:events";
import {init,type Client} from "../src/index.ts";
import {installHttp} from "../src/http.ts";
import {config,signed} from "../../core/test/fixture.ts";
function settings(){const base=config();return {...base,operations:["request"],policy:signed(JSON.stringify({version:1,org:base.org,project:base.project,source:base.source,revision:"1",expires_ns:"9223372036854775807",errors:true,logs:true,replay:false,bodies:false,traces:true},["bodies","errors","expires_ns","jobs","logs","org","project","replay","revision","source","traces","version"].sort()))};}
const spans=(client:Client)=>client.bufferedRecords().map(s=>JSON.parse(s)).filter(s=>s.kind==="span").map(s=>s.payload);
const pair=(finished:boolean,status:number)=>{const request=new EventEmitter() as EventEmitter&{rawHeaders:string[];headers:Record<string,string>},response=new EventEmitter() as EventEmitter&{writableFinished:boolean;statusCode:number};request.rawHeaders=[];request.headers={};response.writableFinished=finished;response.statusCode=status;return {request,response};};

test("serving requests inserts nothing into a Set or Map (the in-flight bookkeeping is a linked list)",()=>{
 const client=init(settings()),lease=installHttp(client,{operation:"request"}),listener=lease.listener(()=>{});
 const serve=():void=>{const {request,response}=pair(true,200);listener(request as never,response as never);response.emit("close");};
 serve();   // first use
 const setAdd=Set.prototype.add,mapSet=Map.prototype.set;let inserts=0;
 Set.prototype.add=function(this:Set<unknown>,value:unknown){inserts++;return Reflect.apply(setAdd,this,[value]) as Set<unknown>;};
 Map.prototype.set=function(this:Map<unknown,unknown>,key:unknown,value:unknown){inserts++;return Reflect.apply(mapSet,this,[key,value]) as Map<unknown,unknown>;};
 try{for(let i=0;i<100;i++)serve();}finally{Set.prototype.add=setAdd;Map.prototype.set=mapSet;}
 expect(inserts).toBe(0);
 lease.close();
});

test("a closing lease ends every request still in flight, oldest first, once, and refuses none that already ended",()=>{
 const client=init(settings()),lease=installHttp(client,{operation:"request"});
 const order:string[]=[];
 const listener=lease.listener((request)=>{order.push(String((request as unknown as {rawHeaders:string[]}).rawHeaders[0]));});
 const flying=[0,1,2,3].map(index=>{const made=pair(false,200);made.request.rawHeaders=["r"+index];listener(made.request as never,made.response as never);return made;});
 flying[1]!.response.emit("close");               // one ends on its own before the lease closes
 flying[2]!.request.emit("aborted");
 const before=spans(client).length;
 expect(before).toBe(2);
 lease.close();
 const rows=spans(client);expect(rows.length).toBe(4);
 expect(rows.slice(before).map(s=>s.status)).toEqual(["incomplete","incomplete"]);
 // settled once: the in-flight requests' own later events change nothing
 for(const made of flying){made.response.emit("close");made.request.emit("aborted");}
 expect(spans(client).length).toBe(4);
 expect(order).toEqual(["r0","r1","r2","r3"]);
});

test("more than 1024 requests in flight: the excess is recorded incomplete at once and the handler still runs; ending one makes room again",()=>{
 const client=init(settings()),lease=installHttp(client,{operation:"request"});let ran=0;
 const listener=lease.listener(()=>{ran++;});
 const open=Array.from({length:1024},()=>{const made=pair(true,200);listener(made.request as never,made.response as never);return made;});
 expect(ran).toBe(1024);expect(spans(client).length).toBe(0);
 const extra=pair(true,200);listener(extra.request as never,extra.response as never);
 expect(ran).toBe(1025);expect(spans(client).map(s=>s.status)).toEqual(["incomplete"]);
 open[0]!.response.emit("close");
 const again=pair(true,200);listener(again.request as never,again.response as never);again.response.emit("close");
 expect(spans(client).map(s=>s.status)).toEqual(["incomplete","ok","ok"]);
 lease.close();
});
