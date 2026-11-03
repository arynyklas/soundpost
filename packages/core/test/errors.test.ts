// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {test,expect} from "bun:test";
import {types} from "node:util";
import {Client,HookEpisodeBindings} from "../src/client.ts";
import {extractException} from "../src/errors.ts";
import {config} from "./fixture.ts";
import {resolve} from "../src/policy.ts";
const policy=resolve(config());
const boundary={isNativeError:types.isNativeError,isProxy:types.isProxy};
test("native cause/group topology is bounded and stack formatters never execute",()=>{
 let calls=0;
 const old=Error.prepareStackTrace;
 Error.prepareStackTrace=()=>{calls++;throw Error("CANARY_FORMATTER");};
 try{
  const cause=new TypeError("CANARY_CAUSE"); const root=new AggregateError([cause],"CANARY_GROUP",{cause});
  Object.defineProperty(cause,"cause",{value:root});
  Object.defineProperty(root,"message",{get(){calls++;throw Error("getter");}});
  const graph=extractException(root,policy,boundary);
  expect(graph.nodes.map(n=>n.exception_class)).toEqual(["AggregateError","TypeError"]);
  expect(graph.reasons).toContain("cycle");
  expect(graph.reasons).toContain("safe_original_stack_unavailable");
  expect(calls).toBe(0);expect(JSON.stringify(graph)).not.toContain("CANARY");
 }finally{Error.prepareStackTrace=old;}
});
test("unknown throws and proxy traps are never inspected",()=>{
 let calls=0;const trap=new Proxy({}, {get(){calls++;throw Error();},getOwnPropertyDescriptor(){calls++;throw Error();},getPrototypeOf(){calls++;throw Error();}});
 const graph=extractException(trap,policy,boundary);
 expect(graph.nodes[0]?.exception_class).toBe("UnknownError");expect(calls).toBe(0);
 const foreign=extractException(new Error("CANARY"),policy);
 expect(foreign.reasons).toContain("native_brand_unavailable");
});
test("node overflow and accessor cause are explicit",()=>{
 let root:Error=new Error();for(let i=0;i<30;i++)root=new Error("CANARY",{cause:root});
 expect(extractException(root,policy,boundary).nodes).toHaveLength(16);
 expect(extractException(root,policy,boundary).reasons).toContain("node_limit");
 const error=new Error();Object.defineProperty(error,"cause",{get(){throw Error("called");}});
 expect(extractException(error,policy,boundary).reasons).toContain("cause_accessor");
});
test("handling episode dedup is explicit and buffers only immutable safe data",()=>{
 const c=new Client(config(),boundary),error=new Error("CANARY");const episode=c.beginHandlingEpisode();
 const first=episode.captureException(error);expect(episode.captureException(error)).toBe(first);
 expect(c.bufferedRecords()).toHaveLength(1);
 expect(c.beginHandlingEpisode().captureException(error)).not.toBe(first);
 expect(c.bufferedRecords().join("")).not.toContain("CANARY");
 expect(JSON.parse(c.bufferedRecords()[0]!).payload.exception_class).toBe("Error");
 episode.close();expect(()=>episode.captureException(error)).toThrow("episode closed");
});
test("nullish causes are absent while non-error causes remain value-free nodes",()=>{
 for(const cause of [undefined,null]){
  const graph=extractException(new Error("CANARY",{cause}),policy,boundary);
  expect(graph.nodes).toHaveLength(1);expect(graph.edges).toHaveLength(0);
  expect(graph.reasons).not.toContain("unknown_throw");
 }
 const graph=extractException(new Error("CANARY",{cause:"CANARY_VALUE"}),policy,boundary);
 expect(graph.nodes).toHaveLength(2);expect(graph.edges[0]?.kind).toBe("cause");
 expect(graph.nodes[1]?.exception_class).toBe("UnknownError");
 expect(JSON.stringify(graph)).not.toContain("CANARY");
});
test("aggregate child limit preserves visible ordinal topology and reports overflow",()=>{
 const graph=extractException(new AggregateError(Array.from({length:40},()=>new TypeError("CANARY"))),policy,boundary);
 expect(graph.nodes).toHaveLength(16);
 expect(graph.edges.filter(edge=>edge.kind==="group").map(edge=>edge.ordinal)).toEqual(Array.from({length:15},(_,i)=>i));
 expect(graph.reasons).toContain("group_limit");expect(graph.reasons).toContain("node_limit");
});
test("episode bindings preserve arms across unrelated sources and object identities",()=>{
 const client=new Client(config(),boundary),bindings=new HookEpisodeBindings(client);
 const error=new Error(),other=new Error(),episode=client.beginHandlingEpisode();episode.captureException(error);
 bindings.arm(episode,error,"uncaught_exception");
 expect(bindings.take(error,"unhandled_rejection")).toBeUndefined();
 expect(bindings.take(other,"uncaught_exception")).toBeUndefined();
 expect(bindings.take(error,"uncaught_exception")).toBe(episode);
 expect(bindings.take(error,"uncaught_exception")).toBeUndefined();
 expect(()=>bindings.arm(episode,"CANARY","uncaught_exception")).toThrow("weak_error_identity_required");
 bindings.arm(episode,error,"uncaught_exception");
 expect(()=>bindings.arm(client.beginHandlingEpisode(),error,"uncaught_exception")).toThrow("ambiguous episode binding");
 bindings.clear(episode);
 expect(bindings.take(error,"uncaught_exception")).toBeUndefined();
});
