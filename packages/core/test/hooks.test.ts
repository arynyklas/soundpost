// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {test,expect} from "bun:test";
import process from "node:process";
import {init} from "../../bun/src/index.ts";
import {installHooks as installBunHooks} from "../../bun/src/hooks.ts";
import {config} from "./fixture.ts";
test("Bun lease installs only the non-consuming uncaughtExceptionMonitor and names the rejection limit",async()=>{
 const counts=[process.listenerCount("uncaughtException"),process.listenerCount("unhandledRejection"),process.listenerCount("uncaughtExceptionMonitor")];
 const c=init(config()),lease=installBunHooks(c);
 expect(lease.capabilities.fatalMonitor).toBe(true);
 expect(lease.capabilities.unhandledRejectionMonitor).toBe(false);
 expect(lease.capabilities.reason).toBe("bun_unhandled_rejection_monitor_unavailable");
 expect([process.listenerCount("uncaughtException"),process.listenerCount("unhandledRejection"),process.listenerCount("uncaughtExceptionMonitor")]).toEqual([counts[0],counts[1],counts[2]!+1]);
 lease.close();lease.close();
 expect([process.listenerCount("uncaughtException"),process.listenerCount("unhandledRejection"),process.listenerCount("uncaughtExceptionMonitor")]).toEqual(counts);
 await c.close();
});
test("hook leases are explicitly capped and client close owns cleanup",async()=>{
 const c=init(config()),leases=Array.from({length:8},()=>installBunHooks(c));
 expect(()=>installBunHooks(c)).toThrow("hook lease limit");
 await c.close();for(const lease of leases)lease.close();
 expect(()=>installBunHooks(c)).toThrow("client closed");
});
test("the fatal hook path stores original frames and never runs a user formatter or getter",async()=>{
 const here=import.meta.dir;
 const c=init({...config(),artifactRoot:here,artifactIds:{"hooks.test.ts":"0123456789abcdef0123456789abcdef"}});
 let calls=0;
 const plain=new Error("CANARY_MESSAGE");
 const hostile=new Error("CANARY_MESSAGE");
 Object.defineProperty(hostile,"stack",{get(){calls++;return "";},configurable:true});
 c.captureHook(plain,"uncaught_exception",true);
 c.captureHook(hostile,"uncaught_exception",true);
 const [first,second]=c.bufferedRecords().map(text=>JSON.parse(text) as {payload:{frames:{artifact_id:string;module_id:string;function:string;line:number}[]}});
 expect(first!.payload.frames.length).toBeGreaterThan(0);
 expect(first!.payload.frames[0]!.artifact_id).toBe("0123456789abcdef0123456789abcdef");
 expect(first!.payload.frames[0]!.module_id).toBe("hooks.test.ts");
 expect(second!.payload.frames).toHaveLength(0);
 expect(calls).toBe(0);
 expect(c.bufferedRecords().join("")).not.toContain("CANARY_MESSAGE");
 await c.close();
});
