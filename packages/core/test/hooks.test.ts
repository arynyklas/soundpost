// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {test,expect} from "bun:test";
import process from "node:process";
import {init} from "../../bun/src/index.ts";
import {installHooks as installBunHooks} from "../../bun/src/hooks.ts";
import {config} from "./fixture.ts";
test("Bun limitation does not install fatal consuming handlers or monitors",async()=>{
 const counts=[process.listenerCount("uncaughtException"),process.listenerCount("unhandledRejection"),process.listenerCount("uncaughtExceptionMonitor")];
 const c=init(config()),lease=installBunHooks(c);
 expect(lease.capabilities.fatalMonitor).toBe(false);
 expect(lease.capabilities.reason).toBe("bun_fatal_monitor_unavailable");
 expect([process.listenerCount("uncaughtException"),process.listenerCount("unhandledRejection"),process.listenerCount("uncaughtExceptionMonitor")]).toEqual(counts);
 lease.close();lease.close();await c.close();
});
test("hook leases are explicitly capped and client close owns cleanup",async()=>{
 const c=init(config()),leases=Array.from({length:8},()=>installBunHooks(c));
 expect(()=>installBunHooks(c)).toThrow("hook lease limit");
 await c.close();for(const lease of leases)lease.close();
 expect(()=>installBunHooks(c)).toThrow("client closed");
});
