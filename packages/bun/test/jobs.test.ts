// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {test,expect} from "bun:test";
import {init} from "../src/index.ts";
import {jobSettings} from "../../core/test/jobs-fixture.ts";
import {assertRuntimeJobIsolation} from "../../core/test/jobs-runtime-fixture.ts";
import {setTimeout as delay} from "node:timers/promises";
test("Bun adapter independently isolates concurrent real async job scopes",async()=>{const client=init(jobSettings());try{await assertRuntimeJobIsolation(client);}finally{await client.close();}});
test("Bun actual timers cancellation uses its own native error brand",async()=>{
 const client=init(jobSettings()),controller=new AbortController();controller.abort();
 try{await expect(client.withJobAttempt("fixture.task","d".repeat(32),1,async()=>{await delay(1000,undefined,{signal:controller.signal});})).rejects.toBeDefined();const events=client.bufferedRecords().map(value=>JSON.parse(value));expect(events.filter(value=>value.kind==="job_attempt").at(-1).payload.state).toBe("cancelled");expect(events.filter(value=>value.kind==="error")).toHaveLength(0);}finally{await client.close();}
});
test("Bun timer calibration never brands ordinary native errors or inspects opaque throws",async()=>{
 const client=init(jobSettings());let traps=0;
 try{
  const opaque=Object.defineProperty(Error("CANARY"),"name",{get(){traps++;throw Error("CANARY_GETTER");}}),proxy=new Proxy(Error("CANARY"),{get(){traps++;throw Error("CANARY_PROXY");},getPrototypeOf(){traps++;throw Error("CANARY_PROXY");},getOwnPropertyDescriptor(){traps++;throw Error("CANARY_PROXY");}});
  for(const error of [Error("CANARY"),new TypeError("CANARY"),opaque,proxy]){await expect(client.withJobAttempt("fixture.task","e".repeat(32),1,async()=>{throw error;})).rejects.toBe(error);expect(JSON.parse(client.bufferedRecords().at(-1)!).payload.state).toBe("failed");}
  expect(traps).toBe(0);expect(client.bufferedRecords().join("")).not.toContain("CANARY");
 }finally{await client.close();}
});
