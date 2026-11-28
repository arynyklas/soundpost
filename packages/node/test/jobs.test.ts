// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {test,expect} from "bun:test";
import {init} from "../src/index.ts";
import {jobSettings} from "../../core/test/jobs-fixture.ts";
import {assertRuntimeJobIsolation} from "../../core/test/jobs-runtime-fixture.ts";
import {setTimeout as delay} from "node:timers/promises";
test("Node adapter isolates concurrent real async job scopes",async()=>{const client=init(jobSettings());try{await assertRuntimeJobIsolation(client);}finally{await client.close();}});
test("Node native timers cancellation is cancelled without observing error getters",async()=>{
 const client=init(jobSettings()),controller=new AbortController();controller.abort();let original:unknown;
 try{await expect(client.withJobAttempt("fixture.task","d".repeat(32),1,async()=>{try{await delay(1000,undefined,{signal:controller.signal});}catch(error){original=error;throw error;}})).rejects.toBeDefined();const events=client.bufferedRecords().map(value=>JSON.parse(value));expect(original).toBeDefined();expect(events.filter(value=>value.kind==="job_attempt").at(-1).payload.state).toBe("cancelled");expect(events.filter(value=>value.kind==="error")).toHaveLength(0);
  let gets=0;const opaque=Object.defineProperties(Error("CANARY"),{name:{get(){gets++;throw Error("CANARY_GETTER");}},code:{value:"ABORT_ERR"}});await expect(client.withJobAttempt("fixture.task","e".repeat(32),1,async()=>{throw opaque;})).rejects.toBe(opaque);expect(gets).toBe(0);expect(JSON.parse(client.bufferedRecords().at(-1)!).payload.state).toBe("failed");
 }finally{await client.close();}
});
