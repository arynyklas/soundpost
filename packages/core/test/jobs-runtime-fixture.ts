// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {expect} from "bun:test";
import type {Client} from "../src/client.ts";
/** Each caller supplies its actual runtime adapter, never a substitute context. */
export async function assertRuntimeJobIsolation(client:Client):Promise<void> {
 const gates=Array.from({length:32},()=>Promise.withResolvers<void>()),runs=Array.from({length:32},(_,index)=>(index+1).toString(16).padStart(32,"0"));
 const outcomes=runs.map((run,index)=>client.withJobAttempt("fixture.task",run,index+1,async()=>{
  const gate=gates[index];if(gate===undefined)throw Error("job_fixture_missing_gate");await gate.promise;
  client.captureException(Error("CANARY_JOB_BODY"));
  if(index===0)throw new DOMException("CANARY_CANCEL","AbortError");
  if(index===1)throw Error("CANARY_FAILED");
  return run;
 }));
 for(const gate of gates.toReversed())gate.resolve();
 const results=await Promise.allSettled(outcomes);
 const first=results[0],second=results[1],third=results[2],expectedRun=runs[2];
 if(first===undefined||second===undefined||third===undefined||expectedRun===undefined)throw Error("job_fixture_missing_result");
 expect(first.status).toBe("rejected");expect(second.status).toBe("rejected");expect(third).toEqual({status:"fulfilled",value:expectedRun});
 client.captureException(Error("outside"));
 const records=client.bufferedRecords().map(value=>JSON.parse(value)),events=records.filter(value=>value.kind==="job_attempt"),errors=records.filter(value=>value.kind==="error");
 expect(events).toHaveLength(64);expect(errors).toHaveLength(34);
 expect(events.map(value=>BigInt(value.payload.sequence)).toSorted((left,right)=>left<right?-1:1)).toEqual(Array.from({length:64},(_,index)=>BigInt(index+1)));
 expect(new Set(events.map(value=>value.payload.producer_epoch)).size).toBe(1);
 for(const [index,run] of runs.entries()){
  const attempts=events.filter(value=>value.payload.run_id===run).map(value=>value.payload);expect(attempts).toHaveLength(2);expect(attempts[0].attempt_id).toBe(attempts[1].attempt_id);expect(attempts[1].state).toBe(index===0?"cancelled":index===1?"failed":"succeeded");
  expect(errors.filter(value=>value.payload.run_id===run)).toHaveLength(index===1?2:1);
 }
 expect(errors.at(-1).payload.run_id).toBeUndefined();expect(client.bufferedRecords().join("")).not.toContain("CANARY");
}
