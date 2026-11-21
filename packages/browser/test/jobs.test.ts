// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {test,expect} from "bun:test";
import {init} from "../src/index.ts";
import {createMetadataContext} from "../src/context.ts";
import {JOB,RUN,jobSettings} from "../../core/test/jobs-fixture.ts";
test("browser job scope restores synchronous extent and does not guess ambient context after await",async()=>{
 const scope=createMetadataContext(),job={jobId:JOB,runId:RUN,attemptId:"c".repeat(32)};
 await scope.runJob(job,async()=>{expect(scope.jobCurrent()).toBe(job);await Promise.resolve();expect(scope.jobCurrent()).toBeUndefined();});expect(scope.jobCurrent()).toBeUndefined();scope.close();
});
test("browser overlapping jobs explicitly rebind terminal errors without leaking post-await ambient links",async()=>{
 const client=init(jobSettings()),gates=[Promise.withResolvers<void>(),Promise.withResolvers<void>()],runs=[RUN,"c".repeat(32)],thrown=[Error("CANARY_FIRST"),Error("CANARY_SECOND")];
 try{
  const jobs=runs.map((run,index)=>client.withJobAttempt("fixture.task",run,index+1,async()=>{client.captureException(Error("CANARY_SYNC"));await gates[index]!.promise;client.captureException(Error("CANARY_ASYNC"));throw thrown[index];}));
  gates[1]!.resolve();await Promise.resolve();gates[0]!.resolve();const outcomes=await Promise.allSettled(jobs);expect(outcomes).toEqual(thrown.map(reason=>({status:"rejected",reason})));
  const records=client.bufferedRecords().map(value=>JSON.parse(value)),events=records.filter(value=>value.kind==="job_attempt"),errors=records.filter(value=>value.kind==="error");
  expect(events).toHaveLength(4);expect(errors).toHaveLength(6);
  for(const run of runs){const terminal=events.find(value=>value.payload.run_id===run&&value.payload.state==="failed");expect(terminal).toBeDefined();expect(errors.find(value=>value.id===terminal.payload.cause_error).payload.run_id).toBe(run);expect(errors.filter(value=>value.payload.run_id===run)).toHaveLength(2);}
  expect(errors.filter(value=>value.payload.run_id===undefined)).toHaveLength(2);client.captureException(Error("outside"));expect(JSON.parse(client.bufferedRecords().at(-1)!).payload.run_id).toBeUndefined();expect(client.bufferedRecords().join("")).not.toContain("CANARY");
 }finally{await client.close();}
});
