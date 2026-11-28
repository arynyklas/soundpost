// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// 03.06-W7 producer half: one real Bun SDK client emits the job attempts of ONE scenario step with a controlled clock and
// delivers them to the real product (the orchestrator, `critical --mode reducer`, reads the product's job view and pairs the
// stored evidence with the real reducer). Prints {job_id,run_id,events:[wire payload,...]} for the orchestrator.
//
//   SOUNDPOST_FIXTURE_REDUCER_STEP = newer | older | retry
//   SOUNDPOST_FIXTURE_REDUCER_AT_NS = observed time (decimal unix ns) of the first event of the step
//
// newer/older: one run, one attempt that succeeds (newer) or fails (older). retry: one run whose attempt 1 fails and whose
// attempt 2 succeeds. Every later event of a step is 1 ms after the previous one.
import {randomBytes} from "node:crypto";
import {init} from "../../../packages/bun/src/index.ts";
import {loadConfig} from "../node/support.mjs";

const step=process.env.SOUNDPOST_FIXTURE_REDUCER_STEP,at=process.env.SOUNDPOST_FIXTURE_REDUCER_AT_NS,jobId=process.env.SOUNDPOST_FIXTURE_JOB_ID;
try{
 if(!["newer","older","retry"].includes(step??"")||!at||!/^[0-9]+$/.test(at)||!jobId)throw Error("reducer_step_environment");
 let tick=0n;
 const client=init({...loadConfig(),jobRegistry:{"fixture.task":jobId},traceSampleProbability:"0000000000000000",clockNs:()=>String(BigInt(at)+tick++*1000000n)});
 const runId=randomBytes(16).toString("hex");
 const attempt=async(ordinal:number,fail:boolean)=>{
  try{await client.withJobAttempt("fixture.task",runId,ordinal,async()=>{await Promise.resolve();if(fail)throw Error("CANARY_REDUCER_FAILURE");});}catch{/* the failure is the scenario */}
 };
 if(step==="newer")await attempt(1,false);
 else if(step==="older")await attempt(1,true);
 else{await attempt(1,true);await attempt(2,false);}
 const records=client.bufferedRecords().map(text=>JSON.parse(text) as {kind:string;payload:unknown});
 const events=records.filter(record=>record.kind==="job_attempt").map(record=>record.payload);
 if(JSON.stringify(records).includes("CANARY_"))throw Error("prequeue_privacy_failure");
 const report=await client.flush(10000);
 if(report.pending!==0||report.lost!==0||report.receipts.length===0)throw Error("durable_delivery_incomplete");
 console.log(JSON.stringify({job_id:jobId,run_id:runId,step,events}));
 await client.close();
}catch{
 console.error(JSON.stringify({fixture:"job_reducer_step",step,code:"failed"}));
 process.exitCode=1;
}
