// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import {request} from "node:https";
import {readFileSync} from "node:fs";
import {randomBytes} from "node:crypto";
import {setTimeout as delay} from "node:timers/promises";
import {loadConfig,safeRecords} from "../node/support.mjs";
import {exclusiveCaptureEnd} from "./window.mjs";
const diagnosticStages=Object.freeze({
 registered_job_id:"configuration",load_config:"configuration",initialize_client:"configuration",
 signed_permissions:"policy",failed_callback_identity:"execution",successful_callback_identity:"execution",timer_callback_identity:"execution",
 prequeue_privacy:"capture",attempt_states:"capture",attempt_sequences:"capture",attempt_identity:"capture",error_count:"capture",error_cause_link:"capture",outside_run_link:"capture",unsampled_spans:"capture",
 flush:"delivery",receipt_pending:"delivery",receipt_lost:"delivery",receipt_present:"delivery",
 verifier_config:"verification",verifier_request:"verification",verifier_response:"verification",verifier_receipt_fence:"verification",verifier_record_present:"verification",verifier_kind:"verification",verifier_job_payload:"verification",verifier_error_run:"verification",verifier_privacy:"verification",
 capture_window:"capture",boundary_stamp:"verification",boundary_exclusion:"verification",boundary_inclusion:"verification",
 client_close:"shutdown",
});
async function readJobReceipts(config,report,start,end,mark){
 mark("receipt_pending");assert.equal(report.pending,0);mark("receipt_lost");assert.equal(report.lost,0);mark("receipt_present");assert.ok(report.receipts.length>0);
 mark("verifier_config");const reader=process.env.SOUNDPOST_FIXTURE_READ_CREDENTIAL,endpoint=process.env.SOUNDPOST_FIXTURE_VERIFY;
 if(!reader||!endpoint||reader===config.credential)throw Error("independent_scoped_verifier_required");
 const url=new URL(endpoint);if(url.protocol!=="https:"||url.username||url.password||url.search||url.hash)throw Error("invalid_verifier_endpoint");
 const body=JSON.stringify({org_id:config.org,project_id:config.project,batch_ids:report.acknowledgedBatchIds,minimum_receipts:report.receipts.map(receipt=>({batch_id:receipt.batch_id,cursor:receipt.cursor})),trace_ids:[],start_ns:start,end_ns:end});
 mark("verifier_request");const response=await new Promise((resolve,reject)=>{
  const req=request(url,{method:"POST",headers:{authorization:"Bearer "+reader,"content-type":"application/json"},...(process.env.SOUNDPOST_FIXTURE_CA_FILE?{ca:readFileSync(process.env.SOUNDPOST_FIXTURE_CA_FILE)}:{})},res=>{const chunks=[];let bytes=0;res.on("data",chunk=>{bytes+=chunk.length;if(bytes>4194304){res.destroy();reject(Error("verifier_result_too_large"));}else chunks.push(chunk);});res.once("error",reject);res.once("end",()=>{try{if(res.statusCode!==200)throw Error("verifier_read_failed");resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));}catch(error){reject(error);}});});req.once("error",reject);req.end(body);
 });
 mark("verifier_response");assert.equal(response.partial,false);
 mark("verifier_receipt_fence");for(const receipt of report.receipts){const watermark=response.watermarks.find(value=>value.group===receipt.cursor.group);assert.ok(watermark&&BigInt(watermark.index)>=BigInt(receipt.cursor.index));}
 return response;
}
export async function verifyJobReceipts(config,report,expected,start,end,mark){
 const response=await readJobReceipts(config,report,start,end,mark);
 for(const record of expected){
  mark("verifier_record_present");const actual=response.records.find(value=>value.id===record.id);
  if(actual===undefined){
   const missingKind=["job_attempt","error","span","loss"].includes(record.kind)?record.kind:"unknown",missingJobState=record.kind==="job_attempt"&&["started","succeeded","failed","cancelled"].includes(record.payload.state)?record.payload.state:"not_applicable";
   console.error(JSON.stringify({fixture:"job_attempts",stage:"verification",code:"verifier_record_present",missing_kind:missingKind,missing_job_state:missingJobState,expected_count:expected.length,actual_count:response.records.length,actual_expected_count:response.records.filter(value=>expected.some(item=>item.id===value.id)).length,observed_equals_end:BigInt(record.observed_at_ns)===BigInt(end),observed_at_or_after_end:BigInt(record.observed_at_ns)>=BigInt(end)}));
  }
  assert.ok(actual);
  mark("verifier_kind");assert.equal(actual.kind,record.kind);
  if(record.kind==="job_attempt"){mark("verifier_job_payload");assert.deepEqual(actual.payload,record.payload);}
  if(record.kind==="error"){mark("verifier_error_run");assert.equal(actual.payload.run_id,record.payload.run_id);}
 }
 mark("verifier_privacy");assert.ok(!JSON.stringify(response.records).includes("CANARY_"));
 return {records:expected.length,batches:report.receipts.length};
}
export async function runJobAttempts(init,runtime){
 let code="registered_job_id";
 const mark=next=>{if(!Object.hasOwn(diagnosticStages,next))throw Error("invalid_fixture_diagnostic");code=next;};
 try{
  const jobId=process.env.SOUNDPOST_FIXTURE_JOB_ID;if(!jobId)throw Error("registered_job_id_required");
  mark("load_config");const config={...loadConfig(),jobRegistry:{"fixture.task":jobId},traceSampleProbability:"0000000000000000"};
  mark("initialize_client");const client=init(config),runId=randomBytes(16).toString("hex"),start=String(BigInt(Date.now())*1000000n);let complete=false;
  try{
   mark("signed_permissions");assert.ok(client.policyDecision.jobs&&client.policyDecision.errors&&client.policyDecision.loss&&client.policyDecision.traces);
   await client.withSpan("worker",async()=>{
    mark("failed_callback_identity");const original=Error("CANARY_TASK_ARGUMENT_MESSAGE");let caught;
    try{await client.withJobAttempt("fixture.task",runId,1,async()=>{await Promise.resolve();throw original;});}catch(error){caught=error;}assert.equal(caught,original);
    mark("successful_callback_identity");const result={private:"CANARY_TASK_RESULT"};assert.equal(await client.withJobAttempt("fixture.task",runId,2,async()=>{await Promise.resolve();client.captureException(Error("CANARY_HANDLED_TASK_ERROR"));return result;}),result);
    mark("timer_callback_identity");const controller=new AbortController();controller.abort();let aborted,cancelledCaught;
    try{await client.withJobAttempt("fixture.task",randomBytes(16).toString("hex"),1,async()=>{try{await delay(1000,undefined,{signal:controller.signal});}catch(error){aborted=error;throw error;}});}catch(error){cancelledCaught=error;}
    assert.ok(aborted);assert.equal(cancelledCaught,aborted);
   });
   client.captureException(Error("outside"));
   mark("prequeue_privacy");const expected=safeRecords(client),events=expected.filter(record=>record.kind==="job_attempt").map(record=>record.payload),errors=expected.filter(record=>record.kind==="error");
   mark("capture_window");const end=exclusiveCaptureEnd(String(BigInt(Date.now())*1000000n),expected);
   mark("attempt_states");assert.deepEqual(events.map(event=>event.state),["started","failed","started","succeeded","started","cancelled"]);
   mark("attempt_sequences");assert.deepEqual(events.map(event=>event.sequence),["1","2","3","4","5","6"]);
   mark("attempt_identity");assert.equal(events[0].attempt_id,events[1].attempt_id);assert.notEqual(events[0].attempt_id,events[2].attempt_id);
   mark("error_count");assert.equal(errors.length,3);
   mark("error_cause_link");assert.equal(events[1].cause_error,errors[0].id);
   mark("outside_run_link");assert.equal(errors.at(-1).payload.run_id,undefined);
   mark("unsampled_spans");assert.equal(expected.filter(record=>record.kind==="span").length,0);
   mark("flush");const report=await client.flush(10000),verified=await verifyJobReceipts(config,report,expected,start,end,mark);
   console.log(JSON.stringify({fixture:"job_attempts",runtime,actual:process.versions,platform:process.platform,real_c03_c05:true,manual_unscheduled:true,current_health_claimed:false,...verified}));complete=true;
  }finally{if(complete)mark("client_close");await client.close();}
 }catch{
  // Never inspect/stringify a thrown value, assertion detail, config or record.
  console.error(JSON.stringify({fixture:"job_attempts",runtime:runtime==="node"?"node":runtime==="bun"?"bun":"unknown",stage:diagnosticStages[code],code}));
  throw Error("job_attempt_fixture_failed");
 }
}

/** Controlled real C05 proof, independent of scheduling speed or wall resolution. */
export async function runJobBoundary(init,runtime){
 let code="registered_job_id";
 const mark=next=>{if(!Object.hasOwn(diagnosticStages,next))throw Error("invalid_fixture_diagnostic");code=next;};
 try{
  const jobId=process.env.SOUNDPOST_FIXTURE_JOB_ID;if(!jobId)throw Error("registered_job_id_required");
  mark("load_config");const at=String(BigInt(Date.now())*1000000n),config={...loadConfig(),jobRegistry:{"fixture.task":jobId},clockNs:()=>at};
  mark("boundary_stamp");if(BigInt(at)<= -9223372036854775808n)throw Error("fixture_boundary_lower_bound");
  const start=String(BigInt(at)-1n);mark("initialize_client");const client=init(config);let complete=false;
  try{
   mark("signed_permissions");assert.ok(client.policyDecision.jobs&&client.policyDecision.errors&&client.policyDecision.loss&&client.policyDecision.traces);
   mark("successful_callback_identity");const result={private:"CANARY_BOUNDARY_RESULT"};
   assert.equal(await client.withJobAttempt("fixture.task",randomBytes(16).toString("hex"),1,async()=>{await Promise.resolve();return result;}),result);
   client.captureException(Error("CANARY_BOUNDARY_ERROR"));
   mark("prequeue_privacy");const expected=safeRecords(client);
   mark("boundary_stamp");assert.equal(expected.length,3);assert.ok(expected.every(record=>record.observed_at_ns===at));
   mark("capture_window");const plusOne=exclusiveCaptureEnd(at,expected);assert.equal(BigInt(plusOne),BigInt(at)+1n);
   mark("flush");const report=await client.flush(10000);
   const equalEnd=await readJobReceipts(config,report,start,at,mark);
   mark("boundary_exclusion");assert.equal(equalEnd.records.filter(record=>expected.some(value=>value.id===record.id)).length,0);
   mark("boundary_inclusion");const verified=await verifyJobReceipts(config,report,expected,start,plusOne,mark);
   console.log(JSON.stringify({fixture:"job_attempt_boundary",runtime,actual:process.versions,platform:process.platform,excluded_at_equal_end:true,included_at_plus_one_ns:true,known_observed_equals_end:true,manual_unscheduled:true,current_health_claimed:false,...verified}));complete=true;
  }finally{if(complete)mark("client_close");await client.close();}
 }catch{
  console.error(JSON.stringify({fixture:"job_attempt_boundary",runtime:runtime==="node"?"node":runtime==="bun"?"bun":"unknown",stage:diagnosticStages[code],code}));
  throw Error("job_attempt_boundary_fixture_failed");
 }
}
