// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {readFileSync} from "node:fs";
import {request} from "node:https";
export const operations=["request","http.call","db.execute","worker","worker.unrelated","navigation"];
export function loadConfig(variable="SOUNDPOST_FIXTURE_CONFIG") {
 const path=process.env[variable];if(!path)throw Error("private_config_required");const raw=JSON.parse(readFileSync(path,"utf8")),keys=raw.trustedKeys??raw.trusted_keys;
 const trustedKeys=Object.fromEntries(Object.entries(keys).map(([name,value])=>[name,Uint8Array.from(Buffer.from(value,"base64url"))]));
 const endpoint=process.env.SOUNDPOST_FIXTURE_INGEST??raw.endpoint;if(new URL(endpoint).protocol!=="https:")throw Error("verified_https_ingest_required");
 return {org:raw.org,project:raw.project,source:raw.source,endpoint,credential:raw.credential,build:raw.build,policy:raw.policy,trustedKeys,resource:raw.resource,descriptor:raw.descriptor,operations,dependencies:["dependency","postgres"],origins:["dependency"],deploymentTraces:true,deploymentErrors:true};
}
export function workerEnvironment() {return Object.fromEntries(["SOUNDPOST_FIXTURE_WORKER_CONFIG","SOUNDPOST_FIXTURE_INGEST","SOUNDPOST_FIXTURE_CA_FILE","NODE_EXTRA_CA_CERTS","SystemRoot"].flatMap(name=>process.env[name]===undefined?[]:[[name,process.env[name]]]));}
export function safeRecords(client) {const records=client.bufferedRecords().map(text=>JSON.parse(text));const raw=JSON.stringify({records,diagnostics:client.diagnostics()});if(/CANARY_|SELECT|division by zero/.test(raw))throw Error("prequeue_privacy_failure");return records;}
export async function verify(client,config,expected,start,end) {
 const report=await client.flush(10000);return verifyReceipts(report,config,expected,start,end);
}
export async function verifyReceipts(report,config,expected,start,end) {
 if(report.pending||report.lost||!report.receipts.length)throw Error("durable_delivery_incomplete");
 const endpoint=process.env.SOUNDPOST_FIXTURE_VERIFY,reader=process.env.SOUNDPOST_FIXTURE_READ_CREDENTIAL;if(!endpoint||!reader||reader===config.credential)throw Error("independent_reader_required");const url=new URL(endpoint);if(url.protocol!=="https:"||url.username||url.password||url.search||url.hash)throw Error("invalid_verifier_endpoint");
 const body=JSON.stringify({org_id:config.org,project_id:config.project,batch_ids:report.acknowledgedBatchIds,minimum_receipts:report.receipts.map(receipt=>({batch_id:receipt.batch_id,cursor:receipt.cursor})),trace_ids:[...new Set(expected.filter(record=>record.kind==="span").map(record=>record.payload.trace_id))].sort(),start_ns:start,end_ns:end});
 const {promise,resolve,reject}=Promise.withResolvers();const req=request(url,{method:"POST",headers:{authorization:"Bearer "+reader,"content-type":"application/json"},...(process.env.SOUNDPOST_FIXTURE_CA_FILE?{ca:readFileSync(process.env.SOUNDPOST_FIXTURE_CA_FILE)}:{})},response=>{const chunks=[];let size=0;response.on("data",chunk=>{size+=chunk.length;if(size>4194304){response.destroy();reject(Error("verifier_result_too_large"));}else chunks.push(chunk);});response.once("error",reject);response.once("end",()=>{try{if(response.statusCode!==200)throw Error("verifier_read_failed");resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));}catch(error){reject(error);}});});req.once("error",reject);req.end(body);const result=await promise;
 if(result.partial!==false)throw Error("partial_verifier_result");const watermarks=new Map(result.watermarks.map(value=>[value.group,BigInt(value.index)]));for(const receipt of report.receipts)if((watermarks.get(receipt.cursor.group)??-1n)<BigInt(receipt.cursor.index))throw Error("minimum_receipt_not_visible");
 const selected=result.records.filter(record=>expected.some(value=>value.id===record.id));if(selected.length!==expected.length)throw Error("admitted_records_missing");const actual=new Map(selected.map(record=>[record.id,record]));for(const record of expected){const admitted=actual.get(record.id);if(admitted.kind!==record.kind)throw Error("admitted_kind_changed");if(record.kind==="span"){const span=admitted.payload;if(span.trace_id!==record.payload.trace_id||span.parent_id!==record.payload.parent_id||span.span_id!==record.payload.span_id||span.operation!==record.payload.operation||span.status!==record.payload.status)throw Error("admitted_causality_changed");if(span.end&&((JSON.stringify(span.start.domain)!==JSON.stringify(span.end.domain))||BigInt(span.end.mono_ns)<BigInt(span.start.mono_ns)))throw Error("invalid_clock_pair");}}
 if(/CANARY_|SELECT|division by zero/.test(JSON.stringify(selected)))throw Error("export_privacy_failure");return {records:selected.length,batches:report.receipts.length};
}
