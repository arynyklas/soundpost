// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {test,expect} from "@playwright/test";
import {readFileSync} from "node:fs";
const targets:Record<string,string>={Chrome:"142.0.7444.59",Edge:"142.0.3595.53",Firefox:"144.0.2",Safari:"26.0.1"};
test("actual browser preserves manual job outcomes and C03/C05 evidence without ambient async guesses",async({page,browser,request})=>{
 const target=process.env.SOUNDPOST_FIXTURE_BROWSER_TARGET,fixture=process.env.SOUNDPOST_FIXTURE_BROWSER_JOB_URL,configPath=process.env.SOUNDPOST_FIXTURE_BROWSER_CONFIG,jobId=process.env.SOUNDPOST_FIXTURE_JOB_ID,verifier=process.env.SOUNDPOST_FIXTURE_VERIFY,reader=process.env.SOUNDPOST_FIXTURE_READ_CREDENTIAL;
 if(!target||!targets[target]||!fixture||!configPath||!jobId||!verifier||!reader)throw Error("exact_browser_job_fixture_config_required");
 if(target==="Safari")throw Error("Safari_requires_actual_pinned_macOS_driver_not_Playwright_WebKit");expect(browser.version()).toBe(targets[target]);
 const config=JSON.parse(readFileSync(configPath,"utf8"));if(config.sourceClass!=="browser"||reader===config.credential)throw Error("independent_browser_writer_and_reader_required");
 const ingestHeaders:Record<string,string>[]=[];page.on("request",event=>{const url=new URL(event.url());if(url.origin===new URL(config.endpoint).origin&&url.pathname.startsWith("/ingest/v1/")&&event.method()==="POST")ingestHeaders.push(event.headers());});
 await page.context().addCookies([{name:"CANARY_INGEST_COOKIE",value:"CANARY_COOKIE",url:new URL(config.endpoint).origin,secure:true,sameSite:"None"}]);
 await page.goto(fixture);await page.waitForFunction(()=>typeof Reflect.get(globalThis,"runJobAttempts")==="function");
 const result=await page.evaluate(async input=>{const keys=Object.fromEntries(Object.entries(input.config.trustedKeys??input.config.trusted_keys).map(([name,value])=>{const text=String(value).replace(/-/g,"+").replace(/_/g,"/");return [name,Uint8Array.from(atob(text+"=".repeat((4-text.length%4)%4)),character=>character.charCodeAt(0))];}));return await Reflect.get(globalThis,"runJobAttempts")({...input.config,trustedKeys:keys,jobRegistry:{"fixture.task":input.jobId}});},{config,jobId});
 expect(result.report.pending).toBe(0);expect(result.report.lost).toBe(0);expect(result.report.receipts.length).toBeGreaterThan(0);expect(ingestHeaders.length).toBeGreaterThan(0);
 for(const headers of ingestHeaders){expect(headers.cookie).toBeUndefined();expect(headers.authorization).toBeUndefined();}
 const response=await request.post(verifier,{data:{org_id:config.org,project_id:config.project,batch_ids:result.report.acknowledgedBatchIds,minimum_receipts:result.report.receipts.map((receipt:any)=>({batch_id:receipt.batch_id,cursor:receipt.cursor})),trace_ids:[],start_ns:result.start_ns,end_ns:result.end_ns},headers:{authorization:"Bearer "+reader},ignoreHTTPSErrors:false});
 expect(response.status()).toBe(200);const admitted=await response.json();expect(admitted.partial).toBe(false);
 for(const receipt of result.report.receipts){const watermark=admitted.watermarks.find((value:any)=>value.group===receipt.cursor.group);expect(watermark).toBeDefined();expect(BigInt(watermark.index)>=BigInt(receipt.cursor.index)).toBe(true);}
 for(const record of result.records){const actual=admitted.records.find((value:any)=>value.id===record.id);expect(actual).toBeDefined();expect(actual.kind).toBe(record.kind);if(record.kind==="job_attempt")expect(actual.payload).toEqual(record.payload);if(record.kind==="error")expect(actual.payload.run_id).toBe(record.payload.run_id);}
 expect(JSON.stringify(admitted.records)).not.toContain("CANARY_");test.info().annotations.push({type:"runtime",description:JSON.stringify({target,actual:browser.version(),userAgent:result.userAgent,platform:process.platform,manualUnscheduled:true,currentHealthClaimed:false})});
});
