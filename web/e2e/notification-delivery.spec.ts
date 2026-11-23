// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect,type APIRequestContext,type Page} from '@playwright/test';
import {readFileSync} from 'node:fs';
import {createServer as createHttps,type Server} from 'node:https';
import type {AddressInfo} from 'node:net';
import {adminCommand,createOrg,createProject,field,id,ingestError,login,onboardErrorSource,owner,postJson} from './support/real';
// [05.03-W1] Failed and uncertain notification delivery against the REAL served process. Nothing is seeded: an error is ingested through
// a real source credential, the leader-only runner opens the incident, the notification worker (acting as the in-process system
// principal) submits it to the durable outbox for every enabled destination of the organization and really SENDS through the signed
// webhook provider. Three organizations, three real destinations:
//   failed     endpoint on 127.0.0.1 -> the provider's egress policy refuses it (terminal, egress_blocked): the delivery FAILED.
//   uncertain  a real HTTPS receiver on the host's private address (allow-listed by `serve --notify-egress-allow`) that reads the
//              request and never answers -> the send times out after the request was written: the provider MAY have accepted it.
//   accepted   the same receiver answering 200 -> accepted by the provider.
// The queue and the incident read the committed outbox/policy state back; the page must name each outcome and never call a failed or
// uncertain delivery sent. The harness (web/e2e-harness/h.sh, E2E_NOTIFY_IP) starts the server with the allow-list, the private CA and a
// short send timeout.
const ip=process.env.E2E_NOTIFY_IP,pki=process.env.E2E_PKI;
if(!ip||!pki)throw new Error('E2E_NOTIFY_IP and E2E_PKI are required: run through web/e2e-harness/h.sh with E2E_NOTIFY_IP set to a private address of this host');
const nsOf=(ms:number):string=>String(BigInt(ms)*1_000_000n);
const WINDOW={start:nsOf(Date.now()-3*3600_000),end:nsOf(Date.now()+3*3600_000)};
const hash=(org:string,project:string,view:string,incident?:string):string=>`#${new URLSearchParams({org,projects:project,start:WINDOW.start,end:WINDOW.end,tz:'UTC',view,...(incident?{incident:`${project}:${incident}`}:{})})}`;
interface Hits{hang:number;ok:number}
function receiver(hits:Hits):Promise<Server>{
 const {promise,resolve}=Promise.withResolvers<Server>();
 const server=createHttps({key:readFileSync(`${pki}/leaf.key`),cert:readFileSync(`${pki}/leaf.pem`)},(req,res)=>{
  req.resume();
  if(req.url==='/ok'){hits.ok++;req.on('end',()=>{res.statusCode=200;res.end('ok');});return;}
  hits.hang++; // read the whole request, never answer: the sender cannot know whether it was taken
 });
 server.listen(0,ip,()=>resolve(server));
 return promise;
}
async function destination(page:Page,org:string,endpoint:string):Promise<void>{
 await adminCommand(page,org,'destination',{id:id(),config:{type:'webhook',endpoint,enabled:true},secret:'e2e-webhook-signing-secret-0123456789'});
}
/** A real org + project + destination + error source; ingests one unhandled error and returns the runner-opened incident. */
async function seed(page:Page,api:APIRequestContext,endpoint:string):Promise<{org:string;project:string;incident:string}> {
 const org=await createOrg(page,'delivery e2e org');
 const project=await createProject(page,org);
 await destination(page,org,endpoint);
 const source=await onboardErrorSource(page,org,project);
 await ingestError(api,source,{at:nsOf(Date.now()),class:'DeliveryE2eFailure',fatal:false,handled:false});
 let incident='';
 await expect.poll(async()=>{
  const r=await postJson(page,'/api/v1/queue',{org,projects:[project],limit:50});
  const entries=field(r.json,'entries');
  const first=Array.isArray(entries)?field(entries[0],'incident_id'):undefined;
  incident=typeof first==='string'?first:'';
  return incident;
 // The runner visits every project of the installation on each pass, so its latency grows with what the specs before this one created (measured in
 // the full suite, l3w15-fine: job-history waits of 42 s against 8 s alone), and an incident needs the issue and the incident stage in turn.
 },{message:'the runner opens an incident for the ingested error',timeout:240_000,intervals:[250,500,1000]}).not.toBe('');
 return {org,project,incident};
}
/** Polls the real queue route until the incident's delivery attention is the wanted one (the worker has really tried to send). */
async function until(page:Page,t:{org:string;project:string;incident:string},attention:string):Promise<void>{
 await expect.poll(async()=>{
  const r=await postJson(page,'/api/v1/queue',{org:t.org,projects:[t.project],limit:50});
  const entries=field(r.json,'entries');
  const row=Array.isArray(entries)?entries.find((e)=>field(e,'incident_id')===t.incident):undefined;
  return field(field(field(row,'notification'),'delivery'),'attention');
 },{message:`the incident's delivery becomes ${attention}`,timeout:240_000,intervals:[500,1000,2000]}).toBe(attention);
}

test('failed, uncertain and accepted delivery are each named in the queue and on the incident',async({page,playwright})=>{
 test.setTimeout(1_200_000);
 const who=owner();
 await login(page,who.email,who.password);
 const api=await playwright.request.newContext();
 const hits:Hits={hang:0,ok:0};
 const server=await receiver(hits);
 try{
  const port=(server.address() as AddressInfo).port;
  const failed=await seed(page,api,'https://127.0.0.1:9/hook');
  const uncertain=await seed(page,api,`https://${ip}:${port}/hang`);
  const accepted=await seed(page,api,`https://${ip}:${port}/ok`);
  await until(page,failed,'failed');
  await until(page,uncertain,'uncertain');
  await until(page,accepted,'accepted');
  // The uncertain send really reached the receiver (it read a request and never answered); the accepted one got its 200.
  expect(hits.hang).toBeGreaterThan(0);
  expect(hits.ok).toBeGreaterThan(0);

  const check=async(t:typeof failed,attention:string,headline:RegExp,entry:RegExp[],forbidden:RegExp[])=>{
   await page.goto(`/${hash(t.org,t.project,'queue')}`);
   const row=page.locator(`tr[data-incident="${t.incident}"]`);
   await expect(row.locator('[data-cell="delivery"]')).toHaveAttribute('data-attention',attention);
   await expect(row.locator('[data-cell="delivery"]')).toHaveText(headline);
   await expect(row.locator('[data-cell="urgency"]')).toContainText('Urgency: urgent, notifies immediately');
   await expect(row.locator('[data-cell="unread"]')).toContainText('Unread change: changed since the last digest covered it');
   await expect(row.locator('[data-cell="digest"]')).toContainText('Digest:');
   const text=await row.locator('[data-cell="delivery-entries"]').innerText();
   for(const re of entry)expect(text).toMatch(re);
   for(const re of forbidden)expect(text+await row.locator('[data-cell="delivery"]').innerText()).not.toMatch(re);
   // Delivery state is visible at once: the row is there before any 09:00 digest and the page says so.
   await expect(page.getByText('not at a scheduled digest time')).toBeVisible();
   await expect(page.locator('[data-section="delivery"]')).toHaveCount(0);
   // The incident page shows the same committed state.
   await page.goto(`/${hash(t.org,t.project,'incidents',t.incident)}`);
   await expect(page.getByTestId('delivery')).toHaveAttribute('data-attention',attention);
   await expect(page.getByTestId('delivery')).toHaveText(headline);
   const entries=await page.getByTestId('delivery-entries').innerText();
   for(const re of entry)expect(entries).toMatch(re);
   expect(await page.locator('main').innerText()).not.toMatch(/\b0\s*%/);
  };
  await check(failed,'failed',/^Delivery failed/,[/open \(immediate\): failed/,/last attempt terminal \(egress_blocked\)/,/1 attempt/],[/accepted by the provider/,/uncertain/]);
  await check(uncertain,'uncertain',/^Delivery uncertain: the provider may have accepted a message the product could not confirm/,[/open \(immediate\): uncertain: the provider may have accepted/,/last attempt unknown \(timeout\)/],[/accepted by the provider/,/failed/]);
  await check(accepted,'accepted',/^Delivery accepted by the provider/,[/open \(immediate\): accepted by the provider/,/1 attempt/],[/failed/,/uncertain/]);
 }finally{
  server.closeAllConnections();
  await new Promise<void>((resolve)=>server.close(()=>resolve()));
 }
});
