// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {mkdtemp,readFile,mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import assert from 'node:assert/strict';
import {createReceiptServer} from './receipt-server.mjs';
import {config,ORG,PROJECT,SOURCE} from '../../../packages/core/test/fixture.ts';
import {Client} from '../../../packages/bun/src/index.ts';
import {HttpsReceiptTransport,type ReceiptTransport,type HttpRequest} from '../../../packages/core/src/transport.ts';
const arguments_=process.argv.slice(2),position=arguments_.indexOf('--scenario');
const scenarios=(position<0?'response-lost,offline,overflow,page-exit,historical-policy-delete,revoked-receipt':arguments_[position+1]!).split(',');
const directory=await mkdtemp(join(tmpdir(),'soundpost-delivery-'));const certPath=join(directory,'cert.pem'),keyPath=join(directory,'key.pem');
// A fresh local CA/leaf fixture, never a machine-wide trust installation or TLS bypass.
const opensslPosition=arguments_.indexOf('--openssl'),openssl=opensslPosition<0?(process.env.SOUNDPOST_OPENSSL??'openssl'):arguments_[opensslPosition+1];if(!openssl)throw Error('OpenSSL fixture executable required');
const generated=spawnSync(openssl,['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1,DNS:localhost','-keyout',keyPath,'-out',certPath],{stdio:'ignore'});
if(generated.error||generated.status!==0)throw Error('OpenSSL fixture certificate generation failed');
const cert=await readFile(certPath,'utf8'),key=await readFile(keyPath,'utf8');
const trustedFetch:HttpRequest=(input,init)=>fetch(input,{...init,tls:{ca:cert,rejectUnauthorized:true}});
const outputs=[];
for(const scenario of scenarios){
 await mkdir(join(directory,scenario));const server=await createReceiptServer({cert,key,directory:join(directory,scenario),org:ORG,project:PROJECT,source:SOURCE});server.setScenario(scenario);
 const cfg={...config(),endpoint:server.endpoint,credential:'fixture-private'},transport=new HttpsReceiptTransport(cfg,trustedFetch);const client=new Client({...cfg,transport});
 try{
  if(scenario==='overflow'){
   for(let i=0;i<1100;i++)client.captureException(Error('SECRET_CANARY'));assert.equal(client.bufferedRecords().length,1024);assert.equal(client.diagnostics().queue_full,76);const r=await client.flush();assert.equal(r.pending,0);outputs.push({scenario,pending:r.pending,lost:r.lost});
  }else if(scenario==='page-exit'){
   const unread:ReceiptTransport={async send(batch,deadline){const response=await trustedFetch(cfg.endpoint,{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+cfg.credential},body:batch.body,keepalive:true,credentials:'omit',redirect:'error',cache:'no-store',referrerPolicy:'no-referrer',signal:AbortSignal.timeout(Math.max(1,Math.floor(deadline-performance.now())))});await response.body?.cancel();return {kind:'unacknowledged'};},lookup:(batch,deadline)=>transport.lookup(batch,deadline),close(){}};const pageClient=new Client({...cfg,transport:unread});pageClient.captureException(Error('SECRET_CANARY'));try{const r=await pageClient.flush(200);assert.equal(r.pending,1);assert.equal(r.acknowledgedBatchIds.length,0);assert.equal(server.stats().admitted,1);outputs.push({scenario,pending:r.pending,acknowledged:0,admitted:1});}finally{await pageClient.close();}
  }else{
   client.captureException(Error('SECRET_CANARY'));const start=performance.now(),first=await client.flush(scenario==='offline'?undefined:200);assert.ok(performance.now()-start<2300);
   if(scenario==='offline'){assert.equal(first.pending,1);assert.equal(first.acknowledgedBatchIds.length,0);outputs.push({scenario,pending:first.pending,deadlineExceeded:first.deadlineExceeded});}
   else{
    assert.equal(first.pending,1);assert.equal(server.stats().admitted,1);
    if(scenario==='historical-policy-delete')await server.restrictAndDelete();if(scenario==='revoked-receipt')server.revoke();if(scenario==='retired-receipt')server.retire();
    const before=server.stats(),second=await client.flush(1000),after=server.stats();
    if(scenario==='revoked-receipt'||scenario==='retired-receipt'){assert.equal(second.pending,1);assert.equal(second.acknowledgedBatchIds.length,0);}
    else{assert.equal(second.pending,0);assert.equal(second.receipts[0]?.historical,true);}
    assert.equal(after.admitted,1);assert.equal(after.normalized,before.normalized);assert.equal(after.reservations,before.reservations);assert.equal(after.appends,before.appends);assert.equal(after.sends,1);
    if(scenario==='historical-policy-delete')assert.equal(after.dataRows,0);
    outputs.push({scenario,admitted:after.admitted,lookups:after.lookups,pending:second.pending,historical:second.receipts[0]?.historical??false});
   }
  }
  assert.ok(!JSON.stringify(client.diagnostics()).includes('SECRET_CANARY'));assert.ok(!client.bufferedRecords().join('').includes('SECRET_CANARY'));
 }finally{await client.close();await server.close();}
}
console.log(JSON.stringify({fixture:'durable_https_receipt_faults',tlsVerification:true,scenarios:outputs,artifacts:directory}));
