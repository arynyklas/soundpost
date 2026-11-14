// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {readFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
import {Client as NodeClient} from '../../../packages/node/src/index.ts';
import {Client as BunClient} from '../../../packages/bun/src/index.ts';
import {HttpsReceiptTransport,type ReceiptTransport,type HttpRequest} from '../../../packages/core/src/transport.ts';
import type {Config,SignedPolicy,Resource,RoutingDescriptor,Template} from '../../../packages/core/src/types.ts';
import {object,text,array} from '../../../packages/core/src/wire.ts';
import {resolve} from '../../../packages/core/src/policy.ts';
import {DeliveryQueue} from '../../../packages/core/src/queue.ts';
const argv=process.argv.slice(2),index=argv.indexOf('--config');if(index<0||!argv[index+1])throw Error('private backend config required');
const data=object(JSON.parse(await readFile(argv[index+1]!,'utf8'))),keys=object(data.trusted_keys),trustedKeys:Record<string,Uint8Array>={};
for(const [key,value] of Object.entries(keys))trustedKeys[key]=new Uint8Array(Buffer.from(text(value),'base64url'));
// Fixture-owned config is additionally validated by the real SDK's policy/resource/descriptor boundaries.
const policy=object(data.policy),resource=object(data.resource),descriptor=object(data.descriptor);
const cfg:Config={org:text(data.org),project:text(data.project),source:text(data.source),endpoint:text(data.endpoint),credential:text(data.credential),build:text(data.build),trustedKeys,policy:{version:policy.version,algorithm:policy.algorithm,key_id:policy.key_id,payload:policy.payload,signature:policy.signature} as SignedPolicy,resource:resource as unknown as Resource,descriptor:descriptor as unknown as RoutingDescriptor,templates:(data.templates===undefined?[]:array(data.templates)) as Template[]};
// Bun can scope this CA to the request. Native Node uses NODE_EXTRA_CA_CERTS at startup.
const ca=await readFile(text(data.ca_file),'utf8');
const request:HttpRequest=typeof Bun==='undefined'?globalThis.fetch.bind(globalThis):(input,init)=>fetch(input,{...init,tls:{ca,rejectUnauthorized:true}});
const real=new HttpsReceiptTransport(cfg,request);let lost=false,sends=0,lookups=0;
const transport:ReceiptTransport={async send(batch,deadline){sends++;const outcome=await real.send(batch,deadline);if(argv.includes('--lost-response')&&!lost&&outcome.kind==='receipt'){lost=true;return {kind:'ambiguous'};}return outcome;},async lookup(batch,deadline){lookups++;return real.lookup(batch,deadline);},close(){real.close();}};
if(argv.includes('--native-loss')){
 assert.equal(resolve(cfg).decision.loss,true);const queue=new DeliveryQueue(cfg,transport);
 try{assert.equal(queue.recordSignalLoss('span','policy',9007199254740993n,String(BigInt(Date.now())*1000000n)),true);let report=await queue.flush();if(report.pending)report=await queue.flush();assert.equal(report.pending,0);assert.equal(report.lost,0);assert.equal(sends,1);const counters=queue.signalLossCounters();assert.equal(counters[0]?.observed_count,'9007199254740993');assert.equal(counters[0]?.acknowledged_count,'9007199254740993');if(argv.includes('--lost-response')){assert.equal(lookups,1);assert.equal(report.receipts[0]?.historical,true);}console.log(JSON.stringify({runtime:typeof Bun==='undefined'?'node':'bun',realGoBackend:true,tlsVerification:true,nativeLoss:true,...report,counters,sends,lookups}));}finally{await queue.close();}
}else{
const RuntimeClient=typeof Bun==='undefined'?NodeClient:BunClient,client=new RuntimeClient({...cfg,transport});
try{
 const event=client.captureException(Error('NEVER_EXPORT_BACKEND_CANARY'));let report=await client.flush();if(report.pending)report=await client.flush();assert.equal(report.pending,0);assert.equal(report.lost,0);assert.equal(report.receipts.length,1);assert.equal(sends,1);if(argv.includes('--lost-response')){assert.equal(lookups,1);assert.equal(report.receipts[0]?.historical,true);}
 console.log(JSON.stringify({runtime:typeof Bun==='undefined'?'node':'bun',realGoBackend:true,tlsVerification:true,eventId:event,...report,sends,lookups}));
}finally{await client.close();}
}
