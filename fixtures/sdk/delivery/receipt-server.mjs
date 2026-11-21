// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Test-only HTTPS durable/idempotent ledger, not a backend durability substitute.
import https from 'node:https';
import {open,mkdir,readFile,rename} from 'node:fs/promises';
import {join} from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
const id=v=>typeof v==='string'&&/^[0-9a-f]{32}$/.test(v)&&v!=='0'.repeat(32);
const canonical=v=>v===null||typeof v!=='object'?JSON.stringify(v).replace(/\u2028/g,'\\u2028').replace(/\u2029/g,'\\u2029'):Array.isArray(v)?'['+v.map(canonical).join(',')+']':'{'+Object.keys(v).sort((a,b)=>Buffer.compare(Buffer.from(a),Buffer.from(b))).map(k=>canonical(k)+':'+canonical(v[k])).join(',')+'}';
function slot(org,project,source,producer,r){const p=r.payload;let owner;if(r.kind==='metric')owner=canonical({name:p.name,labels:p.labels});else if(r.kind==='log')owner=canonical(p.stream_labels);else if(['capability','loss'].includes(r.kind))owner=source+producer+r.kind;else owner=p[{span:'trace_id',error:'occurrence_id',job_attempt:'run_id',replay_chunk:'replay_id',profile_chunk:'profile_id',condition:'condition_id'}[r.kind]];const parts=[org,project,r.kind,owner].map(v=>Buffer.from(v));const h=createHash('sha256');for(const part of parts){const size=Buffer.alloc(4);size.writeUInt32BE(part.length);h.update(size);h.update(part);}return Number(h.digest().readBigUInt64BE()%64n);}
async function persist(path,value){const temp=path+'.'+randomBytes(16).toString('hex');const f=await open(temp,'wx',0o600);try{await f.writeFile(JSON.stringify(value));await f.sync();}finally{await f.close();}await rename(temp,path);if(process.platform!=='win32'){const d=await open(join(path,'..'),'r');try{await d.sync();}finally{await d.close();}}}
export async function createReceiptServer({cert,key,directory,org,project,source,credential='fixture-private'}){
 await mkdir(directory,{recursive:true,mode:0o700});const path=join(directory,'ledger.json');let state={version:1,index:'0',receipts:{},data:{},admitted:0,normalized:0,reservations:0,appends:0};
 try{state=JSON.parse(await readFile(path,'utf8'));if(state.version!==1||!state.receipts||!state.data)throw Error('invalid ledger');}catch(error){if(error?.code!=='ENOENT')throw error;}
 let scenario='normal',lost=false,revoked=false,retired=false,restricted=false,lookups=0,sends=0;const bodies=[];let serial=Promise.resolve();
 const server=https.createServer({cert,key},(request,response)=>{serial=serial.then(async()=>{
  const reply=(status,value)=>{response.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store',...(status===429||status===503?{'Retry-After':'1'}:{})});response.end(JSON.stringify(value));};
  if(request.method!=='POST'||!['/ingest/v1/batches','/ingest/v1/receipts'].includes(request.url)){reply(404,{code:'not_found'});return;}
  if(request.headers.cookie||request.headers.authorization!=='Bearer '+credential||request.headers['x-soundpost-source']||revoked||retired){reply(403,{code:'forbidden'});return;}
  let bytes=Buffer.alloc(0);for await(const part of request){bytes=Buffer.concat([bytes,part]);if(bytes.length>1048576){reply(413,{code:'too_large'});return;}}
  let body;try{body=JSON.parse(bytes.toString('utf8'));}catch{reply(422,{code:'invalid'});return;}
  if(request.url==='/ingest/v1/receipts'){
   lookups++;if(body.source!==source||!id(body.producer)||!id(body.batch_id)||typeof body.route_slot!=='number'){reply(403,{code:'forbidden'});return;}
   const identity=[source,body.producer,body.route_slot,body.batch_id].join(':');const original=state.receipts[identity];if(!original){reply(404,{code:'not_found'});return;}
   if(original.hash!==body.original_hash){reply(409,{code:'conflict'});return;}reply(200,{...original,historical:true});return;
  }
  sends++;bodies.push(bytes.toString('utf8'));
  if(scenario==='offline'){reply(503,{code:'unavailable'});return;}
  if(restricted){reply(403,{code:'forbidden'});return;}
  if(scenario==='quota'){reply(429,{code:'quota'});return;}
  if(body.version!==1||body.project!==project||body.source!==source||!id(body.producer)||!id(body.id)||!Array.isArray(body.records)||!body.records.length||body.records.length>512||!Number.isInteger(body.route_slot)||body.route_slot<0||body.route_slot>=64){reply(422,{code:'invalid'});return;}
  try{for(const record of body.records){if(!id(record.id)||!id(record.resource.service_id)||!id(record.resource.environment_id)||!id(record.resource.build_id)||typeof record.resource.instance_pseudonym!=='string'||slot(org,project,source,body.producer,record)!==body.route_slot)throw Error();}}catch{reply(422,{code:'invalid'});return;}
  const normalized=canonical(body),hash=createHash('sha256').update(normalized).digest('hex'),identity=[source,body.producer,body.route_slot,body.id].join(':');let original=state.receipts[identity];
  if(original&&original.hash!==hash){reply(409,{code:'conflict'});return;}
  if(!original){
   const now=BigInt(Date.now())*1000000n,kinds=[...new Set(body.records.map(r=>r.kind))].sort(),deadlines=kinds.map(kind=>({kind,retain_until_ns:String(now+BigInt(kind==='error'?30:7)*86400000000000n)}));
   original={version:1,batch_id:body.id,hash,cursor:{group:'f'.repeat(32),index:String(BigInt(state.index)+1n)},retain_until_ns:String(deadlines.reduce((a,d)=>BigInt(d.retain_until_ns)<a?BigInt(d.retain_until_ns):a,BigInt(deadlines[0].retain_until_ns))),signal_deadlines:deadlines,dedup_until_ns:String(now+604800000000000n)};
   const next={...state,index:original.cursor.index,receipts:{...state.receipts,[identity]:original},data:{...state.data,[identity]:body.records},admitted:state.admitted+1,normalized:state.normalized+1,reservations:state.reservations+1,appends:state.appends+1};
   await persist(path,next);state=next;
  }
  if(['response-lost','historical-policy-delete','revoked-receipt','retired-receipt'].includes(scenario)&&!lost){lost=true;request.socket.destroy();return;}
  if(scenario==='invalid-receipt'){reply(200,{...original,hash:'0'.repeat(64)});return;}
  reply(200,original);
 }).catch(()=>{if(!response.headersSent)response.writeHead(503,{'Content-Type':'application/json'});response.end('{"code":"unavailable"}');});});
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
 return {endpoint:`https://127.0.0.1:${server.address().port}/ingest/v1/batches`,setScenario(value){scenario=value;lost=false;},async restrictAndDelete(){restricted=true;state={...state,data:{}};await persist(path,state);},revoke(){revoked=true;},retire(){retired=true;},stats(){return {...state,dataRows:Object.keys(state.data).length,lookups,sends,bodies:[...bodies]};},async close(){await serial;await new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));}};
}
