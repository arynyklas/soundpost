// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {createServer,request} from 'node:https';
import {readFileSync} from 'node:fs';
import type {AddressInfo} from 'node:net';
// A fault barrier in front of the REAL server, outside the browser: an HTTPS reverse proxy (the same private leaf certificate the real
// server uses, so the browser trusts it the same way) that forwards every request to the real server, lets the real server compute the
// real answer, and then holds the answer on the wire until the test releases it. The delay is therefore a property of the network path
// between server and browser, not of anything the browser does to its own requests. Origin and Referer are rewritten to the upstream
// origin (the server only accepts its own origin); cookies are host-scoped, so the session of the real origin works through the proxy.
export interface Barrier{
 /** https://127.0.0.1:<port>, the address the browser opens instead of the real server. */
 origin:string;
 /** How many responses are being held right now. */
 held():number;
 /** Release every held response and stop holding anything that follows. */
 release():void;
 close():Promise<void>;
}
/** `hold` decides, per request path and body, whether the real answer is held until release(). */
export async function barrierProxy(upstream:string,pki:string,hold:(path:string,body:string)=>boolean):Promise<Barrier>{
 const target=new URL(upstream);
 const {promise:gate,resolve:openGate}=Promise.withResolvers<void>();
 let open=false;
 let heldNow=0;
 const server=createServer({key:readFileSync(`${pki}/leaf.key`),cert:readFileSync(`${pki}/leaf.pem`)},(req,res)=>{
  const chunks:Buffer[]=[];
  req.on('data',(c:Buffer)=>chunks.push(c));
  req.on('end',()=>{
   const body=Buffer.concat(chunks);
   const headers={...req.headers,host:target.host};
   if(typeof headers.origin==='string')headers.origin=target.origin;
   if(typeof headers.referer==='string')headers.referer=headers.referer.replace(/^https:\/\/[^/]+/,target.origin);
   delete headers['accept-encoding'];
   const forward=request({host:target.hostname,port:target.port,path:req.url,method:req.method,headers},(answer)=>{
    const parts:Buffer[]=[];
    answer.on('data',(c:Buffer)=>parts.push(c));
    answer.on('end',()=>{
     const send=():void=>{res.writeHead(answer.statusCode??502,answer.headers);res.end(Buffer.concat(parts));};
     if(!open&&hold(req.url??'',body.toString('utf8'))){heldNow++;void gate.then(()=>{heldNow--;send();});}else send();
    });
   });
   forward.on('error',()=>{res.writeHead(502);res.end();});
   forward.end(body);
  });
 });
 const {promise:listening,resolve:listen}=Promise.withResolvers<void>();
 server.listen(0,'127.0.0.1',listen);
 await listening;
 const {port}=server.address() as AddressInfo;
 return {
  origin:`https://127.0.0.1:${port}`,
  held:()=>heldNow,
  release:()=>{open=true;openGate();},
  close:()=>{const {promise,resolve}=Promise.withResolvers<void>();server.closeAllConnections();server.close(()=>resolve());return promise;},
 };
}
