// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {RoutingDescriptor} from './types.ts';
import {nativeCanonical,validateDescriptor} from './routing.ts';
import {decimal} from './policy.ts';
import {strictJSON} from './transport.ts';
import {object} from './wire.ts';
export interface SpoolBackend {read(maxBytes:number):Promise<Uint8Array|undefined>;write(value:Uint8Array):Promise<void>;close():void|Promise<void>}
/** Backend-only opt-in seam; runtime packages own filesystem handles. No default disk. */
export class EncryptedSpool {
 // Constructor inference retains this platform's actual WebCrypto key type.
 private readonly key;private readonly aad:Uint8Array;private closed=false;
 constructor(private readonly backend:SpoolBackend,key:Uint8Array,descriptor:RoutingDescriptor,revision:string,private readonly maxBytes=2097152){
  if(key.length!==32||!Number.isInteger(maxBytes)||maxBytes<64||maxBytes>16777216)throw Error('invalid spool configuration');const d=validateDescriptor(descriptor);decimal(revision);
  this.aad=new TextEncoder().encode(nativeCanonical({version:1,org:d.org,project:d.project,source:d.source,routing_version:d.routing_version,slots:d.slots,policy_revision:revision}));
  this.key=crypto.subtle.importKey('raw',new Uint8Array(key),{name:'AES-GCM'},false,['encrypt','decrypt']);
 }
 assertBinding(descriptor:RoutingDescriptor,revision:string):void{const d=validateDescriptor(descriptor);if(new TextDecoder().decode(this.aad)!==nativeCanonical({version:1,org:d.org,project:d.project,source:d.source,routing_version:d.routing_version,slots:d.slots,policy_revision:revision}))throw Error('spool policy binding mismatch');}
 async load():Promise<unknown>{
  if(this.closed)throw Error('spool closed');const raw=await this.backend.read(this.maxBytes);if(raw===undefined)return undefined;
  try{
   if(raw.length>this.maxBytes||raw.length<37||new TextDecoder().decode(raw.subarray(0,5))!=='SPQS2')throw Error();
   const size=new DataView(raw.buffer,raw.byteOffset,raw.byteLength).getUint32(5,false);if(size>4096||raw.length<size+37)throw Error();const header=raw.slice(9,9+size),stored=object(strictJSON(new TextDecoder('utf-8',{fatal:true}).decode(header))),current=object(strictJSON(new TextDecoder().decode(this.aad)));
   decimal(stored.policy_revision);if(Object.keys(stored).sort().join(',')!==Object.keys(current).sort().join(',')||Object.keys(current).some(k=>k!=='policy_revision'&&stored[k]!==current[k]))throw Error();
   const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:new Uint8Array(raw.subarray(9+size,21+size)),additionalData:header},await this.key,new Uint8Array(raw.subarray(21+size)));return strictJSON(new TextDecoder('utf-8',{fatal:true}).decode(plain));
  }
  catch{await this.close();throw Error('spool authentication or corruption failure');}
 }
 async save(value:unknown):Promise<void>{
  if(this.closed)throw Error('spool closed');const plain=new TextEncoder().encode(nativeCanonical(value));if(plain.length+37+this.aad.length>this.maxBytes)throw Error('spool capacity exceeded');
  const nonce=crypto.getRandomValues(new Uint8Array(12)),cipher=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,additionalData:new Uint8Array(this.aad)},await this.key,plain));
  const bytes=new Uint8Array(21+this.aad.length+cipher.length);bytes.set(new TextEncoder().encode('SPQS2'));new DataView(bytes.buffer).setUint32(5,this.aad.length,false);bytes.set(this.aad,9);bytes.set(nonce,9+this.aad.length);bytes.set(cipher,21+this.aad.length);await this.backend.write(bytes);
 }
 async close():Promise<void>{if(this.closed)return;this.closed=true;await this.backend.close();}
}
