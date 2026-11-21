// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {Client} from "@soundpost/core";
export interface PgIntegrationConfig {readonly operation:string;readonly dependency:string}
export interface PgResult<Row=Record<string,unknown>> {rows:Row[];rowCount:number|null;command:string;fields:readonly unknown[]}
export interface PgQueryable {query:(...args:any[])=>any}
const installed=new WeakMap<Client,PgLease>();
export class PgLease {
 private closed=false;private readonly pending=new Set<()=>void>();private readonly operation:string;private readonly dependency:string;
 constructor(private readonly client:Client,config:PgIntegrationConfig){this.operation=config.operation;this.dependency=config.dependency;if(installed.has(client))throw Error("pg_already_installed");if(![this.operation,this.dependency].every(value=>/^[a-zA-Z0-9_.-]{1,128}$/.test(value)))throw Error("invalid_pg_config");client.ownHookLease(this);installed.set(client,this);}
 query<Row=Record<string,unknown>>(target:PgQueryable,text:string,values?:readonly unknown[]):Promise<PgResult<Row>>;
 query(target:PgQueryable,text:string,callback:(error:unknown,result:any)=>void):unknown;
 query(target:PgQueryable,text:string,values:readonly unknown[],callback:(error:unknown,result:any)=>void):unknown;
 query(target:PgQueryable,...args:unknown[]):unknown {
  if(this.closed)throw Error("pg_lease_closed");if(this.pending.size>=1024){const limited=this.client.startSpan(this.operation,{kind:"client",dependency:this.dependency});limited.end("incomplete");return Reflect.apply(target.query,target,args);}
  const span=this.client.startSpan(this.operation,{kind:"client",dependency:this.dependency});let ended=false;
  const end=(status:"ok"|"error"|"incomplete"):void=>{if(ended)return;ended=true;this.pending.delete(incomplete);span.end(status);},incomplete=():void=>end("incomplete");this.pending.add(incomplete);
  const last=args[args.length-1],callback=typeof last==="function"?last:undefined;
  if(callback){const client=this.client;args[args.length-1]=function(this:unknown,...values:unknown[]):unknown{const error=values[0];return span.run(()=>{if(error)client.captureException(error);end(error?"error":"ok");return Reflect.apply(callback,this,values);});};}
  let result:unknown;try{result=span.run(()=>Reflect.apply(target.query,target,args));}catch(error){span.run(()=>this.client.captureException(error));end("error");throw error;}
  if(callback)return result;
  if(result instanceof Promise)return result.then(value=>{end("ok");return value;},error=>{span.run(()=>this.client.captureException(error));end("error");throw error;});
  // Unsupported cursor/query-object lifetimes are not invented as successful spans.
  end("incomplete");return result;
 }
 close():void{if(this.closed)return;this.closed=true;for(const end of [...this.pending])end();installed.delete(this.client);this.client.releaseHookLease(this);}
}
/** Explicit wrapper, never a global pg prototype patch; query text/parameters stay app-owned. */
export function installPg(client:Client,config:PgIntegrationConfig):PgLease{return new PgLease(client,config);}
