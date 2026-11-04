// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {open,mkdir,readdir,unlink,rename,lstat} from 'node:fs/promises';
import {constants} from 'node:fs';
import {dirname,resolve,join} from 'node:path';
import {randomBytes} from 'node:crypto';
import {EncryptedSpool,type SpoolBackend} from '@soundpost/core/spool';
import type {RoutingDescriptor} from '@soundpost/core/types';
/** A persisted contender file per process/lease avoids stale-lock unlink races.
 * Live contenders never steal one another's lease; dead process files grant no lock.
 * Local filesystems only; distributed filesystem locking is not claimed. */
class DiskBackend implements SpoolBackend {
 private closed=false;
 private constructor(private readonly path:string,private readonly lease:string){}
 static async acquire(path:string):Promise<DiskBackend>{
  path=resolve(path);await mkdir(dirname(path),{recursive:true,mode:0o700});const leases=path+'.leases';await mkdir(leases,{recursive:true,mode:0o700});
  if(!(await lstat(leases)).isDirectory()||(await lstat(leases)).isSymbolicLink())throw Error('invalid spool lease directory');
  const lease=join(leases,process.pid+'-'+randomBytes(16).toString('hex'));const file=await open(lease,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try{await file.sync();}finally{await file.close();}
  try{
   const names=await readdir(leases);if(names.length>4096)throw Error('spool lease capacity exceeded');
   for(const name of names){const other=join(leases,name);if(other===lease)continue;const match=/^([1-9][0-9]*)-[0-9a-f]{32}$/.exec(name);if(!match)throw Error('invalid spool lease');const pid=Number(match[1]);let alive=true;try{process.kill(pid,0);}catch(error){if(error instanceof Error&&'code' in error&&error.code==='ESRCH')alive=false;}if(alive)throw Error('spool lease unavailable');}
   return new DiskBackend(path,lease);
  }catch{await unlink(lease);throw Error('spool lease unavailable');}
 }
 async read(maxBytes:number):Promise<Uint8Array|undefined>{
  if(this.closed)throw Error('spool closed');let file;try{file=await open(this.path,constants.O_RDONLY|constants.O_NOFOLLOW);}catch(error){if(error instanceof Error&&'code' in error&&error.code==='ENOENT')return undefined;throw Error('spool read failed');}
  try{const stat=await file.stat();if(!stat.isFile()||stat.size>maxBytes)throw Error('spool capacity exceeded');const result=await file.readFile();if(result.length>maxBytes)throw Error('spool capacity exceeded');return new Uint8Array(result);}finally{await file.close();}
 }
 async write(value:Uint8Array):Promise<void>{
  if(this.closed)throw Error('spool closed');const temp=this.path+'.'+randomBytes(16).toString('hex')+'.tmp';const file=await open(temp,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try{try{await file.writeFile(value);await file.sync();}finally{await file.close();}await rename(temp,this.path);if(process.platform!=='win32'){const directory=await open(dirname(this.path),constants.O_RDONLY);try{await directory.sync();}finally{await directory.close();}}}
  catch{try{await unlink(temp);}catch(error){if(!(error instanceof Error&&'code' in error&&error.code==='ENOENT'))throw Error('spool cleanup failed');}throw Error('spool write failed');}
 }
 async close():Promise<void>{if(this.closed)return;this.closed=true;await unlink(this.lease);}
}
export async function openEncryptedSpool(path:string,key:Uint8Array,descriptor:RoutingDescriptor,revision:string,maxBytes=2097152):Promise<EncryptedSpool>{const backend=await DiskBackend.acquire(path);try{return new EncryptedSpool(backend,key,descriptor,revision,maxBytes);}catch(error){await backend.close();throw error;}}
