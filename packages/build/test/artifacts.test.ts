// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {test,expect} from "bun:test";
import {createHash} from "node:crypto";
import {mkdtempSync,readFileSync,readdirSync,rmSync,writeFileSync,mkdirSync} from "node:fs";
import {tmpdir} from "node:os";
import {join,resolve} from "node:path";
import {inspect} from "node:util";
import {build} from "vite";
import webpack from "webpack";
import {ArtifactError,createUploadConfig,soundpostVite,soundpostWebpack,uploadArtifacts} from "../src/index.ts";
import type {ArtifactFile,ArtifactManifest} from "../src/index.ts";

const CANARY="CANARY_PRIVATE_ARTIFACT_WRITE_CREDENTIAL_7f3a";
const ORG="1".repeat(32),PROJECT="2".repeat(32),SOURCE="3".repeat(32),BUILD="4".repeat(32),BUILD2="5".repeat(32);
const sha=(value:Uint8Array|string)=>createHash("sha256").update(value).digest("hex");
const encode=(value:unknown)=>new TextEncoder().encode(typeof value==="string"?value:JSON.stringify(value));
const root=resolve(import.meta.dir,"../../..");

interface Upload {manifest:Record<string,unknown>;file:Uint8Array;authorization:string|null;raw:string}
function fakeBackend(reply:(upload:Upload)=>Response=()=>Response.json({id:"9".repeat(32),state:"published"})){
 const uploads:Upload[]=[];
 const server=Bun.serve({port:0,hostname:"127.0.0.1",async fetch(request){
  const form=await request.formData(),manifest=String(form.get("manifest")),file=form.get("file") as File;
  const upload={manifest:JSON.parse(manifest),file:new Uint8Array(await file.arrayBuffer()),authorization:request.headers.get("authorization"),raw:manifest};
  uploads.push(upload);return reply(upload);
 }});
 return {uploads,endpoint:"http://127.0.0.1:"+server.port,stop:()=>server.stop(true)};
}
function temp(){return mkdtempSync(join(tmpdir(),"soundpost-build-"));}
function listing(dir:string):string[]{return readdirSync(dir,{recursive:true,withFileTypes:true}).filter(entry=>entry.isFile()).map(entry=>join(entry.parentPath,entry.name));}
async function* iterate(...files:ArtifactFile[]){for(const file of files)yield file;}
const VLQ="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/** Independent minimal v3 decoder: original (source,line,column) for a zero-based generated position. */
function originalPosition(map:{sources:string[];mappings:string},line:number,column:number){
 let source=0,origLine=0,origColumn=0,best:{source:string;line:number;column:number}|undefined;
 map.mappings.split(";").forEach((row,index)=>{
  let generated=0;
  for(const segment of row.split(",")){
   if(segment==="")continue;
   const values:number[]=[];let shift=0,value=0;
   for(const char of segment){const digit=VLQ.indexOf(char);value|=(digit&31)<<shift;if(digit&32){shift+=5;}else{values.push(value&1?-(value>>1):value>>1);value=0;shift=0;}}
   generated+=values[0]!;
   if(values.length>=4){source+=values[1]!;origLine+=values[2]!;origColumn+=values[3]!;if(index===line&&generated<=column)best={source:map.sources[source]!,line:origLine+1,column:origColumn};}
  }
 });
 return best;
}
function thrownPosition(file:string){
 const run=Bun.spawnSync([process.execPath,file],{stderr:"pipe",stdout:"pipe"});
 const text=new TextDecoder().decode(run.stderr);
 const match=text.split("\n").find(line=>/soundpostReleaseThrow/.test(line)&&/:\d+:\d+/.test(line))?.match(/:(\d+):(\d+)\)?\s*$/);
 if(!match)throw Error("fixture did not throw with a positioned stack: "+text.slice(0,400));
 return {line:Number(match[1])-1,column:Number(match[2])-1};
}
async function viteBuild(out:string,options:Record<string,unknown>){
 await build({configFile:false,root,logLevel:"silent",plugins:[soundpostVite(options as never)],build:{outDir:out,emptyOutDir:true,minify:false,target:"es2022",lib:{entry:join(root,"fixtures/sdk/releases/source.ts"),formats:["es"],fileName:()=>"source.mjs"}}});
}
const identity={org:ORG,project:PROJECT,source:SOURCE};

test("vite build uploads exact generated/map hashes and the uploaded map still resolves the thrown original line",async()=>{
 const backend=fakeBackend(),out=temp();
 try{
  await viteBuild(out,{...identity,build:BUILD,upload:{endpoint:backend.endpoint,credential:CANARY}});
  expect(backend.uploads).toHaveLength(1);
  const upload=backend.uploads[0]!,m=upload.manifest;
  const generated=readFileSync(join(out,"source.mjs")),map=readFileSync(join(out,"source.mjs.map"));
  expect(m.version).toBe(1);expect([m.org,m.project,m.source,m.build]).toEqual([ORG,PROJECT,SOURCE,BUILD]);
  expect(m.path).toBe("source.mjs");
  expect(m.generated_sha256).toBe(sha(generated));expect(m.map_sha256).toBe(sha(upload.file));expect(sha(map)).toBe(m.map_sha256);
  expect(m.size).toBe(String(upload.file.length));expect(m.source_content).toBe(false);
  expect(typeof m.retain_until_ns).toBe("string");expect(BigInt(m.retain_until_ns as string)>BigInt(Date.now())*1000000n).toBe(true);
  expect(String(m.debug_id)).toMatch(/^[0-9a-f]{32}$/);
  expect(generated.toString()).toContain("//# debugId="+m.debug_id);expect(JSON.parse(map.toString()).debugId).toBe(m.debug_id);
  // Hidden maps: the bundle never advertises a URL a runtime could fetch.
  expect(generated.toString()).not.toContain("sourceMappingURL");
  // Default policy: no source text leaves the build or stays in the emitted map.
  expect(JSON.parse(new TextDecoder().decode(upload.file)).sourcesContent).toBeUndefined();
  expect(Object.keys(upload.manifest).sort()).toEqual(["build","debug_id","generated_sha256","map_sha256","org","path","project","retain_until_ns","size","source","source_content","version"]);
  const where=thrownPosition(join(out,"source.mjs")),original=originalPosition(JSON.parse(new TextDecoder().decode(upload.file)),where.line,where.column);
  expect(original?.source).toBe("fixtures/sdk/releases/source.ts");expect(original?.line).toBe(6);
 }finally{backend.stop();rmSync(out,{recursive:true,force:true});}
});

test("debug identity is content-bound and survives a release rename; build identity is the configured immutable build",async()=>{
 const backend=fakeBackend(),a=temp(),b=temp();
 try{
  await viteBuild(a,{...identity,build:BUILD,upload:{endpoint:backend.endpoint,credential:CANARY}});
  await viteBuild(b,{...identity,build:BUILD2,upload:{endpoint:backend.endpoint,credential:CANARY}});
  const [first,second]=backend.uploads.map(upload=>upload.manifest);
  expect(first!.debug_id).toBe(second!.debug_id);expect(first!.generated_sha256).toBe(second!.generated_sha256);
  expect([first!.build,second!.build]).toEqual([BUILD,BUILD2]);
 }finally{backend.stop();rmSync(a,{recursive:true,force:true});rmSync(b,{recursive:true,force:true});}
});

test("private credential never reaches the bundle, maps, plugin shape, logs or errors",async()=>{
 const backend=fakeBackend(),out=temp(),logs:string[]=[];
 const originals={log:console.log,warn:console.warn,error:console.error,info:console.info};
 for(const name of Object.keys(originals) as (keyof typeof originals)[])console[name]=(...args:unknown[])=>{logs.push(args.map(value=>typeof value==="string"?value:inspect(value,{depth:5})).join(" "));};
 try{
  const plugin=soundpostVite({...identity,build:BUILD,upload:{endpoint:backend.endpoint,credential:CANARY}});
  expect(JSON.stringify(plugin)??"").not.toContain(CANARY);expect(inspect(plugin,{depth:8,showHidden:true})).not.toContain(CANARY);
  await viteBuild(out,{...identity,build:BUILD,upload:{endpoint:backend.endpoint,credential:CANARY}});
  for(const file of listing(out))expect(readFileSync(file).toString()).not.toContain(CANARY);
  expect(backend.uploads[0]!.raw).not.toContain(CANARY);
  const config=createUploadConfig({endpoint:backend.endpoint,credential:CANARY});
  expect(JSON.stringify(config)).not.toContain(CANARY);expect(inspect(config,{depth:8,showHidden:true})).not.toContain(CANARY);expect(String(config)).not.toContain(CANARY);
  // Rejected upload: the error is a closed reason, not a response/credential echo.
  const refused=fakeBackend(()=>new Response("denied "+CANARY,{status:403}));
  try{
   await viteBuild(temp(),{...identity,build:BUILD,upload:{endpoint:refused.endpoint,credential:CANARY}}).then(()=>{throw Error("upload must fail");},error=>{
    expect((error as {name:string}).name).toBe("SoundpostArtifactError");expect((error as {reason:string}).reason).toBe("upload_rejected");
    expect(String(error.message)+String(error.stack)+inspect(error,{depth:8})).not.toContain(CANARY);
   });
  }finally{refused.stop();}
 }finally{Object.assign(console,originals);backend.stop();rmSync(out,{recursive:true,force:true});}
 expect(logs.join("\n")).not.toContain(CANARY);
});

test("vite build without an upload target still assigns identities and never uploads",async()=>{
 const out=temp();
 try{
  await viteBuild(out,{...identity,build:BUILD});
  expect(readFileSync(join(out,"source.mjs")).toString()).toMatch(/\/\/# debugId=[0-9a-f]{32}/);
 }finally{rmSync(out,{recursive:true,force:true});}
});

test("webpack build produces a real map, assigns identities and uploads exact hashes with the same policy",async()=>{
 const backend=fakeBackend(),dir=temp(),out=join(dir,"dist");
 try{
  mkdirSync(join(dir,"src"));
  writeFileSync(join(dir,"src/throw.js"),"// first\n// second\nfunction soundpostReleaseThrow() {\n  throw new Error('soundpost release fixture');\n}\nsoundpostReleaseThrow();\n");
  const compiler=webpack({mode:"none",context:dir,entry:"./src/throw.js",devtool:"source-map",target:"node",output:{path:out,filename:"main.js"},plugins:[soundpostWebpack({...identity,build:BUILD,upload:{endpoint:backend.endpoint,credential:CANARY}})]});
  await new Promise<void>((done,fail)=>compiler.run((error,stats)=>{compiler.close(()=>{if(error)fail(error);else if(stats?.hasErrors())fail(Error(stats.toString("errors-only")));else done();});}));
  expect(backend.uploads).toHaveLength(1);
  const upload=backend.uploads[0]!,m=upload.manifest,generated=readFileSync(join(out,"main.js")),map=readFileSync(join(out,"main.js.map"));
  expect(m.path).toBe("main.js");expect(m.generated_sha256).toBe(sha(generated));expect(m.map_sha256).toBe(sha(upload.file));expect(sha(map)).toBe(m.map_sha256);
  expect(generated.toString()).toContain("//# debugId="+m.debug_id);expect(generated.toString()).not.toContain("sourceMappingURL");
  expect(JSON.parse(new TextDecoder().decode(upload.file)).sourcesContent).toBeUndefined();
  for(const file of listing(out))expect(readFileSync(file).toString()).not.toContain(CANARY);
  const where=thrownPosition(join(out,"main.js")),original=originalPosition(JSON.parse(new TextDecoder().decode(upload.file)),where.line,where.column);
  expect(original?.line).toBe(4);expect(original?.source).toBe("src/throw.js");
 }finally{backend.stop();rmSync(dir,{recursive:true,force:true});}
});

function manifestFor(generated:Uint8Array,map:Uint8Array,changes:Record<string,unknown>={}):ArtifactManifest{
 return {version:1,org:ORG,project:PROJECT,source:SOURCE,build:BUILD,debug_id:"d".repeat(32),generated_sha256:sha(generated),map_sha256:sha(map),path:"assets/app.js",source_content:false,size:String(map.length),retain_until_ns:String(BigInt(Date.now()+86400000)*1000000n),...changes} as ArtifactManifest;
}
const GOOD_MAP={version:3,sources:["src/app.ts"],names:[],mappings:"AAAA"};
async function attempt(map:unknown,changes:Record<string,unknown>={},filesOverride?:(generated:Uint8Array,map:Uint8Array)=>ArtifactFile[]){
 const backend=fakeBackend(),generated=encode("export{};"),bytes=map instanceof Uint8Array?map:encode(map),manifest=manifestFor(generated,bytes,changes);
 const files=filesOverride?filesOverride(generated,bytes):[{path:"assets/app.js",role:"generated" as const,bytes:generated},{path:"assets/app.js.map",role:"map" as const,bytes}];
 try{
  const receipt=await uploadArtifacts(manifest,iterate(...files),createUploadConfig({endpoint:backend.endpoint,credential:CANARY})).then(value=>({receipt:value}),(error:unknown)=>({error}));
  return {...receipt,uploads:backend.uploads.length};
 }finally{backend.stop();}
}
async function reason(map:unknown,changes?:Record<string,unknown>,files?:Parameters<typeof attempt>[2]){
 const result=await attempt(map,changes,files);
 expect("receipt" in result).toBe(false);expect(result.uploads).toBe(0);
 expect((result as {error:unknown}).error).toBeInstanceOf(ArtifactError);
 return ((result as {error:ArtifactError}).error).code;
}

test("a valid map uploads once and the receipt carries the backend artifact id and bound identity",async()=>{
 const result=await attempt(GOOD_MAP);
 expect(result.uploads).toBe(1);const receipt=(result as {receipt:Record<string,string>}).receipt;
 expect(receipt.id).toBe("9".repeat(32));expect(receipt.build).toBe(BUILD);expect(receipt.debug_id).toBe("d".repeat(32));expect(receipt.path).toBe("assets/app.js");
});

test("missing or mismatched maps and generated files produce visible reasons and no upload",async()=>{
 expect(await reason(GOOD_MAP,{},(generated)=>[{path:"assets/app.js",role:"generated",bytes:generated}])).toBe("map_missing");
 expect(await reason(GOOD_MAP,{},(generated)=>[{path:"assets/app.js",role:"generated",bytes:generated},{path:"assets/app.js.map",role:"map",bytes:encode({...GOOD_MAP,mappings:"AACA"})}])).toBe("map_hash_mismatch");
 expect(await reason(GOOD_MAP,{},(_generated,map)=>[{path:"assets/app.js",role:"generated",bytes:encode("changed();")},{path:"assets/app.js.map",role:"map",bytes:map}])).toBe("generated_hash_mismatch");
 expect(await reason(GOOD_MAP,{},(_generated,map)=>[{path:"assets/app.js.map",role:"map",bytes:map}])).toBe("generated_missing");
});

test("indexed, recursive, traversal, oversize and over-deep maps are rejected before any upload",async()=>{
 expect(await reason({version:3,sections:[{offset:{line:0,column:0},map:GOOD_MAP}]})).toBe("map_indexed");
 expect(await reason({version:3,sections:[{offset:{line:0,column:0},map:{version:3,sections:[{offset:{line:0,column:0},map:GOOD_MAP}]}}]})).toBe("map_indexed");
 expect(await reason({...GOOD_MAP,sources:["../../etc/passwd"]})).toBe("map_path_unsafe");
 expect(await reason({...GOOD_MAP,sources:["/abs/app.ts"]})).toBe("map_path_unsafe");
 expect(await reason({...GOOD_MAP,sources:["src\\app.ts"]})).toBe("map_path_unsafe");
 expect(await reason(GOOD_MAP,{path:"../escape.js"})).toBe("path_invalid");
 expect(await reason(GOOD_MAP,{path:"/abs/app.js"})).toBe("path_invalid");
 let deep:unknown="x";for(let i=0;i<9;i++)deep={n:deep};
 expect(await reason({...GOOD_MAP,x_deep:deep})).toBe("map_too_deep");
 const big=encode(JSON.stringify({...GOOD_MAP,x_pad:"a".repeat(32*1024*1024)}));
 expect(await reason(big)).toBe("map_too_large");
 expect(await reason({...GOOD_MAP,sources:Array.from({length:1025},(_,i)=>"src/f"+i+".ts")})).toBe("too_many_files");
 expect(await reason(encode("{not json"))).toBe("map_invalid");
 expect(await reason({version:2,sources:[],names:[],mappings:""})).toBe("map_invalid");
});

test("file-count and expanded-size limits apply to the iterated bundle",async()=>{
 const generated=encode("export{};"),map=encode(GOOD_MAP);
 const many=()=>(async function*(){yield {path:"assets/app.js",role:"generated" as const,bytes:generated};yield {path:"assets/app.js.map",role:"map" as const,bytes:map};for(let i=0;i<1023;i++)yield {path:"assets/extra"+i+".js",role:"generated" as const,bytes:encode("x")};})();
 const backend=fakeBackend();
 try{
  const error=await uploadArtifacts(manifestFor(generated,map),many(),createUploadConfig({endpoint:backend.endpoint,credential:CANARY})).then(()=>undefined,(value:unknown)=>value as ArtifactError);
  expect(error?.code).toBe("too_many_files");expect(backend.uploads).toHaveLength(0);
  const huge=new Uint8Array(32*1024*1024+1);
  const error2=await uploadArtifacts(manifestFor(generated,map),iterate({path:"assets/app.js",role:"generated",bytes:huge},{path:"assets/app.js.map",role:"map",bytes:map}),createUploadConfig({endpoint:backend.endpoint,credential:CANARY})).then(()=>undefined,(value:unknown)=>value as ArtifactError);
  expect(error2?.code).toBe("bundle_too_large");expect(backend.uploads).toHaveLength(0);
 }finally{backend.stop();}
});

test("source content is absent by default and required when the grant policy asks for it",async()=>{
 const withContent={...GOOD_MAP,sourcesContent:["PRIVATE SOURCE TEXT"]};
 expect(await reason(withContent)).toBe("source_content_unexpected");
 expect(await reason(GOOD_MAP,{source_content:true})).toBe("source_content_missing");
 expect(await reason({...GOOD_MAP,sourcesContent:[null]},{source_content:true})).toBe("source_content_missing");
 const granted=await attempt(withContent,{source_content:true});
 expect(granted.uploads).toBe(1);
});

test("manifest shape is closed and identities/limits are validated like the backend",async()=>{
 expect(await reason(GOOD_MAP,{org:"zz"})).toBe("manifest_invalid");
 expect(await reason(GOOD_MAP,{generated_sha256:"A".repeat(64)})).toBe("manifest_invalid");
 expect(await reason(GOOD_MAP,{version:2})).toBe("manifest_invalid");
 expect(await reason(GOOD_MAP,{debug_id:"a/b"})).toBe("manifest_invalid");
 expect(await reason(GOOD_MAP,{size:"1"})).toBe("manifest_invalid");
 expect(await reason(GOOD_MAP,{retain_until_ns:"0"})).toBe("manifest_invalid");
 expect(await reason(GOOD_MAP,{extra:"field"})).toBe("manifest_invalid");
});

test("upload refuses plaintext non-loopback endpoints and invalid credentials before sending",async()=>{
 const generated=encode("export{};"),map=encode(GOOD_MAP),files=()=>iterate({path:"assets/app.js",role:"generated",bytes:generated},{path:"assets/app.js.map",role:"map",bytes:map});
 const code=async(config:()=>unknown)=>{try{await uploadArtifacts(manifestFor(generated,map),files(),config() as never);return "uploaded";}catch(error){const text=String((error as Error).message)+inspect(error,{depth:6});expect(text).not.toContain(CANARY);return (error as ArtifactError).code;}};
 expect(await code(()=>createUploadConfig({endpoint:"http://artifacts.example.test",credential:CANARY}))).toBe("endpoint_insecure");
 expect(await code(()=>createUploadConfig({endpoint:"https://user:"+CANARY+"@artifacts.example.test",credential:CANARY}))).toBe("endpoint_invalid");
 expect(await code(()=>createUploadConfig({endpoint:"https://artifacts.example.test",credential:CANARY+"\r\nX-Injected: 1"}))).toBe("credential_invalid");
 expect(await code(()=>createUploadConfig({endpoint:"https://artifacts.example.test",credential:""}))).toBe("credential_invalid");
});

test("redirects are never followed with the credential and transport failures do not echo it",async()=>{
 const sink=fakeBackend(),redirector=Bun.serve({port:0,hostname:"127.0.0.1",fetch:()=>new Response(null,{status:307,headers:{location:sink.endpoint+"/stolen"}})});
 try{
  const result=await attempt(GOOD_MAP).then(()=>undefined);void result;
  const generated=encode("export{};"),map=encode(GOOD_MAP);
  const error=await uploadArtifacts(manifestFor(generated,map),iterate({path:"assets/app.js",role:"generated",bytes:generated},{path:"assets/app.js.map",role:"map",bytes:map}),createUploadConfig({endpoint:"http://127.0.0.1:"+redirector.port,credential:CANARY})).then(()=>undefined,(value:unknown)=>value as ArtifactError);
  expect(error?.code).toBe("upload_failed");expect(sink.uploads).toHaveLength(0);
  expect(String(error?.message)+inspect(error,{depth:6})).not.toContain(CANARY);
  const closed=Bun.serve({port:0,hostname:"127.0.0.1",fetch:()=>new Response("")}),port=closed.port;closed.stop(true);
  const unreachable=await uploadArtifacts(manifestFor(generated,map),iterate({path:"assets/app.js",role:"generated",bytes:generated},{path:"assets/app.js.map",role:"map",bytes:map}),createUploadConfig({endpoint:"http://127.0.0.1:"+port,credential:CANARY})).then(()=>undefined,(value:unknown)=>value as ArtifactError);
  expect(unreachable?.code).toBe("upload_failed");expect(String(unreachable?.message)+inspect(unreachable,{depth:6})).not.toContain(CANARY);
 }finally{redirector.stop(true);sink.stop();}
});

test("a receipt that does not bind the uploaded identity is rejected",async()=>{
 const backend=fakeBackend(()=>Response.json({id:"not-an-id"})),generated=encode("export{};"),map=encode(GOOD_MAP);
 try{
  const error=await uploadArtifacts(manifestFor(generated,map),iterate({path:"assets/app.js",role:"generated",bytes:generated},{path:"assets/app.js.map",role:"map",bytes:map}),createUploadConfig({endpoint:backend.endpoint,credential:CANARY})).then(()=>undefined,(value:unknown)=>value as ArtifactError);
  expect(error?.code).toBe("receipt_invalid");
 }finally{backend.stop();}
});

test("inline source maps are refused by both plugins because they cannot be kept private",async()=>{
 const out=temp();
 try{
  await expect(build({configFile:false,root,logLevel:"silent",plugins:[soundpostVite({...identity,build:BUILD})],build:{outDir:out,sourcemap:"inline",lib:{entry:join(root,"fixtures/sdk/releases/source.ts"),formats:["es"],fileName:()=>"source.mjs"}}})).rejects.toMatchObject({reason:"sourcemap_inline_unsupported"});
  expect(()=>soundpostWebpack({...identity,build:BUILD}).apply({options:{devtool:"inline-source-map"},context:out,outputPath:out,hooks:{afterEmit:{tapPromise(){}}}})).toThrow(/sourcemap_inline_unsupported/);
  expect(()=>soundpostVite({...identity,build:"short"})).toThrow(/options_invalid/);
  expect(()=>soundpostWebpack({...identity,build:BUILD,retainDays:0})).toThrow(/options_invalid/);
 }finally{rmSync(out,{recursive:true,force:true});}
});
