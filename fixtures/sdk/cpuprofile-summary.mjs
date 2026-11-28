// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Attributes the self time of V8 .cpuprofile files (node --cpu-prof, see fixtures/sdk/overhead.mjs --cpu-prof-dir) to functions
// and to source files. Usage: node fixtures/sdk/cpuprofile-summary.mjs [--top 25] FILE.cpuprofile...
// Output: JSON {profiles:[{file,total_ms,by_file:[{file,self_ms,percent}],top_functions:[{function,file,line,self_ms,percent}]}]}.
import {readFileSync} from "node:fs";
const args=process.argv.slice(2),topAt=args.indexOf("--top"),top=topAt>=0?Number(args[topAt+1]):25;
const files=args.filter((value,index)=>!(value==="--top"||index===topAt+1&&topAt>=0));
const short=url=>url===""?"(native)":url.replace(/^file:\/\/\/?/,"").replace(/^.*\/(packages|fixtures|node_modules)\//,"$1/");
const out=[];
for(const file of files){
 const profile=JSON.parse(readFileSync(file,"utf8")),byId=new Map(profile.nodes.map(node=>[node.id,node]));
 const self=new Map();let total=0;
 profile.samples.forEach((id,index)=>{const delta=(profile.timeDeltas[index]??0)/1000;self.set(id,(self.get(id)??0)+delta);total+=delta;});
 const functions=new Map(),files_=new Map();
 for(const [id,ms] of self){
  const frame=byId.get(id).callFrame,key=`${frame.functionName||"(anonymous)"}\u0000${short(frame.url)}\u0000${frame.lineNumber+1}`;
  functions.set(key,(functions.get(key)??0)+ms);
  files_.set(short(frame.url),(files_.get(short(frame.url))??0)+ms);
 }
 const pct=ms=>Number((100*ms/total).toFixed(2));
 out.push({file,total_ms:Number(total.toFixed(1)),
  by_file:[...files_].sort((a,b)=>b[1]-a[1]).slice(0,top).map(([name,ms])=>({file:name,self_ms:Number(ms.toFixed(1)),percent:pct(ms)})),
  top_functions:[...functions].sort((a,b)=>b[1]-a[1]).slice(0,top).map(([key,ms])=>{const [fn,source,line]=key.split("\u0000");return {function:fn,file:source,line:Number(line),self_ms:Number(ms.toFixed(1)),percent:pct(ms)};})});
}
process.stdout.write(JSON.stringify({profiles:out},null,1)+"\n");
