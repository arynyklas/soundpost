// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Compiles fixtures/sdk/releases/source.ts with the REAL bundler (Vite 7 or webpack 5), uploads the private
// source map through packages/build to a real Soundpost endpoint, and writes the build receipt (generated
// path -> server ArtifactID). Run by frames-e2e (Go) with the Windows Node that owns the installed bundlers.
//
//   node frames-build.mjs --bundler vite|webpack --config <json> --out <dir> --receipt <file>
// config JSON: {endpoint, org, project, source, build, token}. Nothing here prints a credential.
import {createRequire} from "node:module";
import {readFileSync,realpathSync,writeFileSync} from "node:fs";
import {dirname,join,resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {build as viteBuild} from "vite";
import {soundpostVite,soundpostWebpack} from "../../../packages/build/src/index.ts";

const here=dirname(fileURLToPath(import.meta.url)),root=resolve(here,"../../..");
const arg=name=>{const i=process.argv.indexOf(name);return i<0?undefined:process.argv[i+1];};
const bundler=arg("--bundler"),out=arg("--out"),receiptFile=arg("--receipt"),config=JSON.parse(readFileSync(arg("--config"),"utf8"));
if(!["vite","webpack"].includes(bundler)||!out||!receiptFile)throw Error("arguments");
const ids={org:config.org,project:config.project,source:config.source,build:config.build,upload:{endpoint:config.endpoint,credential:config.token}};
const receipts=[];
const entry=join(root,"fixtures/sdk/releases/source.ts");

if(bundler==="vite"){
 await viteBuild({configFile:false,root,logLevel:"silent",plugins:[soundpostVite({...ids,onReceipt:r=>receipts.push(r)})],
  build:{outDir:out,emptyOutDir:true,minify:false,target:"es2022",lib:{entry,formats:["es"],fileName:()=>"source.mjs"}}});
}else{
 const requireBuild=createRequire(join(root,"packages/build/package.json"));
 const webpack=requireBuild("webpack");
 // webpack parses JavaScript only. The TypeScript step is esbuild (already a Vite dependency in the lock), run as a
 // real webpack loader that hands webpack its own source map, so webpack still composes the final map.
 const requireVite=createRequire(realpathSync(requireBuild.resolve("vite")));
 const {transform}=requireVite("esbuild");
 const loader=join(out+"-loader.cjs");
 writeFileSync(loader,`const {transform}=require(${JSON.stringify(requireVite.resolve("esbuild"))});
module.exports=function(source){const done=this.async();transform(source,{loader:"ts",sourcemap:true,sourcefile:this.resourcePath,target:"es2022"}).then(r=>done(null,r.code,r.map),done);};\n`);
 const compiler=webpack({mode:"production",context:root,entry,target:"node",devtool:false,
  output:{path:out,filename:"source.js",library:{type:"commonjs2"},clean:true},
  optimization:{minimize:false,concatenateModules:false},
  module:{rules:[{test:/\.ts$/,use:[loader]}]},resolve:{extensions:[".ts",".js"]},
  plugins:[soundpostWebpack({...ids,onReceipt:r=>receipts.push(r)})]});
 await new Promise((ok,fail)=>compiler.run((error,stats)=>compiler.close(()=>error?fail(error):stats.hasErrors()?fail(Error("webpack_errors")):ok())));
 void transform;
}
if(receipts.length!==1)throw Error("expected_one_receipt");
const r=receipts[0];
writeFileSync(receiptFile,JSON.stringify({bundler,id:r.id,build:r.build,debug_id:r.debug_id,path:r.path,generated_sha256:r.generated_sha256,map_sha256:r.map_sha256}));
console.log(JSON.stringify({bundler,uploaded:true,path:r.path}));
