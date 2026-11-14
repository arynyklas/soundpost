// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Runs fixtures/sdk/hooks/browser.ts (real global error/unhandledrejection events, no DOM emulator) in a
// real installed browser through playwright-core, and prints one JSON evidence line with the exact browser build.
//   node fixtures/sdk/hooks/browser-run.mjs --executable <chrome|msedge binary> --bun <bun> [--label chrome142] [--channel-args --no-sandbox]
import {spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
import {mkdtempSync,readFileSync,statSync} from "node:fs";
import {createServer} from "node:http";
import {tmpdir} from "node:os";
import {dirname,join,resolve} from "node:path";
import {createRequire} from "node:module";
import {fileURLToPath} from "node:url";

const here=dirname(fileURLToPath(import.meta.url)),root=resolve(here,"../../..");
const args=process.argv.slice(2),option=(name,fallback)=>{const i=args.indexOf(name);return i>=0&&i+1<args.length?args[i+1]:fallback;};
const executable=option("--executable",""),bun=option("--bun","bun"),label=option("--label","browser");
if(!executable)throw Error("--executable is required");
const requireFrom=path=>{try{return createRequire(path)("playwright-core");}catch{return undefined;}};
const playwright=requireFrom(join(root,"web/package.json"))??requireFrom(join(root,"node_modules/.pnpm/playwright-core@1.64.1/node_modules/x.js"));
if(!playwright)throw Error("playwright-core is not installed (pnpm install)");
const {chromium}=playwright;

const dir=mkdtempSync(join(tmpdir(),"soundpost-hooks-"));
const built=spawnSync(bun,["build",join(root,"fixtures/sdk/hooks/browser.ts"),"--target=browser","--format=esm","--outfile",join(dir,"hooks.js")],{encoding:"utf8"});
if(built.status!==0)throw Error("bun build failed: "+built.stderr);
const bundle=readFileSync(join(dir,"hooks.js"));
const page=`<!doctype html><meta charset="utf-8"><script type="module">
import {runBrowserHooksFixture} from "/hooks.js";
window.__result=runBrowserHooksFixture().then(value=>({ok:true,value}),error=>({ok:false,error:String(error&&error.message||error)}));
</script>`;
const server=createServer((request,response)=>{
 if(request.url==="/hooks.js"){response.writeHead(200,{"content-type":"text/javascript"});response.end(bundle);}
 else{response.writeHead(200,{"content-type":"text/html"});response.end(page);}
}).listen(0,"127.0.0.1");
await new Promise(done=>server.once("listening",done));
const url="http://127.0.0.1:"+server.address().port+"/";
const browser=await chromium.launch({executablePath:executable,headless:true,args:["--no-sandbox"]});
let outcome,version,userAgent;
try{
 version=browser.version();
 const tab=await browser.newPage(),consoleErrors=[];
 tab.on("pageerror",()=>{});tab.on("console",message=>{if(message.type()==="error")consoleErrors.push(message.text().slice(0,200));});
 await tab.goto(url);
 userAgent=await tab.evaluate(()=>navigator.userAgent);
 outcome=await tab.evaluate(()=>window.__result);
}finally{await browser.close();server.close();}
const sha256=bytes=>createHash("sha256").update(bytes).digest("hex");
const evidence={label,ok:outcome.ok,browser_version:version,user_agent:userAgent,executable_size:statSync(executable).size,bundle_sha256:sha256(bundle),fixture:"fixtures/sdk/hooks/browser.ts",result:outcome.ok?outcome.value:undefined,error:outcome.ok?undefined:outcome.error};
process.stdout.write("SOUNDPOST_HOOKS_EVIDENCE "+JSON.stringify(evidence)+"\n");
process.exit(outcome.ok?0:1);
