// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// An authorized real dependency is REQUIRED. There is no canned/model fallback.
import {init} from "../../../packages/bun/src/index.ts";
import {installServe} from "../../../packages/bun/src/serve.ts";
import {installFetch} from "../../../packages/bun/src/fetch.ts";
import {loadConfig} from "../node/support.mjs";
const marker=process.argv.indexOf("--dependency-env"),variable=marker<0?"SOUNDPOST_FIXTURE_DEPENDENCY_URL":process.argv[marker+1];
if(Bun.version!=="1.3.14"||!variable||!/^[A-Z][A-Z0-9_]+$/.test(variable))throw Error("qualified_runtime_and_dependency_env_required");
const dependency=process.env[variable];if(!dependency)throw Error("real_dependency_required");const url=new URL(dependency);if(url.protocol!=="https:"||url.username||url.password)throw Error("verified_https_dependency_required");
const client=init(loadConfig()),serve=installServe(client,{operation:"request"}),outbound=installFetch(client,{operation:"http.call",origins:[{origin:url.origin,dependency:"dependency"}]});
const server=Bun.serve({hostname:"127.0.0.1",port:Number(process.env.SOUNDPOST_FIXTURE_GATEWAY_PORT??0),fetch:serve.handler(async request=>{const headers=new Headers(),contentType=request.headers.get("content-type");if(contentType)headers.set("content-type",contentType);return outbound.fetch(url,{method:request.method,headers,...(request.method==="GET"||request.method==="HEAD"?{}:{body:request.body}),signal:request.signal});}),error(){return new Response(null,{status:502});}});
console.log(JSON.stringify({fixture:"bun_real_dependency_gateway",runtime:Bun.version,port:server.port,dependency_alias:"dependency",internal_dependency:"unobserved",qualification:"not_claimed_until_real_outbound_verified"}));
let closing=false;async function close():Promise<void>{if(closing)return;closing=true;server.stop(true);serve.close();outbound.close();try{const report=await client.flush(10000);if(report.pending||report.lost)process.exitCode=1;}finally{await client.close();}}
process.once("SIGINT",close);process.once("SIGTERM",close);
