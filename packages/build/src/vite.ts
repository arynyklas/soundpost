// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {dirname} from "node:path";
import type {Plugin} from "vite";
import {ArtifactError,asBuildFailure,resolveBuildOptions} from "./manifest.ts";
import type {BuildOptions} from "./manifest.ts";
import {createUploadConfig,publishBuildOutput} from "./uploader.ts";

const SCRIPT=/\.(?:m|c)?js$/;
/**
 * Vite 7 build plugin. Forces a private (`hidden`) map, assigns content-bound debug IDs after
 * the bundle is written, and uploads with the private artifact-write credential only. The
 * credential is sealed in a closure at construction; it is never injected into the bundle.
 */
export function soundpostVite(options:BuildOptions):Plugin {
 const settings=resolveBuildOptions(options);
 if(settings.upload!==undefined)createUploadConfig(settings.upload);
 let root=process.cwd();
 return {
  name:"soundpost:artifacts",
  apply:"build",
  enforce:"post",
  config(user){
   const requested=user.build?.sourcemap;
   if(requested==="inline")throw asBuildFailure(new ArtifactError("sourcemap_inline_unsupported"));
   return {build:{sourcemap:requested===true?true:"hidden"}};
  },
  configResolved(config){root=config.root;},
  async writeBundle(output,bundle){
   const dir=output.dir??(output.file===undefined?undefined:dirname(output.file));
   if(dir===undefined)throw new ArtifactError("options_invalid");
   const assets=Object.values(bundle).filter(item=>item.type==="chunk"&&SCRIPT.test(item.fileName)).map(item=>({path:item.fileName,mapPath:Object.hasOwn(bundle,item.fileName+".map")?item.fileName+".map":undefined}));
   await publishBuildOutput({dir,root,assets,options:settings}).catch((error:unknown)=>{throw asBuildFailure(error);});
  },
 };
}
