// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {ArtifactError,asBuildFailure,resolveBuildOptions} from "./manifest.ts";
import type {BuildOptions,ResolvedBuildOptions} from "./manifest.ts";
import {createUploadConfig,publishBuildOutput} from "./uploader.ts";

/** The narrow webpack 5 surface this plugin touches; structurally satisfied by `webpack.Compiler`. */
export interface WebpackCompilerLike {
 readonly options:{devtool?:string|false;context?:string};
 readonly context:string;
 readonly outputPath:string;
 readonly hooks:{readonly afterEmit:{tapPromise(name:string,callback:(compilation:{getAssets():readonly {readonly name:string}[]})=>Promise<void>):void}};
}
export interface WebpackPlugin {apply(compiler:WebpackCompilerLike):void}

const SCRIPT=/\.(?:m|c)?js$/;
class SoundpostWebpackPlugin implements WebpackPlugin {
 readonly #settings:ResolvedBuildOptions;
 constructor(settings:ResolvedBuildOptions){this.#settings=settings;}
 apply(compiler:WebpackCompilerLike):void {
  const devtool=compiler.options.devtool;
  if(typeof devtool==="string"&&/inline|eval/.test(devtool))throw asBuildFailure(new ArtifactError("sourcemap_inline_unsupported"));
  // Plugins run before webpack applies devtool, so an unset devtool becomes a private map.
  if(devtool===undefined||devtool===false)(compiler.options as {devtool?:string|false}).devtool="hidden-source-map";
  compiler.hooks.afterEmit.tapPromise("SoundpostArtifacts",async compilation=>{
   const names=new Set(compilation.getAssets().map(asset=>asset.name));
   const assets=[...names].filter(name=>SCRIPT.test(name)).map(name=>({path:name,mapPath:names.has(name+".map")?name+".map":undefined}));
   await publishBuildOutput({dir:compiler.outputPath,root:compiler.context,assets,options:this.#settings}).catch((error:unknown)=>{throw asBuildFailure(error);});
  });
 }
}
/** webpack 5 plugin with the same identity, source-content and credential rules as {@link soundpostVite}. */
export function soundpostWebpack(options:BuildOptions):WebpackPlugin {
 const settings=resolveBuildOptions(options);
 if(settings.upload!==undefined)createUploadConfig(settings.upload);
 return new SoundpostWebpackPlugin(settings);
}
