// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {defineConfig,devices} from '@playwright/test';
const origin=process.env.SOUNDPOST_TEST_ORIGIN;
if(!origin || new URL(origin).protocol!=='https:')throw new Error('SOUNDPOST_TEST_ORIGIN must name the real trusted HTTPS server');
// The source digest of the tree this run belongs to (go run ./build source-digest), recorded as config.metadata.source_sha256 in the
// JSON reporter's `--list` and run outputs. tools/browserevidence refuses results whose stamp differs from the other producers' and the
// release gate refuses a stamp that is not the release's build_id source. It fails closed: no digest, no run.
const repoRoot=fileURLToPath(new URL('..',import.meta.url)).replace(/[\\/]$/,'');
function sourceDigest():string{
  let out:string;
  try{out=execFileSync('go',['run','./build','source-digest','--root',repoRoot],{cwd:repoRoot,encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();}
  catch{throw new Error('cannot compute the source digest: `go run ./build source-digest` failed in '+repoRoot);}
  if(!/^[0-9a-f]{64}$/.test(out))throw new Error('`go run ./build source-digest` printed no 64-hex digest');
  return out;
}
// The supported-browser matrix is Chromium, Firefox and WebKit. A project whose browser is not installed on the host FAILS to launch;
// it is never skipped or reported as passed. `--project=chromium` selects the one browser installed where the acceptance was run.
export default defineConfig({testDir:'./e2e',fullyParallel:false,workers:1,retries:0,metadata:{source_sha256:sourceDigest()},use:{baseURL:origin,ignoreHTTPSErrors:false,trace:'off',screenshot:'off',video:'off'},projects:[{name:'chromium',use:{...devices['Desktop Chrome']}},{name:'firefox',use:{...devices['Desktop Firefox']}},{name:'webkit',use:{...devices['Desktop Safari']}}]});
