// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {defineConfig} from "@playwright/test";
// One pinned real browser per run: the driver (fixtures/sdk/critical, --mode browser) names the executable and the
// exact certificate pin for the private CA leaf. There is no fallback browser and no ignoreHTTPSErrors.
const executablePath=process.env.SOUNDPOST_FIXTURE_BROWSER_EXECUTABLE;
if(!executablePath)throw Error("SOUNDPOST_FIXTURE_BROWSER_EXECUTABLE is required");
const pin=process.env.SOUNDPOST_FIXTURE_BROWSER_SPKI;
export default defineConfig({testDir:".",testMatch:"critical-path.spec.ts",workers:1,retries:0,reporter:"line",timeout:120000,outputDir:process.env.SOUNDPOST_FIXTURE_BROWSER_OUTPUT??"test-results",
 use:{headless:true,ignoreHTTPSErrors:false,launchOptions:{executablePath,args:["--no-sandbox",...(pin?["--ignore-certificate-errors-spki-list="+pin]:[])]}}});
