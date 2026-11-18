// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {defineConfig} from "@playwright/test";
import {firefoxProject} from "../firefox/project.ts";
// One pinned real browser per run: the driver (fixtures/sdk/critical, --mode browser) names the executable and the
// exact certificate pin for the private CA leaf. There is no fallback browser and no ignoreHTTPSErrors.
// Stock Firefox (target Firefox) is driven through Playwright's WebDriver BiDi channel (fixtures/sdk/firefox); it trusts the private CA through
// the enterprise policy file the driver installs, not through a flag.
const executablePath=process.env.SOUNDPOST_FIXTURE_BROWSER_EXECUTABLE;
if(!executablePath)throw Error("SOUNDPOST_FIXTURE_BROWSER_EXECUTABLE is required");
const pin=process.env.SOUNDPOST_FIXTURE_BROWSER_SPKI;
if(process.env.SOUNDPOST_FIXTURE_BROWSER_TARGET==="Firefox")process.env.SOUNDPOST_FIREFOX=executablePath;
const firefox=process.env.SOUNDPOST_FIXTURE_BROWSER_TARGET==="Firefox"?firefoxProject():undefined;
export default defineConfig({testDir:".",testMatch:"critical-path.spec.ts",workers:1,retries:0,reporter:"line",timeout:120000,outputDir:process.env.SOUNDPOST_FIXTURE_BROWSER_OUTPUT??"test-results",
 use:{headless:true,ignoreHTTPSErrors:false,...(firefox?{}:{launchOptions:{executablePath,args:["--no-sandbox",...(pin?["--ignore-certificate-errors-spki-list="+pin]:[])]}})},
 ...(firefox?{projects:[firefox]}:{})});
