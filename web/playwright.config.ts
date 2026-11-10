// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {defineConfig,devices} from '@playwright/test';
const origin=process.env.SOUNDPOST_TEST_ORIGIN;
if(!origin || new URL(origin).protocol!=='https:')throw new Error('SOUNDPOST_TEST_ORIGIN must name the real trusted HTTPS server');
// The supported-browser matrix is Chromium, Firefox and WebKit. A project whose browser is not installed on the host FAILS to launch;
// it is never skipped or reported as passed. `--project=chromium` selects the one browser installed where the acceptance was run.
export default defineConfig({testDir:'./e2e',fullyParallel:false,workers:1,retries:0,use:{baseURL:origin,ignoreHTTPSErrors:false,trace:'off',screenshot:'off',video:'off'},projects:[{name:'chromium',use:{...devices['Desktop Chrome']}},{name:'firefox',use:{...devices['Desktop Firefox']}},{name:'webkit',use:{...devices['Desktop Safari']}}]});
