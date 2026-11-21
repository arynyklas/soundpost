// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {defineConfig,devices} from '@playwright/test';
const origin=process.env.SOUNDPOST_TEST_ORIGIN;
if(!origin || new URL(origin).protocol!=='https:')throw new Error('SOUNDPOST_TEST_ORIGIN must name the real trusted HTTPS server');
// Provisioning only (see e2e-provision/provision.spec.ts): one chromium run that writes the environment the suite reads.
export default defineConfig({testDir:'./e2e-provision',workers:1,retries:0,use:{baseURL:origin,ignoreHTTPSErrors:false},projects:[{name:'chromium',use:{...devices['Desktop Chrome']}}]});
