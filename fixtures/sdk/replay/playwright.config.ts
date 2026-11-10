// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {defineConfig, devices} from "@playwright/test";
// SOUNDPOST_CHROME optionally names a managed Chrome binary; the default is Playwright's own Chromium.
const executablePath = process.env.SOUNDPOST_CHROME;
export default defineConfig({
 testDir: ".",
 testMatch: "recorder.spec.ts",
 fullyParallel: false, workers: 1, retries: 0,
 use: {trace: "off", screenshot: "off", video: "off"},
 projects: [{name: "chromium", use: {...devices["Desktop Chrome"], ...(executablePath ? {launchOptions: {executablePath}} : {})}}],
});
