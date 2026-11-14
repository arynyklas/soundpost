// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {defineConfig, devices} from "@playwright/test";
// SOUNDPOST_CHROME optionally names a managed Chrome binary; the default is Playwright's own Chromium.
const executablePath = process.env.SOUNDPOST_CHROME;
// SOUNDPOST_CHROME_ARGS: extra space-separated launch flags for hosts that cannot sandbox (for example an unprivileged Linux VM: --no-sandbox).
const args = (process.env.SOUNDPOST_CHROME_ARGS ?? "").split(" ").filter(Boolean);
export default defineConfig({
 testDir: ".",
 testMatch: ["recorder.spec.ts", "viewer.spec.ts"],
 fullyParallel: false, workers: 1, retries: 0,
 use: {trace: "off", screenshot: "off", video: "off"},
 projects: [{name: "chromium", use: {...devices["Desktop Chrome"], ...(executablePath ? {launchOptions: {executablePath, args}} : {})}}],
});
