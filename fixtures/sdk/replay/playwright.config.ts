// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {defineConfig, devices} from "@playwright/test";
import {firefoxProject} from "../firefox/project.ts";
// SOUNDPOST_CHROME optionally names a managed Chrome binary; the default is Playwright's own Chromium.
const executablePath = process.env.SOUNDPOST_CHROME;
// SOUNDPOST_CHROME_ARGS: extra space-separated launch flags for hosts that cannot sandbox (for example an unprivileged Linux VM: --no-sandbox).
const args = (process.env.SOUNDPOST_CHROME_ARGS ?? "").split(" ").filter(Boolean);
// SOUNDPOST_PLAYWRIGHT_WEBKIT=1 runs ONLY Playwright's own WebKit build (the engine, not real Safari: Safari on macOS is out of release scope, D10); a Firefox run and a WebKit run are each their own project, never satisfied by a Chromium result.
const webkit = process.env.SOUNDPOST_PLAYWRIGHT_WEBKIT === "1" ? {name: "webkit", use: {...devices["Desktop Safari"]}} : undefined;
const firefox = firefoxProject();
// Both selectors set (a shell that exported SOUNDPOST_FIREFOX for a Firefox run and was reused for WebKit) would silently run Firefox under a WebKit label: refuse instead.
if (webkit && firefox) throw Error("SOUNDPOST_PLAYWRIGHT_WEBKIT=1 and SOUNDPOST_FIREFOX are both set: a run is one engine; unset one");
export default defineConfig({
 testDir: ".",
 testMatch: ["recorder.spec.ts", "viewer.spec.ts"],
 fullyParallel: false, workers: 1, retries: 0,
 use: {trace: "off", screenshot: "off", video: "off"},
 projects: [firefox ?? webkit ?? {name: "chromium", use: {...devices["Desktop Chrome"], ...(executablePath ? {launchOptions: {executablePath, args}} : {})}}],
});
