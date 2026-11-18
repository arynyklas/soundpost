// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {resolve} from "node:path";

// SOUNDPOST_FIREFOX names a stock Firefox binary (the frozen target is 144.0.2). When set, a Playwright config runs ONLY this project, so
// a Firefox run can never be satisfied by a Chromium result. The launcher stands in for the executable (see bidi-proxy.ts) and the
// real binary is handed over through SOUNDPOST_FIREFOX_BINARY.
export function firefoxProject() {
 const binary = process.env.SOUNDPOST_FIREFOX;
 if (!binary) return undefined;
 process.env.SOUNDPOST_FIREFOX_BINARY = binary;
 return {name: "firefox", use: {browserName: "firefox" as const, channel: "moz-firefox", launchOptions: {executablePath: resolve(__dirname, "firefox-bidi")}}};
}
