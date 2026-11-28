// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Budget gates (design 13) kept out of the default replay run so a failing budget never masks the behavior specs:
//   cd web && pnpm exec playwright test -c ../fixtures/sdk/replay/budget.config.ts
import base from "./playwright.config.ts";
// Firefox rounds performance.now() to 1 ms by default (privacy.reduceTimerPrecision), which would floor every per-batch duration the spec measures. The measuring Firefox runs with the
// reduction off (the page and the recorder are untouched; only the clock the gate reads is exact), so a Firefox row is as precise as a Chromium one.
const exactClock = {"privacy.reduceTimerPrecision": false, "privacy.resistFingerprinting": false};
export default {
 ...base, testMatch: ["mutation-batch.spec.ts"],
 projects: base.projects?.map(project => project.name === "firefox" ? {...project, use: {...project.use, launchOptions: {...project.use?.launchOptions, firefoxUserPrefs: exactClock}}} : project),
};
