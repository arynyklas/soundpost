// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Budget gates (design 13) kept out of the default replay run so a failing budget never masks the behavior specs:
//   cd web && pnpm exec playwright test -c ../fixtures/sdk/replay/budget.config.ts
import base from "./playwright.config.ts";
export default {...base, testMatch: ["mutation-batch.spec.ts"]};
