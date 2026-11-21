// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Real Bun 1.3.14 job journey against an actual Soundpost endpoint: failure ordinal 1, success
// ordinal 2 and a runtime cancellation all travel through C03/C05 and are read back by an
// independent scoped verifier (see journey.mjs). Run: bun fixtures/sdk/jobs/bun-attempts.ts
import {init} from "../../../packages/bun/src/index.ts";
import {runJobAttempts} from "./journey.mjs";
try{await runJobAttempts(init,"bun");}catch{console.error("bun_job_attempt_fixture_failed");process.exitCode=1;}
