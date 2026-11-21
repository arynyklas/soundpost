// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {init} from "../../../packages/bun/src/index.ts";
import {runJobAttempts} from "../jobs/journey.mjs";
try{await runJobAttempts(init,"bun");}catch{console.error("bun_job_attempt_fixture_failed");process.exitCode=1;}
