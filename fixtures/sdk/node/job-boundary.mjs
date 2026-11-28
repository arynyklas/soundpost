// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {init} from "../../../packages/node/src/index.ts";
import {runJobBoundary} from "../jobs/journey.mjs";
try{await runJobBoundary(init,"node");}catch{console.error("node_job_boundary_fixture_failed");process.exitCode=1;}
