// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {canonical} from "../src/policy.ts";
import {config,signed} from "./fixture.ts";
import type {Config} from "../src/types.ts";
export const JOB="a".repeat(32),RUN="b".repeat(32);
export function jobSettings(changes:Partial<Config>={}):Config {
 const base=config();return {...base,jobRegistry:{"fixture.task":JOB},policy:signed(canonical({version:1,org:base.org,project:base.project,source:base.source,revision:"1",expires_ns:"9223372036854775807",errors:true,logs:true,replay:false,bodies:false,traces:true,jobs:true,loss:true})),...changes};
}
