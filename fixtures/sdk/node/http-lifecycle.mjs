// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {init,installHttp} from "../../../packages/node/src/index.ts";
import {exerciseHttpLifecycle} from "./http-lifecycle-fixture.mjs";
if(!/^v(?:22|24)\./.test(process.version)||process.versions.bun)throw Error("actual_Node22_or24_required");
await exerciseHttpLifecycle(init,installHttp,"Node"+process.version);
