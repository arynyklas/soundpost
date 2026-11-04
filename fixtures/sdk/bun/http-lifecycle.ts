// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {init,installHttp} from "../../../packages/bun/src/index.ts";
import {exerciseHttpLifecycle} from "../node/http-lifecycle-fixture.mjs";
if(Bun.version!=="1.3.14")throw Error("actual_Bun1.3.14_required");
await exerciseHttpLifecycle(init,installHttp,"Bun"+Bun.version);
