// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {init} from "../src/client.ts";
import {config} from "./fixture.ts";
const c=init(config());const hostile={get message(){throw Error("getter invoked");},toJSON(){throw Error("toJSON invoked");}};
c.captureException(hostile);c.captureLog("operation.failed",{status:503,sql:"SELECT PRIVATE_CANARY",credential:"SECRET"});
const data=JSON.stringify({records:c.bufferedRecords(),diagnostics:c.diagnostics()});
if(data.includes("PRIVATE_CANARY")||data.includes("SECRET")||!data.includes("UnknownError")||!data.includes("operation.failed"))throw Error("privacy smoke failed");
const record=JSON.parse(c.bufferedRecords()[0]!) as {observed_at_ns:string};
if(record.observed_at_ns!=="9007199254740993")throw Error("exact timestamp smoke failed");
console.log(JSON.stringify({records:c.bufferedRecords().length,privacy_canaries:0,observed_at_ns:record.observed_at_ns}));
