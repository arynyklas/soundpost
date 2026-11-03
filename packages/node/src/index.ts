// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {Client as CoreClient} from "@soundpost/core";
import type {Config} from "@soundpost/core/types";
import {types} from "node:util";
export class Client extends CoreClient {
 constructor(config:Config){super(config,{isNativeError:types.isNativeError,isProxy:types.isProxy});}
}
export function init(config:Config):Client{return new Client(config);}
export {installHooks,HookLease} from "./hooks.ts";
export type {Config, EventId, PolicyDecision, FlushReport, Template, Severity} from "@soundpost/core/types";
