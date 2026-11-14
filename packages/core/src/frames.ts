// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
export interface SafeFrame {
 readonly artifact_id:string;readonly module_id:string;readonly function:string;
 readonly line:number;readonly column:number|null;readonly in_app:boolean;readonly async:boolean;
}
/** V8's own stack descriptor may lazily call Error.prepareStackTrace and message/name
 * accessors. Neither strings nor user CallSite objects are an intrinsic frame boundary.
 * Until an owned runtime structured-exception source is installed, return a capability
 * reason, never inspect .stack and never invent an empty-success frame extraction. */
export const originalStackLimitation="safe_original_stack_unavailable";
