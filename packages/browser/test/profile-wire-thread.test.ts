// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {test, expect} from "bun:test";
import {profileWire} from "../src/profile_wire.ts";

test("a sample thread named like an Object.prototype member maps to thread 0, never a function", () => {
 for (const thread of ["constructor", "__proto__", "hasOwnProperty", "toString"]) {
  const d = {host: "1".repeat(32), boot: "2".repeat(32), runtime: "3".repeat(32)};
  const report = {capability: {id: "4".repeat(32), runtime: "Chrome/1", version: "1", build: "b", os: "linux", arch: "x86_64", signal: "profile_chunk", method: "browser_js_self_profile", status: "supported", reason: "ok",
   coverage: {frames: "partial", threads: "partial", workers: "none", tasks: "none"}, clock_domain: d, expires_ns: "9"},
   clock: {domain: d, uncertainty_ns: "0", wall_start_ns: "1", wall_end_ns: "2"}, frames: [], stacks: [{frames: []}], samples: [{at_us: "0", stack: 0, thread}], truncated: false, losses: []};
  const wire = profileWire(report as never, {process: "5".repeat(32), id: () => "6".repeat(32)});
  const samples = (wire.chunks[0]!.payload as {samples: {thread: unknown}[]}).samples;
  expect(samples[0]!.thread).toBe("0");
 }
});
