// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {test} from "node:test";
import assert from "node:assert/strict";
import {exclusiveCaptureEnd} from "./window.mjs";
test("half-open fixture end includes a known equal-boundary capture exactly",()=>{
 assert.equal(exclusiveCaptureEnd("9007199254740993",[{observed_at_ns:"9007199254740993"}]),"9007199254740994");
 assert.equal(exclusiveCaptureEnd("9007199254741993",[{observed_at_ns:"9007199254740993"}]),"9007199254741993");
 assert.equal(exclusiveCaptureEnd("9007199254740993",[{observed_at_ns:"9007199254741993"},{observed_at_ns:"9007199254740993"}]),"9007199254741994");
 assert.equal(exclusiveCaptureEnd("-17",[{observed_at_ns:"-17"}]),"-16");
});
test("capture window rejects impossible signed-int64 exclusive ends rather than wrapping",()=>{
 assert.equal(exclusiveCaptureEnd("9223372036854775807",[{observed_at_ns:"9223372036854775806"}]),"9223372036854775807");
 assert.throws(()=>exclusiveCaptureEnd("9223372036854775807",[{observed_at_ns:"9223372036854775807"}]),/fixture_window_exhausted/);
 for(const value of ["01","1.0","9223372036854775808",9007199254740992])assert.throws(()=>exclusiveCaptureEnd(value,[]),/invalid_fixture_clock/);
});
