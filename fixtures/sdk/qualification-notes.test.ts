// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// 03.09-C16 (review finding 2): the notes baked into the SDK qualification manifest must not state capability falsehoods.
// Run: bun test fixtures/sdk/qualification-notes.test.ts
import {describe,expect,test} from "bun:test";
import {readFileSync} from "node:fs";
import {resolve} from "node:path";

const root=resolve(import.meta.dir,"../..");
const read=(path:string)=>readFileSync(resolve(root,path),"utf8");
const manifest=JSON.parse(read("fixtures/sdk/qualification.json")) as {measured_evidence:{unqualified_rows:{row:string;reason:string}[]}};
const qualify=read("fixtures/sdk/qualify.mjs");
const ROW="runtime-supplement-export-through-C03";
const manifestReason=manifest.measured_evidence.unqualified_rows.find(entry=>entry.row===ROW)?.reason??"";
const scriptReason=new RegExp(`note\\("${ROW}","((?:[^"\\\\]|\\\\.)*)"\\)`).exec(qualify)?.[1]??"";

describe("runtime-supplement-export-through-C03 note",()=>{
 test("the manifest row and the script that regenerates it say the same thing",()=>{
  expect(scriptReason).not.toBe("");
  expect(manifestReason).toBe(scriptReason);
 });

 test("it does not claim that core has no capability/profile input or that the backend admits only three profile methods",()=>{
  for(const text of [manifestReason,scriptReason]){
   expect(text).not.toContain("has no capability/profile input");
   expect(text).not.toContain("accepts only runtime_cpu|native_cpu|native_offcpu");
   expect(text).not.toContain("cannot be admitted");
  }
 });

 test("every capability claim the note makes is true of the tree",()=>{
  expect(read("packages/core/src/types.ts")).toMatch(/export type CaptureInput=[^;\n]*ProfileInput[^;\n]*CapabilityInput/);
  expect(read("packages/core/src/client.ts")).toContain("captureProfile(capability:CapabilityInput");
  const validation=read("internal/model/telemetry_validation.go");
  expect(validation).toContain('"runtime_cpu"');
  expect(validation).toContain("case Profile:");
 });
});
