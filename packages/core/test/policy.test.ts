// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {test, expect} from "bun:test";
import {init} from "../src/client.ts";
import {config,signed} from "./fixture.ts";
test("policy precedes queue without evaluating hostile values",()=>{
 const c=init(config()); const trap={get message(){throw Error("getter");},toJSON(){throw Error("toJSON");}};
 expect(c.captureLog("unknown",{})).toBeUndefined();
 expect(c.diagnostics().unknown_template).toBe(1);
 c.captureException(trap); c.captureLog("operation.failed",{status:503,password:trap});
 const data=c.bufferedRecords().join("");
 expect(data).toContain("9007199254740993"); expect(data).toContain("operation failed: 503");
 for(const x of ["SECRET","password","getter","toJSON"]) expect(data).not.toContain(x);
 expect(c.policyDecision.replay).toBe(false); expect(c.policyDecision.bodies).toBe(false);
});
test("templates are immutable history and clients independent",()=>{
 const c=init(config()),d=init(config("other")); c.captureLog("operation.failed",{status:503}); const before=c.bufferedRecords();
 c.registerTemplate({id:"operation.failed",revision:"2",line:"new: {status}",fields:{status:[503]},severity:"error"});
 expect(c.bufferedRecords()).toEqual(before); expect(d.bufferedRecords()).toEqual([]);
 c.captureLog("operation.failed",{status:503}); expect(c.bufferedRecords()[1]).toContain("new: 503");
});
test("invalid signatures, bindings, expiry and bounds",()=>{
 expect(()=>init({...config(),trustedKeys:{test:new Uint8Array(32)}})).toThrow();
 expect(()=>init({...config(),project:"wrong"})).toThrow();
 const c=init({...config(),clockNs:()=>"99999999999999999999"}); expect(c.captureLog("operation.failed",{status:503})).toBeUndefined(); expect(c.diagnostics().policy_expired).toBe(1);
 const d=init({...config(),maxRecords:1});d.captureException(null);d.captureException(null);expect(d.bufferedRecords()).toHaveLength(1);expect(d.diagnostics().queue_full).toBe(1);
});
test("canonical signature and source trust fail closed",()=>{
 const c=config(),valid=Buffer.from(c.policy.payload,"base64url").toString("utf8");
 const doc=JSON.parse(valid) as Record<string,unknown>;
 const unsorted=JSON.stringify(doc,Object.keys(doc).reverse());
 for(const text of [valid.replace('"version":1','"version":1.0'),valid.replace('"version":1','"version":NaN'),valid.replace('"version":1','"version":1,"version":1'),unsorted])
  expect(()=>init({...c,policy:signed(text)})).toThrow("invalid signed policy");
 expect(()=>init({...c,trustedKeys:{}})).toThrow("invalid signed policy");
 expect(()=>init({...c,policy:{...c.policy,key_id:"unknown"}})).toThrow("invalid signed policy");
 const signature=Buffer.from(c.policy.signature,"base64url");signature[0]=(signature[0]??0)^1;
 expect(()=>init({...c,policy:{...c.policy,signature:signature.toString("base64url")}})).toThrow("invalid signed policy");
 expect(()=>init({...c,source:"other"})).toThrow("invalid signed policy");
 expect(()=>init({...c,policy:{...c.policy,payload:c.policy.payload+"="}})).toThrow("invalid signed policy");
 expect(()=>init({...c,policy:{...c.policy,signature:c.policy.signature+"="}})).toThrow("invalid signed policy");
});
test("approved-field accessors are rejected without invocation and close destroys queue",async()=>{
 const c=init(config());const fields={get status(){throw Error("getter invoked");}};
 expect(c.captureLog("operation.failed",fields)).toBeUndefined();
 expect(c.diagnostics().invalid_field).toBe(1);
 c.captureException(null);await c.close();expect(c.bufferedRecords()).toEqual([]);
 expect(c.diagnostics().closed_pending).toBe(1);
 c.captureException(null);expect(c.diagnostics().closed).toBe(1);
});
test("safe records use the exact native snake_case wire mirror",()=>{
 const c=init(config());c.captureException(null);c.captureLog("operation.failed",{status:503});
 const records=c.bufferedRecords().map(text=>JSON.parse(text) as {kind:string;payload:Record<string,unknown>});
 for(const record of records)expect(Object.keys(record).sort()).toEqual(["id","kind","observed_at_ns","payload","policy_revision"]);
 expect(Object.keys(records[0]!.payload).sort()).toEqual(["build_id","code","exception_class","fatal","frames","handled","occurrence_id"]);
 expect(Object.keys(records[1]!.payload).sort()).toEqual(["fields","line","severity","source_class","stream_labels","structured_metadata","template_id","template_revision"]);
});
test("UTF-8 byte boundaries preserve registered severity and reject unpaired surrogates",()=>{
 const c=init(config()),value="😀".repeat(64);
 c.registerTemplate({id:"unicode",revision:"1",line:"😀".repeat(1024),fields:{value:[value]},severity:"info"});
 c.captureLog("unicode",{value});
 const record=JSON.parse(c.bufferedRecords()[0]!) as {payload:{severity:string;line:string}};
 expect(record.payload.severity).toBe("info");expect(record.payload.line).toBe("😀".repeat(1024));
 for(const template of [
  {id:"long.line",revision:"1",line:"😀".repeat(1024)+"a",fields:{},severity:"warn" as const},
  {id:"long.value",revision:"1",line:"{value}",fields:{value:[value+"a"]},severity:"warn" as const},
  {id:"surrogate.line",revision:"1",line:"\ud800",fields:{},severity:"warn" as const},
  {id:"surrogate.value",revision:"1",line:"{value}",fields:{value:["\ud800"]},severity:"warn" as const},
 ])expect(()=>c.registerTemplate(template)).toThrow();
 expect(()=>init({...config(),build:"😀".repeat(32)})).not.toThrow();
 expect(()=>init({...config(),build:"😀".repeat(32)+"a"})).toThrow();
 expect(()=>init({...config(),build:"\ud800"})).toThrow();
});
