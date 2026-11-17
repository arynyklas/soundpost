// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Pins the arithmetic, arm alternation and load phases of the overhead harness (fixtures/sdk/overhead-lib.mjs, D54).
// Run: bun test fixtures/sdk/overhead.test.ts
import {describe,expect,test} from "bun:test";
// @ts-ignore the library is plain ESM shared with the Node harness
import {PROTOCOL,armOrder,compare,compareArms,conformance,counterDelta,d54Row,figures,latencyStats,mean,planPhases,quantile,runLoad,stdev,summary} from "./overhead-lib.mjs";

const BUDGET={p95_percent:5,cpu_percent:5};

describe("statistics", () => {
 test("mean, sample standard deviation and the nearest-rank quantile", () => {
  expect(mean([2,4,6])).toBe(4);
  expect(stdev([2,4,6])).toBe(2);
  expect(stdev([5])).toBe(0);
  const sorted=Array.from({length:100},(_,i)=>i+1);
  expect(quantile(sorted,0.5)).toBe(50);
  expect(quantile(sorted,0.95)).toBe(95);
  expect(quantile(sorted,0.99)).toBe(99);
  expect(quantile(sorted,1)).toBe(100);
  expect(quantile([],0.95)).toBeNull();
 });
 test("latency stats sort their input and leave it alone", () => {
  const input=[9,1,5,3,7,2,8,4,6,10];
  const stats=latencyStats(input);
  expect(input).toEqual([9,1,5,3,7,2,8,4,6,10]);
  expect(stats).toEqual({count:10,p50_ms:5,p95_ms:10,p99_ms:10,max_ms:10});
 });
 test("compare is (variant-base)/base of the means with a two-standard-error flag", () => {
  const c=compare([100,100,100,100,100],[110,110,110,110,110]);
  expect(c.delta_percent).toBe(10);
  expect(c.delta_abs).toBe(10);
  expect(c.standard_error_abs).toBe(0);
  expect(c.delta_exceeds_two_standard_errors).toBe(true);
  const noisy=compare([90,110,95,105,100],[93,109,100,103,98]);
  expect(noisy.delta_percent).toBe(0.6);
  expect(noisy.delta_exceeds_two_standard_errors).toBe(false);
  expect(summary([1,2,3]).mean).toBe(2);
  expect(summary([1,2,3]).cv_percent).toBe(50);
 });
});

describe("arm alternation", () => {
 const arms=["baseline","capture"];
 test("every repetition runs both arms once and the first arm alternates", () => {
  const runs=Array.from({length:6},(_,i)=>armOrder(i,arms));
  for(const order of runs)expect([...order].sort()).toEqual(["baseline","capture"]);
  expect(runs.map(o=>o[0])).toEqual(["baseline","capture","baseline","capture","baseline","capture"]);
  expect(runs.filter(o=>o[0]==="baseline").length).toBe(runs.filter(o=>o[0]==="capture").length);
 });
 test("an odd count of repetitions favours neither arm by more than one start", () => {
  const firsts=Array.from({length:5},(_,i)=>armOrder(i,arms)[0]);
  expect(Math.abs(firsts.filter(a=>a==="baseline").length-firsts.filter(a=>a==="capture").length)).toBe(1);
 });
 test("the arm list is not mutated", () => {
  const list=["baseline","capture"];
  armOrder(1,list);
  expect(list).toEqual(["baseline","capture"]);
 });
});

describe("protocol", () => {
 test("the defaults are D54: fixed warm-up, >=30 s steady state, >=5 repetitions", () => {
  expect(PROTOCOL.steadyS).toBeGreaterThanOrEqual(30);
  expect(PROTOCOL.runs).toBeGreaterThanOrEqual(5);
  expect(conformance(PROTOCOL)).toEqual({conforms_d54:true,not_conforming:[]});
 });
 test("a shorter protocol is reported as not conforming, with every reason", () => {
  const c=conformance({warmupS:2,steadyS:3,runs:3});
  expect(c.conforms_d54).toBe(false);
  expect(c.not_conforming.length).toBe(3);
  expect(conformance({...PROTOCOL,steadyS:29.9}).conforms_d54).toBe(false);
  expect(conformance({...PROTOCOL,runs:4}).conforms_d54).toBe(false);
  expect(conformance({...PROTOCOL,warmupS:9}).conforms_d54).toBe(false);
 });
 test("phases: discarded ramp and warm-up, the cold window inside the warm-up, then the steady state in slices", () => {
  const phases=planPhases({warmupS:10,steadyS:30});
  expect(phases.map((p:any)=>[p.name,p.seconds,p.group])).toEqual([["ramp",1,null],["cold",3,"cold"],["warm-up",6,null],["warm.0",10,"warm"],["warm.1",10,"warm"],["warm.2",10,"warm"]]);
  const discarded=phases.filter((p:any)=>!p.group).reduce((n:number,p:any)=>n+p.seconds,0)+3;
  expect(discarded).toBe(10);
  expect(phases.filter((p:any)=>p.group==="warm").reduce((n:number,p:any)=>n+p.seconds,0)).toBe(30);
 });
 test("a steady window that is not a multiple of the slice keeps its full length", () => {
  const warm=planPhases({warmupS:10,steadyS:25}).filter((p:any)=>p.group==="warm");
  expect(warm.map((p:any)=>p.seconds)).toEqual([10,10,5]);
 });
 test("without a cold window the whole warm-up is one discarded phase", () => {
  expect(planPhases({warmupS:1,steadyS:3,cold:false}).map((p:any)=>[p.name,p.seconds,p.group])).toEqual([["warm-up",1,null],["warm.0",3,"warm"]]);
 });
 test("a warm-up shorter than the cold window it contains, or an empty steady state, is refused", () => {
  expect(() => planPhases({warmupS:3,steadyS:30})).toThrow();
  expect(() => planPhases({warmupS:10,steadyS:0})).toThrow();
 });
});

describe("counters", () => {
 test("a window's counters are the difference of two snapshots, CPU in microseconds", () => {
  const d=counterDelta({requests:100,user_us:5000,system_us:1000,elu_active_ms:20,queue_bytes:0,max_queue_bytes:0,diagnostics:{}},{requests:1100,user_us:305000,system_us:81000,elu_active_ms:70,queue_bytes:12,max_queue_bytes:40,diagnostics:{queue_full:2}});
  expect(d).toEqual({requests:1000,cpu_us:380000,user_us:300000,system_us:80000,elu_active_us:50000,queue_bytes_end:12,max_queue_bytes:40,diagnostics:{queue_full:2}});
  expect(figures({latency:latencyStats([1,2,3]),errors:0,sent:1000,wall_s:2,server:d}).cpu_us_per_request).toBe(380);
  expect(figures({latency:latencyStats([1]),errors:0,sent:1000,wall_s:2,server:d}).achieved_rps).toBe(500);
 });
 test("a window that saw no request divides by one, not by zero", () => {
  const d=counterDelta({requests:5,user_us:0,system_us:0,elu_active_ms:0,queue_bytes:0,max_queue_bytes:0,diagnostics:{}},{requests:5,user_us:10,system_us:0,elu_active_ms:0,queue_bytes:0,max_queue_bytes:0,diagnostics:{}});
  expect(figures({latency:latencyStats([]),errors:0,sent:0,wall_s:1,server:d}).cpu_us_per_request).toBe(10);
 });
});

/** A fake server and clock for runLoad: a request costs `cost(now)` CPU microseconds and has latency `latency(now)`. */
function fakeWorld(cost:(ms:number)=>number,latency:(ms:number)=>number){
 let clock=0,requests=0,cpu=0;
 const world={
  now:()=>clock,
  sleep:async(ms:number)=>{clock+=ms;},
  send:async(_i:number)=>{requests++;cpu+=cost(clock);return latency(clock);},
  snapshot:async()=>({requests,user_us:cpu,system_us:0,elu_active_ms:0,queue_bytes:0,max_queue_bytes:0,diagnostics:{}}),
 };
 return world;
}

describe("load phases", () => {
 test("the warm figure is the steady state only; the warm-up is discarded and the cold window is its own figure", async () => {
  // First 10 s: 300 us and 50 ms per request (interpreter and compile); afterwards 100 us and 1 ms.
  const w=fakeWorld(ms=>ms<10000?300:100,ms=>ms<10000?50:1);
  const {windows,slices}=await runLoad({phases:planPhases({warmupS:10,steadyS:30}),rps:1000,...w});
  const warm=figures(windows.warm),cold=figures(windows.cold);
  expect(warm.cpu_us_per_request).toBe(100);
  expect(warm.stats.p95_ms).toBe(1);
  expect(cold.cpu_us_per_request).toBe(300);
  expect(cold.stats.p95_ms).toBe(50);
  expect(windows.warm.wall_s).toBeGreaterThanOrEqual(30);
  expect(windows.warm.wall_s).toBeLessThan(31);
  expect(windows.cold.wall_s).toBeGreaterThanOrEqual(3);
  expect(warm.achieved_rps).toBeGreaterThan(990);
  expect(warm.achieved_rps).toBeLessThan(1010);
  expect(windows.warm.sent).toBeGreaterThan(29900);
  expect(slices.length).toBe(3);
  expect(slices.map((s:any)=>figures(s).cpu_us_per_request)).toEqual([100,100,100]);
 });
 test("a request is counted in the phase that sent it, and the total sent follows the requested rate", async () => {
  const w=fakeWorld(()=>10,()=>1);
  const {windows}=await runLoad({phases:planPhases({warmupS:10,steadyS:30}),rps:500,...w});
  expect(windows.cold.sent).toBeGreaterThan(1490);
  expect(windows.cold.sent).toBeLessThan(1510);
  expect(windows.warm.sent).toBeGreaterThan(14950);
  expect(windows.warm.sent).toBeLessThan(15050);
  expect(windows.warm.server.requests).toBe(windows.warm.sent);
 });
 test("failed requests are counted as errors and carry no latency", async () => {
  const w=fakeWorld(()=>1,()=>1);
  let n=0;
  const send=async(i:number)=>{if(++n%10===0)throw new Error("reset");return w.send(i);};
  const {windows}=await runLoad({phases:planPhases({warmupS:5,steadyS:10,cold:false}),rps:100,now:w.now,sleep:w.sleep,snapshot:w.snapshot,send});
  expect(windows.warm.errors).toBe(100);
  expect(windows.warm.latency.count+windows.warm.errors).toBe(windows.warm.sent);
 });
});

describe("the D54 row", () => {
 const run=(cpuCold:number,cpuWarm:number,p95Cold:number,p95Warm:number,slices=[cpuWarm,cpuWarm,cpuWarm])=>{
  const win=(cpu:number,p95:number,sent:number,wall:number)=>({latency:{count:sent,p50_ms:p95/2,p95_ms:p95,p99_ms:p95*2,max_ms:p95*3},errors:0,sent,wall_s:wall,server:{requests:sent,cpu_us:cpu*sent,user_us:cpu*sent,system_us:0,elu_active_us:0,queue_bytes_end:0,max_queue_bytes:0,diagnostics:{queue_full:0}}});
  return {cold:win(cpuCold,p95Cold,3000,3),warm:win(cpuWarm,p95Warm,30000,30),slices:slices.map((c,i)=>({name:"warm."+i,...win(c,p95Warm,10000,10)}))};
 };
 const budget=BUDGET;
 test("the warm figures are gated and sit at the top level; the cold window is reported next to them", () => {
  // Cold: capture +50 % CPU; warm: capture +4 %.
  const collected={baseline:[run(300,200,2,1),run(300,200,2,1),run(300,200,2,1),run(300,200,2,1),run(300,200,2,1)],capture:[run(450,208,3,1.04),run(450,208,3,1.04),run(450,208,3,1.04),run(450,208,3,1.04),run(450,208,3,1.04)]};
  const row=d54Row(collected,{capture:"capture",protocol:{...PROTOCOL},budget,delivered:true});
  expect(row.process_cpu_us_per_request.delta_percent).toBe(4);
  expect(row.p95_latency_ms.delta_percent).toBe(4);
  expect(row.verdict.process_cpu).toBe("within_budget_point_estimate");
  expect(row.verdict.p95).toBe("within_budget_point_estimate");
  expect(row.cold_window.process_cpu_us_per_request.delta_percent).toBe(50);
  expect(row.cold_window.verdict.process_cpu).toBe("exceeds_budget");
  expect(row.process_cpu_us_per_request.baseline.values).toEqual([200,200,200,200,200]);
  expect(row.process_cpu_us_per_request.capture.n).toBe(5);
  expect(row.measurement.conforms_d54).toBe(true);
  expect(row.measurement.gated_window).toBe("warm");
 });
 test("a warm figure over the budget fails even when the cold window is under it", () => {
  const collected={baseline:Array(5).fill(run(300,200,1,1)),capture:Array(5).fill(run(310,230,1,1))};
  const row=d54Row(collected,{capture:"capture",protocol:{...PROTOCOL},budget,delivered:true});
  expect(row.verdict.process_cpu).toBe("exceeds_budget");
  expect(row.cold_window.verdict.process_cpu).toBe("within_budget_point_estimate");
 });
 test("the arms are listed in the order they ran and alternate", () => {
  const collected={baseline:Array(5).fill(run(1,1,1,1)),"capture-delivered":Array(5).fill(run(1,1,1,1))};
  const row=d54Row(collected,{capture:"capture-delivered",protocol:{...PROTOCOL},budget});
  expect(row.measurement.arm_order).toEqual([["baseline","capture-delivered"],["capture-delivered","baseline"],["baseline","capture-delivered"],["capture-delivered","baseline"],["baseline","capture-delivered"]]);
 });
 test("steady-state slices are reported per repetition so a drifting warm-up shows", () => {
  const collected={baseline:Array(5).fill(run(1,100,1,1,[130,110,100])),capture:Array(5).fill(run(1,100,1,1,[140,112,101]))};
  const row=d54Row(collected,{capture:"capture",protocol:{...PROTOCOL},budget});
  expect(row.warm_slices_cpu_us_per_request.baseline[0]).toEqual([130,110,100]);
  expect(row.warm_slices_cpu_us_per_request.capture[4]).toEqual([140,112,101]);
 });
 test("a shortened protocol is marked not conforming and drops queue-full drops into the verdict", () => {
  const w=run(1,1,1,1);
  const dropping={...w,warm:{...w.warm,server:{...w.warm.server,diagnostics:{queue_full:7}}}};
  const collected={baseline:Array(3).fill(w),capture:Array(3).fill(dropping)};
  const row=d54Row(collected,{capture:"capture",protocol:{warmupS:1,steadyS:3,runs:3,sliceS:10},budget,delivered:true});
  expect(row.measurement.conforms_d54).toBe(false);
  expect(row.queue_full_drops).toEqual([7,7,7]);
  expect(row.verdict.delivered_without_queue_full).toBe(false);
 });
 test("compareArms reads the baseline and capture arms by name", () => {
  const f=(cpu:number)=>figures(run(cpu,cpu,1,1).warm);
  const out=compareArms({baseline:[f(100),f(100)],other:[f(120),f(120)]},{capture:"other",budget});
  expect(out.process_cpu_us_per_request.delta_percent).toBe(20);
  expect(out.verdict.process_cpu).toBe("exceeds_budget");
  expect(out.event_loop_active_us_per_request).toBeUndefined();
 });
});
