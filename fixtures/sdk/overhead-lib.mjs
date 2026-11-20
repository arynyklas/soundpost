// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// The arithmetic, arm scheduling and load-phase logic of fixtures/sdk/overhead.mjs, kept free of process and runtime
// dependencies so overhead.test.ts can pin it (the harness itself starts servers and a load process).
//
// D54 (server SDK overhead is measured warm, as design section 13 states): every server run starts a fresh process, drives the
// open-loop load through a fixed warm-up that is discarded for both arms identically, then measures a steady-state window of at
// least 30 s; arms alternate over at least 5 repetitions. The same process also yields the cold-window figure (the legacy
// 1 s ramp + 3 s window of the pre-D54 harness): it is reported, never gated, so a cold-start regression stays visible.

/** The D54 protocol: warm-up (includes the cold window), steady-state window, repetitions. The legacy window is the cold one. */
export const PROTOCOL={warmupS:10,steadyS:30,runs:5,rampS:1,coldS:3,sliceS:10};
/** The least a run may be shortened to and still be gated by D54; anything below is reported with `conforms_d54:false`. */
export const D54_MINIMUM={warmupS:10,steadyS:30,runs:5};

// ---------------------------------------------------------------- statistics
export const mean=v=>v.reduce((a,b)=>a+b,0)/v.length;
export const stdev=v=>v.length<2?0:Math.sqrt(v.reduce((a,b)=>a+(b-mean(v))**2,0)/(v.length-1));
export const quantile=(sorted,q)=>sorted.length?sorted[Math.min(sorted.length-1,Math.ceil(q*sorted.length)-1)]:null;
export function summary(values){return {n:values.length,values:values.map(v=>Number(v.toFixed(4))),mean:Number(mean(values).toFixed(4)),stdev:Number(stdev(values).toFixed(4)),min:Math.min(...values),max:Math.max(...values),cv_percent:Number((100*stdev(values)/mean(values)).toFixed(3))};}
export function compare(base,variant){
 const delta=mean(variant)-mean(base),percent=100*delta/mean(base),se=Math.sqrt(stdev(base)**2/base.length+stdev(variant)**2/variant.length);
 return {delta_percent:Number(percent.toFixed(3)),delta_abs:Number(delta.toFixed(4)),standard_error_abs:Number(se.toFixed(4)),delta_exceeds_two_standard_errors:Math.abs(delta)>2*se};
}
export function latencyStats(latencies){const s=[...latencies].sort((a,b)=>a-b);return {count:s.length,p50_ms:quantile(s,0.5),p95_ms:quantile(s,0.95),p99_ms:quantile(s,0.99),max_ms:s.at(-1)};}

// ---------------------------------------------------------------- scheduling
/** Arm order of repetition `run` (0-based): ABBA..., so slow drift and "second arm runs on a warmer machine" hit both arms equally. */
export function armOrder(run,arms){return run%2===0?[...arms]:[...arms].reverse();}

/** Whether a protocol is long enough to be gated by D54, with the reasons when it is not. */
export function conformance({warmupS,steadyS,runs}){
 const why=[];
 if(!(warmupS>=D54_MINIMUM.warmupS))why.push(`warm-up ${warmupS} s < ${D54_MINIMUM.warmupS} s`);
 if(!(steadyS>=D54_MINIMUM.steadyS))why.push(`steady-state window ${steadyS} s < ${D54_MINIMUM.steadyS} s`);
 if(!(runs>=D54_MINIMUM.runs))why.push(`${runs} repetitions < ${D54_MINIMUM.runs}`);
 return {conforms_d54:why.length===0,not_conforming:why};
}

/**
 * The phases one server process runs through, in order. `group` names a measured window ("cold" is the legacy 1 s ramp + 3 s
 * window, "warm" the steady state split in slices of `sliceS` so the warm-up's adequacy shows as drift between slices);
 * group null is discarded warm-up. With `cold:false` the whole warm-up is one discarded ramp (queue probes that need no cold figure).
 */
export function planPhases({warmupS,steadyS,cold=true,rampS=PROTOCOL.rampS,coldS=PROTOCOL.coldS,sliceS=PROTOCOL.sliceS}){
 const phases=[];
 if(cold){
  if(warmupS<rampS+coldS)throw new Error(`warm-up ${warmupS} s is shorter than the cold window it contains (${rampS+coldS} s)`);
  phases.push({name:"ramp",seconds:rampS,group:null},{name:"cold",seconds:coldS,group:"cold"});
  if(warmupS>rampS+coldS)phases.push({name:"warm-up",seconds:warmupS-rampS-coldS,group:null});
 }else if(warmupS>0)phases.push({name:"warm-up",seconds:warmupS,group:null});
 if(!(steadyS>0))throw new Error("the steady-state window must be longer than 0 s");
 for(let at=0,i=0;at<steadyS;at+=sliceS,i++)phases.push({name:"warm."+i,seconds:Math.min(sliceS,steadyS-at),group:"warm"});
 return phases;
}

// ---------------------------------------------------------------- one window of counters
/** Server-side counter difference between two /__cpu snapshots: requests handled and CPU consumed in between, read at the same instants. */
export function counterDelta(before,after){
 return {requests:after.requests-before.requests,cpu_us:after.user_us+after.system_us-before.user_us-before.system_us,user_us:after.user_us-before.user_us,system_us:after.system_us-before.system_us,elu_active_us:(after.elu_active_ms-before.elu_active_ms)*1000,queue_bytes_end:after.queue_bytes,max_queue_bytes:after.max_queue_bytes,diagnostics:after.diagnostics};
}

/**
 * Open-loop load through `phases`. One continuous request clock (no gap between phases); a request belongs to the phase it was sent
 * in; the server's counters are read at every phase boundary, so a window's CPU per request is counter delta / counter delta.
 * Injected: now() ms, sleep(ms), send(i) -> latency ms (rejects on error), snapshot() -> /__cpu object.
 */
export async function runLoad({phases,rps,send,snapshot,now,sleep}){
 const t0=now(),pending=new Set(),recs=[];
 let sent=0,snap=await snapshot(),phaseStart=now(),end=0;
 for(const phase of phases){
  end+=phase.seconds*1000;
  const rec={name:phase.name,group:phase.group,latencies:[],errors:0,sent:0,before:snap};
  recs.push(rec);
  while(now()-t0<end){
   const due=Math.floor((now()-t0)/1000*rps);
   while(sent<due){
    sent++;rec.sent++;
    const p=send(sent).then(ms=>{rec.latencies.push(ms);},()=>{rec.errors++;}).finally(()=>pending.delete(p));
    pending.add(p);
   }
   await sleep(1);
  }
  snap=await snapshot();
  rec.after=snap;rec.wall_s=(now()-phaseStart)/1000;phaseStart=now();
 }
 await Promise.all(pending);
 const windowOf=list=>({latency:latencyStats(list.flatMap(r=>r.latencies)),errors:list.reduce((n,r)=>n+r.errors,0),sent:list.reduce((n,r)=>n+r.sent,0),wall_s:list.reduce((n,r)=>n+r.wall_s,0),server:counterDelta(list[0].before,list.at(-1).after)});
 const windows={};
 for(const group of new Set(recs.filter(r=>r.group).map(r=>r.group)))windows[group]=windowOf(recs.filter(r=>r.group===group));
 const slices=recs.filter(r=>r.group==="warm").map(r=>({name:r.name,...windowOf([r])}));
 return {windows,slices};
}

// ---------------------------------------------------------------- one run's figures and the arm comparison
/** The harness's per-run figures of one window (as returned by the load process). */
export function figures(window){
 const s=window.server;
 return {stats:window.latency,cpu_us_per_request:s.cpu_us/Math.max(1,s.requests),loop_active_us_per_request:s.elu_active_us/Math.max(1,s.requests),achieved_rps:window.sent/window.wall_s,errors:window.errors,server:s};
}

/**
 * Baseline-vs-capture comparison of one window over the repetitions. `runs[mode]` is the list of figures(); the means are over the
 * repetitions, the delta is (capture-baseline)/baseline of the means, and the verdict compares it with `budget` (never edited here).
 */
export function compareArms(runs,{baseline="baseline",capture,budget,loop=false,delivered=false,cpuNote}){
 const series=(mode,pick)=>runs[mode].map(pick);
 const metric=pick=>({baseline:summary(series(baseline,pick)),capture:summary(series(capture,pick)),...compare(series(baseline,pick),series(capture,pick))});
 const p95=metric(r=>r.stats.p95_ms),cpu=metric(r=>r.cpu_us_per_request),elu=metric(r=>r.loop_active_us_per_request);
 const within=p=>p<=budget.p95_percent?"within_budget_point_estimate":"exceeds_budget",withinCpu=p=>p<=budget.cpu_percent?"within_budget_point_estimate":"exceeds_budget";
 const out={
  p95_latency_ms:p95,p99_latency_ms:metric(r=>r.stats.p99_ms),p50_latency_ms:metric(r=>r.stats.p50_ms),
  process_cpu_us_per_request:cpuNote?{note:cpuNote,...cpu}:cpu,
 };
 if(loop)out.event_loop_active_us_per_request={note:"performance.eventLoopUtilization active time per request: high-resolution busy time of the single JS thread, a CPU proxy that excludes GC/helper threads",...elu};
 out.achieved_rps={baseline:summary(series(baseline,r=>r.achieved_rps)),capture:summary(series(capture,r=>r.achieved_rps))};
 const lost=series(capture,r=>r.server.diagnostics.queue_full??0);
 if(delivered)out.queue_full_drops=lost;
 out.errors={baseline:series(baseline,r=>r.errors),capture:series(capture,r=>r.errors)};
 out.verdict={p95:within(p95.delta_percent),process_cpu:withinCpu(cpu.delta_percent)};
 if(loop)out.verdict.loop_active_cpu_proxy=withinCpu(elu.delta_percent);
 if(delivered)out.verdict.delivered_without_queue_full=lost.every(n=>n===0);
 out.verdict.p95_difference_distinguishable_from_run_noise=p95.delta_exceeds_two_standard_errors;
 out.verdict.process_cpu_difference_distinguishable_from_run_noise=cpu.delta_exceeds_two_standard_errors;
 if(loop)out.verdict.loop_difference_distinguishable_from_run_noise=elu.delta_exceeds_two_standard_errors;
 return out;
}

/**
 * The D54 row body: the warm (gated) figures at the top level, where consumers read them, the cold-window figures (reported, never
 * gated) under `cold_window`, per-slice CPU per request of the steady state so warm-up adequacy is visible, and the protocol used.
 * `collected[mode]` is a list of {cold?,warm,slices} per repetition, in run order.
 */
export function d54Row(collected,{capture,protocol,budget,loop=false,delivered=false,cpuNote}){
 const fig=(mode,key)=>collected[mode].map(r=>figures(r[key]));
 const warm=compareArms({baseline:fig("baseline","warm"),[capture]:fig(capture,"warm")},{capture,budget,loop,delivered,cpuNote});
 const row={...warm};
 if(collected.baseline.every(r=>r.cold)&&collected[capture].every(r=>r.cold)){
  row.cold_window={note:`legacy window (${PROTOCOL.rampS} s ramp discarded, then ${PROTOCOL.coldS} s) of the same fresh processes: reported, not gated (D54)`,...compareArms({baseline:fig("baseline","cold"),[capture]:fig(capture,"cold")},{capture,budget,loop,delivered,cpuNote})};
 }
 const slicesOf=mode=>collected[mode].map(r=>(r.slices??[]).map(s=>Number(figures(s).cpu_us_per_request.toFixed(3))));
 row.warm_slices_cpu_us_per_request={slice_s:protocol.sliceS,note:"per repetition, per steady-state slice; a trend across slices means the warm-up was too short",baseline:slicesOf("baseline"),capture:slicesOf(capture)};
 const c=conformance(protocol);
 row.measurement={protocol:c.conforms_d54?"D54":"shortened diagnostic window, not D54",...protocol,...c,gated_window:"warm",arm_order:Array.from({length:protocol.runs},(_,run)=>armOrder(run,["baseline",capture]))};
 return row;
}

/** Environment of the recorder-batch Playwright run. The spec drives Chromium: a SOUNDPOST_FIREFOX inherited from the host (the frozen tool bundle exports it for the Firefox rows) would make fixtures/sdk/firefox/project.ts turn the run into a Firefox run, so it is emptied here. */
export function recorderBatchEnv(env,bunPathValue,root){
 return {...env,SOUNDPOST_FIREFOX:"",SOUNDPOST_BUN:bunPathValue,NODE_PATH:root+"/web/node_modules"};
}
