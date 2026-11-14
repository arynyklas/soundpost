// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// The replay entry (`@soundpost/browser/replay`). Replay is a separate bundle from the core client (design 13: core <=40 KiB gzip, replay
// separate <=60 KiB gzip), so nothing in the core entry imports the recorder; an application that records opts in by importing this module.
import type {Client} from "./index.ts";
import {createRecorder} from "./replay/recorder.ts";
import type {EnqueueResult,ReplayChunk,ReplayConfig,ReplayRecorder} from "./replay/types.ts";

const recorders=new WeakMap<Client,ReplayRecorder>();

/** Creates the owned recorder under `client`'s policy. Capture stays off until setReplayConsent(client, true). Every chunk the recorder emits is enqueued by THIS client on its ordinary delivery path
 * (closed wire validation, batching, retry, receipts); a chunk the queue refuses is the recorder's counted loss and is healed by a gap-marked checkpoint. `tap` is an optional local consumer
 * (for example a ReplayStream feeding a viewer) that sees every chunk; its own failure never affects delivery. Revoking consent also destroys this client's not-yet-batched replay chunks.
 * Closing the client closes the recorder. */
export function startReplay(client:Client,config:Omit<ReplayConfig,"projectPolicy"|"deploymentOptIn">,tap?:(chunk:ReplayChunk)=>void):ReplayRecorder{
 if(recorders.has(client))throw Error("replay recorder already started");
 // policyDecision.replay is project policy AND deployment opt-in already combined by core.
 const allowed=client.policyDecision.replay;
 const deliver=(chunk:ReplayChunk):EnqueueResult=>{
  const queued=client.captureReplay({...chunk});
  if(tap!==undefined){try{tap(chunk);}catch{/* a local consumer cannot break delivery */}}
  return queued?"accepted":"rejected";
 };
 const onRevoked=():void=>{client.discardUnsentReplay();config.onRevoked?.();};
 const recorder=createRecorder({...config,projectPolicy:allowed,deploymentOptIn:allowed,onRevoked},deliver);
 recorders.set(client,recorder);
 client.ownHookLease({close:()=>recorder.close()});
 return recorder;
}
/** Sets explicit replay consent on the recorder started for `client`; a no-op before startReplay. */
export function setReplayConsent(client:Client,enabled:boolean):void{recorders.get(client)?.setConsent(enabled);}
export {createRecorder} from "./replay/recorder.ts";
export {ReplayStream} from "./replay/stream.ts";
export type {ReplayChunk,ReplayNode,ReplayConfig,ReplayRecorder,EnqueueResult} from "./replay/types.ts";
