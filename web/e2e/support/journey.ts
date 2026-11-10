// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Real-server fixture shared by the 05.09 journey and accessibility specs. Everything goes through public routes: orgs,
// projects, users and grants through the real admin commands, sources through POST /api/v1/sources, metrics, logs, spans,
// closed-format replay chunks and a native profile through the real POST /ingest/v1/batches. No route is faked and no
// temporary seed route exists: what the committed routes cannot create (incidents, releases, jobs) is NOT created, and the
// specs assert the typed state the server really answers.
import type {APIRequestContext,Page} from '@playwright/test';
import {at,seedExplore,type ExploreSeed} from './real';
import {NATIVE_PROFILE,onboardReplaySource,seedProfiles,seedReplays,setPermissions,type ReplaySeed} from './replay';
import {onboardSpanSource,seedTraces,type TraceSeed} from './trace';

export interface JourneySeed{explore:ExploreSeed;traces:TraceSeed;replays:ReplaySeed;profile:string;start:bigint;end:bigint}

/** One org, project P1 (everything is ingested here) and P2 (metrics only), a reader holding telemetry.read, replay.read and
 * profiles.read on P1 and telemetry.read on P2. One window [T0-1s, T0+70s) holds every record. */
export async function seedJourney(owners:Page,api:APIRequestContext):Promise<JourneySeed>{
 const explore=await seedExplore(owners,api);
 const spans=await onboardSpanSource(owners,explore.org,explore.p1);
 const traces=await seedTraces(api,spans);
 const replaySource=await onboardReplaySource(owners,explore.org,explore.p1);
 const replays=await seedReplays(api,replaySource);
 await seedProfiles(api,replaySource);
 await setPermissions(owners,explore.org,explore.reader.id,explore.p1,true,['telemetry.read','replay.read','profiles.read']);
 return {explore,traces,replays,profile:NATIVE_PROFILE,start:at(-1),end:at(70)};
}

/** The URL fragment a native deep link carries: scope and window, never data. */
export function deepLink(seed:JourneySeed,view:string,extra:Record<string,string>={}):string{
 const {org,p1}=seed.explore;
 return `/#${new URLSearchParams({org,projects:p1,start:String(seed.start),end:String(seed.end),tz:'UTC',view,...extra})}`;
}
