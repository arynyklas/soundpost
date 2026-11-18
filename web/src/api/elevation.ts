// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import type { ElevationState } from '../auth/ElevationDialog';
import type { Id } from './types';

const ID = /^[0-9a-f]{32}$/;

/**
 * The audited elevation handle a console read carries, or undefined for the ordinary read (D60).
 *
 * The handle is sent only for an organization the person selected when they elevated (each organization is a separate scope, there is
 * no wildcard), only while it has not expired (the server refuses an expired or foreign handle and counts the miss toward its throttle,
 * so the console never sends one it already knows is dead), and only when it is well formed. The server remains the authority: this
 * decides what to offer, never what is allowed.
 */
export function elevationFor(elevation: ElevationState | null, org: Id, nowMs: number): Id | undefined {
 if (elevation === null || !ID.test(elevation.id) || !elevation.orgs.includes(org)) return undefined;
 if (!/^[0-9]{1,18}$/.test(elevation.expires) || BigInt(elevation.expires) * 1000n <= BigInt(Math.trunc(nowMs))) return undefined;
 return elevation.id;
}

/**
 * The read routes whose server scope accepts an elevation (the ScopeFields of internal/httpapi). Nothing else carries one: a write
 * (action, settings, saved view), a live ticket (the server refuses elevated live streams) and a profile view (its grant is fixed; an
 * elevation cannot carry it) go out exactly as before.
 */
export const ELEVATED_READ_PATHS: readonly string[] = ['/api/v1/query', '/api/v1/query/format', '/api/v1/discover', '/api/v1/exemplars'];

let bound: ElevationState | null = null;
let boundOwner: object | null = null;
/** The console binds the active elevation (or null) during render, like the session token; it is in memory only, never persisted or put in a URL. */
export function bindElevation(elevation: ElevationState | null, owner: object | null = null): void { bound = elevation; boundOwner = owner; }

/** Unbinds the elevation only if `owner` is the console instance that bound it; a newer instance's binding is left alone. */
export function releaseElevation(owner: object): void { if (boundOwner === owner) { bound = null; boundOwner = null; } }

/** The body of a POST to `path`, with the bound elevation added when the path is an elevated read and the body names an organization it covers. */
export function withElevation(path: string, body: unknown, nowMs: number = Date.now()): unknown {
 if (!ELEVATED_READ_PATHS.includes(path) || typeof body !== 'object' || body === null || Array.isArray(body)) return body;
 const org: unknown = Reflect.get(body, 'org');
 if (typeof org !== 'string' || Reflect.has(body, 'elevation')) return body;
 const handle = elevationFor(bound, org, nowMs);
 return handle === undefined ? body : { ...body, elevation: handle };
}
