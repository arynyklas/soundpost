// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import type { Session } from './api';
/**
 * What the session boundary does with the result of a revalidation read of the session.
 * `remount`: no session was held or the account changed, so the console is cleared and every read is made again.
 * `update`: same account, rotated csrf token or expiry; the mounted console and its view state stay.
 * `keep`: nothing changed; the mounted console and its view state stay.
 * A revoked session (401/403) never reaches this function: the boundary clears the console on the failure itself.
 */
export type RevalidationOutcome = 'remount' | 'update' | 'keep';
export function classifyRevalidation(previous: Session | null, current: Session): RevalidationOutcome {
 if (!previous || previous.user !== current.user) return 'remount';
 return previous.csrf !== current.csrf || previous.expires !== current.expires ? 'update' : 'keep';
}
