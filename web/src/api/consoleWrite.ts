// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { ApiFault, OutcomeUnknown } from './types';
import type { ConsoleResult } from './console';

/** The answer of an audited write to a console route, as the throw an audited form understands: a transport failure is an unknown outcome (the same command ID may be sent
 * again), a refusal carries its status, and a route this installation does not serve is the one not-found. Only an `ok` answer is a committed write. */
export function unwrapWrite<T>(r: ConsoleResult<T>): T {
 if (r.kind === 'ok') return r.data;
 if (r.kind === 'not_built') throw new ApiFault(404, 'not_found', '', '');
 if (r.fault.status === 0) throw new OutcomeUnknown();
 throw r.fault;
}
