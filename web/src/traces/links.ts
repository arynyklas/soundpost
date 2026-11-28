// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import type { Id, SpanTarget } from '../api/types';
import { encodeHash, type ViewContext } from '../app/context';

/** Where a resolved span reference opens, or null when it has no view of its own. Jobs, replays and profiles open in their own view; an error occurrence opens the issue that holds it, which only the server can say (`issue_id`). Every destination checks the scope again when it opens; nothing here grants access. */
export function targetLocation(context: ViewContext, project: Id, target: SpanTarget): string | null {
 const ref = { project, id: target.id };
 switch (target.kind) {
  case 'job': return encodeHash(context, 'jobs', '', null, ref);
  case 'replay': return encodeHash(context, 'replays', '', null, ref);
  case 'profile': return encodeHash(context, 'profiles', '', null, ref);
  case 'error': return target.issue_id === undefined ? null : encodeHash(context, 'issues', '', null, { project, id: target.issue_id });
 }
}
