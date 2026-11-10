// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { LoadState } from '../api/types';
import type { ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';

/** Saved views belong to the C11 saved-view actions and exports, which this installation does not have. The state is an explicit
 * typed not-available answer, never an empty list and never a local fallback: nothing about a query is saved in this browser
 * (no storage, no cookie, no URL), so nothing can outlive the scope or the page. Saving will need an explicit project-owned action. */
const STATE: LoadState<never> = { kind: 'unsupported', reason: 'saved_views_not_built' };

export function SavedViews(props: { context: ViewContext }): React.JSX.Element {
 return (
  <section className="panel" aria-labelledby="saved-heading" data-section="saved-views" data-state="unsupported">
   <h3 id="saved-heading">Saved views</h3>
   <StatusPanel state={STATE} />
   <p>Project <code>{props.context.projects.join(', ')}</code> has no saved views to show because none can be saved: the query text lives only in this page&rsquo;s memory and is dropped when you leave this page or change the scope. Persisting a query will need an explicit project-owned saved-view action.</p>
  </section>
 );
}
