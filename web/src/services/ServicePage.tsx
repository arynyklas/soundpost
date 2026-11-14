// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { Id } from '../api/types';
import { formatNs, useInvestigation, type ViewContext } from '../app/context';
import { SectionList, StatusPanel } from '../app/StatusPanel';

/** A service as the scoped server answers it: evidence sources and metric names the
 * caller may read, with health, dependencies and releases each listed as their own
 * section. A part the server cannot answer yet is shown as not available, never as
 * healthy, zero or empty. All values are bounded plain text. */
export function ServicePage(props: { id: Id; context: ViewContext }): React.JSX.Element {
 const state = useInvestigation(props.context, 'service', props.id);
 const view = 'data' in state ? state.data : undefined;
 return (
  <section className="panel" aria-labelledby="service-heading">
   <h2 id="service-heading">Service <code>{props.id}</code></h2>
   <StatusPanel state={state} />
   {view && (
    <>
     <SectionList sections={view.sections} />
     <h3>Evidence sources</h3>
     {view.projects.map((p) => (
      <div key={p.project_id} data-project={p.project_id}>
       <p>Project <code>{p.project_id}</code></p>
       {p.sources.length === 0
        ? <p>No readable source in this project.</p>
        : <ul>{p.sources.map((s) => <li key={s.id}><code>{s.id}</code> — class {s.class}, kinds {s.kinds.join(', ')}{s.replay ? ', replay' : ''}</li>)}</ul>}
      </div>
     ))}
     <h3>Metric names observed</h3>
     {view.metric_names.length === 0
      ? <p>No metric names are shown for this window.</p>
      : <ul>{view.metric_names.map((n) => <li key={n}><code>{n}</code></li>)}</ul>}
     {view.more && <p>More metric names exist beyond this page.</p>}
     {view.freshness && <p>Freshness: {view.freshness.completeness}, {view.freshness.watermarks.length} watermark{view.freshness.watermarks.length === 1 ? '' : 's'}{view.freshness.cached ? ', from cache' : ''}. Window {formatNs(view.window.start, props.context.timezone)} to {formatNs(view.window.end, props.context.timezone)} ({props.context.timezone}).</p>}
    </>
   )}
  </section>
 );
}
