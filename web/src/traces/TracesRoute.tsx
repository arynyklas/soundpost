// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { Navigation, ViewContext } from '../app/context';
import { OpenByRef } from '../app/OpenByRef';
import { Content, PageHead } from '../shell/Frames';
import { useShell } from '../shell/ShellContext';
import { Icon } from '../ui/Icon';
import { Card, NotAvailable, shortId } from '../ui/primitives';
import { TracePage } from './TracePage';

/** Traces. This installation has no trace list or search route, so the screen is the entry: a trace is opened by its ID or from a link (an exemplar,
 * an error, a job, a replay or a profile). Nothing is listed, searched or counted in its place. */
export function TracesRoute(props: { context: ViewContext; nav: Navigation }): React.JSX.Element {
 const shell = useShell();
 const { target } = props.nav;
 if (target) {
  return (
   <>
    <PageHead crumb={<><a href={shell.href('traces')}>Traces</a><Icon name="right" size="xs" /><code title={target.id}>{shortId(target.id)}</code></>} />
    <div data-entity><TracePage key={`${target.project}:${target.id}`} id={target.id} project={target.project} context={props.context} /></div>
   </>
  );
 }
 return (
  <>
   <PageHead title="Traces" sub="requests across services" />
   <Content>
    <Card title="Open a trace" titleId="open-trace-heading" bodyClass="col g12">
     <OpenByRef context={props.context} noun="trace" current={null} open={(ref) => shell.go('traces', { target: ref })} />
     <p role="status" className="small t2">Open a trace by its ID.</p>
    </Card>
    <div className="card">
     <NotAvailable icon="trace" title="Trace search is not available yet" testId="trace-search-not-available">
      This installation has no trace list or search route, so no list of slow or failing traces is shown and none is estimated. Open a trace by its ID, or follow a trace link from an exemplar on Metrics, an error, a job, a replay or a profile.
     </NotAvailable>
    </div>
   </Content>
  </>
 );
}
