// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { Navigation, ViewContext } from '../app/context';
import { OpenByRef } from '../app/OpenByRef';
import { Content, PageHead } from '../shell/Frames';
import { useShell } from '../shell/ShellContext';
import { Icon } from '../ui/Icon';
import { Card, shortId } from '../ui/primitives';
import { ReplayList } from './ReplayList';
import { ReplayPage } from './ReplayPage';

/** Replays: the masked recordings of the selected projects, and a replay opened by its ID or from a link. */
export function ReplaysRoute(props: { context: ViewContext; nav: Navigation }): React.JSX.Element {
 const shell = useShell();
 const { target } = props.nav;
 if (target) {
  return (
   <>
    <PageHead crumb={<><a href={shell.href('replays')}>Replays</a><Icon name="right" size="xs" /><code title={target.id}>{shortId(target.id)}</code></>} />
    <div data-entity><ReplayPage key={`${target.project}:${target.id}`} id={target.id} project={target.project} context={props.context} /></div>
   </>
  );
 }
 return (
  <>
   <PageHead title="Replays" sub="masked session recordings" />
   <Content>
    <Card title="Open a replay" titleId="open-replay-heading" bodyClass="col g12">
     <OpenByRef context={props.context} noun="replay" current={null} open={(ref) => shell.go('replays', { target: ref })} />
     <p role="status" className="small t2">Open a replay by its ID.</p>
    </Card>
    <ReplayList context={props.context} />
   </Content>
  </>
 );
}
