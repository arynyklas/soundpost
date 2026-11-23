// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { ViewContext } from '../app/context';
import { Content, PageHead } from '../shell/Frames';
import { useShell } from '../shell/ShellContext';
import { Callout } from '../ui/primitives';
import { CutoverPanel } from './CutoverPanel';

/** Migration and cutover: for each project in scope, who sends normal notifications and the committed record of the move from another tool. It is read-only: the cutover is advanced only by the operator flow. */
export function CutoverRoute(props: { context: ViewContext }): React.JSX.Element {
 const shell = useShell();
 return (
  <>
   <PageHead crumb={<><a href={shell.href('settings')}>Settings</a><span aria-hidden="true">›</span></>} title="Migration and cutover" sub="move notifications from another tool" />
   <Content>
    <Callout tone="info" icon="move">Only one system sends normal notifications at a time. Legacy history stays read-only and outside this product.</Callout>
    {props.context.projects.map((project) => <CutoverPanel key={project} context={props.context} project={project} />)}
   </Content>
  </>
 );
}
