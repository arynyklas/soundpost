// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { Navigation, ViewContext } from '../app/context';
import { OpenByRef } from '../app/OpenByRef';
import { Content, PageHead } from '../shell/Frames';
import { useShell } from '../shell/ShellContext';
import { Card } from '../ui/primitives';
import { IssuePage } from './IssuePage';
import { IssuesList } from './IssuesList';

/** The issue list, or one issue when the address names it. `Open an issue` by ID is on both: a person who holds an identifier opens it without browsing. */
export function IssuesRoute(props: { context: ViewContext; nav: Navigation }): React.JSX.Element {
 const shell = useShell();
 const { target } = props.nav;
 const open = (ref: { project: string; id: string }): void => shell.go('issues', { target: ref });
 if (target) {
  return (
   <div data-entity>
    <IssuePage
     key={`${target.project}:${target.id}`} id={target.id} project={target.project} context={props.context} names={shell.names} href={shell.href}
     footer={<Card title="Open another issue" titleId="issue-open-h"><OpenByRef context={props.context} noun="issue" current={target} open={open} /></Card>}
    />
   </div>
  );
 }
 return (
  <>
   <PageHead title="Issues" sub="recurring errors, grouped" />
   <Content><IssuesList context={props.context} names={shell.names} href={shell.href} open={open} current={null} /></Content>
  </>
 );
}
