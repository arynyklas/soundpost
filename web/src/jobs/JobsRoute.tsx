// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { scopeKey, type Navigation, type ViewContext } from '../app/context';
import { Content, PageHead } from '../shell/Frames';
import { useShell } from '../shell/ShellContext';
import { JobPage, JobsList } from './JobsPage';

/** The job list, or one job (with its runs and attempts) when the address names it. A job named by a link (a trace's span) opens in its own project; the server checks the scope of that read like any other. */
export function JobsRoute(props: { context: ViewContext; nav: Navigation }): React.JSX.Element {
 const shell = useShell();
 const { target } = props.nav;
 if (target) {
  return (
   <div data-entity>
    <JobPage key={`${scopeKey(props.context)}|${target.project}:${target.id}`} context={props.context} project={target.project} job={target.id} href={shell.href} />
   </div>
  );
 }
 return (
  <>
   <PageHead title="Jobs" sub="scheduled and background work" />
   <Content><JobsList context={props.context} href={shell.href} /></Content>
  </>
 );
}
