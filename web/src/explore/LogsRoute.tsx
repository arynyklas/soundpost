// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { ViewContext } from '../app/context';
import { Content, PageHead } from '../shell/Frames';
import { Workbench } from './Workbench';

/** Logs: a LogQL query over the selected projects, its lines with exact nanoseconds, a histogram of the lines this page holds and a live tail. */
export function LogsRoute(props: { context: ViewContext }): React.JSX.Element {
 return (
  <>
   <PageHead title="Logs" sub="search and follow log lines" />
   <Content><Workbench context={props.context} language="logql" /></Content>
  </>
 );
}
