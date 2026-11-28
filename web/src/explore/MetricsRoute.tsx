// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { ViewContext } from '../app/context';
import { Content, PageHead } from '../shell/Frames';
import { Workbench } from './Workbench';

/** Metrics: a PromQL query over the selected projects, drawn as charts with their gaps, and listed series by series. */
export function MetricsRoute(props: { context: ViewContext }): React.JSX.Element {
 return (
  <>
   <PageHead title="Metrics" sub="query and chart metrics" />
   <Content><Workbench context={props.context} language="promql" /></Content>
  </>
 );
}
