// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { Content, PageHead } from '../shell/Frames';
import { NotAvailable } from '../ui/primitives';

/** Dashboards are planned after the first release; the screen says so and shows nothing in their place. */
export function DashboardsRoute(): React.JSX.Element {
 return (
  <>
   <PageHead title="Dashboards" sub="planned after the first release" />
   <Content><div className="card"><NotAvailable icon="dash" title="Dashboards are planned after the first release">Saved metric views and the Metrics screen cover charts today. Dashboards with several panels are not part of the first release, and nothing is shown in their place.</NotAvailable></div></Content>
  </>
 );
}
