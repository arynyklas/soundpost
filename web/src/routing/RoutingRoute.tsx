// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { ViewContext } from '../app/context';
import { Content, PageHead } from '../shell/Frames';
import { NotificationPolicyPanel } from '../settings/PolicySettings';
import { Panel, ProjectSelect, useChosenProject } from '../settings/SettingsUi';
import { useShell } from '../shell/ShellContext';
import { Callout, EmptyState } from '../ui/primitives';
import { DestinationsPanel } from './Destinations';

/** Notification routes: who is told, how and when, as far as the product's own contracts carry it: the organization's destinations (POST /api/v1/destinations) and the urgency policy
 * of a project (POST /api/v1/policies). Routes by severity, project or rule type, maintenance window lists, a test of a route and escalation to a second person are not part of
 * any contract of the installation, so none is drawn: the screen says how notifications reach destinations instead. */
export function RoutingRoute(props: { context: ViewContext }): React.JSX.Element {
 const c = props.context;
 const shell = useShell();
 const [project, pick] = useChosenProject(c.projects);
 return (
  <>
   <PageHead crumb={<><a href={shell.href('incidents')}>Incidents</a><span aria-hidden="true">›</span></>} title="Notification routes" sub="who is told, how and when" />
   <Content>
    {project === undefined ? <div className="card"><EmptyState icon="globe" title="Select a project">Destinations and the urgency policy are read through a project you hold policy.write on.</EmptyState></div> : (
     <>
      <div className="row wrap"><ProjectSelect projects={c.projects} value={project} onChange={pick} /></div>
      <div className="grid-side">
       <div className="col g16">
        <Panel title="How a notification reaches a destination">
         <div className="col g12">
          <Callout tone="info" icon="route">Every enabled destination receives the notifications of every project of the organization. This installation has no routes by severity, project or rule type: what changes is which destinations are enabled and the urgency policy of each project.</Callout>
          <p className="small t2">Notifications that no enabled destination can take stay in the product queue and are never sent.</p>
         </div>
        </Panel>
        <NotificationPolicyPanel key={project} context={c} project={project} />
       </div>
       <aside className="col g16" aria-label="Notification destinations">
        <DestinationsPanel key={project} context={c} project={project} />
       </aside>
      </div>
     </>
    )}
   </Content>
  </>
 );
}
