// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { Navigation, ViewContext } from '../app/context';
import { OpenByRef } from '../app/OpenByRef';
import { Content, PageHead } from '../shell/Frames';
import { useShell } from '../shell/ShellContext';
import { Card } from '../ui/primitives';
import { IncidentPage } from './IncidentPage';
import { IncidentsList } from './IncidentsList';

/** Incidents: the list (the shared queue) and, with an incident in the address, the incident page. */
export function IncidentsRoute(props: { context: ViewContext; nav: Navigation }): React.JSX.Element {
 const shell = useShell();
 const { incident } = props.nav;
 if (incident) return <IncidentPage key={`${incident.project}:${incident.id}`} id={incident.id} project={incident.project} context={props.context} />;
 return (
  <>
   <PageHead title="Incidents" sub="human response to alerts" />
   <Content>
    <IncidentsList context={props.context} open={(project, id) => shell.go('incidents', { incident: { project, id } })} />
    <Card title="Open an incident by ID" titleId="incident-open-by-id-h" className="open-by-id-card"><OpenByRef context={props.context} noun="incident" current={null} open={(ref) => shell.go('incidents', { incident: ref })} /></Card>
   </Content>
  </>
 );
}
