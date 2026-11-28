// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { Navigation, ViewContext } from '../app/context';
import { OpenService } from '../app/OpenByRef';
import { Content, PageHead } from '../shell/Frames';
import { useShell } from '../shell/ShellContext';
import { Card } from '../ui/primitives';
import { ServiceList } from './ServicesList';
import { ServicePage } from './ServicePage';

/** The service list, or one service when the address names it. `Open a service` by ID is on both. */
export function ServicesRoute(props: { context: ViewContext; nav: Navigation }): React.JSX.Element {
 const shell = useShell();
 const { service } = props.nav;
 const open = (id: string): void => shell.go('services', { service: id });
 if (service) {
  return (
   <div data-entity>
    <ServicePage id={service} context={props.context} names={shell.names} href={shell.href} footer={<Card title="Open another service" titleId="service-open-h"><OpenService key={service} service={service} open={open} /></Card>} />
   </div>
  );
 }
 return (
  <>
   <PageHead title="Services" sub="health of what you run" />
   <Content>
    <OpenService key="" service="" open={open} />
    <ServiceList context={props.context} names={shell.names} href={shell.href} open={open} />
   </Content>
  </>
 );
}
