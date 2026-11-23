// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { Navigation, ViewContext } from '../app/context';
import { OpenByRef } from '../app/OpenByRef';
import { Content, PageHead } from '../shell/Frames';
import { useShell } from '../shell/ShellContext';
import { Icon } from '../ui/Icon';
import { Card, shortId } from '../ui/primitives';
import { ProfileList } from './ProfileList';
import { ProfilePage } from './ProfilePage';

/** Profiles: the profiles of the selected projects, each in its own unit, and a profile opened by its ID or from a link. */
export function ProfilesRoute(props: { context: ViewContext; nav: Navigation }): React.JSX.Element {
 const shell = useShell();
 const { target } = props.nav;
 if (target) {
  return (
   <>
    <PageHead crumb={<><a href={shell.href('profiles')}>Profiles</a><Icon name="right" size="xs" /><code title={target.id}>{shortId(target.id)}</code></>} />
    <div data-entity><ProfilePage key={`${target.project}:${target.id}`} id={target.id} project={target.project} context={props.context} /></div>
   </>
  );
 }
 return (
  <>
   <PageHead title="Profiles" sub="where time is spent" />
   <Content>
    <Card title="Open a profile" titleId="open-profile-heading" bodyClass="col g12">
     <OpenByRef context={props.context} noun="profile" current={null} open={(ref) => shell.go('profiles', { target: ref })} />
     <p role="status" className="small t2">Open a profile by its ID.</p>
    </Card>
    <ProfileList context={props.context} />
   </Content>
  </>
 );
}
