// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { Navigation, ViewContext } from '../app/context';
import { OpenByRef } from '../app/OpenByRef';
import { Content, PageHead } from '../shell/Frames';
import { useShell } from '../shell/ShellContext';
import { Card } from '../ui/primitives';
import { ReleasePage } from './ReleasePage';
import { ReleasesList } from './ReleasesList';

/** The release list, or one release when the address names it. `Open a release` by ID is on both. */
export function ReleasesRoute(props: { context: ViewContext; nav: Navigation }): React.JSX.Element {
 const shell = useShell();
 const { target } = props.nav;
 const open = (ref: { project: string; id: string }): void => shell.go('releases', { target: ref });
 if (target) {
  return (
   <div data-entity>
    <ReleasePage
     key={`${target.project}:${target.id}`} id={target.id} project={target.project} context={props.context} names={shell.names} href={shell.href}
     footer={<Card title="Open another release" titleId="release-open-h"><OpenByRef context={props.context} noun="release" current={target} open={open} /></Card>}
    />
   </div>
  );
 }
 return (
  <>
   <PageHead title="Releases" sub="builds, deploys and the errors they brought" />
   <Content><ReleasesList context={props.context} names={shell.names} href={shell.href} open={open} /></Content>
  </>
 );
}
