// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { Navigation, ViewContext } from '../app/context';
import { Content, PageHead } from '../shell/Frames';
import { useShell } from '../shell/ShellContext';
import { OperationsPage } from './OperationsPage';
import { OrganizationSettings } from './OrganizationSettings';
import { pageOf, SETTINGS_TILES, type PageDef } from './pages';
import { ProjectPage } from './ProjectSettings';
import { SettingsNav } from './SettingsUi';
import { SourcePolicies } from './SourcePolicies';
import { SSOSettings } from './SSOSettings';
import { TeamSettings } from './TeamSettings';

function Hub(): React.JSX.Element {
 const shell = useShell();
 return (
  <>
   <PageHead title="Settings" sub="sources, retention, access and routing" />
   <Content>
    <div className="grid-3 set-tiles">
     {SETTINGS_TILES.map((t) => (
      <a key={t.title} className="card set-tile" href={shell.href(t.section, t.page ? { page: t.page } : {})} data-settings-tile={t.page ?? t.section}>
       <h2>{t.title}</h2>
       <p>{t.summary}</p>
      </a>
     ))}
    </div>
   </Content>
  </>
 );
}

function PageBody(props: { page: PageDef; context: ViewContext }): React.JSX.Element {
 switch (props.page.id) {
  case 'project': return <ProjectPage context={props.context} />;
  case 'sources': return <SourcePolicies context={props.context} />;
  case 'organization': return <OrganizationSettings context={props.context} />;
  case 'teams': return <TeamSettings context={props.context} />;
  case 'sso': return <SSOSettings context={props.context} />;
  case 'operations': return <OperationsPage context={props.context} />;
 }
}

/** Settings: the hub of configuration screens, and its own pages (the `page` of the address): the project's sources and retention, source policies, the organization, teams, single sign-on, and audit
 * and operations. Notification routes, alert rules, GitLab, event webhooks and migration are screens of their own that the hub links to. Each page is read and written under the caller's own
 * authority: another organization's administrator and an ordinary member see an administration page as not found. */
export function SettingsRoute(props: { context: ViewContext; nav: Navigation }): React.JSX.Element {
 const shell = useShell();
 const page = pageOf(props.nav.page);
 if (page === undefined) return <Hub />;
 return (
  <>
   <PageHead crumb={<><a href={shell.href('settings')}>Settings</a><span aria-hidden="true">›</span></>} title={page.title} />
   <Content>
    <SettingsNav current={page.id} />
    <PageBody page={page} context={props.context} />
   </Content>
  </>
 );
}
