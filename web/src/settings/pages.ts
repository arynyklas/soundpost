// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import type { SectionId } from '../app/context';

/** The pages of Settings (the `page` parameter of the address) and the tiles of its hub. A tile of the hub opens either one of these pages or a screen of its own. */
export type SettingsPage = 'project' | 'sources' | 'organization' | 'teams' | 'sso' | 'operations';

export interface PageDef { id: SettingsPage; title: string; nav: string; /** The `data-settings-page` marker of the page's content. */ marker: string }
export const SETTINGS_PAGES: readonly PageDef[] = [
 { id: 'project', title: 'Project', nav: 'Project', marker: 'project' },
 { id: 'sources', title: 'Source policies', nav: 'Source policies', marker: 'source-policies' },
 { id: 'organization', title: 'Organization', nav: 'Organization', marker: 'organization' },
 { id: 'teams', title: 'Teams', nav: 'Teams', marker: 'teams' },
 { id: 'sso', title: 'Single sign-on', nav: 'Single sign-on', marker: 'sso' },
 { id: 'operations', title: 'Audit and operations', nav: 'Audit and operations', marker: 'operations' },
];
export function pageOf(name: string): PageDef | undefined { return SETTINGS_PAGES.find((p) => p.id === name); }

export interface Tile { title: string; summary: string; section: SectionId; page?: SettingsPage }
/** What the hub offers. Everything here is served by a real route; a thing the product does not have (personal notification settings, escalation) is not a tile. */
export const SETTINGS_TILES: readonly Tile[] = [
 { title: 'Project', summary: 'The sources this account may read and the retention of each signal', section: 'settings', page: 'project' },
 { title: 'Source policies', summary: 'What each source may send, who may use and read it', section: 'settings', page: 'sources' },
 { title: 'Notification routes', summary: 'Destinations, urgency policy, reminders and digest time zone', section: 'routing' },
 { title: 'Alert rules', summary: 'The rules that open incidents, and recording rules', section: 'rules' },
 { title: 'Members and teams', summary: 'Projects, members, administrators and project grants', section: 'settings', page: 'organization' },
 { title: 'Teams', summary: 'Sets of members holding the same permissions on the same projects', section: 'settings', page: 'teams' },
 { title: 'Single sign-on', summary: 'OIDC providers and identity mapping', section: 'settings', page: 'sso' },
 { title: 'Audit and operations', summary: 'Audited changes, deletion and restriction progress', section: 'settings', page: 'operations' },
 { title: 'GitLab', summary: 'Create a GitLab issue from an incident or an error and keep the link', section: 'gitlab' },
 { title: 'Event webhooks', summary: 'Signed events for your own scripts and the GitLab bridge', section: 'events' },
 { title: 'Migration and cutover', summary: 'Who sends normal notifications, shadow decisions and the history boundary', section: 'cutover' },
];
