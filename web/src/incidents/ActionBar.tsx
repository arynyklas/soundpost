// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { IncidentActionKind } from '../api/types';
import { useMenu } from '../gitlab/useMenu';
import { Icon } from '../ui/Icon';
import { availableActions } from './model';
import type { IncidentActions } from './useIncidentActions';

const MORE: readonly IncidentActionKind[] = ['impact', 'link', 'maintenance', 'maintenance_end', 'title'];
const MORE_LABEL: Partial<Record<IncidentActionKind, string>> = { impact: 'Report impact', link: 'Link evidence', maintenance: 'Start maintenance', maintenance_end: 'End maintenance', title: 'Set title' };

function MoreMenu(props: { actions: IncidentActions; kinds: readonly IncidentActionKind[] }): React.JSX.Element {
 const { open, setOpen, wrap, trigger } = useMenu();
 return (
  <div className="menu-wrap" ref={wrap}>
   <button ref={trigger} type="button" className="btn btn-icon" aria-haspopup="menu" aria-expanded={open} aria-label="More actions: report impact, link evidence, maintenance, set title" onClick={() => setOpen(!open)}><Icon name="dots" size="s" /></button>
   {open && (
    <div className="menu" role="menu" aria-label="More actions">
     {props.kinds.map((k) => <button key={k} type="button" role="menuitem" onClick={() => { setOpen(false); props.actions.openAction(k); }}>{MORE_LABEL[k]}</button>)}
    </div>
   )}
  </div>
 );
}

/** The incident's action bar. Each action opens its own dialog, which shows the revision acted on and the words of what the action does; the server decides. A
 * resolved incident accepts no response action, so only the GitLab issue and the Markdown copy remain. */
export function ActionBar(props: { actions: IncidentActions; copy: React.ReactNode; onGitlab: () => void }): React.JSX.Element {
 const { actions } = props;
 const { view } = actions;
 const kinds = availableActions(view);
 const can = (k: IncidentActionKind): boolean => kinds.includes(k);
 const more = MORE.filter((k) => k === 'title' ? true : can(k));
 return (
  <div className="row wrap inc-actions" role="group" aria-label="Incident actions">
   {can('ack') && <button type="button" className="btn" onClick={() => actions.openAction('ack')}><Icon name="check" size="s" />Acknowledge</button>}
   {can('assign') && <button type="button" className="btn" onClick={() => actions.openAction('assign')}><Icon name="user" size="s" />{view.owner ? 'Reassign' : 'Assign owner'}</button>}
   {(can('snooze') || can('unsnooze')) && <button type="button" className="btn" onClick={() => actions.openAction(can('unsnooze') ? 'unsnooze' : 'snooze')}><Icon name="snooze" size="s" />{can('unsnooze') ? 'End snooze' : 'Snooze'}</button>}
   <button type="button" className="btn" onClick={props.onGitlab}><Icon name="git" size="s" />Create GitLab issue</button>
   {props.copy}
   {more.length > 0 && <MoreMenu actions={actions} kinds={more} />}
   {can('resolve') && <button type="button" className="btn btn-primary" onClick={() => actions.openAction('resolve')}><Icon name="check" size="s" />Resolve incident</button>}
  </div>
 );
}
