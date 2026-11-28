// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { listProfiles, type ProfileListItem } from '../api/console';
import { formatNs, scopeKey, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { envelopeStatus, useConsoleList } from '../explore/useConsoleList';
import { projectLabel, useShell } from '../shell/ShellContext';
import { Card, DataTable, NotAvailable, Pill, shortId } from '../ui/primitives';
import { coverageView, reasonWords, unitWord, windowText } from './listModel';

const LIMIT = 50;

/** The profiles of the selected projects in the window, read under the separate profiles grant. Every profile keeps its own unit and nothing is added across profiles; an unsupported runtime is its reason in words, never zero samples. */
export function ProfileList(props: { context: ViewContext }): React.JSX.Element {
 const { context } = props;
 const shell = useShell();
 const key = `${scopeKey(context)}|${context.generation}`;
 const list = useConsoleList<ProfileListItem>(key, (cursor, signal) => listProfiles({ org: context.org, projects: context.projects, window: { start: context.start, end: context.end }, limit: LIMIT, ...(cursor !== undefined ? { cursor } : {}) }, signal));
 const { state } = list;
 const when = (ns: string): string => formatNs(ns, context.timezone);
 return (
  <Card title="Profiles in this window" titleId="profile-list-heading" bodyClass={state.kind === 'ready' && state.envelope.items.length > 0 ? false : 'col g12'} testId="profile-list">
   {state.kind === 'loading' && <StatusPanel state={{ kind: 'loading' }} />}
   {state.kind === 'not_built' && <NotAvailable icon="flame" title="The profile list is not available yet" testId="profile-list-not-built">This installation does not serve the profile list route yet. Nothing is listed and nothing is estimated; open a profile by its ID or from a link.</NotAvailable>}
   {state.kind === 'fault' && <StatusPanel state={state.state} />}
   {state.kind === 'ready' && (
    <>
     {(state.envelope.state !== 'ready' || state.envelope.items.length === 0) && <div className={state.envelope.items.length > 0 ? 'card-body' : undefined}><StatusPanel state={envelopeStatus(state.envelope)} /></div>}
     {state.envelope.items.length > 0 && (
      <>
       <DataTable
        label="Profile list" caption="Profiles in the selected window, in the server's order" rows={state.envelope.items} rowKey={(r) => `${r.project_id}:${r.profile_id}`} testId="profile-table"
        columns={[
         { key: 'profile', header: 'Profile', cell: (r) => <div className="cell-title"><a className="a" href={shell.href('profiles', { target: { project: r.project_id, id: r.profile_id } })} title={r.profile_id}>Profile {shortId(r.profile_id)}</a><span className="s">source {r.source_id === null ? 'not stated' : <code>{shortId(r.source_id)}</code>}</span></div> },
         { key: 'project', header: 'Project', cell: (r) => projectLabel(shell.names, r.project_id) },
         { key: 'method', header: 'Method', cell: (r) => (r.method === undefined ? <span className="t3">not stated</span> : <code title={r.method}>{reasonWords(r.method)}</code>) },
         { key: 'unit', header: 'Unit', cell: (r) => unitWord(r.unit) },
         { key: 'window', header: 'Window', cell: (r) => windowText(r.firstAt, r.lastAt, when) },
         { key: 'coverage', header: 'Coverage', cell: (r) => { const v = coverageView(r); return <div className="cell-title"><span><Pill tone={v.tone}>{v.word}</Pill></span><span className="s">{v.detail}</span></div>; } },
        ]}
       />
       <div className="table-foot">
        <span>{state.envelope.items.length} {state.envelope.items.length === 1 ? 'profile' : 'profiles'} listed{state.envelope.more ? '; more exist' : ''}. Each profile keeps its own unit: samples, nanoseconds and events are never added together.</span>
        {state.envelope.more && state.envelope.nextCursor !== undefined && <button type="button" className="btn btn-sm ml-auto" disabled={list.loadingMore} onClick={list.loadMore}>{list.loadingMore ? 'Loading…' : 'Load more'}</button>}
       </div>
      </>
     )}
    </>
   )}
  </Card>
 );
}
