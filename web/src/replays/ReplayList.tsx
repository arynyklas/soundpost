// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { listReplays, type ReplayListItem } from '../api/console';
import { formatNs, scopeKey, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { envelopeStatus, useConsoleList } from '../explore/useConsoleList';
import { projectLabel, useShell } from '../shell/ShellContext';
import { Card, DataTable, NotAvailable, Pill, shortId } from '../ui/primitives';
import { chunksText, lengthText, recordingView } from './listModel';

const LIMIT = 50;

/** The masked replays of the selected projects in the window. The list is read under the separate replay grant: without it the server says so and nothing is probed. No masked content is ever listed here. */
export function ReplayList(props: { context: ViewContext }): React.JSX.Element {
 const { context } = props;
 const shell = useShell();
 const key = `${scopeKey(context)}|${context.generation}`;
 const list = useConsoleList<ReplayListItem>(key, (cursor, signal) => listReplays({ org: context.org, projects: context.projects, window: { start: context.start, end: context.end }, limit: LIMIT, ...(cursor !== undefined ? { cursor } : {}) }, signal));
 const { state } = list;
 return (
  <Card title="Replays in this window" titleId="replay-list-heading" bodyClass={state.kind === 'ready' && state.envelope.items.length > 0 ? false : 'col g12'} testId="replay-list">
   {state.kind === 'loading' && <StatusPanel state={{ kind: 'loading' }} />}
   {state.kind === 'not_built' && <NotAvailable icon="replay" title="The replay list is not available yet" testId="replay-list-not-built">This installation does not serve the replay list route yet. Nothing is listed and nothing is estimated; open a replay by its ID or from a link.</NotAvailable>}
   {state.kind === 'fault' && <StatusPanel state={state.state} />}
   {state.kind === 'ready' && (
    <>
     {(state.envelope.state !== 'ready' || state.envelope.items.length === 0) && <div className={state.envelope.items.length > 0 ? 'card-body' : undefined}><StatusPanel state={envelopeStatus(state.envelope)} /></div>}
     {state.envelope.items.length > 0 && (
      <>
       <DataTable
        label="Replay list" caption="Masked replays in the selected window, newest first as the server orders them" rows={state.envelope.items} rowKey={(r) => `${r.project_id}:${r.replay_id}`} testId="replay-table"
        columns={[
         { key: 'replay', header: 'Replay', cell: (r) => <div className="cell-title"><a className="a" href={shell.href('replays', { target: { project: r.project_id, id: r.replay_id } })} title={r.replay_id}>Replay {shortId(r.replay_id)}</a><span className="s">session <code>{r.session_id === '' ? 'not stated' : r.session_id}</code></span></div> },
         { key: 'project', header: 'Project', cell: (r) => projectLabel(shell.names, r.project_id) },
         { key: 'started', header: 'Started', cell: (r) => (r.firstAt === null ? <span className="t3">not stated</span> : formatNs(r.firstAt, context.timezone)) },
         { key: 'length', header: 'Length', cell: (r) => lengthText(r.firstAt, r.lastAt) },
         { key: 'chunks', header: 'Chunks', cell: (r) => chunksText(r.chunks) },
         { key: 'recording', header: 'Recording', cell: (r) => { const v = recordingView(r); return <div className="cell-title"><span><Pill tone={v.tone}>{v.word}</Pill></span><span className="s">{v.detail}</span></div>; } },
        ]}
       />
       <div className="table-foot">
        <span>{state.envelope.items.length} {state.envelope.items.length === 1 ? 'replay' : 'replays'} listed{state.envelope.more ? '; more exist' : ''}. Text and inputs are masked in every replay; the recorder never captures page text or form values.</span>
        {state.envelope.more && state.envelope.nextCursor !== undefined && <button type="button" className="btn btn-sm ml-auto" disabled={list.loadingMore} onClick={list.loadMore}>{list.loadingMore ? 'Loading…' : 'Load more'}</button>}
       </div>
      </>
     )}
    </>
   )}
  </Card>
 );
}
