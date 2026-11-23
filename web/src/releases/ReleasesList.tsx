// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { listReleases, type ReleaseListItem } from '../api/console';
import { usePagedList } from '../api/useConsoleRead';
import type { IncidentRef, ViewContext } from '../app/context';
import { OpenByRef } from '../app/OpenByRef';
import { StatusPanel } from '../app/StatusPanel';
import { listNotice, sectionNotes } from '../issues/listModel';
import { projectLabel, type Names, type ShellApi } from '../shell/ShellContext';
import { Icon } from '../ui/Icon';
import { Callout, Card, DataTable, EmptyState, NotAvailable, shortId, type Column } from '../ui/primitives';
import { DEFAULT_RELEASE_QUERY, builtText, countCell, deployLines, releaseFilter, releaseItemKey, releaseListKey, releaseListRequest, shownText, type ReleaseQuery } from './model';

function Count(props: { value: string | null; incomplete: boolean; hot?: boolean }): React.JSX.Element {
 const c = countCell(props.value, props.incomplete);
 return <span className={c.known ? `num${props.hot && c.text !== '0' ? ' tone-crit' : ''}` : 'rel-count-unknown'}>{c.text}</span>;
}

/** The releases as a table: when each was deployed (the recorded marker per environment, or `deploy time unknown`; the build time is shown apart and never as a deploy), the issues it brought, fixed or regressed, and its declared parents. */
export function ReleaseTable(props: { items: readonly ReleaseListItem[]; context: ViewContext; names: Names; href: ShellApi['href'] }): React.JSX.Element {
 const { context, names, href } = props;
 const columns: Column<ReleaseListItem>[] = [
  {
   key: 'release', header: 'Release', cell: (it) => (
    <div className="cell-title">
     <a className="a" href={href('releases', { target: { project: it.project_id, id: it.release_id } })}>{it.label === '' ? shortId(it.release_id) : it.label}</a>
     <span className="s"><code title={it.release_id}>{shortId(it.release_id)}</code></span>
    </div>
   ),
  },
  { key: 'project', header: 'Project', cell: (it) => projectLabel(names, it.project_id) },
  {
   key: 'deployed', header: 'Deployed', cell: (it) => (
    <div className="rel-deploys" data-testid="release-deploys" data-deploy={it.deployState}>
     {deployLines(it, context.timezone).map((l) => <span key={l.key} className={it.deployState === 'known' ? 'small' : 'small t3'}>{l.text}</span>)}
     <span className="xsmall t3">{builtText(it.buildTime, context.timezone)}</span>
    </div>
   ),
  },
  { key: 'new', header: 'New', align: 'right', cell: (it) => <Count value={it.newIssues} incomplete={it.countsIncomplete} /> },
  { key: 'regressed', header: 'Regressed', align: 'right', cell: (it) => <Count value={it.regressedIssues} incomplete={it.countsIncomplete} hot /> },
  { key: 'resolved', header: 'Resolved', align: 'right', cell: (it) => <Count value={it.resolvedIssues} incomplete={it.countsIncomplete} /> },
  {
   key: 'parents', header: 'Parents', cell: (it) => it.parents.length === 0
    ? <span className="small t3">no parent declared</span>
    : <span className="row wrap g4">{it.parents.map((p) => <a key={p} className="pill pill-line mono" href={href('releases', { target: { project: it.project_id, id: p } })} title={`Release ${p}`}><Icon name="tag" size="xs" />{shortId(p)}</a>)}</span>,
  },
 ];
 return (
  <DataTable
   label="Releases" caption="Releases of the selected projects with their deploy times, new, regressed and resolved issues and parents." rows={props.items} rowKey={releaseItemKey} columns={columns}
   rowAttrs={(it) => ({ 'data-testid': 'release-row', 'data-release': it.release_id })}
  />
 );
}

/** The release list screen. `Open a release` by ID keeps working whatever the list says. */
export function ReleasesList(props: { context: ViewContext; names: Names; href: ShellApi['href']; open: (ref: IncidentRef) => void }): React.JSX.Element {
 const { context, names } = props;
 const [query, setQuery] = React.useState<ReleaseQuery>(DEFAULT_RELEASE_QUERY);
 const [draft, setDraft] = React.useState('');
 const list = usePagedList<ReleaseListItem>(releaseListKey(context, query), releaseItemKey, (cursor, signal) => listReleases({ ...releaseListRequest(context, query), ...(cursor ? { cursor } : {}) }, releaseFilter(context, query), signal));
 const env = list.state.kind === 'ok' ? list.state.data : undefined;
 const notice = env ? listNotice(env) : null;
 const notes = env ? sectionNotes(env.sections) : [];
 return (
  <>
   <OpenByRef context={context} noun="release" current={null} open={props.open} />
   <form className="iss-filters" role="search" aria-label="Search releases" onSubmit={(e) => { e.preventDefault(); setQuery((q) => ({ ...q, search: draft })); }}>
    <div className="searchbar grow">
     <Icon name="search" size="s" />
     <input name="search" aria-label="Search releases by ID prefix or label" placeholder="Search by the start of a release ID, or by label" value={draft} onChange={(e) => setDraft(e.target.value)} autoComplete="off" spellCheck={false} maxLength={200} />
     {query.search !== '' && <button type="button" className="btn btn-ghost btn-sm" onClick={() => { setDraft(''); setQuery((q) => ({ ...q, search: '' })); }}>Clear search</button>}
     <button type="submit" className="btn btn-sm">Search</button>
    </div>
    <button type="button" className="chip" aria-pressed={query.regressionsOnly} onClick={() => setQuery((q) => ({ ...q, regressionsOnly: !q.regressionsOnly }))}>With regressions</button>
   </form>
   {context.environment !== '' && <p className="small t3 iss-note" role="note" data-testid="releases-environment">The list is narrowed by the server to releases deployed to environment <code>{context.environment}</code>.</p>}
   {list.state.kind === 'loading' && <StatusPanel state={{ kind: 'loading' }} />}
   {list.state.kind === 'fault' && <StatusPanel state={list.state.state} />}
   {list.state.kind === 'not_built' && (
    <Card bodyClass={false} ariaLabel="Release list">
     <NotAvailable title="The release list is not available yet" testId="releases-list-unavailable">
      This installation does not serve the release list yet, so no release is listed and nothing is shown in its place. A release you hold the ID of still opens with Open a release above.
     </NotAvailable>
    </Card>
   )}
   {env && (
    <>
     {notice && <Callout tone={notice.tone === 'warn' ? 'warn' : 'unk'} role="status" testId="releases-list-notice"><strong>{notice.label}.</strong> {notice.text}</Callout>}
     {notes.length > 0 && <ul className="small t2 iss-notes" aria-label="Parts of this list">{notes.map((n) => <li key={n}>{n}</li>)}</ul>}
     <Card bodyClass={false} ariaLabel="Release list">
      {list.items.length === 0
       ? (env.state === 'not_available'
        ? <NotAvailable title="The release list is not available" testId="releases-list-unavailable">{notice?.text}</NotAvailable>
        : <EmptyState icon="tag" title="No release matches" testId="releases-list-empty">No registered release of the selected projects matches this filter.</EmptyState>)
       : <ReleaseTable items={list.items} context={context} names={names} href={props.href} />}
      {list.items.length > 0 && (
       <div className="card-foot">
        <span data-testid="releases-count">{shownText(list.items.length, list.more)}</span>
        {list.more && <button type="button" className="btn btn-sm ml-auto" disabled={list.busy} onClick={list.loadMore}>{list.busy ? 'Loading…' : 'Load more'}</button>}
       </div>
      )}
     </Card>
     {list.moreFault && <StatusPanel state={list.moreFault} />}
    </>
   )}
  </>
 );
}
