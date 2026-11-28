// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { listIssues, type IssueListItem } from '../api/console';
import type { Id } from '../api/types';
import { usePagedList } from '../api/useConsoleRead';
import type { ViewContext } from '../app/context';
import { OpenByRef } from '../app/OpenByRef';
import { StatusPanel } from '../app/StatusPanel';
import type { IncidentRef } from '../app/context';
import { projectLabel, type Names, type ShellApi } from '../shell/ShellContext';
import { GitlabLink } from '../gitlab';
import { Icon } from '../ui/Icon';
import { Callout, Card, DataTable, EmptyState, FilterChips, NotAvailable, Person, Pill, shortId, type Column } from '../ui/primitives';
import {
 DEFAULT_ISSUE_QUERY, SORT_CHOICES, WORKFLOW_CHOICES, countText, issueFilter, issueItemKey, issueListKey, issueListRequest, listNotice, ownerChoices, sectionNotes, seenText, shownText, titleText, workflowWord,
 type IssueQuery, type IssueSort,
} from './listModel';

const MAX_RELEASE_CHIPS = 3;

/** The issues as a table. Every cell states what the server states: a title it cannot read is `Title not available`, a count it cannot state is `not available`, an issue without an owner is `Unassigned`. */
export function IssueTable(props: { items: readonly IssueListItem[]; context: ViewContext; names: Names; href: ShellApi['href'] }): React.JSX.Element {
 const { context, names, href } = props;
 const columns: Column<IssueListItem>[] = [
  {
   key: 'issue', header: 'Issue', cell: (it) => {
    return (
     <div className="cell-title">
      <a className={it.titleState === 'ready' ? 'a' : 'a t2'} href={href('issues', { target: { project: it.project_id, id: it.issue_id } })}>{titleText(it)}</a>
      <span className="s row wrap g4">
       <code title={it.issue_id}>{shortId(it.issue_id)}</code>
       <span aria-hidden="true">·</span>
       <span>{projectLabel(names, it.project_id)}</span>
       {it.compacted && <Pill tone="unk" icon="info" title="Older evidence of this issue was compacted; counts and the title may cover only what remains">Evidence compacted</Pill>}
       {it.gitlab && <span className="pill pill-line" title="The GitLab issue linked to this issue. Its state lives in GitLab and is not read back."><Icon name="git" size="xs" /><GitlabLink link={it.gitlab} /></span>}
      </span>
     </div>
    );
   },
  },
  { key: 'state', header: 'State', cell: (it) => { const w = workflowWord(it.workflow); return <Pill tone={w.tone} state={it.workflow}>{w.text}</Pill>; } },
  {
   key: 'releases', header: 'Releases', cell: (it) => it.releases.length === 0
    ? <span className="small t3">no release named</span>
    : (
     <span className="row wrap g4">
      {it.releases.slice(0, MAX_RELEASE_CHIPS).map((r) => <a key={r} className="pill pill-line mono" href={href('releases', { target: { project: it.project_id, id: r } })} title={`Release ${r}`}><Icon name="tag" size="xs" />{shortId(r)}</a>)}
      {it.releases.length > MAX_RELEASE_CHIPS && <span className="small t3">+{it.releases.length - MAX_RELEASE_CHIPS} more</span>}
     </span>
    ),
  },
  { key: 'owner', header: 'Owner', cell: (it) => <Person id={it.owner} name={it.owner ? names.members.get(it.owner) : undefined} /> },
  { key: 'first', header: 'First seen', cell: (it) => <span className="small nowrap">{seenText(it.firstSeen, context.timezone)}</span> },
  { key: 'last', header: 'Last seen', cell: (it) => <span className="small nowrap">{seenText(it.lastSeen, context.timezone)}</span> },
  { key: 'occ', header: 'Occurrences', align: 'right', cell: (it) => <span className={it.occurrences === null ? 'small t3' : 'num'}>{countText(it.occurrences)}</span> },
 ];
 return (
  <DataTable
   label="Error issues" caption="Error issues of the selected projects, with state, releases, owner, first and last seen and occurrences." rows={props.items} rowKey={issueItemKey} columns={columns}
   rowAttrs={(it) => ({ 'data-testid': 'issue-row', 'data-issue': it.issue_id, 'data-workflow': it.workflow })}
  />
 );
}

/** The issue list screen: filters, search, the table, and the honest state of the list endpoint. `Open an issue` by ID keeps working whatever the list says. */
export function IssuesList(props: { context: ViewContext; names: Names; href: ShellApi['href']; open: (ref: IncidentRef) => void; current: IncidentRef | null }): React.JSX.Element {
 const { context, names } = props;
 const [query, setQuery] = React.useState<IssueQuery>(DEFAULT_ISSUE_QUERY);
 const [draft, setDraft] = React.useState('');
 const list = usePagedList<IssueListItem>(issueListKey(context, query), issueItemKey, (cursor, signal) => listIssues({ ...issueListRequest(context, query), ...(cursor ? { cursor } : {}) }, issueFilter(query), signal));
 const set = (patch: Partial<IssueQuery>): void => setQuery((q) => ({ ...q, ...patch }));
 const owners = ownerChoices(names.members);
 const env = list.state.kind === 'ok' ? list.state.data : undefined;
 const notice = env ? listNotice(env) : null;
 const notes = env ? sectionNotes(env.sections) : [];
 return (
  <>
   <form className="iss-filters" role="search" aria-label="Search issues" onSubmit={(e) => { e.preventDefault(); set({ search: draft }); }}>
    <div className="searchbar grow">
     <Icon name="search" size="s" />
     <input name="search" aria-label="Search issues by ID prefix or title" placeholder="Search by the start of an issue ID, or by title" value={draft} onChange={(e) => setDraft(e.target.value)} autoComplete="off" spellCheck={false} maxLength={200} />
     {query.search !== '' && <button type="button" className="btn btn-ghost btn-sm" onClick={() => { setDraft(''); set({ search: '' }); }}>Clear search</button>}
     <button type="submit" className="btn btn-sm">Search</button>
    </div>
   </form>
   <div className="row wrap iss-toolbar">
    <FilterChips<IssueQuery['workflow']> label="Workflow state" value={query.workflow} options={WORKFLOW_CHOICES} onChange={(workflow) => set({ workflow })} />
    <button type="button" className="chip" aria-pressed={query.regressed} onClick={() => set({ regressed: !query.regressed })}>Regressed</button>
    <label className="iss-select"><span className="t3 small">Owner</span>
     <select aria-label="Owner" value={query.owner} onChange={(e) => set({ owner: e.target.value as IssueQuery['owner'] })}>{owners.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}</select>
    </label>
    <label className="iss-select"><span className="t3 small">Sort</span>
     <select aria-label="Sort issues by" value={query.sort} onChange={(e) => set({ sort: e.target.value as IssueSort })}>{SORT_CHOICES.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}</select>
    </label>
   </div>
   {names.state === 'not_built' && <p className="small t3 iss-note" role="note">Owners are shown by short account ID: this installation does not serve display names yet.</p>}
   {list.state.kind === 'loading' && <StatusPanel state={{ kind: 'loading' }} />}
   {list.state.kind === 'fault' && <StatusPanel state={list.state.state} />}
   {list.state.kind === 'not_built' && (
    <Card bodyClass={false} ariaLabel="Issue list">
     <NotAvailable title="The issue list is not available yet" testId="issues-list-unavailable">
      This installation does not serve the issue list yet, so no issue is listed and nothing is shown in its place. An issue you hold the ID of still opens with Open an issue above.
     </NotAvailable>
    </Card>
   )}
   {env && (
    <>
     {notice && <Callout tone={notice.tone === 'warn' ? 'warn' : 'unk'} role="status" testId="issues-list-notice"><strong>{notice.label}.</strong> {notice.text}</Callout>}
     {notes.length > 0 && <ul className="small t2 iss-notes" aria-label="Parts of this list">{notes.map((n) => <li key={n}>{n}</li>)}</ul>}
     <Card bodyClass={false} ariaLabel="Issue list">
      {list.items.length === 0
       ? (env.state === 'not_available'
        ? <NotAvailable title="The issue list is not available" testId="issues-list-unavailable">{notice?.text}</NotAvailable>
        : <EmptyState icon="bug" title="No issue matches" testId="issues-list-empty">{query.search !== '' || query.regressed || query.owner !== '' || query.workflow !== 'open' ? 'No issue in the selected projects matches this filter. Widen the filter or clear the search.' : 'No open issue in the selected projects.'}</EmptyState>)
       : <IssueTable items={list.items} context={context} names={names} href={props.href} />}
      {list.items.length > 0 && (
       <div className="card-foot">
        <span data-testid="issues-count">{shownText(list.items.length, list.more)}</span>
        {list.more && <button type="button" className="btn btn-sm ml-auto" disabled={list.busy} onClick={list.loadMore}>{list.busy ? 'Loading…' : 'Load more'}</button>}
       </div>
      )}
     </Card>
     {list.moreFault && <StatusPanel state={list.moreFault} />}
    </>
   )}
   <Card title="Open an issue by ID" titleId="issue-open-by-id-h" className="open-by-id-card"><OpenByRef context={context} noun="issue" current={props.current} open={props.open} /></Card>
  </>
 );
}
