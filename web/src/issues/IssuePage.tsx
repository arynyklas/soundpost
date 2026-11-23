// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { getIssueEvidence, getQueue } from '../api/client';
import { listIssues, type IssueListItem } from '../api/console';
import type { Id, IssueEvidenceView, LoadState, OccurrenceEvidence, QueueView } from '../api/types';
import { useConsoleRead, type ConsoleState } from '../api/useConsoleRead';
import { FrameLookup } from '../artifacts/FrameLookup';
import { formatNs, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { EvidenceSections } from '../evidence/Sections';
import { occurrenceAncestryWords } from '../evidence/model';
import { dataOf, useEvidence } from '../evidence/useEvidence';
import { Content, Explain, Hero, PageHead, Tools } from '../shell/Frames';
import { projectLabel, type Names, type ShellApi } from '../shell/ShellContext';
import { Icon } from '../ui/Icon';
import { Callout, DataTable, IdCode, Lineage, Pill, shortId, type Column, type LineageItem } from '../ui/primitives';
import { IssueActions } from './IssueActions';
import { CopyMenu, GitlabCreateDialog, GitlabLink } from '../gitlab';
import { countText, seenText, titleText, workflowWord } from './listModel';
import { OccurrenceDetail } from './OccurrenceDetail';
import { RegressionTable } from './RegressionTable';
import { chosenOccurrence, issueReadKey, selectedFor, type Selection } from './model';
import { issueLineage, linkedIncidents, ownerOfIssue, regressionStory } from './pageModel';
import { Section } from './Section';

/** The reload control: disabled exactly while the page re-reads. */
export function ReloadIssueButton({ reloading, onReload }: { reloading: boolean; onReload: () => void }): React.ReactElement {
 return <button type="button" className="btn btn-ghost" onClick={onReload} disabled={reloading}><Icon name="refresh" size="s" />Reload issue</button>;
}

type Href = ShellApi['href'];

function OccurrenceTable(props: { caption: string; rows: OccurrenceEvidence[]; tz: string; empty: string; selected: Id | null; onSelect: (id: Id) => void }): React.JSX.Element {
 const { rows } = props;
 if (rows.length === 0) return <p>{props.empty}</p>;
 const columns: Column<OccurrenceEvidence>[] = [
  { key: 'occurrence', header: 'Occurrence', cell: (o) => <><IdCode value={o.occurrence_id} />{o.late ? <> <Pill tone="high">late</Pill></> : null}</> },
  { key: 'event', header: 'Event time', cell: (o) => <span className="small">{seenText(o.event_time_ns, props.tz)}</span> },
  { key: 'arrived', header: 'Arrived', cell: (o) => <span className="small">{seenText(o.arrival_time_ns, props.tz)}</span> },
  { key: 'grouping', header: 'Grouping', cell: (o) => <span className="small">version {o.grouping_version}, hash <IdCode value={o.fingerprint} /></span> },
  { key: 'ancestry', header: 'Release ancestry', cell: (o) => <span className="small">{occurrenceAncestryWords(o)}</span> },
  { key: 'freshness', header: 'Freshness', cell: (o) => <span className="small">{o.freshness}</span> },
  { key: 'record', header: 'Stored record', cell: (o) => <button type="button" className="btn btn-sm" onClick={() => props.onSelect(o.occurrence_id)} aria-pressed={props.selected === o.occurrence_id} aria-label={`Show stored detail of occurrence ${o.occurrence_id}`}>Show stored detail</button> },
 ];
 return (
  <DataTable
   label={props.caption} rows={rows} rowKey={(o) => o.occurrence_id} columns={columns} tight
   rowClass={(o) => (props.selected === o.occurrence_id ? 'selected' : undefined)}
   rowAttrs={(o) => ({ 'data-occurrence': o.occurrence_id, 'data-late': o.late ? 'yes' : 'no', 'data-ancestry': o.ancestry, 'aria-selected': String(props.selected === o.occurrence_id) })}
  />
 );
}

function ReleaseLinks(props: { ids: readonly Id[]; project: Id; href: Href }): React.JSX.Element {
 return <span className="row wrap g4">{props.ids.map((r) => <a key={r} className="pill pill-line mono" href={props.href('releases', { target: { project: props.project, id: r } })} title={`Release ${r}`}><Icon name="tag" size="xs" />{shortId(r)}</a>)}</span>;
}

/** What the issue view says, as markup, for the occurrence selected now. The page's state (the reads, the selection) lives in IssuePage; this is a function of it. */
export function IssueBody(props: { context: ViewContext; project: Id; id: Id; view: IssueEvidenceView; selected: Id | null; onSelect: (id: Id) => void; href: Href }): React.JSX.Element {
 const { context, project, id, view, selected } = props;
 const tz = context.timezone;
 const chosen = chosenOccurrence(view, selected);
 const story = regressionStory(view, tz);
 return (
  <>
   <div className="grid-side">
    <div className="col g16">
     {view.grouping && (
      <Section id="grouping-heading" section="grouping" title="Grouping">
       <dl className="scope-bar">
        <dt>Grouping version</dt><dd data-testid="grouping-version">{view.grouping.grouping_version}</dd>
        <dt>Grouping hash</dt><dd data-testid="grouping-hash"><IdCode value={view.grouping.fingerprint} copy="Copy grouping hash" /></dd>
        <dt>Workflow state</dt><dd data-testid="workflow">{view.grouping.workflow} (revision {view.grouping.revision})</dd>
        {view.grouping.resolution_time_ns !== undefined && <><dt>Resolved at</dt><dd>{formatNs(view.grouping.resolution_time_ns, tz)}</dd></>}
        <dt>Audited grouping migrations</dt><dd data-testid="migrations">{view.grouping.migration_links.length === 0 ? 'None recorded' : view.grouping.migration_links.map((m) => <code key={m}>{m} </code>)}</dd>
       </dl>
      </Section>
     )}
     <Section id="occ-heading" section="occurrences" title="Occurrences">
      <OccurrenceTable caption="Stored occurrences" rows={view.occurrences} tz={tz} empty="No occurrence evidence is stored for this issue." selected={selected} onSelect={props.onSelect} />
      <h3 className="iss-sub">Late history</h3>
      <Explain line="Evidence that arrived after the issue was resolved.">Evidence that arrived after the issue was resolved is listed here, apart from the occurrences above. It is never merged into them and never rewrites the resolution.</Explain>
      <OccurrenceTable caption="Late history" rows={view.late_history} tz={tz} empty="No late evidence is recorded." selected={selected} onSelect={props.onSelect} />
     </Section>
     <Section id="regression-heading" section="regression-explanations" title="Regression">
      <Explain testId="regression-note" line="Decided from the stored resolution and the registered release graph.">A regression is decided from the issue&apos;s stored resolution boundary or fix frontier and the registered release graph, and recorded as an explanation when evidence arrives after the resolution. It is never inferred from timestamps or release labels, and an occurrence with unknown ancestry stays unknown.</Explain>
      {view.regression === undefined
       ? <p data-testid="regression-unavailable">The stored explanations are not available here, so no regression is claimed.</p>
       : view.regression.explanations.length === 0
        ? <p data-testid="regression-none">No regression has been evaluated for this issue: no occurrence has arrived after a resolution. That is not a statement that none can happen.</p>
        : <RegressionTable context={context} project={project} rows={view.regression.explanations} caption="Stored regression evaluations, oldest first" byRelease={false} />}
     </Section>
     {chosen && <OccurrenceDetail key={chosen.occurrence_id} context={context} project={project} issue={id} occurrence={chosen} />}
    </div>
    <aside className="col g16" aria-label="Workflow, releases and the parts of this view">
     <Section id="story-heading" section="story" title="Workflow and regression">
      <ul className="iss-story">
       {story.map((l) => (
        <li key={l.key} data-story={l.key}>
         <span className={`iss-story-icon tone-${l.tone}`}><Icon name={l.icon} size="s" /></span>
         <span>{l.text}{l.releases && <> <ReleaseLinks ids={l.releases} project={project} href={props.href} /></>}</span>
        </li>
       ))}
      </ul>
     </Section>
     {view.grouping && view.grouping.observed_releases.length > 0 && (
      <Section id="observed-heading" section="observed-releases" title="Releases it ran in">
       <ReleaseLinks ids={view.grouping.observed_releases} project={project} href={props.href} />
      </Section>
     )}
     <Section id="parts-heading" section="parts" title="Parts of this view"><EvidenceSections sections={view.sections} /></Section>
    </aside>
   </div>
  </>
 );
}

type SummaryState = ConsoleState<{ item: IssueListItem | undefined }>;

function TitleLine(props: { summary: SummaryState }): React.JSX.Element {
 const s = props.summary;
 if (s.kind === 'loading') return <span className="t3">Reading the title…</span>;
 if (s.kind === 'not_built') return <span className="t3" data-testid="issue-title-unavailable">Title not available: this installation does not serve the issue list yet.</span>;
 if (s.kind === 'fault' || s.data.item === undefined) return <span className="t3" data-testid="issue-title-unavailable">Title not available</span>;
 return <span className={s.data.item.titleState === 'ready' ? '' : 't3'} data-testid="issue-title-text">{titleText(s.data.item)}</span>;
}

/** The identity block of the issue: its ID as the one h1, the title when the list can read it, the facts, the lineage and the actions. */
export function IssueHero(props: { id: Id; context: ViewContext; view: IssueEvidenceView | undefined; summary: SummaryState; lineage: LineageItem[]; actions: React.ReactNode }): React.JSX.Element {
 const { view, summary, context } = props;
 const item = summary.kind === 'ok' ? summary.data.item : undefined;
 return (
  <Hero>
   <div className="row top g12 wrap">
    <div className="col g4 grow">
     <h1 tabIndex={-1} data-issue={props.id}>{item && item.titleState === 'ready' ? titleText(item) : 'Error issue'}</h1>
     <div className="row wrap small t2 g12">
      {!(item && item.titleState === 'ready') && <TitleLine summary={summary} />}
      <span className="mono" title={props.id}>issue {props.id.slice(0, 4)}…{props.id.slice(-4)}</span>
      {view?.grouping && <span>grouping v{view.grouping.grouping_version}</span>}
      {item ? <><span>first seen {seenText(item.firstSeen, context.timezone)}</span><span>last seen {seenText(item.lastSeen, context.timezone)}</span></> : null}
     </div>
    </div>
    <div className="kpis" role="group" aria-label="Issue figures">
     {view?.grouping && <div className="kpi"><span className="label">Revision</span><span className="value num" data-testid="issue-expected-version">{view.grouping.revision}</span></div>}
     {view?.grouping && (() => { const w = workflowWord(view.grouping.workflow); return <div className="kpi"><span className="label">State</span><span className="value"><Pill tone={w.tone} state={view.grouping.workflow}>{w.text}</Pill></span></div>; })()}
     {item && <div className="kpi"><span className="label">Occurrences</span><span className={item.occurrences === null ? 'small t3' : 'value num'}>{countText(item.occurrences)}</span></div>}
    </div>
   </div>
   <Lineage items={props.lineage} />
   {props.actions}
  </Hero>
 );
}

/** Persisted evidence for one issue: the grouping version and hash, every stored occurrence, the late history listed apart, release ancestry stated as known or unknown, and, on request, the stored error record behind one occurrence (class, mechanism, handled, fatal, code, exception chain, frames mapped through the real source map, links to the release and trace it names). A regression is never computed or guessed here. A chosen occurrence belongs to the read it was chosen under: another scope, project, issue or generation shows none. */
export function IssuePage(props: { id: Id; project: Id; context: ViewContext; names: Names; href: Href; footer?: React.ReactNode }): React.JSX.Element {
 const { context, project, id, names, href } = props;
 const key = issueReadKey(context, project, id);
 const evidence = useEvidence<IssueEvidenceView>(key, (signal) => getIssueEvidence(context.org, project, id, signal));
 const summary = useConsoleRead<{ item: IssueListItem | undefined }>(`${key}|summary`, async (signal) => {
  const r = await listIssues({ org: context.org, projects: [project], query: id, limit: 5 }, {}, signal);
  return r.kind === 'ok' ? { kind: 'ok', data: { item: r.data.items.find((i) => i.issue_id === id && i.project_id === project) } } : r;
 });
 const queue = useEvidence<QueueView>(`${key}|queue`, (signal) => getQueue(context.org, [project], 100, signal));
 const [held, setHeld] = React.useState<Selection | null>(null);
 const view = dataOf(evidence.state);
 const item = summary.state.kind === 'ok' ? summary.state.data.item : undefined;
 const queueView = dataOf(queue.state);
 const incidents = queueView ? queueView.entries : null;
 const reload = (): void => { evidence.reload(); summary.reload(); queue.reload(); };
 const lineage = issueLineage({
  project, issue: id, workflow: view?.grouping?.workflow ?? item?.workflow, incidents,
  releases: view?.grouping?.observed_releases.length ? view.grouping.observed_releases : (item?.releases ?? []),
  links: { incident: (p, i) => href('incidents', { incident: { project: p, id: i } }), release: (r) => href('releases', { target: { project, id: r } }), service: (s) => href('services', { service: s }), rules: href('rules') },
 });
 const owner = ownerOfIssue(view, item);
 const [gitlabOpen, setGitlabOpen] = React.useState(false);
 const reloading = evidence.reloading || summary.reloading || queue.reloading;
 const actions = view ? (
  <IssueActions
   org={context.org} project={project} view={view} busy={reloading} names={names} owner={owner} incidents={incidents === null ? null : linkedIncidents(incidents, id)} onChanged={reload}
   extra={(
    <>
     {item?.gitlab
      ? <span className="row small" title="The linked GitLab issue. Its state lives in GitLab and is not read back."><Icon name="git" size="s" />GitLab <GitlabLink link={item.gitlab} /></span>
      : <button type="button" className="btn" data-testid="gitlab-create" onClick={() => setGitlabOpen(true)}><Icon name="git" size="s" />Create GitLab issue</button>}
     <CopyMenu entity="issue" org={context.org} project={project} id={id} />
     <ReloadIssueButton reloading={reloading} onReload={reload} />
    </>
   )}
  />
 ) : null;
 const state: LoadState<IssueEvidenceView> = evidence.state;
 return (
  <>
   <PageHead crumb={<><a href={href('issues')}>Issues</a><Icon name="right" size="xs" /><span>{projectLabel(names, project)}</span><Icon name="right" size="xs" /><span className="mono">{shortId(id)}</span></>} />
   <IssueHero id={id} context={context} view={view} summary={summary.state} lineage={lineage} actions={actions} />
   <Content>
    {state.kind !== 'ready' && <StatusPanel state={state} />}
    {incidents === null && queue.state.kind !== 'loading' && view && <Callout tone="unk" role="status" testId="issue-queue-unavailable">Which incidents link to this issue could not be read, so the lineage above does not claim any.</Callout>}
    {view && <IssueBody context={context} project={project} id={id} view={view} selected={selectedFor(held, key)} onSelect={(chosen) => setHeld({ key, id: chosen })} href={href} />}
    {view && <GitlabCreateDialog entity="issue" org={context.org} project={project} id={id} subject={item && item.titleState === 'ready' ? titleText(item) : `Issue ${shortId(id)}`} open={gitlabOpen} onClose={() => setGitlabOpen(false)} onLinked={reload} />}
    <Tools label="Tools: map frames, open another issue">
     <section className="card iss-framewrap" aria-labelledby="frames-card-heading">
      <div className="card-head"><h2 id="frames-card-heading">Map frames</h2></div>
      <div className="card-body"><FrameLookup context={context} project={project} /></div>
     </section>
     {props.footer}
    </Tools>
   </Content>
  </>
 );
}
