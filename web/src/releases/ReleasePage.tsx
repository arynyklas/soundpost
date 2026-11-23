// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { getQueue, getReleaseEvidence } from '../api/client';
import { listDeploys, listIssues, listReleases, type DeployRecord, type IssueListItem, type ReleaseListItem } from '../api/console';
import type { Id, QueueView, ReleaseView } from '../api/types';
import { useConsoleRead, type ConsoleState } from '../api/useConsoleRead';
import { formatNs, scopeKey, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { EvidenceSections } from '../evidence/Sections';
import { orderWords, parseCompareIds } from '../evidence/model';
import { dataOf, useEvidence } from '../evidence/useEvidence';
import { IssueTable } from '../issues/IssuesList';
import { RegressionTable } from '../issues/RegressionTable';
import { Section } from '../issues/Section';
import { Content, Explain, Hero, PageHead, Tools } from '../shell/Frames';
import { projectLabel, type Names, type ShellApi } from '../shell/ShellContext';
import { Icon } from '../ui/Icon';
import { IdCode, Lineage, NotAvailable, shortId } from '../ui/primitives';
import { builtText, countCell, deployRecordLines, regressionIssues, releaseLineage } from './model';

type Href = ShellApi['href'];
type Deploys = ConsoleState<DeployRecord[]>;

function DeploySummary(props: { deploys: Deploys; timezone: string }): React.JSX.Element {
 const d = props.deploys;
 if (d.kind === 'loading') return <span className="t3">Reading deploy times…</span>;
 if (d.kind === 'not_built') return <span className="t3" data-testid="release-deploy-unavailable">Deploy times are not available yet on this installation.</span>;
 if (d.kind === 'fault') return <span className="t3" data-testid="release-deploy-unavailable">Deploy times could not be read.</span>;
 const lines = deployRecordLines(d.data, props.timezone);
 return <span data-testid="release-deploy-summary" data-deploy={d.data.length === 0 ? 'unknown' : 'known'}>{d.data.length === 0 ? 'deploy time unknown' : `deployed: ${lines[0]?.text.replace(/^Environment /, 'environment ') ?? ''}`}</span>;
}

/** One release: its immutable identity (build and debug artifacts), its label as a separate revisioned display value, when it was deployed (the recorded marker only), its declared parents and the partial-order relation to the releases you name. Ancestry comes only from immutable parent edges: an unregistered parent or release is shown as unknown, never ordered by name, version string or time. A regression appears only as the stored evaluation of an occurrence that ran in this release; none is inferred. */
export function ReleasePage(props: { id: Id; project: Id; context: ViewContext; names: Names; href: Href; footer?: React.ReactNode }): React.JSX.Element {
 const { context, project, id, names, href } = props;
 const [text, setText] = React.useState('');
 const [compare, setCompare] = React.useState<Id[]>([]);
 const [error, setError] = React.useState('');
 const key = `${scopeKey(context)}|${project}|${id}|${compare.join(',')}|${context.generation}`;
 const base = `${scopeKey(context)}|${project}|${id}|${context.generation}`;
 const evidence = useEvidence<ReleaseView>(key, (signal) => getReleaseEvidence(context.org, project, id, compare, signal));
 const deploys = useConsoleRead<DeployRecord[]>(`${base}|deploys`, (signal) => listDeploys(context.org, [project], id, signal));
 const summary = useConsoleRead<{ item: ReleaseListItem | undefined }>(`${base}|summary`, async (signal) => {
  const r = await listReleases({ org: context.org, projects: [project], query: id, limit: 5 }, {}, signal);
  return r.kind === 'ok' ? { kind: 'ok', data: { item: r.data.items.find((i) => i.release_id === id && i.project_id === project) } } : r;
 });
 const issues = useConsoleRead<IssueListItem[]>(`${base}|issues`, async (signal) => {
  const r = await listIssues({ org: context.org, projects: [project], limit: 25 }, { release: id }, signal);
  return r.kind === 'ok' ? { kind: 'ok', data: r.data.items } : r;
 });
 const queue = useEvidence<QueueView>(`${base}|queue`, (signal) => getQueue(context.org, [project], 100, signal));
 const view = dataOf(evidence.state);
 const record = view?.release;
 const tz = context.timezone;
 const item = summary.state.kind === 'ok' ? summary.state.data.item : undefined;
 const queueView = dataOf(queue.state);
 const lineage = releaseLineage({
  release: id, incidents: queueView ? queueView.entries : null, issues: regressionIssues(view),
  links: { incident: (p, i) => href('incidents', { incident: { project: p, id: i } }), issue: (i) => href('issues', { target: { project, id: i } }), service: (s) => href('services', { service: s }), rules: href('rules') },
 });
 const counts = item ? [['New issues', item.newIssues], ['Regressed', item.regressedIssues], ['Resolved here', item.resolvedIssues]] as const : [];
 return (
  <>
   <PageHead crumb={<><a href={href('releases')}>Releases</a><Icon name="right" size="xs" /><span>{projectLabel(names, project)}</span><Icon name="right" size="xs" /><span className="mono">{shortId(id)}</span></>} />
   <Hero>
    <div className="row top g12 wrap">
     <div className="col g4 grow">
      <h1 tabIndex={-1} data-release={id}>{record ? record.label : 'Release'}</h1>
      <div className="row wrap small t2 g12">
       <span className="mono" title={id}>release {id.slice(0, 4)}…{id.slice(-4)}</span>
       <span>{projectLabel(names, project)}</span>
       <DeploySummary deploys={deploys.state} timezone={tz} />
       {record && <span>build <code title={record.build_id}>{shortId(record.build_id)}</code></span>}
       {view && view.parents.length > 0 && <span className="row wrap g4">parent{view.parents.length === 1 ? '' : 's'} {view.parents.map((p) => p.known ? <a key={p.id} className="pill pill-line mono" href={href('releases', { target: { project, id: p.id } })}>{shortId(p.id)}</a> : <span key={p.id} className="pill pill-unk mono">{shortId(p.id)} · not registered</span>)}</span>}
      </div>
     </div>
     <div className="kpis" role="group" aria-label="Issue counts of this release">
      {counts.map(([label, value]) => { const c = countCell(value, item?.countsIncomplete === true); return <div key={label} className="kpi"><span className="label">{label}</span>{c.known ? <span className="value num">{c.text}</span> : <span className="small t3">{c.text}</span>}</div>; })}
     </div>
    </div>
    {summary.state.kind !== 'ok' && summary.state.kind !== 'loading' && <p className="small t3" data-testid="release-counts-unavailable">New, regressed and resolved counts are not available {summary.state.kind === 'not_built' ? 'yet on this installation' : 'from the release list'}.</p>}
    <Lineage items={lineage} />
   </Hero>
   <Content>
    {evidence.state.kind !== 'ready' && <StatusPanel state={evidence.state} />}
    {view && (
     <div className="grid-side">
      <div className="col g16">
       <Section id="rel-issues-heading" section="release-issues" title="Error issues that ran in this release">
        {issues.state.kind === 'loading' && <p className="t3">Reading the issues of this release…</p>}
        {issues.state.kind === 'not_built' && <NotAvailable title="The issue list is not available yet" testId="release-issues-unavailable">This installation does not serve the issue list yet, so the issues of this release are not listed here. The stored regression evaluations below are real.</NotAvailable>}
        {issues.state.kind === 'fault' && <StatusPanel state={issues.state.state} />}
        {issues.state.kind === 'ok' && (issues.state.data.length === 0
         ? <p data-testid="release-issues-none">No issue names this release among the releases its occurrences ran in.</p>
         : <IssueTable items={issues.state.data} context={context} names={names} href={href} />)}
       </Section>
       {record && (
        <Section id="rel-regression-heading" section="release-regressions" title="Regression evaluations that ran in this release">
         <Explain line="The regression evaluations stored for occurrences that ran in this release.">These are the evaluations the issue lifecycle stored for occurrences that ran in this release, with the issue each belongs to. A regression is never inferred here from the release&apos;s label, order or time, and a release with no stored evaluation is not thereby shown to be free of regressions.</Explain>
         {view.sections.find((s) => s.name === 'regression')?.state === 'not_available'
          ? <p data-testid="release-regressions-unavailable">The stored explanations are not available here, so no regression is claimed for this release.</p>
          : view.regressions.length === 0
           ? <p data-testid="release-regressions-none">No stored regression evaluation names an occurrence that ran in this release.</p>
           : <RegressionTable context={context} project={project} rows={view.regressions} caption="Stored regression evaluations of occurrences that ran in this release" byRelease />}
        </Section>
       )}
       {record && (
        <Section id="rel-ancestry-heading" section="release-ancestry" title="Ancestry">
         <p>Order here is a partial order from immutable parent edges. Two releases may be concurrent, and a missing edge leaves ancestry unknown.</p>
         <h3 className="iss-sub">Parents</h3>
         {view.parents.length === 0 ? <p>No parent is declared: this release is a root of its registered history.</p>
          : <ul data-testid="release-parents">{view.parents.map((p) => <li key={p.id} data-known={p.known ? 'yes' : 'no'}><IdCode value={p.id} />: {p.known ? 'registered' : 'ancestry unknown (this parent was never registered, so what precedes it is not known)'}</li>)}</ul>}
         <h3 className="iss-sub">Registered children</h3>
         {view.children.length === 0 ? <p>No registered release lists this one as a parent.</p> : <ul>{view.children.map((c) => <li key={c}><IdCode value={c} /></li>)}</ul>}
         <h3 className="iss-sub">Comparisons</h3>
         <Tools label="Compare with other releases">
          <form aria-label="Compare releases" onSubmit={(e) => {
           e.preventDefault();
           const parsed = parseCompareIds(text);
           if (!parsed.ok) return setError(parsed.error);
           setError('');
           setCompare(parsed.value);
          }}>
           <label>Compare with release IDs (comma separated, at most 16) <input name="compare" value={text} onChange={(e) => setText(e.target.value)} autoComplete="off" spellCheck={false} /></label>
           <button type="submit" className="btn">Compare ancestry</button>
           {error && <p role="alert" className="error">{error}</p>}
          </form>
         </Tools>
         {view.comparisons.length === 0 ? <p>No release was chosen to compare with.</p>
          : <ul data-testid="release-comparisons">{view.comparisons.map((c) => <li key={c.release} data-order={c.order}>Compared with <IdCode value={c.release} />: {orderWords(c.order)}</li>)}</ul>}
        </Section>
       )}
      </div>
      <aside className="col g16" aria-label="Identity, deploys and the parts of this view">
       {record && (
        <Section id="rel-identity-heading" section="release-identity" title="Identity">
         <dl className="iss-facts">
          <dt>Build</dt><dd data-testid="release-build"><IdCode value={record.build_id} copy="Copy build ID" /></dd>
          <dt>Display label</dt><dd data-testid="release-label">{record.label} (label revision {record.revision}). The label is display text only: renaming it never changes the build or the debug artifacts below.</dd>
          <dt>Built at</dt><dd>{formatNs(record.build_time_ns, tz)}</dd>
         </dl>
         <h3 className="iss-sub">Debug artifacts</h3>
         {record.debug_artifacts.length === 0
          ? <p>No debug artifact is bound to this release, so no source map is selected for it.</p>
          : <ul data-testid="release-artifacts">{record.debug_artifacts.map((d) => <li key={d.artifact_id}>Artifact <IdCode value={d.artifact_id} copy="Copy artifact ID" />, debug identity <IdCode value={d.debug_id} copy="Copy debug identity" />, hash <IdCode value={d.sha256} copy="Copy artifact hash" /></li>)}</ul>}
         <h3 className="iss-sub">Label history</h3>
         <ol aria-label="Label history">{record.label_history.map((h) => <li key={h.revision}>Revision {h.revision}: {h.label}</li>)}</ol>
        </Section>
       )}
       <Section id="rel-deploy-heading" section="release-deploys" title="Deploys">
        {deploys.state.kind === 'loading' && <p className="t3">Reading deploy times…</p>}
        {deploys.state.kind === 'not_built' && <p data-testid="release-deploys-unavailable">Deploy times are not available yet on this installation. The build time is not shown in their place.</p>}
        {deploys.state.kind === 'fault' && <StatusPanel state={deploys.state.state} />}
        {deploys.state.kind === 'ok' && <ul data-testid="release-deploy-list" data-deploy={deploys.state.data.length === 0 ? 'unknown' : 'known'}>{deployRecordLines(deploys.state.data, tz).map((l) => <li key={l.key}>{l.text}</li>)}</ul>}
        {record && <p className="small t3">{builtText(record.build_time_ns, tz)}</p>}
       </Section>
       <Section id="rel-parts-heading" section="parts" title="Parts of this view"><EvidenceSections sections={view.sections} /></Section>
      </aside>
     </div>
    )}
    {props.footer !== undefined && <Tools label="Tools: open another release">{props.footer}</Tools>}
   </Content>
  </>
 );
}
