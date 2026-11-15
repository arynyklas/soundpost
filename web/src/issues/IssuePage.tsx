// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { getIssueEvidence } from '../api/client';
import type { Id, IssueEvidenceView, OccurrenceEvidence } from '../api/types';
import { FrameLookup } from '../artifacts/FrameLookup';
import { formatNs, scopeKey, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { EvidenceSections } from '../evidence/Sections';
import { occurrenceAncestryWords } from '../evidence/model';
import { dataOf, useEvidence } from '../evidence/useEvidence';
import { IssueActions } from './IssueActions';
import { OccurrenceDetail } from './OccurrenceDetail';
import { RegressionTable } from './RegressionTable';

function OccurrenceTable(props: { caption: string; rows: OccurrenceEvidence[]; tz: string; empty: string; selected: Id | null; onSelect: (id: Id) => void }): React.JSX.Element {
 const { rows } = props;
 if (rows.length === 0) return <p>{props.empty}</p>;
 return (
  <table className="data-table">
   <caption>{props.caption}</caption>
   <thead><tr><th scope="col">Occurrence</th><th scope="col">Event time</th><th scope="col">Arrived</th><th scope="col">Grouping</th><th scope="col">Release ancestry</th><th scope="col">Freshness</th><th scope="col">Stored record</th></tr></thead>
   <tbody>
    {rows.map((o) => (
     <tr key={o.occurrence_id} data-occurrence={o.occurrence_id} data-late={o.late ? 'yes' : 'no'} data-ancestry={o.ancestry} aria-selected={props.selected === o.occurrence_id}>
      <td><code>{o.occurrence_id}</code>{o.late ? <> <strong>(late)</strong></> : null}</td>
      <td>{formatNs(o.event_time_ns, props.tz)}</td>
      <td>{formatNs(o.arrival_time_ns, props.tz)}</td>
      <td>version {o.grouping_version}, hash <code>{o.fingerprint}</code></td>
      <td>{occurrenceAncestryWords(o)}</td>
      <td>{o.freshness}</td>
      <td><button type="button" onClick={() => props.onSelect(o.occurrence_id)} aria-pressed={props.selected === o.occurrence_id} aria-label={`Show stored detail of occurrence ${o.occurrence_id}`}>Show stored detail</button></td>
     </tr>
    ))}
   </tbody>
  </table>
 );
}

/** Persisted evidence for one issue: the grouping version and hash, every stored occurrence, the late history listed apart, release ancestry stated as known or unknown, and, on request, the stored error record behind one occurrence (class, mechanism, handled, fatal, code, exception chain, frames mapped through the real source map, links to the release and trace it names). A regression is never computed or guessed here. */
export function IssuePage(props: { id: Id; project: Id; context: ViewContext }): React.JSX.Element {
 const { context, project, id } = props;
 const key = `${scopeKey(context)}|${project}|${id}|${context.generation}`;
 const evidence = useEvidence<IssueEvidenceView>(key, (signal) => getIssueEvidence(context.org, project, id, signal));
 const [selected, setSelected] = React.useState<Id | null>(null);
 React.useEffect(() => { setSelected(null); }, [key]);
 const view = dataOf(evidence.state);
 const tz = context.timezone;
 const chosen = view && selected ? [...view.occurrences, ...view.late_history].find((o) => o.occurrence_id === selected) : undefined;
 return (
  <section className="panel" aria-labelledby="issue-heading">
   <h2 id="issue-heading">Issue <code>{id}</code></h2>
   <StatusPanel state={evidence.state} />
   {view && (
    <>
     <button type="button" onClick={evidence.reload} disabled={evidence.reloading}>Reload issue</button>
     <EvidenceSections sections={view.sections} />
     {view.grouping && (
      <section className="panel" aria-labelledby="grouping-heading" data-section="grouping">
       <h3 id="grouping-heading">Grouping</h3>
       <dl className="scope-bar">
        <dt>Grouping version</dt><dd data-testid="grouping-version">{view.grouping.grouping_version}</dd>
        <dt>Grouping hash</dt><dd data-testid="grouping-hash"><code>{view.grouping.fingerprint}</code></dd>
        <dt>Workflow state</dt><dd data-testid="workflow">{view.grouping.workflow} (revision {view.grouping.revision})</dd>
        {view.grouping.resolution_time_ns !== undefined && <><dt>Resolved at</dt><dd>{formatNs(view.grouping.resolution_time_ns, tz)}</dd></>}
        <dt>Audited grouping migrations</dt><dd data-testid="migrations">{view.grouping.migration_links.length === 0 ? 'None recorded' : view.grouping.migration_links.map((m) => <code key={m}>{m} </code>)}</dd>
       </dl>
      </section>
     )}
     <section className="panel" aria-labelledby="occ-heading" data-section="occurrences">
      <h3 id="occ-heading">Occurrences</h3>
      <OccurrenceTable caption="Stored occurrences" rows={view.occurrences} tz={tz} empty="No occurrence evidence is stored for this issue." selected={selected} onSelect={setSelected} />
      <h4>Late history</h4>
      <p>Evidence that arrived after the issue was resolved is listed here, apart from the occurrences above. It is never merged into them and never rewrites the resolution.</p>
      <OccurrenceTable caption="Late history" rows={view.late_history} tz={tz} empty="No late evidence is recorded." selected={selected} onSelect={setSelected} />
     </section>
     <section className="panel" aria-labelledby="regression-heading" data-section="regression-explanations">
      <h3 id="regression-heading">Regression</h3>
      <p data-testid="regression-note">A regression is decided from the issue's stored resolution boundary or fix frontier and the registered release graph, and recorded as an explanation when evidence arrives after the resolution. It is never inferred from timestamps or release labels, and an occurrence with unknown ancestry stays unknown.</p>
      {view.regression === undefined
       ? <p data-testid="regression-unavailable">The stored explanations are not available here, so no regression is claimed.</p>
       : view.regression.explanations.length === 0
        ? <p data-testid="regression-none">No regression has been evaluated for this issue: no occurrence has arrived after a resolution. That is not a statement that none can happen.</p>
        : <RegressionTable context={context} project={project} rows={view.regression.explanations} caption="Stored regression evaluations, oldest first" byRelease={false} />}
     </section>
     {chosen && <OccurrenceDetail key={chosen.occurrence_id} context={context} project={project} issue={id} occurrence={chosen} />}
     <IssueActions org={context.org} project={project} view={view} busy={evidence.reloading} onChanged={evidence.reload} />
    </>
   )}
   <FrameLookup context={context} project={project} />
  </section>
 );
}
