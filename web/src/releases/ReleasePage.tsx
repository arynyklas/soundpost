// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { getReleaseEvidence } from '../api/client';
import type { Id, ReleaseView } from '../api/types';
import { formatNs, scopeKey, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { EvidenceSections } from '../evidence/Sections';
import { orderWords, parseCompareIds } from '../evidence/model';
import { dataOf, useEvidence } from '../evidence/useEvidence';

/** One release: its immutable identity (build and debug artifacts), its label as a separate revisioned display value, its declared parents and the partial-order relation to the releases you name. Ancestry comes only from immutable parent edges: an unregistered parent or release is shown as unknown, never ordered by name, version string or time, and no regression is claimed here. */
export function ReleasePage(props: { id: Id; project: Id; context: ViewContext }): React.JSX.Element {
 const { context, project, id } = props;
 const [text, setText] = React.useState('');
 const [compare, setCompare] = React.useState<Id[]>([]);
 const [error, setError] = React.useState('');
 const key = `${scopeKey(context)}|${project}|${id}|${compare.join(',')}|${context.generation}`;
 const evidence = useEvidence<ReleaseView>(key, (signal) => getReleaseEvidence(context.org, project, id, compare, signal));
 const view = dataOf(evidence.state);
 const record = view?.release;
 const tz = context.timezone;
 return (
  <section className="panel" aria-labelledby="release-heading">
   <h2 id="release-heading">Release <code>{id}</code></h2>
   <form aria-label="Compare releases" onSubmit={(e) => {
    e.preventDefault();
    const parsed = parseCompareIds(text);
    if (!parsed.ok) return setError(parsed.error);
    setError('');
    setCompare(parsed.value);
   }}>
    <label>Compare with release IDs (comma separated, at most 16) <input name="compare" value={text} onChange={(e) => setText(e.target.value)} autoComplete="off" spellCheck={false} /></label>
    <button type="submit">Compare ancestry</button>
    {error && <p role="alert" className="error">{error}</p>}
   </form>
   <StatusPanel state={evidence.state} />
   {view && (
    <>
     <EvidenceSections sections={view.sections} />
     {record && (
      <section className="panel" aria-labelledby="rel-identity-heading" data-section="release-identity">
       <h3 id="rel-identity-heading">Identity</h3>
       <dl className="scope-bar">
        <dt>Build</dt><dd data-testid="release-build"><code>{record.build_id}</code></dd>
        <dt>Display label</dt><dd data-testid="release-label">{record.label} (label revision {record.revision}). The label is display text only: renaming it never changes the build or the debug artifacts below.</dd>
        <dt>Built at</dt><dd>{formatNs(record.build_time_ns, tz)}</dd>
       </dl>
       <h4>Debug artifacts</h4>
       {record.debug_artifacts.length === 0
        ? <p>No debug artifact is bound to this release, so no source map is selected for it.</p>
        : <ul data-testid="release-artifacts">{record.debug_artifacts.map((d) => <li key={d.artifact_id}>Artifact <code>{d.artifact_id}</code>, debug identity <code>{d.debug_id}</code>, hash <code>{d.sha256}</code></li>)}</ul>}
       <h4>Label history</h4>
       <ol aria-label="Label history">{record.label_history.map((h) => <li key={h.revision}>Revision {h.revision}: {h.label}</li>)}</ol>
      </section>
     )}
     {record && (
      <section className="panel" aria-labelledby="rel-ancestry-heading" data-section="release-ancestry">
       <h3 id="rel-ancestry-heading">Ancestry</h3>
       <p>Order here is a partial order from immutable parent edges. Two releases may be concurrent, and a missing edge leaves ancestry unknown.</p>
       <h4>Parents</h4>
       {view.parents.length === 0 ? <p>No parent is declared: this release is a root of its registered history.</p>
        : <ul data-testid="release-parents">{view.parents.map((p) => <li key={p.id} data-known={p.known ? 'yes' : 'no'}><code>{p.id}</code>: {p.known ? 'registered' : 'ancestry unknown (this parent was never registered, so what precedes it is not known)'}</li>)}</ul>}
       <h4>Registered children</h4>
       {view.children.length === 0 ? <p>No registered release lists this one as a parent.</p> : <ul>{view.children.map((c) => <li key={c}><code>{c}</code></li>)}</ul>}
       <h4>Comparisons</h4>
       {view.comparisons.length === 0 ? <p>No release was chosen to compare with.</p>
        : <ul data-testid="release-comparisons">{view.comparisons.map((c) => <li key={c.release} data-order={c.order}>Compared with <code>{c.release}</code>: {orderWords(c.order)}</li>)}</ul>}
      </section>
     )}
    </>
   )}
  </section>
 );
}
