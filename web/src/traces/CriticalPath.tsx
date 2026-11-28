// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { PathResult, SpanId } from '../api/types';
import { Card } from '../ui/primitives';
import { basisWords, boundsText, flagWords, gapWords, limits, observedWords, offPath, rows } from './model';

const MAX_ROWS = 1000;
const MAX_OFF_PATH = 200;

/** The critical path of one trace as the analysis found it: what lies on the path, the observed duration as bounds, and every limit in words. Every value from the trace is a text node; nothing here is markup. Colour never carries a state: each limit, ambiguity and gap is a sentence. */
export function CriticalPath(props: { path: PathResult; selectedSpan: SpanId | null; partial?: boolean; onSelect?: (id: SpanId) => void }): React.JSX.Element {
 const { path, selectedSpan } = props;
 const all = React.useMemo(() => rows(path), [path]);
 const shown = all.slice(0, MAX_ROWS);
 const off = React.useMemo(() => offPath(path), [path]);
 const lim = React.useMemo(() => limits(path, props.partial === true), [path, props.partial]);
 return (
  <Card title="Critical path" titleId="cp-heading" testId="critical-path" bodyClass="col g16">
   <p data-testid="observed-duration">{observedWords(path)}</p>
   <p data-testid="path-counts" className="small t2">{path.span_count} {path.span_count === 1 ? 'span was' : 'spans were'} read. {all.length} {all.length === 1 ? 'is' : 'are'} on a critical path; {off.length} {off.length === 1 ? 'is' : 'are'} off every path (parallel work, asynchronous work, orphans or excluded copies).</p>
   <section aria-labelledby="cp-limits-heading" data-testid="limits" className="exp-limits">
    <h3 id="cp-limits-heading">Limits of this analysis</h3>
    <ul>{lim.map((l) => <li key={l.code} data-limit={l.code}>{l.text}</li>)}</ul>
   </section>
   {path.producer_gaps.length > 0 && (
    <section aria-labelledby="cp-gaps-heading" data-testid="producer-gaps">
     <h3 id="cp-gaps-heading">Gaps reported by the producers of this trace</h3>
     <ul>{path.producer_gaps.map((g, i) => <li key={`${i}:${g.source}:${g.start_ns}`} data-gap-reason={g.reason}>{gapWords(g)}</li>)}</ul>
    </section>
   )}
   {path.late_spans.length > 0 && (
    <section aria-labelledby="cp-late-heading" data-testid="late-spans">
     <h3 id="cp-late-heading">Spans reported late</h3>
     <ul>{path.late_spans.map((l) => <li key={l.span_id} data-span={l.span_id}>{path.spans.find((s) => s.span_id === l.span_id)?.operation ?? l.span_id} ended at {l.ended_wall_ns} and was reported at {l.reported_wall_ns} (wall ns), {l.late_by_ns} ns later.</li>)}</ul>
    </section>
   )}
   {path.trees.map((t, treeIndex) => {
    const treeRows = shown.filter((r) => r.tree === treeIndex);
    return (
     <div key={`${treeIndex}:${t.root_span_id}`} className="table-region" tabIndex={0} role="region" aria-label={`Critical path of tree ${treeIndex + 1}`}>
      <table className="table tight path-table" data-tree={treeIndex} data-orphan={t.orphan ? 'yes' : 'no'}>
       <caption>
        {t.orphan ? `Orphan tree ${treeIndex + 1}: its parent is missing or ambiguous, so it is not part of the root's duration.` : `Tree ${treeIndex + 1}: a span without a parent.`}{' '}
        Observed duration of this tree: {boundsText(t.duration)}. {basisWords(t.duration)}
       </caption>
       <thead><tr><th scope="col">Span</th><th scope="col">Level</th><th scope="col">Time on the path itself</th><th scope="col">Observed duration</th><th scope="col">Notes</th></tr></thead>
       <tbody>
        {treeRows.map((r) => {
         const isSelected = r.span.span_id === selectedSpan;
         return (
          <tr key={r.key} data-span={r.span.span_id} data-depth={r.segment.depth} data-ambiguous={r.segment.ambiguous ? 'yes' : 'no'} aria-selected={isSelected} className={isSelected ? 'selected' : undefined}>
           <th scope="row" className={`exp-ind-${Math.min(r.segment.depth, 8)}`}>
            <button type="button" className="btn btn-sm exp-path-btn" aria-pressed={isSelected} aria-label={`Show details of span ${r.span.operation}, ${r.span.span_kind}, level ${r.segment.depth + 1}`} onClick={() => props.onSelect?.(r.span.span_id)}>{r.span.operation}</button>{' '}
            <small>({r.span.span_kind})</small>
           </th>
           <td>Level {r.segment.depth + 1}</td>
           <td>{r.selfText}</td>
           <td>{r.durationText}</td>
           <td>{r.notes.length === 0 ? 'No limit reported for this span.' : r.notes.join('; ')}</td>
          </tr>
         );
        })}
       </tbody>
      </table>
     </div>
    );
   })}
   {all.length > shown.length && <p role="status">Showing the first {shown.length} of {all.length} path segments; the rest are not drawn.</p>}
   {off.length > 0 && (
    <section aria-labelledby="cp-off-heading" data-testid="off-path">
     <h3 id="cp-off-heading">Spans on no path</h3>
     <ul>
      {off.slice(0, MAX_OFF_PATH).map((s, i) => (
       <li key={`${i}:${s.span_id}`} data-span={s.span_id}>
        {s.operation} ({s.span_kind}): {boundsText(s.duration)}{s.flags.length > 0 ? `; ${s.flags.map(flagWords).join('; ')}` : '; ran in parallel with, or could not be ordered against, work on the path'}
       </li>
      ))}
     </ul>
     {off.length > MAX_OFF_PATH && <p role="status">{off.length - MAX_OFF_PATH} more spans on no path are not listed.</p>}
    </section>
   )}
  </Card>
 );
}
