// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { PathResult, SpanId, SpanReport, SpanTarget } from '../api/types';
import { basisWords, boundsText, detailsOf, flagWords, gapWords, limits, observedWords, offPath, rows, targetsOf } from './model';

const MAX_ROWS = 1000;
const MAX_OFF_PATH = 200;

const TARGET_WORDS: Record<SpanTarget['kind'], string> = { job: 'Job', replay: 'Replay', profile: 'Profile', error: 'Error occurrence' };
const TARGET_KINDS: readonly SpanTarget['kind'][] = ['job', 'replay', 'profile', 'error'];

/** One reference of the selected span, resolved by the server under this account's scope. An available one is an anchor (or, for an error occurrence, a statement) that opens the target, which checks the scope again;
 * an unavailable one is one sentence that does not say whether it is missing, elsewhere or not readable. */
function TargetItem(props: { target: SpanTarget; href: string | null }): React.JSX.Element {
 const { target, href } = props;
 const word = TARGET_WORDS[target.kind];
 if (!target.available) return <li data-target-kind={target.kind} data-target-available="no">{word} <code>{target.id}</code>: not available to this account.</li>;
 return (
  <li data-target-kind={target.kind} data-target-available="yes">
   {word} <code>{target.id}</code>: {href !== null ? <a href={href}>{target.kind === 'error' ? 'Open the issue holding this occurrence' : `Open this ${word.toLowerCase()}`}</a> : 'readable by this account; no issue holds it yet, so it has no view of its own.'} Access is checked again when it opens.
  </li>
 );
}

/** The critical path of one trace as the analysis found it: what lies on the path, the observed duration as bounds, and every limit in words. Every value from the trace is a text node; nothing here is markup. Colour never carries a state: each limit, ambiguity and gap is a sentence. */
export function CriticalPath(props: { path: PathResult; selectedSpan: SpanId | null; partial?: boolean; onSelect?: (id: SpanId) => void; exploreHref?: (span: SpanReport) => string; targets?: readonly SpanTarget[] | undefined; targetHref?: (target: SpanTarget) => string | null }): React.JSX.Element {
 const { path, selectedSpan } = props;
 const all = React.useMemo(() => rows(path), [path]);
 const shown = all.slice(0, MAX_ROWS);
 const off = React.useMemo(() => offPath(path), [path]);
 const lim = React.useMemo(() => limits(path, props.partial === true), [path, props.partial]);
 const details = detailsOf(path, selectedSpan);
 const selected = selectedSpan === null ? undefined : path.spans.find((s) => s.span_id === selectedSpan);
 const heading = React.useRef<HTMLHeadingElement>(null);
 React.useEffect(() => { if (selectedSpan !== null && details !== null) heading.current?.focus(); }, [selectedSpan]);
 return (
  <section className="panel" aria-labelledby="cp-heading" data-testid="critical-path">
   <h3 id="cp-heading">Critical path</h3>
   <p data-testid="observed-duration">{observedWords(path)}</p>
   <p data-testid="path-counts">{path.span_count} {path.span_count === 1 ? 'span was' : 'spans were'} read. {all.length} {all.length === 1 ? 'is' : 'are'} on a critical path; {off.length} {off.length === 1 ? 'is' : 'are'} off every path (parallel work, asynchronous work, orphans or excluded copies).</p>
   <section aria-labelledby="cp-limits-heading" data-testid="limits">
    <h4 id="cp-limits-heading">Limits of this analysis</h4>
    <ul>{lim.map((l) => <li key={l.code} data-limit={l.code}>{l.text}</li>)}</ul>
   </section>
   {path.producer_gaps.length > 0 && (
    <section aria-labelledby="cp-gaps-heading" data-testid="producer-gaps">
     <h4 id="cp-gaps-heading">Gaps reported by the producers of this trace</h4>
     <ul>{path.producer_gaps.map((g, i) => <li key={`${i}:${g.source}:${g.start_ns}`} data-gap-reason={g.reason}>{gapWords(g)}</li>)}</ul>
    </section>
   )}
   {path.late_spans.length > 0 && (
    <section aria-labelledby="cp-late-heading" data-testid="late-spans">
     <h4 id="cp-late-heading">Spans reported late</h4>
     <ul>{path.late_spans.map((l) => <li key={l.span_id} data-span={l.span_id}>{path.spans.find((s) => s.span_id === l.span_id)?.operation ?? l.span_id} ended at {l.ended_wall_ns} and was reported at {l.reported_wall_ns} (wall ns), {l.late_by_ns} ns later.</li>)}</ul>
    </section>
   )}
   {path.trees.map((t, treeIndex) => {
    const treeRows = shown.filter((r) => r.tree === treeIndex);
    return (
     <table key={`${treeIndex}:${t.root_span_id}`} className="data-table path-table" data-tree={treeIndex} data-orphan={t.orphan ? 'yes' : 'no'}>
      <caption>
       {t.orphan ? `Orphan tree ${treeIndex + 1}: its parent is missing or ambiguous, so it is not part of the root's duration.` : `Tree ${treeIndex + 1}: a span without a parent.`}{' '}
       Observed duration of this tree: {boundsText(t.duration)}. {basisWords(t.duration)}
      </caption>
      <thead><tr><th scope="col">Span</th><th scope="col">Level</th><th scope="col">Time on the path itself</th><th scope="col">Observed duration</th><th scope="col">Notes</th></tr></thead>
      <tbody>
       {treeRows.map((r) => {
        const isSelected = r.span.span_id === selectedSpan;
        return (
         <tr key={r.key} data-span={r.span.span_id} data-depth={r.segment.depth} data-ambiguous={r.segment.ambiguous ? 'yes' : 'no'} aria-selected={isSelected}>
          <th scope="row" className={`indent-${Math.min(r.segment.depth, 8)}`}>
           <button type="button" aria-pressed={isSelected} aria-label={`Show details of span ${r.span.operation}, ${r.span.span_kind}, level ${r.segment.depth + 1}`} onClick={() => props.onSelect?.(r.span.span_id)}>{r.span.operation}</button>{' '}
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
    );
   })}
   {all.length > shown.length && <p role="status">Showing the first {shown.length} of {all.length} path segments; the rest are not drawn.</p>}
   {off.length > 0 && (
    <section aria-labelledby="cp-off-heading" data-testid="off-path">
     <h4 id="cp-off-heading">Spans on no path</h4>
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
   <section aria-labelledby="cp-detail-heading" data-testid="span-details">
    <h4 id="cp-detail-heading" tabIndex={-1} ref={heading}>Selected span</h4>
    {details === null ? <p>No span is selected. Choose one on the path to see its recorded details.</p> : (
     <>
      <dl className="scope-bar">{details.map((d, i) => <React.Fragment key={`${i}:${d.label}`}><dt>{d.label}</dt><dd>{d.value}</dd></React.Fragment>)}</dl>
      <ul className="span-links">
       {selected && props.targets !== undefined && TARGET_KINDS.flatMap((kind) => targetsOf(props.targets, selected.span_id, kind)).map((t) => <TargetItem key={`${t.kind}:${t.id}`} target={t} href={props.targetHref?.(t) ?? null} />)}
       {selected && props.targets === undefined && selected.job_id && <li>Job <code>{selected.job_id}</code>: open Jobs for this ID; its access is checked there, not here.</li>}
       {selected && props.targets === undefined && selected.replay_id && <li>Replay <code>{selected.replay_id}</code>: open Replays for this ID; its access is checked there, not here.</li>}
       {selected && props.targets === undefined && selected.profile_id && <li>Profile <code>{selected.profile_id}</code>: open Profiles for this ID; its access is checked there, not here.</li>}
       {selected && props.exploreHref && <li><a href={props.exploreHref(selected)}>Explore metrics and logs in the window of this span</a></li>}
      </ul>
     </>
    )}
   </section>
  </section>
 );
}
