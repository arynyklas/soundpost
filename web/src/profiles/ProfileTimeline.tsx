// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { durationText } from '../traces/model';
import { correlationWords, flame, frameList, groupDigits, timeline, type Present, type Weights } from './model';
import type { Correlation, ProfileView } from './types';

const MAX_FRAME_ROWS = 200;
const MAX_FLAME_ROWS = 500;
const MAX_TIMELINE_ROWS = 500;

function weightHeads(view: ProfileView, p: Present): { key: keyof Weights; label: string }[] {
 const heads: { key: keyof Weights; label: string }[] = [];
 if (p.samples) heads.push({ key: 'samples', label: view.method === 'runtime_cpu' ? `Engine-reported ${view.units}` : 'OS on-CPU samples' });
 if (p.blocked) heads.push({ key: 'blocked', label: 'Blocked time' });
 if (p.runnable) heads.push({ key: 'runnable', label: 'Runnable delay' });
 if (p.unknown) heads.push({ key: 'unknown', label: 'Off-CPU time, unknown split' });
 return heads;
}
function weightText(view: ProfileView, key: keyof Weights, w: Weights): string {
 const n = w[key];
 if (key !== 'samples') return durationText(n);
 return view.method === 'runtime_cpu' && view.units === 'nanoseconds' ? `${groupDigits(n)} ns` : groupDigits(n);
}

/** The frames, stacks and timeline of one profile. Every value from the profile is a text node. Weights of different kinds are separate columns and are never added. Lost time is a gap or a loss row; nothing is interpolated. */
export function ProfileTimeline(props: { view: ProfileView; correlation: Correlation }): React.JSX.Element {
 const { view, correlation } = props;
 const frames = React.useMemo(() => frameList(view, MAX_FRAME_ROWS), [view]);
 const tree = React.useMemo(() => flame(view, MAX_FLAME_ROWS), [view]);
 const tl = React.useMemo(() => timeline(view, MAX_TIMELINE_ROWS), [view]);
 const heads = weightHeads(view, frames.present);
 const none = view.samples.length + view.intervals.length === 0;
 return (
  <section className="panel profile-timeline" aria-labelledby="pt-heading" data-testid="profile-timeline">
   <h3 id="pt-heading">Frames, stacks and timeline</h3>
   <section aria-labelledby="pc-heading" data-testid="profile-correlation" data-correlation={correlation.kind}>
    <h4 id="pc-heading">Link to a request</h4>
    <p>{correlationWords(correlation)}</p>
    <p>Only an explicit link attributes a profile to a request. Work that overlaps in time on a thread is shown as overlap only and is not counted against any request.</p>
   </section>
   {none && <p role="status" data-testid="profile-no-observations">no observations: no sample or interval of this profile falls in the selected window. This is not zero, and no chart is drawn for it.</p>}
   {!none && (
    <>
     <section aria-labelledby="pf-heading" data-testid="frame-list">
      <h4 id="pf-heading">Frames</h4>
      <table className="data-table profile-table">
       <caption>Each frame with the weight of the observations whose stack contains it, counted once per stack, heaviest first. Weights of different kinds are separate columns and are never added.</caption>
       <thead><tr><th scope="col">Frame</th><th scope="col">Distinct stacks</th>{heads.map((h) => <th scope="col" key={h.key}>{h.label}</th>)}</tr></thead>
       <tbody>
        {frames.rows.map((r) => (
         <tr key={r.key} data-unresolved={r.text.startsWith('unresolved frame') ? 'yes' : 'no'}>
          <th scope="row">{r.text}</th>
          <td>{r.stacks}</td>
          {heads.map((h) => <td key={h.key}>{r.w[h.key] === 0n ? 'none' : weightText(view, h.key, r.w)}</td>)}
         </tr>
        ))}
       </tbody>
      </table>
      {frames.total > frames.rows.length && <p role="status">Showing the first {frames.rows.length} of {frames.total} frames; the rest are not drawn.</p>}
     </section>
     <section aria-labelledby="ps-heading" data-testid="stack-tree">
      <h4 id="ps-heading">Stacks</h4>
      <table className="data-table profile-table">
       <caption>Stacks nested in the order they were recorded: the first recorded frame is the top level. The profile does not say whether that is the outermost or the innermost frame. A line with no weight in a column has no observation of that kind.</caption>
       <thead><tr><th scope="col">Frame</th>{heads.map((h) => <th scope="col" key={h.key}>{h.label}</th>)}</tr></thead>
       <tbody>
        {tree.rows.map((r) => (
         <tr key={r.key} data-depth={r.depth}>
          <th scope="row" className={`indent-${Math.min(r.depth, 8)}`}>{r.text}</th>
          {heads.map((h) => <td key={h.key}>{r.w[h.key] === 0n ? 'none' : weightText(view, h.key, r.w)}</td>)}
         </tr>
        ))}
       </tbody>
      </table>
      {tree.total > tree.rows.length && <p role="status">Showing the first {tree.rows.length} of {tree.total} stack lines; the rest are not drawn.</p>}
     </section>
    </>
   )}
   <section aria-labelledby="pl-heading" data-testid="timeline-rows">
    <h4 id="pl-heading">Timeline</h4>
    <p>
     {tl.counts.sample} {tl.counts.sample === 1 ? 'sample' : 'samples'}, {tl.counts.blocked} blocked, {tl.counts.runnable} runnable, {tl.counts.unknown_offcpu} off-CPU with an unknown split,{' '}
     {tl.counts.loss} {tl.counts.loss === 1 ? 'loss record' : 'loss records'} and {tl.counts.gap} {tl.counts.gap === 1 ? 'gap' : 'gaps'}. Times are offsets from the earliest observation, on the monotonic clock of this profile.
    </p>
    {tl.rows.length === 0 ? <p>Nothing was recorded, so there is no timeline. Nothing is drawn for time without a record.</p> : (
     <table className="data-table profile-table">
      <caption>Observations in time order. A gap row states that nothing was recorded for that time; gaps are never filled and no stack is invented for lost time.</caption>
      <thead><tr><th scope="col">Time</th><th scope="col">Observation</th><th scope="col">Thread</th><th scope="col">Quantity</th><th scope="col">Stack (first recorded frame)</th><th scope="col">Notes</th></tr></thead>
      <tbody>
       {tl.rows.map((r) => (
        <tr key={r.key} data-kind={r.kind} data-gap={r.kind === 'gap' ? 'yes' : undefined}>
         <th scope="row">{r.offset}</th>
         <td>{r.label}</td>
         <td>{r.thread}</td>
         <td>{r.quantity}</td>
         <td>{r.stack}</td>
         <td>{r.notes.length === 0 ? 'no note' : r.notes.join('; ')}</td>
        </tr>
       ))}
      </tbody>
     </table>
    )}
    {tl.total > tl.rows.length && <p role="status">Showing the first {tl.rows.length} of {tl.total} timeline rows; the rest are not drawn.</p>}
    {view.next_cursor !== undefined && <p role="status">More observations exist beyond this page of the profile. They are not shown here and are not estimated.</p>}
   </section>
  </section>
 );
}
