// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { DurationBounds, PathResult, SpanId, SpanReport } from '../api/types';
import { Card, Pill } from '../ui/primitives';
import { durationText } from './model';
import { MAX_WATERFALL_ROWS, waterfall, type WaterfallRow } from './waterfallModel';

const UNBOUNDED_NS = 1n << 62n;

/** A duration for a narrow cell: exact, an interval, a lower bound or "not measured". The sentence form lives in the critical path table. */
export function durationShort(b: DurationBounds): string {
 if (!b.known) return 'not measured';
 const lo = BigInt(b.min_ns), hi = BigInt(b.max_ns);
 if (hi >= UNBOUNDED_NS) return `at least ${durationText(lo)}`;
 return lo === hi ? durationText(lo) : `${durationText(lo)} to ${durationText(hi)}`;
}

const KIND_TONE: Record<string, string> = { server: 'c1', client: 'c2', internal: 'c3', consumer: 'c4', producer: 'c4' };
const toneOf = (s: SpanReport): string => (s.status === 'error' ? 'crit' : KIND_TONE[s.span_kind] ?? 'c5');

function Bar(props: { row: WaterfallRow }): React.JSX.Element {
 const { row: r } = props;
 const tone = toneOf(r.span);
 const w = Math.max(r.width, 0.4);
 return (
  <svg className="exp-wf-bar" viewBox="0 0 100 14" preserveAspectRatio="none" aria-hidden="true" focusable="false">
   {r.widthMax > r.width && <rect className={`exp-wf-more ch-f-${tone}`} x={r.left} y="3" width={r.widthMax} height="8" rx="1" />}
   {!r.measured
    ? <rect className="exp-wf-none" x={r.left} y="3" width="1.2" height="8" />
    : r.ambiguous
     ? <rect className="exp-wf-amb" x={r.left} y="3" width={w} height="8" rx="1" />
     : <rect className={`ch-f-${tone}`} x={r.left} y="3" width={w} height="8" rx="1" />}
   {r.onPath && r.measured && <rect className="exp-wf-cp" x={r.left} y="11.5" width={w} height="1.8" />}
  </svg>
 );
}

/** Every span read, under its parent, on one time axis. The bar is the shortest observed duration and a lighter extension reaches the longest it could be; a span with no measured duration has a mark and no bar. The waterfall only draws what the analysis found: it never says which work caused which. */
export function Waterfall(props: { path: PathResult; selectedSpan: SpanId | null; onSelect: (id: SpanId) => void }): React.JSX.Element {
 const w = React.useMemo(() => waterfall(props.path), [props.path]);
 return (
  <Card title="Span waterfall" titleId="wf-heading" bodyClass={false} testId="waterfall" footer={<span>{w.shown === w.total ? `${w.total} ${w.total === 1 ? 'span' : 'spans'}` : `${w.shown} of ${w.total} spans shown; the rest are not drawn`}{w.total > MAX_WATERFALL_ROWS ? ' (bounded)' : ''}. A bar under a span marks a critical path; a dashed outline marks an ambiguous branch.</span>}>
   <div className="table-region" tabIndex={0} role="region" aria-label="Spans on the time axis">
    <table className="table tight exp-wf">
     <caption className="sr-only">Every span read, under its parent, on one time axis from the earliest recorded start. The bar is the shortest observed duration; a lighter extension is the longest it could be. A span with no measured duration has a mark and no bar.</caption>
     <thead>
      <tr>
       <th scope="col">Span</th>
       <th scope="col"><span className="sr-only">Timeline</span><span className="exp-wf-ticks" aria-hidden="true">{w.ticks.map((t) => <span key={t.at}>{t.text}</span>)}</span></th>
       <th scope="col" className="right">Observed duration</th>
      </tr>
     </thead>
     <tbody>
      {w.rows.map((r) => {
       const selected = r.span.span_id === props.selectedSpan;
       return (
        <tr key={r.key} data-wf-span={r.span.span_id} className={selected ? 'selected' : undefined} onClick={() => props.onSelect(r.span.span_id)}>
         <th scope="row">
          <div className={`exp-wf-name exp-ind-${Math.min(r.depth, 8)}`}>
           <button type="button" className="btn btn-sm btn-ghost exp-wf-btn" aria-pressed={selected} aria-label={`Select span ${r.span.operation} (${r.span.span_kind}) in the waterfall`}>{r.span.operation}</button>
           <small className="t3">{r.span.span_kind}</small>
           {r.span.status === 'error' && <Pill tone="crit" icon="x">error</Pill>}
           {r.ambiguous && <Pill tone="high">ambiguous branch</Pill>}
           {r.detached !== null && <><Pill tone="unk">detached</Pill><small className="t3">{r.detached}</small></>}
          </div>
         </th>
         <td className="exp-wf-cell"><Bar row={r} /></td>
         <td className="right num">{durationShort(r.span.duration)}</td>
        </tr>
       );
      })}
     </tbody>
    </table>
   </div>
  </Card>
 );
}
