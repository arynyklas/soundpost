// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { EvaluationWire, Label, NativeHistogram, ProjectResult, Sample, Series, VectorElement } from '../api/types';
import { histogramView, labelsText, nsToIso, planSeries, sampleText, type FloatKind, type Gap, type SeriesPlan } from './model';

const PAGE = 200;
const MAX_SERIES = 50;
const NOTE: Record<Exclude<FloatKind, 'finite'>, string> = {
 nan: 'not a number: a real value, not a missing one',
 pos_inf: 'positive infinity',
 neg_inf: 'negative infinity',
 stale: 'a stale marker: the absence of a sample, not a value',
};

/** A nanosecond instant, exact: the canonical decimal string is shown next to its UTC form, never rounded. */
export function TimeText(props: { ns: string }): React.JSX.Element {
 return <span className="time"><code>{props.ns}</code> <small>{nsToIso(props.ns)}</small></span>;
}

export function LabelText(props: { labels: Label[] }): React.JSX.Element {
 return <code className="labels">{labelsText(props.labels)}</code>;
}

function Histogram(props: { h: NativeHistogram }): React.JSX.Element {
 const v = histogramView(props.h);
 const [shown, setShown] = React.useState(PAGE);
 const table = (name: string, buckets: { index: number; count: string }[]): React.JSX.Element | null => buckets.length === 0 ? null : (
  <table className="data-table">
   <caption>{name} buckets (index of the bucket, count)</caption>
   <thead><tr><th scope="col">Bucket index</th><th scope="col">Count</th></tr></thead>
   <tbody>{buckets.slice(0, shown).map((b) => <tr key={b.index}><td><code>{b.index}</code></td><td><code>{b.count}</code></td></tr>)}</tbody>
  </table>
 );
 const total = v.positive.length + v.negative.length;
 return (
  <details className="histogram" data-kind="histogram">
   <summary>Native histogram ({v.variant} variant): count {v.count}, sum {v.sum.text}, schema {v.schema}</summary>
   <dl>
    <dt>Zero bucket</dt><dd>count {v.zeroCount}, threshold {v.zeroThreshold.text}</dd>
    <dt>Flavor</dt><dd>{v.flavor}, reset hint {v.resetHint}</dd>
    {v.customBounds.length > 0 && <><dt>Custom bounds</dt><dd>{v.customBounds.map((b) => b.text).join(', ')}</dd></>}
   </dl>
   {table('Positive', v.positive)}
   {table('Negative', v.negative)}
   {total > shown && <button type="button" onClick={() => setShown(shown + PAGE)}>Show more buckets ({Math.min(shown, Math.max(v.positive.length, v.negative.length))} shown of {Math.max(v.positive.length, v.negative.length)})</button>}
   {total === 0 && <p>This histogram has no non-zero buckets.</p>}
  </details>
 );
}

/** One sample's value in words: a number, NaN, an infinity, a stale marker or a native histogram. The IEEE bits are shown for anything that is not a plain number. */
export function SampleValue(props: { sample: Sample }): React.JSX.Element {
 const s = props.sample;
 if (s.histogram !== undefined) return <Histogram h={s.histogram} />;
 const t = sampleText(s);
 const bits = s.float ?? '';
 return (
  <span className={`value value-${t.kind}`} data-kind={t.kind} data-bits={bits} title={`IEEE-754 bits ${bits}`}>
   {t.text}
   {t.kind !== 'finite' && t.kind !== 'histogram' && <small> ({NOTE[t.kind]}; bits <code>{bits}</code>)</small>}
  </span>
 );
}

function VectorTable(props: { vector: VectorElement[] }): React.JSX.Element {
 const [shown, setShown] = React.useState(PAGE);
 if (props.vector.length === 0) return <p data-result="vector-empty">The query matched no series. Nothing is missing.</p>;
 return (
  <>
   <table className="data-table" data-result="vector">
    <caption>Instant vector: one row per series ({props.vector.length} series)</caption>
    <thead><tr><th scope="col">Series</th><th scope="col">Value</th><th scope="col">Sample time (nanoseconds)</th></tr></thead>
    <tbody>
     {props.vector.slice(0, shown).map((e, i) => (
      <tr key={i} data-series>
       <th scope="row"><LabelText labels={e.labels} /></th>
       <td><SampleValue sample={e.sample} /></td>
       <td><TimeText ns={e.sample.time} /></td>
      </tr>
     ))}
    </tbody>
   </table>
   {props.vector.length > shown && <button type="button" onClick={() => setShown(shown + PAGE)}>Show more series ({shown} shown of {props.vector.length})</button>}
  </>
 );
}

const STEP_WORD = (n: number | null): string => (n === null ? 'some evaluation steps' : n === 1 ? '1 evaluation step' : `${n} evaluation steps`);

function GapText(props: { gap: Gap }): React.JSX.Element {
 const { gap } = props;
 const where = gap.after === null
  ? <>from the start of the range until <TimeText ns={gap.before ?? ''} /></>
  : gap.before === null ? <>after <TimeText ns={gap.after} /> to the end of the range</> : <>after <TimeText ns={gap.after} /> and before <TimeText ns={gap.before} /></>;
 return <li data-gap data-after={gap.after ?? ''} data-before={gap.before ?? ''}><strong>Gap:</strong> no sample for {STEP_WORD(gap.missing)} {where}. A missing sample is absent, not zero.</li>;
}

const W = 640, H = 150, PAD = 10, STRIP = 18;

function SeriesChart(props: { plan: SeriesPlan; samples: Sample[]; evaluation: EvaluationWire | null; labels: Label[] }): React.JSX.Element {
 const { plan, samples, evaluation } = props;
 const times = samples.map((s) => BigInt(s.time));
 const range = evaluation !== null && !evaluation.instant && BigInt(evaluation.end) > BigInt(evaluation.start);
 const x0 = range ? BigInt(evaluation.start) : times.reduce((a, b) => (b < a ? b : a), times[0] ?? 0n);
 const x1 = range ? BigInt(evaluation.end) : times.reduce((a, b) => (b > a ? b : a), times[0] ?? 0n);
 const span = Number(x1 - x0);
 const xOf = (ns: string): number => (span === 0 ? W / 2 : PAD + (Number(BigInt(ns) - x0) / span) * (W - 2 * PAD));
 const values = plan.segments.flat().map((p) => p.value);
 const lo = values.length > 0 ? Math.min(...values) : 0, hi = values.length > 0 ? Math.max(...values) : 0;
 const plotH = H - 2 * PAD - STRIP;
 const yOf = (v: number): number => (hi === lo ? PAD + plotH / 2 : PAD + plotH - ((v - lo) / (hi - lo)) * plotH);
 const stripY = H - PAD - STRIP / 2 + 4;
 const counts = { nan: 0, inf: 0, stale: 0, histogram: 0 };
 for (const m of plan.marks) { if (m.kind === 'nan') counts.nan++; else if (m.kind === 'stale') counts.stale++; else if (m.kind === 'histogram') counts.histogram++; else counts.inf++; }
 const label = `Chart of ${labelsText(props.labels)}: ${plan.points} samples, ${plan.gaps.length} gaps, ${plan.marks.length} values that are not plotted. Gaps are dashed boxes and are not zero.`;
 return (
  <svg className="series-chart" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={label} data-segments={plan.segments.length} data-gap-count={plan.gaps.length} data-nan-count={counts.nan} data-inf-count={counts.inf} data-stale-count={counts.stale} data-histogram-count={counts.histogram}>
   <rect x={PAD} y={PAD} width={W - 2 * PAD} height={plotH} fill="none" stroke="currentColor" strokeOpacity="0.35" />
   {plan.gaps.map((g, i) => {
    const from = g.after === null ? x0 : BigInt(g.after), to = g.before === null ? x1 : BigInt(g.before);
    const a = xOf(String(from)), b = xOf(String(to));
    return <rect key={`g${i}`} data-gap data-after={g.after ?? ''} data-before={g.before ?? ''} x={Math.min(a, b)} y={PAD} width={Math.max(Math.abs(b - a), 2)} height={plotH} fill="none" stroke="currentColor" strokeDasharray="5 4" strokeWidth="1.5"><title>{`Gap: no sample for ${STEP_WORD(g.missing)}`}</title></rect>;
   })}
   {plan.segments.map((seg, i) => seg.length === 1
    ? <circle key={`s${i}`} data-segment cx={xOf(seg[0]?.time ?? '0')} cy={yOf(seg[0]?.value ?? 0)} r="3" fill="currentColor" />
    : <polyline key={`s${i}`} data-segment points={seg.map((p) => `${xOf(p.time).toFixed(1)},${yOf(p.value).toFixed(1)}`).join(' ')} fill="none" stroke="currentColor" strokeWidth="2" />)}
   {plan.marks.map((m, i) => {
    const x = xOf(m.time);
    switch (m.kind) {
     case 'nan': return <path key={`m${i}`} data-mark="nan" d={`M${x - 4},${stripY - 4} L${x + 4},${stripY + 4} M${x + 4},${stripY - 4} L${x - 4},${stripY + 4}`} stroke="currentColor" strokeWidth="2" fill="none"><title>NaN (a value, not a gap)</title></path>;
     case 'pos_inf': return <polygon key={`m${i}`} data-mark="pos_inf" points={`${x},${stripY - 5} ${x - 5},${stripY + 4} ${x + 5},${stripY + 4}`} fill="currentColor"><title>+Inf</title></polygon>;
     case 'neg_inf': return <polygon key={`m${i}`} data-mark="neg_inf" points={`${x},${stripY + 5} ${x - 5},${stripY - 4} ${x + 5},${stripY - 4}`} fill="currentColor"><title>-Inf</title></polygon>;
     case 'stale': return <rect key={`m${i}`} data-mark="stale" x={x - 4} y={stripY - 4} width="8" height="8" fill="none" stroke="currentColor" strokeWidth="2" transform={`rotate(45 ${x} ${stripY})`}><title>stale marker</title></rect>;
     default: return <rect key={`m${i}`} data-mark="histogram" x={x - 4} y={stripY - 4} width="8" height="8" fill="currentColor"><title>native histogram</title></rect>;
    }
   })}
  </svg>
 );
}

function SeriesBlock(props: { series: Series; evaluation: EvaluationWire | null }): React.JSX.Element {
 const { series, evaluation } = props;
 const plan = React.useMemo(() => planSeries(series.samples, evaluation), [series, evaluation]);
 const [shown, setShown] = React.useState(PAGE);
 const gapAt = new Map<string, Gap>();
 for (const g of plan.gaps) gapAt.set(`${g.after ?? ''}|${g.before ?? ''}`, g);
 const rows: React.JSX.Element[] = [];
 let previous: string | null = null;
 const lead = gapAt.get(`|${series.samples[0]?.time ?? ''}`);
 if (lead) rows.push(<tr key="lead" data-gap><td colSpan={2}><strong>Gap:</strong> no sample for {STEP_WORD(lead.missing)} from the start of the range</td></tr>);
 for (const [i, s] of series.samples.slice(0, shown).entries()) {
  const g = previous === null ? undefined : gapAt.get(`${previous}|${s.time}`);
  if (g) rows.push(<tr key={`g${i}`} data-gap><td colSpan={2}><strong>Gap:</strong> no sample for {STEP_WORD(g.missing)} (absent, not zero)</td></tr>);
  rows.push(<tr key={i} data-sample><td><TimeText ns={s.time} /></td><td><SampleValue sample={s} /></td></tr>);
  previous = s.time;
 }
 const last = series.samples[series.samples.length - 1];
 const trail = last === undefined ? undefined : gapAt.get(`${last.time}|`);
 if (trail && shown >= series.samples.length) rows.push(<tr key="trail" data-gap><td colSpan={2}><strong>Gap:</strong> no sample for {STEP_WORD(trail.missing)} until the end of the range</td></tr>);
 return (
  <section className="series" data-series data-samples={series.samples.length} data-gaps={plan.gaps.length}>
   <h4><LabelText labels={series.labels} /></h4>
   <SeriesChart plan={plan} samples={series.samples} evaluation={evaluation} labels={series.labels} />
   <p className="legend">{plan.points} samples, {plan.gaps.length} {plan.gaps.length === 1 ? 'gap' : 'gaps'}. Marks under the line: × NaN, ▲ +Inf, ▼ −Inf, ◇ stale marker, ■ native histogram. Dashed boxes are gaps.</p>
   {plan.gaps.length > 0 && <ul className="gap-list">{plan.gaps.map((g, i) => <GapText key={i} gap={g} />)}</ul>}
   <details>
    <summary>Data table ({series.samples.length} samples)</summary>
    <table className="data-table">
     <thead><tr><th scope="col">Time (nanoseconds)</th><th scope="col">Value</th></tr></thead>
     <tbody>{rows}</tbody>
    </table>
    {series.samples.length > shown && <button type="button" onClick={() => setShown(shown + PAGE)}>Show more samples ({shown} shown of {series.samples.length})</button>}
   </details>
  </section>
 );
}

/** A project's scalar, string, instant vector or range matrix. Numbers keep their exact text, NaN, infinities and stale markers
 * are named, a native histogram is shown bucket by bucket, and a missing sample is a gap in the line, never a zero. */
export function MetricResult(props: { result: ProjectResult; evaluation?: EvaluationWire }): React.JSX.Element {
 const v = props.result.value;
 const evaluation = props.evaluation ?? null;
 if (v === null) return <p role="status" data-result="none">No value: this project returned no result.</p>;
 switch (v.type) {
  case 'scalar': return <p data-result="scalar">Scalar <SampleValue sample={v.scalar} /> at <TimeText ns={v.scalar.time} /></p>;
  case 'string': return <p data-result="string">String: <code data-testid="string-value">{v.string}</code></p>;
  case 'vector': return <VectorTable vector={v.vector} />;
  case 'matrix': return v.matrix.length === 0
   ? <p data-result="matrix-empty">The query matched no series. Nothing is missing.</p>
   : (
    <div data-result="matrix">
     <p>Range matrix: {v.matrix.length} {v.matrix.length === 1 ? 'series' : 'series'}{v.matrix.length > MAX_SERIES ? `, the first ${MAX_SERIES} are drawn` : ''}.</p>
     {v.matrix.slice(0, MAX_SERIES).map((s, i) => <SeriesBlock key={i} series={s} evaluation={evaluation} />)}
    </div>
   );
  case 'streams': return <p role="status" data-result="streams">This result is log lines; it is shown as a log result.</p>;
 }
}
