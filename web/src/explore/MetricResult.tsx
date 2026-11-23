// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { EvaluationWire, Label, NativeHistogram, ProjectResult, Sample, Series, VectorElement } from '../api/types';
import { DataTable } from '../ui/primitives';
import { LineChart, type SeriesTone } from '../ui/chart/Chart';
import { MAX_CHART_POINTS, MAX_DRAWN, chartSamples, chartWindow, downsample, formatNumber, markCounts, markSentence, seriesStats } from './chartModel';
import { emptyWords, histogramView, labelsText, nsToIso, planSeries, sampleText, type FloatKind, type Gap, type SeriesPlan } from './model';

const PAGE = 200;
const MAX_SERIES = 50;
const TONES: readonly SeriesTone[] = ['c1', 'c2', 'c3', 'c4', 'c5', 'c6'];
const NOTE: Record<Exclude<FloatKind, 'finite'>, string> = {
 nan: 'not a number: a real value, not a missing one',
 pos_inf: 'positive infinity',
 neg_inf: 'negative infinity',
 stale: 'a stale marker: the absence of a sample, not a value',
};

/** A nanosecond instant, exact: the canonical decimal string is shown next to its UTC form, never rounded. */
export function TimeText(props: { ns: string }): React.JSX.Element {
 return <span className="exp-time"><code>{props.ns}</code> <small>{nsToIso(props.ns)}</small></span>;
}

export function LabelText(props: { labels: Label[] }): React.JSX.Element {
 return <code className="exp-labels">{labelsText(props.labels)}</code>;
}

function Histogram(props: { h: NativeHistogram; where: string }): React.JSX.Element {
 const v = histogramView(props.h);
 const [shown, setShown] = React.useState(PAGE);
 const table = (name: string, buckets: { index: number; count: string }[]): React.JSX.Element | null => buckets.length === 0 ? null : (
  <div className="table-region" tabIndex={0} role="region" aria-label={`${name} buckets of a native histogram, ${props.where}`}>
   <table className="table tight">
    <caption className="sr-only">{name} buckets (index of the bucket, count)</caption>
    <thead><tr><th scope="col">Bucket index</th><th scope="col">Count</th></tr></thead>
    <tbody>{buckets.slice(0, shown).map((b) => <tr key={b.index}><td><code>{b.index}</code></td><td><code>{b.count}</code></td></tr>)}</tbody>
   </table>
  </div>
 );
 const total = v.positive.length + v.negative.length;
 return (
  <details className="exp-histogram" data-kind="histogram">
   <summary>Native histogram ({v.variant} variant): count {v.count}, sum {v.sum.text}, schema {v.schema}</summary>
   <dl className="props">
    <dt>Zero bucket</dt><dd>count {v.zeroCount}, threshold {v.zeroThreshold.text}</dd>
    <dt>Flavor</dt><dd>{v.flavor}, reset hint {v.resetHint}</dd>
    {v.customBounds.length > 0 && <><dt>Custom bounds</dt><dd>{v.customBounds.map((b) => b.text).join(', ')}</dd></>}
   </dl>
   {table('Positive', v.positive)}
   {table('Negative', v.negative)}
   {total > shown && <button type="button" className="btn btn-sm" onClick={() => setShown(shown + PAGE)}>Show more buckets ({Math.min(shown, Math.max(v.positive.length, v.negative.length))} shown of {Math.max(v.positive.length, v.negative.length)})</button>}
   {total === 0 && <p>This histogram has no non-zero buckets.</p>}
  </details>
 );
}

/** One sample's value in words: a number, NaN, an infinity, a stale marker or a native histogram. The IEEE bits are shown for anything that is not a plain number. */
export function SampleValue(props: { sample: Sample; where?: string }): React.JSX.Element {
 const s = props.sample;
 if (s.histogram !== undefined) return <Histogram h={s.histogram} where={props.where ?? 'this result'} />;
 const t = sampleText(s);
 const bits = s.float ?? '';
 return (
  <span className={`exp-val exp-val-${t.kind}`} data-kind={t.kind} data-bits={bits} title={`IEEE-754 bits ${bits}`}>
   {t.text}
   {t.kind !== 'finite' && t.kind !== 'histogram' && <small> ({NOTE[t.kind]}; bits <code>{bits}</code>)</small>}
  </span>
 );
}

interface VectorRow { e: VectorElement; i: number }

function VectorTable(props: { vector: VectorElement[]; result: ProjectResult; where: string }): React.JSX.Element {
 const [shown, setShown] = React.useState(PAGE);
 if (props.vector.length === 0) return <p data-result="vector-empty">{emptyWords(props.result, 'The query matched no series')}</p>;
 const rows: VectorRow[] = props.vector.slice(0, shown).map((e, i) => ({ e, i }));
 return (
  <div data-result="vector">
   <DataTable
    label={`Instant vector of ${props.where}`} caption={`Instant vector: one row per series (${props.vector.length} series)`} tight rows={rows} rowKey={(r) => String(r.i)} rowAttrs={() => ({ 'data-series': '' })}
    columns={[
     { key: 'series', header: 'Series', cell: (r) => <LabelText labels={r.e.labels} /> },
     { key: 'value', header: 'Value', cell: (r) => <SampleValue sample={r.e.sample} where={`${props.where}, series ${r.i + 1}`} /> },
     { key: 'time', header: 'Sample time (nanoseconds)', label: 'Sample time', cell: (r) => <TimeText ns={r.e.sample.time} /> },
    ]}
   />
   {props.vector.length > shown && <button type="button" className="btn btn-sm" onClick={() => setShown(shown + PAGE)}>Show more series ({shown} shown of {props.vector.length})</button>}
  </div>
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

function statsWords(plan: SeriesPlan): string {
 const st = seriesStats(plan);
 if (st === null) return `${plan.points} ${plan.points === 1 ? 'sample' : 'samples'}, none of them a plottable number.`;
 return `${plan.points} ${plan.points === 1 ? 'sample' : 'samples'}: minimum ${formatNumber(st.min)}, maximum ${formatNumber(st.max)}, mean ${formatNumber(st.avg)}, last ${formatNumber(st.last)}.`;
}

function SeriesBlock(props: { series: Series; plan: SeriesPlan; tone: SeriesTone | null; where: string }): React.JSX.Element {
 const { series, plan } = props;
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
  rows.push(<tr key={i} data-sample><td><TimeText ns={s.time} /></td><td><SampleValue sample={s} where={`${props.where}, sample ${i + 1}`} /></td></tr>);
  previous = s.time;
 }
 const last = series.samples[series.samples.length - 1];
 const trail = last === undefined ? undefined : gapAt.get(`${last.time}|`);
 if (trail && shown >= series.samples.length) rows.push(<tr key="trail" data-gap><td colSpan={2}><strong>Gap:</strong> no sample for {STEP_WORD(trail.missing)} until the end of the range</td></tr>);
 const label = labelsText(series.labels);
 return (
  <section className="exp-series" data-series data-samples={series.samples.length} data-gaps={plan.gaps.length}>
   <h4 className="exp-series-head">{props.tone !== null ? <i className={`exp-sw exp-sw-${props.tone}`} aria-hidden="true" /> : null}<LabelText labels={series.labels} />{props.tone === null && <small className="t3"> not drawn on the chart</small>}</h4>
   <p className="small t2">{statsWords(plan)}</p>
   {plan.gaps.length > 0 && <ul className="exp-gap-list">{plan.gaps.map((g, i) => <GapText key={i} gap={g} />)}</ul>}
   <details className="exp-details">
    <summary>Data table ({series.samples.length} samples)</summary>
    <div className="table-region" tabIndex={0} role="region" aria-label={`Samples of ${label} in ${props.where}`}>
     <table className="table tight">
      <caption className="sr-only">Samples of {label}, oldest first, with the gaps between them</caption>
      <thead><tr><th scope="col">Time (nanoseconds)</th><th scope="col">Value</th></tr></thead>
      <tbody>{rows}</tbody>
     </table>
    </div>
    {series.samples.length > shown && <button type="button" className="btn btn-sm" onClick={() => setShown(shown + PAGE)}>Show more samples ({shown} shown of {series.samples.length})</button>}
   </details>
  </section>
 );
}

function MatrixView(props: { matrix: Series[]; evaluation: EvaluationWire | null; timeZone: string; where: string }): React.JSX.Element {
 const { matrix, evaluation } = props;
 const plans = React.useMemo(() => matrix.map((s) => planSeries(s.samples, evaluation)), [matrix, evaluation]);
 const win = chartWindow(evaluation);
 const drawn = win === null ? 0 : Math.min(MAX_DRAWN, matrix.length);
 const chart = React.useMemo(() => {
  let thinned = false;
  const series = matrix.slice(0, drawn).map((s, i) => { const d = downsample(chartSamples(s.samples, evaluation)); if (d.thinned) thinned = true; return { id: String(i), name: labelsText(s.labels), tone: TONES[i] ?? 'c1', samples: d.samples }; });
  return { series, thinned };
 }, [matrix, evaluation, drawn]);
 const shownPlans = plans.slice(0, drawn);
 const marks = markCounts(shownPlans);
 const segments = shownPlans.reduce((n, p) => n + p.segments.length, 0);
 const gaps = shownPlans.reduce((n, p) => n + p.gaps.length, 0);
 return (
  <div data-result="matrix" className="exp-matrix">
   <p className="small t2">Range matrix: {matrix.length} series{matrix.length > MAX_SERIES ? `, the first ${MAX_SERIES} are listed` : ''}.</p>
   {win !== null && drawn > 0 && (
    <div className="exp-chart" data-series-chart data-segments={segments} data-gap-count={gaps} data-nan-count={marks.nan} data-inf-count={marks.inf} data-stale-count={marks.stale} data-histogram-count={marks.histogram}>
     <LineChart label={`Chart of ${drawn} series of ${props.where}. A missing sample is a break or a no-samples band, never zero.`} series={chart.series} start={win.start} end={win.end} timeZone={props.timeZone} format={formatNumber} height={220} />
     {markSentence(marks) !== '' && <p className="small t2" data-testid="chart-marks">{markSentence(marks)}</p>}
     {matrix.length > drawn && <p className="small t2" role="status">The chart draws the first {drawn} of {matrix.length} series on one axis; the others are listed below without a chart.</p>}
     {chart.thinned && <p className="small t2" role="status" data-testid="chart-thinned">The chart draws at most {MAX_CHART_POINTS} points per series (the lowest and highest of each group, so peaks stay); the figures and the data tables use every sample.</p>}
    </div>
   )}
   {win === null && <p className="small t2" role="status">An instant evaluation has one moment, so the series are listed as tables. Choose Range over the selected window to chart them over time.</p>}
   {matrix.slice(0, MAX_SERIES).map((s, i) => <SeriesBlock key={i} series={s} plan={plans[i] ?? planSeries(s.samples, evaluation)} tone={i < drawn ? TONES[i] ?? null : null} where={props.where} />)}
  </div>
 );
}

/** A project's scalar, string, instant vector or range matrix. Numbers keep their exact text, NaN, infinities and stale markers
 * are named, a native histogram is shown bucket by bucket, and a missing sample is a gap in the line, never a zero. */
export function MetricResult(props: { result: ProjectResult; evaluation?: EvaluationWire; timeZone?: string }): React.JSX.Element {
 const v = props.result.value;
 const evaluation = props.evaluation ?? null;
 const where = `project ${props.result.project_id.slice(0, 8)}`;
 if (v === null) return <p role="status" data-result="none">No value: this project returned no result.</p>;
 switch (v.type) {
  case 'scalar': return <p data-result="scalar">Scalar <SampleValue sample={v.scalar} where={where} /> at <TimeText ns={v.scalar.time} /></p>;
  case 'string': return <p data-result="string">String: <code data-testid="string-value">{v.string}</code></p>;
  case 'vector': return <VectorTable vector={v.vector} result={props.result} where={where} />;
  case 'matrix': return v.matrix.length === 0
   ? <p data-result="matrix-empty">{emptyWords(props.result, 'The query matched no series')}</p>
   : <MatrixView matrix={v.matrix} evaluation={evaluation} timeZone={props.timeZone ?? 'UTC'} where={where} />;
  case 'streams': return <p role="status" data-result="streams">This result is log lines; it is shown as a log result.</p>;
 }
}
