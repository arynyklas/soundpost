// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { clockFormatter, detectGaps, estimateTextWidth, inGap, intersectGaps, linePath, mergeGaps, nearestIndex, niceMax, niceMin, runs, sampleStep, timeTicks, yTicks, type Gap, type Sample } from './model';

export type SeriesTone = 'c1' | 'c2' | 'c3' | 'c4' | 'c5' | 'c6' | 'crit' | 'ok' | 'high' | 'info' | 'unk';
export interface LineSeries { id: string; name: string; tone: SeriesTone; samples: readonly Sample[]; dashed?: boolean }
export interface Mark { t: number; label: string }

const L = 48, R = 10, B = 20;

let canvas: CanvasRenderingContext2D | null | undefined;
/** Text width in CSS px for the in-chart tooltip (it is drawn as SVG, so it cannot size itself). */
function textWidth(text: string, bold = false): number {
 if (canvas === undefined) { try { canvas = document.createElement('canvas').getContext('2d'); } catch { canvas = null; } }
 if (!canvas) return estimateTextWidth(text);
 canvas.font = `${bold ? 600 : 400} 12.5px "Segoe UI",system-ui,sans-serif`;
 return Math.ceil(canvas.measureText(text).width);
}

/** The chart is drawn at its measured width (1 SVG unit = 1 CSS px), so labels and strokes keep their size at every width, and it is redrawn on resize. */
function useMeasuredWidth(ref: React.RefObject<HTMLElement | null>, fallback = 900): number {
 const [w, setW] = React.useState(fallback);
 React.useLayoutEffect(() => {
  const el = ref.current;
  if (!el) return;
  const read = (): void => { const next = Math.floor(el.getBoundingClientRect().width); if (next > 0) setW(next); };
  read();
  if (typeof ResizeObserver === 'undefined') return;
  const ro = new ResizeObserver(read);
  ro.observe(el);
  return () => ro.disconnect();
 }, [ref]);
 return w;
}

interface TipRow { tone: SeriesTone; name: string; value: string; none: boolean }
function Tip(props: { x: number; W: number; top: number; title: string; rows: readonly TipRow[] }): React.JSX.Element {
 const titleW = textWidth(props.title);
 const rowW = Math.max(0, ...props.rows.map((r) => 15 + textWidth(r.name) + 14 + textWidth(r.value, true)));
 const w = Math.max(150, Math.ceil(Math.max(titleW, rowW)) + 20);
 const h = 12 + 18 + props.rows.length * 18;
 const left = props.x + 14 + w > props.W - 4 ? props.x - 14 - w : props.x + 14;
 return (
  <g className="ch-tip" transform={`translate(${Math.max(2, left)} ${props.top})`} pointerEvents="none">
   <rect width={w} height={h} rx="8" />
   <text className="ch-tip-time" x="10" y="19">{props.title}</text>
   {props.rows.map((r, i) => (
    <g key={r.name + i} transform={`translate(10 ${32 + i * 18})`}>
     <rect className={`ch-f-${r.tone}`} y="-9" width="9" height="9" rx="2" />
     <text x="15" y="0">{r.name}</text>
     <text className={r.none ? 'ch-tip-none' : 'ch-tip-val'} x={w - 20} y="0" textAnchor="end">{r.value}</text>
    </g>
   ))}
  </g>
 );
}

function GapBand(props: { x1: number; x2: number; T: number; ih: number; W: number; text?: string | undefined }): React.JSX.Element {
 const mid = (props.x1 + props.x2) / 2;
 const wide = props.x2 - props.x1 > 70;
 const near = mid > props.W - 70;
 return (
  <g className="ch-gap" data-testid="chart-gap">
   <rect x={props.x1} y={props.T} width={Math.max(3, props.x2 - props.x1)} height={props.ih} />
   <line x1={props.x1} x2={props.x1} y1={props.T} y2={props.T + props.ih} />
   <line x1={props.x2} x2={props.x2} y1={props.T} y2={props.T + props.ih} />
   {wide && <text x={near ? props.x1 - 6 : mid} y={props.T + props.ih - 8} textAnchor={near ? 'end' : 'middle'}>{props.text ?? 'no samples'}</text>}
  </g>
 );
}

function Marks(props: { marks: readonly Mark[]; start: number; end: number; iw: number; T: number; ih: number }): React.JSX.Element {
 return (
  <>
   {props.marks.map((m) => {
    if (m.t < props.start) return <text key={m.label} className="ch-mark-text" x={L + 2} y={props.T - 8}>{`◂ ${m.label}`}</text>;
    if (m.t > props.end) return null;
    const x = L + (props.iw * (m.t - props.start)) / (props.end - props.start);
    const flip = x > L + props.iw * 0.75;
    return (
     <g key={`${m.t}:${m.label}`}>
      <line className="ch-mark" x1={x} x2={x} y1={props.T - 4} y2={props.T + props.ih} />
      <text className="ch-mark-text" x={flip ? x - 4 : x + 4} y={props.T - 8} textAnchor={flip ? 'end' : 'start'}>{m.label}</text>
     </g>
    );
   })}
  </>
 );
}

function Axes(props: { W: number; H: number; T: number; iw: number; ih: number; yMin: number; yMax: number; format: (v: number) => string; start: number; end: number; timeZone: string }): React.JSX.Element {
 const clock = clockFormatter(props.end - props.start, props.timeZone);
 const maxTicks = Math.max(2, Math.floor(props.iw / 90) + 1);
 const ts = timeTicks(props.start, props.end, maxTicks);
 return (
  <>
   {yTicks(props.yMin, props.yMax, 4).map((v, i) => {
    const y = props.T + (props.ih * i) / 3;
    return <g key={i}><line className="ch-grid" x1={L} x2={props.W - R} y1={y} y2={y} /><text className="ch-axis" x={L - 6} y={y + 4} textAnchor="end">{props.format(v)}</text></g>;
   })}
   {ts.map((t, i) => {
    const x = L + (props.iw * (t - props.start)) / (props.end - props.start);
    const edgeL = i === 0 && t === props.start, edgeR = i === ts.length - 1 && t === props.end;
    return <text key={t} className="ch-axis" x={x} y={props.H - 3} textAnchor={edgeL ? 'start' : edgeR ? 'end' : 'middle'}>{clock(t)}</text>;
   })}
  </>
 );
}

export interface LineChartProps {
 /** The accessible name: what the chart shows, including where it has no samples. */
 label: string;
 series: readonly LineSeries[];
 /** The window, in epoch milliseconds. */
 start: number;
 end: number;
 timeZone: string;
 format: (v: number) => string;
 height?: number;
 /** A fixed top of the value axis; otherwise it is the next round number above the data and threshold. */
 yMax?: number;
 /** A fixed bottom of the value axis; otherwise zero, or the next round number below the lowest value when values are negative. */
 yMin?: number;
 /** Spans the server says have no samples (drawn as bands); gaps in the data itself are found automatically. */
 gaps?: readonly Gap[];
 threshold?: { value: number; label: string };
 marks?: readonly Mark[];
 area?: boolean;
 testId?: string;
}

/** A line chart with a crosshair, a tooltip (time and every series' value) and "no samples" bands. A gap is never drawn as zero and never says 0. */
export function LineChart(props: LineChartProps): React.JSX.Element {
 const wrap = React.useRef<HTMLDivElement>(null);
 const W = useMeasuredWidth(wrap);
 const H = props.height ?? 200;
 const T = 22;
 const iw = W - L - R, ih = H - B - T;
 const span = props.end - props.start;
 const [hoverT, setHoverT] = React.useState<number | null>(null);
 const svgRef = React.useRef<SVGSVGElement>(null);
 const values = props.series.flatMap((s) => s.samples.flatMap((p) => (p.v === null ? [] : [p.v])));
 const peak = Math.max(0, props.threshold?.value ?? 0, ...values);
 const yMax = props.yMax ?? niceMax(peak);
 const yMin = props.yMin ?? niceMin(Math.min(0, ...values));
 const xOf = (t: number): number => L + (iw * (t - props.start)) / span;
 const yOf = (v: number): number => T + ih * (1 - (Math.min(Math.max(v, yMin), yMax) - yMin) / (yMax - yMin));
 const gapSets = props.series.map((s) => detectGaps(s.samples, props.start, props.end));
 const common = gapSets.length === 0 ? [] : gapSets.reduce((acc, g) => intersectGaps(acc, g));
 const bands = mergeGaps([...(props.gaps ?? []), ...common]);
 const gapsOf = (i: number): Gap[] => [...(gapSets[i] ?? []), ...bands];
 const timeAt = (clientX: number): number | null => {
  const r = svgRef.current?.getBoundingClientRect();
  if (!r || r.width === 0) return null;
  const x = (clientX - r.left) * (W / r.width);
  if (x < L || x > W - R) return null;
  return props.start + ((x - L) / iw) * span;
 };
 const clock = clockFormatter(span, props.timeZone);
 let hover: { x: number; title: string; rows: TipRow[]; dots: { x: number; y: number; tone: SeriesTone }[] } | null = null;
 if (hoverT !== null) {
  const rows: TipRow[] = [];
  const dots: { x: number; y: number; tone: SeriesTone }[] = [];
  let snap = hoverT;
  const lead = props.series[0];
  if (lead) { const i = nearestIndex(lead.samples, hoverT); if (i >= 0) snap = lead.samples[i]!.t; }
  props.series.forEach((s, si) => {
   const step = sampleStep(s.samples) || span / 60;
   const i = nearestIndex(s.samples, hoverT);
   const sample = i >= 0 ? s.samples[i]! : undefined;
   const gap = inGap(gapsOf(si), hoverT) !== undefined || inGap(bands, hoverT) !== undefined;
   const present = sample !== undefined && (sample.v !== null || sample.special !== undefined);
   const none = !sample || !present || gap || Math.abs(sample.t - hoverT) > step * 1.5;
   rows.push({ tone: s.tone, name: s.name, value: none || !sample ? 'no samples' : sample.v === null ? (sample.special ?? 'no samples') : props.format(sample.v), none });
   if (!none && sample && sample.v !== null) dots.push({ x: xOf(sample.t), y: yOf(sample.v), tone: s.tone });
  });
  const anyNone = rows.length > 0 && rows.every((r) => r.none);
  hover = { x: anyNone ? xOf(hoverT) : xOf(snap), title: clock(anyNone ? hoverT : snap), rows, dots };
 }
 const onKey = (e: React.KeyboardEvent<SVGSVGElement>): void => {
  const lead = props.series[0];
  const step = (lead && sampleStep(lead.samples)) || span / 60;
  if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
   e.preventDefault();
   const base = hoverT ?? (e.key === 'ArrowLeft' ? props.end : props.start);
   setHoverT(Math.min(props.end, Math.max(props.start, base + (e.key === 'ArrowRight' ? step : -step))));
  } else if (e.key === 'Escape') setHoverT(null);
 };
 return (
  <div ref={wrap} className="chart-wrap" data-testid={props.testId}>
   <svg ref={svgRef} className="chart" width={W} height={H} viewBox={`0 0 ${W} ${H}`} role="img" aria-label={props.label} tabIndex={0}
    onPointerMove={(e) => setHoverT(timeAt(e.clientX))} onPointerLeave={() => setHoverT(null)} onBlur={() => setHoverT(null)} onKeyDown={onKey}>
    <Axes W={W} H={H} T={T} iw={iw} ih={ih} yMin={yMin} yMax={yMax} format={props.format} start={props.start} end={props.end} timeZone={props.timeZone} />
    {bands.map((g) => <GapBand key={`${g.from}:${g.to}`} x1={xOf(Math.max(g.from, props.start))} x2={xOf(Math.min(g.to, props.end))} T={T} ih={ih} W={W} text={g.text ?? `no samples ${clock(Math.max(g.from, props.start))}–${clock(Math.min(g.to, props.end))}`} />)}
    {props.threshold && <g><line className="ch-threshold" x1={L} x2={W - R} y1={yOf(props.threshold.value)} y2={yOf(props.threshold.value)} /><text className="ch-threshold-text" x={L + 6} y={yOf(props.threshold.value) - 5}>{props.threshold.label}</text></g>}
    {props.marks && <Marks marks={props.marks} start={props.start} end={props.end} iw={iw} T={T} ih={ih} />}
    {props.series.flatMap((s) => s.samples.filter((p) => p.v === null && p.special !== undefined && p.t >= props.start && p.t <= props.end).map((p) => <path key={`${s.id}:${p.t}`} className={`ch-special ch-f-${s.tone}`} d={`M${xOf(p.t).toFixed(1)} ${T + ih - 9} l4 4.5 l-4 4.5 l-4 -4.5 z`}><title>{`${s.name}: ${p.special}`}</title></path>))}
    {props.series.map((s, si) => runs(s.samples, gapsOf(si)).map((run, ri) => {
     const pts = run.map((p) => ({ x: xOf(p.t), y: yOf(p.v ?? 0) }));
     const d = linePath(pts);
     const first = pts[0]!, last = pts[pts.length - 1]!;
     return (
      <g key={`${s.id}:${ri}`}>
       {props.area && si === 0 && pts.length > 1 && <path className={`ch-area ch-f-${s.tone}`} d={`${d} L${last.x.toFixed(1)} ${T + ih} L${first.x.toFixed(1)} ${T + ih}Z`} />}
       <path className={`ch-line ch-s-${s.tone}`} d={d} strokeDasharray={s.dashed ? '4 3' : undefined} />
       {pts.length === 1 && <circle className={`ch-f-${s.tone}`} cx={first.x} cy={first.y} r="2.5" />}
      </g>
     );
    }))}
    {hover && (
     <g className="ch-hover" pointerEvents="none">
      <line x1={hover.x} x2={hover.x} y1={T} y2={T + ih} />
      {hover.dots.map((d, i) => <circle key={i} className={`ch-f-${d.tone}`} cx={d.x} cy={d.y} r="3.5" />)}
      <Tip x={hover.x} W={W} top={T + 4} title={hover.title} rows={hover.rows} />
     </g>
    )}
   </svg>
   {hover && <div className="sr-only" role="status">{`${hover.title}: ${hover.rows.map((r) => `${r.name} ${r.value}`).join(', ')}`}</div>}
   {props.series.length > 1 && <ul className="legend" aria-label="Series">{props.series.map((s) => <li key={s.id}><i className={`sq c-${s.tone}`} aria-hidden="true" />{s.name}</li>)}</ul>}
  </div>
 );
}

export interface Bucket { start: number; end: number; /** Values per series; null means the bucket has no samples (not zero). */ values: readonly number[] | null }
export interface BarChartProps {
 label: string;
 buckets: readonly Bucket[];
 names: readonly string[];
 tones: readonly SeriesTone[];
 start: number;
 end: number;
 timeZone: string;
 format?: (v: number) => string;
 height?: number;
 marks?: readonly Mark[];
 gaps?: readonly Gap[];
 testId?: string;
}

/** A stacked bar chart over equal time buckets. Hover shows the bucket's time range and each series' count; a bucket with no samples says so. */
export function BarChart(props: BarChartProps): React.JSX.Element {
 const wrap = React.useRef<HTMLDivElement>(null);
 const W = useMeasuredWidth(wrap);
 const H = props.height ?? 100;
 const T = 18;
 const iw = W - L - R, ih = H - B - T;
 const span = props.end - props.start;
 const [hover, setHover] = React.useState<number | null>(null);
 const svgRef = React.useRef<SVGSVGElement>(null);
 const format = props.format ?? ((v: number) => v.toLocaleString('en-US'));
 const totals = props.buckets.map((b) => (b.values ? b.values.reduce((a, v) => a + v, 0) : 0));
 const yMax = niceMax(Math.max(0, ...totals));
 const xOf = (t: number): number => L + (iw * (t - props.start)) / span;
 const clock = clockFormatter(span, props.timeZone);
 const bucketAt = (clientX: number): number | null => {
  const r = svgRef.current?.getBoundingClientRect();
  if (!r || r.width === 0) return null;
  const x = (clientX - r.left) * (W / r.width);
  const t = props.start + ((x - L) / iw) * span;
  const i = props.buckets.findIndex((b) => t >= b.start && t < b.end);
  return i < 0 ? null : i;
 };
 const b = hover !== null ? props.buckets[hover] : undefined;
 const rows: TipRow[] = b ? (b.values ? props.names.map((n, j) => ({ tone: props.tones[j] ?? 'c1', name: n, value: format(b.values![j] ?? 0), none: false })).filter((r, j) => props.names.length === 1 || (b.values![j] ?? 0) > 0 || b.values!.every((v) => v === 0)) : [{ tone: 'unk' as SeriesTone, name: 'Samples', value: 'no samples', none: true }]) : [];
 const onKey = (e: React.KeyboardEvent<SVGSVGElement>): void => {
  if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') { e.preventDefault(); const n = props.buckets.length; setHover((h) => (h === null ? (e.key === 'ArrowLeft' ? n - 1 : 0) : Math.min(n - 1, Math.max(0, h + (e.key === 'ArrowRight' ? 1 : -1))))); }
  else if (e.key === 'Escape') setHover(null);
 };
 return (
  <div ref={wrap} className="chart-wrap" data-testid={props.testId}>
   <svg ref={svgRef} className="chart" width={W} height={H} viewBox={`0 0 ${W} ${H}`} role="img" aria-label={props.label} tabIndex={0}
    onPointerMove={(e) => setHover(bucketAt(e.clientX))} onPointerLeave={() => setHover(null)} onBlur={() => setHover(null)} onKeyDown={onKey}>
    <Axes W={W} H={H} T={T} iw={iw} ih={ih} yMin={0} yMax={yMax} format={format} start={props.start} end={props.end} timeZone={props.timeZone} />
    {props.buckets.map((bk, i) => {
     if (!bk.values) return <GapBand key={bk.start} x1={xOf(bk.start)} x2={xOf(bk.end)} T={T} ih={ih} W={W} text="no samples" />;
     let y = T + ih;
     const x = xOf(bk.start) + 1, w = Math.max(1, xOf(bk.end) - xOf(bk.start) - 2);
     return <g key={bk.start}>{bk.values.map((v, j) => { const h = (v / yMax) * ih; y -= h; return h > 0 ? <rect key={j} className={`ch-f-${props.tones[j] ?? 'c1'}`} x={x} y={y} width={w} height={h} rx="1" /> : null; })}</g>;
    })}
    {(props.gaps ?? []).map((g) => <GapBand key={`${g.from}:${g.to}`} x1={xOf(Math.max(g.from, props.start))} x2={xOf(Math.min(g.to, props.end))} T={T} ih={ih} W={W} text={g.text ?? 'no samples'} />)}
    {props.marks && <Marks marks={props.marks} start={props.start} end={props.end} iw={iw} T={T} ih={ih} />}
    {b && hover !== null && (
     <g className="ch-hover" pointerEvents="none">
      <rect className="ch-bucket" x={xOf(b.start)} y={T} width={Math.max(1, xOf(b.end) - xOf(b.start))} height={ih} />
      <Tip x={(xOf(b.start) + xOf(b.end)) / 2} W={W} top={T + 4} title={`${clock(b.start)}–${clock(b.end)}`} rows={rows} />
     </g>
    )}
   </svg>
   {b && <div className="sr-only" role="status">{`${clock(b.start)}–${clock(b.end)}: ${rows.map((r) => `${r.name} ${r.value}`).join(', ')}`}</div>}
   {props.names.length > 1 && <ul className="legend" aria-label="Series">{props.names.map((n, j) => <li key={n}><i className={`sq c-${props.tones[j] ?? 'c1'}`} aria-hidden="true" />{n}</li>)}</ul>}
  </div>
 );
}

/** A small trend line for a table cell. Missing samples break the line; nothing is drawn as zero. */
export function Sparkline(props: { label: string; samples: readonly Sample[]; start: number; end: number; tone?: SeriesTone; dashed?: boolean }): React.JSX.Element {
 const w = 90, h = 22;
 const vals = props.samples.map((s) => s.v).filter((v): v is number => v !== null);
 const max = Math.max(1e-9, ...vals);
 const gaps = detectGaps(props.samples, props.start, props.end);
 const span = props.end - props.start;
 const pts = (run: Sample[]) => run.map((p) => ({ x: (w * (p.t - props.start)) / span, y: h - 2 - ((p.v ?? 0) / max) * (h - 4) }));
 return (
  <svg className="spark" viewBox={`0 0 ${w} ${h}`} role="img" aria-label={props.label}>
   {runs(props.samples, gaps).map((run, i) => <path key={i} className={`ch-line ch-s-${props.tone ?? 'c1'}`} d={linePath(pts(run))} strokeDasharray={props.dashed ? '3 3' : undefined} />)}
  </svg>
 );
}
