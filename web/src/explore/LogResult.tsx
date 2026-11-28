// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { ProjectResult } from '../api/types';
import { BarChart } from '../ui/chart/Chart';
import { DataTable } from '../ui/primitives';
import { nsToMs } from './chartModel';
import { logHistogram, widthWords } from './logModel';
import { emptyWords, entriesInOrder, labelsText, type OrderedEntry } from './model';
import { TimeText } from './MetricResult';

const PAGE = 500;

/** What the histogram needs to know about the request that produced the result. */
export interface LogContext { window: { start: string; end: string }; order: 'backward' | 'forward'; timeZone: string }

function Histogram(props: { rows: OrderedEntry[]; result: ProjectResult; log: LogContext }): React.JSX.Element | null {
 const { rows, result, log } = props;
 const h = React.useMemo(
  () => logHistogram({ entries: rows.map((r) => r.entry), window: log.window, complete: result.completeness === 'complete' && result.failure === undefined, limitReached: result.stats.limit_reached, order: log.order }),
  [rows, result, log.window, log.order],
 );
 if (h === null) return null;
 return (
  <div className="exp-hist" data-testid="log-histogram">
   <h4>Lines per {widthWords(h.width).replace(/^1 /, '')}</h4>
   <BarChart label={`Lines per ${widthWords(h.width)} held for project ${result.project_id.slice(0, 8)}. A bucket with no samples is drawn as a gap, never as zero.`} buckets={h.buckets} names={['lines']} tones={['c1']} start={nsToMs(log.window.start)} end={nsToMs(log.window.end)} timeZone={log.timeZone} height={100} />
   <p className="small t3">{h.note}</p>
  </div>
 );
}

/** A project's log streams as one table in the language-defined order. Every line, label and value is a text node: no log text
 * is ever interpreted as markup. Stream labels and structured metadata are separate columns, nothing is renamed or merged, and
 * two entries at the same nanosecond are two rows with their own position and record ID. */
export function LogResult(props: { result: ProjectResult; log?: LogContext }): React.JSX.Element {
 const v = props.result.value;
 const [shown, setShown] = React.useState(PAGE);
 const rows = React.useMemo(() => (v !== null && v.type === 'streams' ? entriesInOrder(v.streams) : []), [v]);
 if (v === null) return <p role="status" data-result="none">No value: this project returned no result.</p>;
 if (v.type !== 'streams') return <p role="status" data-result="not-logs">This result is not a log stream; it is shown as a metric result.</p>;
 if (rows.length === 0) return <p data-result="logs-empty">{emptyWords(props.result, 'No log entry matched')}</p>;
 const label = `Log lines of project ${props.result.project_id.slice(0, 8)}`;
 return (
  <div data-result="logs" className="exp-logs">
   {props.log !== undefined && <Histogram rows={rows} result={props.result} log={props.log} />}
   <DataTable
    label={label} testId="log-table" tight rows={rows.slice(0, shown)} rowKey={(r) => r.entry.index} rowAttrs={(r) => ({ 'data-entry': '', 'data-index': r.entry.index, 'data-time': r.entry.time })}
    caption={`${rows.length} log ${rows.length === 1 ? 'entry' : 'entries'} in ${v.streams.length} ${v.streams.length === 1 ? 'stream' : 'streams'}, in the language-defined order. Lines are the immutable safe rendering of their template revision.`}
    columns={[
     { key: 'index', header: 'Position', cell: (r) => <code>{r.entry.index}</code> },
     { key: 'time', header: 'Time (nanoseconds)', label: 'Time', cell: (r) => <TimeText ns={r.entry.time} /> },
     { key: 'line', header: 'Line', cell: (r) => <><code className="exp-line" data-line>{r.entry.line}</code>{r.entry.multiplicity !== '1' && <small> (× {r.entry.multiplicity} identical entries)</small>}</> },
     { key: 'stream', header: 'Stream labels', cell: (r) => <span data-cell="stream-labels"><code>{labelsText(r.streamLabels)}</code></span> },
     { key: 'meta', header: 'Structured metadata', cell: (r) => <span data-cell="structured-metadata">{r.entry.structured_metadata.length === 0 ? <small>none</small> : <code>{labelsText(r.entry.structured_metadata)}</code>}</span> },
     { key: 'record', header: 'Record', cell: (r) => <><code>{r.entry.id}</code>{r.entry.source !== undefined && <small> source <code>{r.entry.source}</code></small>}</> },
    ]}
   />
   {rows.length > shown && <button type="button" className="btn btn-sm" onClick={() => setShown(shown + PAGE)}>Show more entries ({shown} shown of {rows.length})</button>}
  </div>
 );
}
