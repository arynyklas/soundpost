// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { ProjectResult } from '../api/types';
import { entriesInOrder, labelsText } from './model';
import { TimeText } from './MetricResult';

const PAGE = 500;

/** A project's log streams as one table in the language-defined order. Every line, label and value is a text node: no log text
 * is ever interpreted as markup. Stream labels and structured metadata are separate columns, nothing is renamed or merged, and
 * two entries at the same nanosecond are two rows with their own position and record ID. */
export function LogResult(props: { result: ProjectResult }): React.JSX.Element {
 const v = props.result.value;
 const [shown, setShown] = React.useState(PAGE);
 const rows = React.useMemo(() => (v !== null && v.type === 'streams' ? entriesInOrder(v.streams) : []), [v]);
 if (v === null) return <p role="status" data-result="none">No value: this project returned no result.</p>;
 if (v.type !== 'streams') return <p role="status" data-result="not-logs">This result is not a log stream; it is shown as a metric result.</p>;
 if (rows.length === 0) return <p data-result="logs-empty">No log entry matched. Nothing is missing.</p>;
 return (
  <>
   <table className="data-table log-table" data-result="logs">
    <caption>{rows.length} log {rows.length === 1 ? 'entry' : 'entries'} in {v.streams.length} {v.streams.length === 1 ? 'stream' : 'streams'}, in the language-defined order. Lines are the immutable safe rendering of their template revision.</caption>
    <thead><tr><th scope="col">Position</th><th scope="col">Time (nanoseconds)</th><th scope="col">Line</th><th scope="col">Stream labels</th><th scope="col">Structured metadata</th><th scope="col">Record</th></tr></thead>
    <tbody>
     {rows.slice(0, shown).map(({ entry, streamLabels }) => (
      <tr key={entry.index} data-entry data-index={entry.index} data-time={entry.time}>
       <th scope="row"><code>{entry.index}</code></th>
       <td><TimeText ns={entry.time} /></td>
       <td><code className="log-line" data-line>{entry.line}</code>{entry.multiplicity !== '1' && <small> (× {entry.multiplicity} identical entries)</small>}</td>
       <td data-cell="stream-labels"><code>{labelsText(streamLabels)}</code></td>
       <td data-cell="structured-metadata">{entry.structured_metadata.length === 0 ? <small>none</small> : <code>{labelsText(entry.structured_metadata)}</code>}</td>
       <td><code>{entry.id}</code>{entry.source !== undefined && <small> source <code>{entry.source}</code></small>}</td>
      </tr>
     ))}
    </tbody>
   </table>
   {rows.length > shown && <button type="button" onClick={() => setShown(shown + PAGE)}>Show more entries ({shown} shown of {rows.length})</button>}
  </>
 );
}
