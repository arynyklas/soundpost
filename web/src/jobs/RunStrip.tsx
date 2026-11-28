// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { RUN_KINDS, RUN_KIND_WORD, STRIP_WIDTH, stripText, type StripState } from './strip';

/** The runs of a job at the instants they started, drawn across the scope's window. The drawing has a text alternative that says the same thing in words; a window with no run says so, and a job whose runs could not be read is not drawn as having none. */
export function RunStrip(props: { state: StripState; /** What the drawing is of, for its accessible name. */ job: string }): React.JSX.Element {
 const { state } = props;
 if (state.kind === 'loading') return <span className="xsmall t3" data-testid="run-strip" data-state="loading">Reading runs…</span>;
 if (state.kind === 'failed') return <span className="xsmall t3" data-testid="run-strip" data-state="failed">Runs could not be read, so none are drawn.</span>;
 const { strip } = state;
 const text = stripText(strip);
 return (
  <span className="job-strip-wrap" data-testid="run-strip" data-state="ready">
   <svg className="job-strip" viewBox={`0 0 ${STRIP_WIDTH} 22`} preserveAspectRatio="none" role="img" aria-label={`Runs of job ${props.job}: ${text}`}>
    {[0.25, 0.5, 0.75].map((f) => <line key={f} className="job-grid" x1={STRIP_WIDTH * f} x2={STRIP_WIDTH * f} y1="0" y2="22" />)}
    {strip.marks.map((m) => <rect key={m.id} className={`job-r job-r-${m.kind}`} x={Math.max(0, m.x - 1.5)} y="3" width="3" height="16" rx="1" />)}
    {strip.expected.map((x) => <rect key={`e${x}`} className="job-r-expected" x={Math.max(0, x - 3)} y="3" width="6" height="16" rx="1.5" />)}
   </svg>
  </span>
 );
}

/** The key to the colours of the strip, in words: colour never carries a state alone. */
export function StripLegend(): React.JSX.Element {
 return (
  <ul className="job-legend" aria-label="What the marks of the run strip mean">
   {RUN_KINDS.map((k) => <li key={k}><i className={`job-sw job-sw-${k}`} aria-hidden="true" />{RUN_KIND_WORD[k]}</li>)}
   <li><i className="job-sw job-sw-expected" aria-hidden="true" />expected run, no record</li>
  </ul>
 );
}
