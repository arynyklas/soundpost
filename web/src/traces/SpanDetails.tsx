// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { PathResult, SpanId, SpanReport, SpanTarget } from '../api/types';
import { Pill } from '../ui/primitives';
import { Icon } from '../ui/Icon';
import { detailsOf, flagWords, targetsOf } from './model';

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

/** The recorded details of the selected span, as text. Selecting a span moves focus to the heading, so a keyboard or screen-reader user lands on the result. */
export function SpanDetails(props: {
 path: PathResult; selectedSpan: SpanId | null;
 targets?: readonly SpanTarget[] | undefined; targetHref?: (target: SpanTarget) => string | null;
 /** Where the Logs or Metrics screen opens for the window around this span. */
 windowHref?: (screen: 'logs' | 'metrics', span: SpanReport) => string;
}): React.JSX.Element {
 const { path, selectedSpan } = props;
 const details = detailsOf(path, selectedSpan);
 const selected = selectedSpan === null ? undefined : path.spans.find((s) => s.span_id === selectedSpan);
 const heading = React.useRef<HTMLHeadingElement>(null);
 React.useEffect(() => { if (selectedSpan !== null && details !== null) heading.current?.focus(); }, [selectedSpan]);
 const segment = selected === undefined ? undefined : path.trees.flatMap((t) => t.segments).find((g) => g.span_id === selected.span_id);
 return (
  <section className="card exp-span-details" aria-labelledby="cp-detail-heading" data-testid="span-details">
   <div className="card-head"><h2 id="cp-detail-heading" tabIndex={-1} ref={heading}>Selected span</h2></div>
   <div className="card-body col g12">
    {details === null || selected === undefined ? <p>No span is selected. Choose one on the path or in the waterfall to see its recorded details.</p> : (
     <>
      <div className="row wrap g4">
       <Pill tone={selected.status === 'error' ? 'crit' : 'line'} {...(selected.status === 'error' ? { icon: 'x' as const } : {})}>{`status ${selected.status}`}</Pill>
       <Pill tone="line">{selected.span_kind}</Pill>
       <Pill tone={segment === undefined ? 'unk' : 'acc'}>{segment === undefined ? 'on no critical path' : 'on a critical path'}</Pill>
       {segment?.ambiguous === true && <Pill tone="high" icon="warn">ambiguous branch</Pill>}
       {selected.flags.map((f) => <Pill key={f} tone="line">{flagWords(f)}</Pill>)}
      </div>
      <dl className="props exp-span-props">{details.map((d, i) => <React.Fragment key={`${i}:${d.label}`}><dt>{d.label}</dt><dd>{d.value}</dd></React.Fragment>)}</dl>
      <ul className="exp-span-links">
       {selected && props.targets !== undefined && TARGET_KINDS.flatMap((kind) => targetsOf(props.targets, selected.span_id, kind)).map((t) => <TargetItem key={`${t.kind}:${t.id}`} target={t} href={props.targetHref?.(t) ?? null} />)}
       {selected && props.targets === undefined && selected.job_id && <li>Job <code>{selected.job_id}</code>: open Jobs for this ID; its access is checked there, not here.</li>}
       {selected && props.targets === undefined && selected.replay_id && <li>Replay <code>{selected.replay_id}</code>: open Replays for this ID; its access is checked there, not here.</li>}
       {selected && props.targets === undefined && selected.profile_id && <li>Profile <code>{selected.profile_id}</code>: open Profiles for this ID; its access is checked there, not here.</li>}
       {selected && props.windowHref && <li><Icon name="logs" size="s" /> <a href={props.windowHref('logs', selected)}>Logs in the window of this span</a></li>}
       {selected && props.windowHref && <li><Icon name="chart" size="s" /> <a href={props.windowHref('metrics', selected)}>Metrics in the window of this span</a></li>}
      </ul>
     </>
    )}
   </div>
  </section>
 );
}
