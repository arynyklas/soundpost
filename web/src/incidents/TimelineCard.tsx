// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { formatNs } from '../app/context';
import { clockText } from '../shell/ScopeControls';
import { Icon } from '../ui/Icon';
import { Card, FilterChips, cx, shortId } from '../ui/primitives';
import { LANE_FILTERS, filterTimeline, laneCounts, type LaneFilter, type TimelineItem } from './timelineModel';

/** One timeline entry. Text a person wrote (a note, a reason, a title) is rendered as plain text only. */
export function TimelineEntryRow(props: { item: TimelineItem; tz: string; nameOf: (id: string) => string | undefined }): React.JSX.Element {
 const { item, tz } = props;
 const who = item.actor === undefined ? undefined : props.nameOf(item.actor) ?? (item.system ? 'System' : shortId(item.actor));
 const owner = item.owner === undefined ? undefined : props.nameOf(item.owner) ?? shortId(item.owner);
 const full = formatNs(item.at, tz);
 return (
  <li data-version={item.version} data-type={item.type} data-lane={item.lane}>
   <span className="when"><time dateTime={new Date(Number(BigInt(item.at) / 1_000_000n)).toISOString()}><span aria-hidden="true">{clockText(item.at, tz, true)}</span><span className="sr-only">{full}</span></time></span>
   <span className={cx('mark', item.system && 'mark-sys', `mark-${item.tone}`)} aria-hidden="true"><Icon name={item.icon} size="xs" /></span>
   <div className="what">
    <div><span className={cx('lane', `lane-${item.lane}`)}>{item.tag}</span>{who !== undefined && <b title={item.actor}>{who}</b>}{who !== undefined && ' '}{item.text}{owner !== undefined && <> <b title={item.owner}>{owner}</b></>}</div>
    {item.quote && <div className="quote inc-quote">{item.quote}</div>}
   </div>
  </li>
 );
}

/** The incident timeline with lane filters. Every chip's count is the number of entries it would show. */
export function TimelineCard(props: { items: readonly TimelineItem[]; tz: string; nameOf: (id: string) => string | undefined; composer: React.ReactNode; initial?: LaneFilter }): React.JSX.Element {
 const [lane, setLane] = React.useState<LaneFilter>(props.initial ?? 'all');
 const counts = laneCounts(props.items);
 const shown = filterTimeline(props.items, lane);
 return (
  <Card title="Timeline" titleId="inc-timeline-h" actions={<FilterChips label="Timeline lanes" value={lane} onChange={setLane} options={LANE_FILTERS.map((f) => ({ value: f.value, label: f.label, count: counts[f.value] }))} />} testId="timeline-card">
   <div className="col g12">
    {props.composer}
    {shown.length === 0
     ? <p className="t2" role="status" data-state="empty">{lane === 'all' ? 'Nothing is recorded on this incident yet.' : 'No entry in this lane. Nothing is hidden: the other lanes are one chip away.'}</p>
     : <ol className="events inc-timeline" aria-label="Timeline entries, newest first">{shown.map((i) => <TimelineEntryRow key={i.key} item={i} tz={props.tz} nameOf={props.nameOf} />)}</ol>}
   </div>
  </Card>
 );
}
