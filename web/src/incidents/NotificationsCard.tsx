// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { formatNs } from '../app/context';
import type { DeliveryEntryView, IncidentView } from '../api/types';
import { Icon } from '../ui/Icon';
import { Card, Pill, type Tone } from '../ui/primitives';
import { deliveryEntryText, deliveryHeadline, digestText, unreadText, urgencyText } from './model';

const STATUS_TONE: Record<DeliveryEntryView['status'], { tone: Tone; word: string }> = {
 accepted: { tone: 'ok', word: 'Accepted' }, failed: { tone: 'crit', word: 'Failed' }, uncertain: { tone: 'unk', word: 'Uncertain' }, retrying: { tone: 'high', word: 'Retrying' },
 sending: { tone: 'info', word: 'Sending' }, pending: { tone: 'info', word: 'Pending' }, queued: { tone: 'line', word: 'In-product queue only' }, suppressed: { tone: 'line', word: 'Suppressed' }, cancelled: { tone: 'line', word: 'Cancelled' },
};

/** Reminders, worse-impact eligibility, urgency, every delivery (a failed or uncertain one is named as such, never called sent), digest and unread change, all from what the
 * notification policy and the durable outbox hold for this incident. A part that is not available says why. */
export function NotificationsCard(props: { view: IncidentView; tz: string; routesHref: string }): React.JSX.Element {
 const { view } = props;
 const n = view.notification;
 const fmt = (ns: string): string => formatNs(ns, props.tz);
 const entries = n.delivery.state === 'ready' ? (n.delivery.entries ?? []) : [];
 const failing = entries.filter((d) => d.status === 'failed').length;
 const uncertain = entries.filter((d) => d.status === 'uncertain').length;
 return (
  <Card title="Notifications" titleId="inc-notify-h" testId="notifications-card" actions={failing + uncertain > 0 ? <Pill tone={failing > 0 ? 'crit' : 'unk'} icon={failing > 0 ? 'x' : 'question'}>{[failing > 0 ? `${failing} failed` : '', uncertain > 0 ? `${uncertain} uncertain` : ''].filter(Boolean).join(', ')}</Pill> : undefined}>
   <div className="col g12" data-section="notifications">
    <ul className="inc-notes">
     <li data-testid="reminders">{n.reminders_paused ? `Reminders are paused by ${n.paused_by === 'ack+snooze' ? 'the acknowledgement and the snooze' : n.paused_by === 'snooze' ? 'the snooze' : 'the acknowledgement'}.` : 'Reminders are not paused.'}</li>
     <li data-testid="worse-impact">{n.worse_impact_eligible ? 'A worse impact is eligible to notify: acknowledging or snoozing does not suppress it.' : `A worse impact is not eligible to notify: ${n.suppressed_by === 'maintenance' ? 'an active maintenance window suppresses new notifications' : 'the incident is resolved, so a worse impact proposes a new linked incident'}.`}</li>
     {n.urgency.state === 'ready' && <li data-testid="urgency">{urgencyText(n.urgency)}</li>}
     <li>
      <span data-testid="delivery" data-attention={n.delivery.attention ?? n.delivery.state} className={n.delivery.attention === 'failed' ? 'inc-bad' : n.delivery.attention === 'uncertain' ? 'inc-unsure' : undefined}>{deliveryHeadline(n.delivery)}</span>
      {entries.length > 0 && (
       <ul className="inc-deliveries" data-testid="delivery-entries">
        {entries.map((d) => <li key={d.id} data-status={d.status}><Pill tone={STATUS_TONE[d.status].tone}>{STATUS_TONE[d.status].word}</Pill><span>{deliveryEntryText(d, fmt)}</span></li>)}
       </ul>
      )}
      {n.delivery.truncated && <p className="xsmall t3">Older deliveries are not listed.</p>}
     </li>
    </ul>
    {/* An evaluated urgency is the card's lead line, above. A not-ready urgency, the digest and digest coverage repeat the same policy sentence on most incidents; they stay here, folded. */}
    <details className="inc-policy">
     <summary>Policy and digest</summary>
     <ul className="inc-notes">
      {n.urgency.state !== 'ready' && <li data-testid="urgency">{urgencyText(n.urgency)}</li>}
      <li data-testid="digest">{digestText(n.digest, fmt)}</li>
      <li data-testid="unread">{unreadText(n.unread_change)}</li>
     </ul>
    </details>
    <a className="btn btn-sm inc-self-start" href={props.routesHref}><Icon name="route" size="s" />Open notification routes</a>
   </div>
  </Card>
 );
}
