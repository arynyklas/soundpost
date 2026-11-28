// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// This file projects what the durable notification outbox (control.Deliveries)
// and the committed notification policy state (control.PolicyRecords) hold about
// one incident into the queue and the incident view: its urgency tier, every
// delivery with its attempt outcome (failed and uncertain stay visible), the
// digest state and whether the incident changed since the last digest covered
// it. Nothing here decides or sends anything and nothing is inferred: a section
// the committed state cannot answer says why (no policy has evaluated the
// incident yet, or the reader is not wired) and is never empty-and-healthy.

// Reason codes of the notification projection: closed static strings.
const (
	ReasonOutboxNotWired   = "notification_outbox_not_wired"
	ReasonNoPolicyState    = "no_notification_policy_state"
	ReasonNoDeliveries     = "no_delivery_created"
	ReasonNoDigestSchedule = "no_digest_recipient"
)

// NotificationReader reads the committed notification outbox and policy state of
// one project under scope; *control.Store implements it.
type NotificationReader interface {
	Deliveries(ctx context.Context, scope auth.Scope, project model.ID, phase string, now model.UnixNano, limit int) ([]control.DeliveryRecord, error)
	PolicyRecords(ctx context.Context, scope auth.Scope, project model.ID) ([]control.PolicyRecord, error)
}

// MaxDeliveryEntries bounds the deliveries listed on one incident (newest
// first); the counts always cover all of them.
const MaxDeliveryEntries = 8

// UrgencyView is the canonical urgency tier the notification policy computed:
// urgent notifies immediately, queue is visible at once and is a digest
// candidate, none is no notifiable evidence. Mode shadow means nothing leaves
// the product.
type UrgencyView struct {
	State       ViewState `json:"state"`
	Reason      string    `json:"reason,omitempty"`
	Tier        string    `json:"tier,omitempty"`
	Mode        string    `json:"mode,omitempty"`
	EpisodeOpen bool      `json:"episode_open,omitempty"`
}

// DeliveryEntryView is one outbox delivery. Status is one of accepted, failed,
// uncertain, retrying, sending, pending, queued, suppressed, cancelled; uncertain
// means the provider may have accepted a message the product could not confirm.
type DeliveryEntryView struct {
	ID                model.ID    `json:"id"`
	Kind              string      `json:"kind"`
	Route             string      `json:"route"`
	Phase             string      `json:"phase"`
	Status            string      `json:"status"`
	Code              string      `json:"code,omitempty"`
	Hold              string      `json:"hold,omitempty"`
	Attempts          uint32      `json:"attempts"`
	LastOutcome       string      `json:"last_outcome,omitempty"`
	LastCode          string      `json:"last_code,omitempty"`
	LastAt            model.Int64 `json:"last_at,omitempty"`
	NextAt            model.Int64 `json:"next_at,omitempty"`
	Eligible          model.Int64 `json:"eligible_at"`
	Recipient         *model.ID   `json:"recipient,omitempty"`
	Uncertain         bool        `json:"uncertain,omitempty"`
	PossibleDuplicate bool        `json:"possible_duplicate,omitempty"`
}

// DeliverySummaryView is the delivery state of one incident. Attention is the
// most urgent thing a reader must see: failed, uncertain, held, pending,
// accepted, or none.
type DeliverySummaryView struct {
	State     ViewState           `json:"state"`
	Reason    string              `json:"reason,omitempty"`
	Attention string              `json:"attention,omitempty"`
	Counts    map[string]uint32   `json:"counts,omitempty"`
	Entries   []DeliveryEntryView `json:"entries,omitempty"`
	Truncated bool                `json:"truncated,omitempty"`
}

// DigestView is the daily digest state. NextAt is the earliest next digest of an
// enabled recipient; Pending says a queue-visible change is not covered by the
// last digest yet. Entries are visible in the queue at once either way.
type DigestView struct {
	State   ViewState   `json:"state"`
	Reason  string      `json:"reason,omitempty"`
	NextAt  model.Int64 `json:"next_at,omitempty"`
	Pending bool        `json:"pending,omitempty"`
	Sent    uint32      `json:"sent"`
}

// UnreadView says whether the incident changed in a queue-visible way since the
// last delivered digest covered it. Soundpost keeps no per-reader read marker:
// this is the digest coverage, and the view says so.
type UnreadView struct {
	State         ViewState    `json:"state"`
	Reason        string       `json:"reason,omitempty"`
	Changed       bool         `json:"changed"`
	QueueRevision model.Uint64 `json:"queue_revision"`
	SeenRevision  model.Uint64 `json:"seen_revision"`
}

// notificationFacts is the committed outbox and policy state of one project,
// read once and indexed by incident.
type notificationFacts struct {
	wired      bool
	deliveries map[string][]control.DeliveryRecord
	states     map[string][]notify.PolicyState
}

func incidentSubject(id model.ID) string { return string(notify.EntityIncident) + ":" + id.String() }

// notificationFacts reads the project's deliveries and policy state. Without a
// wired reader the result says so (every section then answers not_available with
// ReasonOutboxNotWired); a read or decode failure is returned, never hidden.
func (a *Actions) notificationFacts(ctx context.Context, scope auth.Scope, project model.ID) (notificationFacts, error) {
	if a.notices == nil {
		return notificationFacts{}, nil
	}
	f := notificationFacts{wired: true, deliveries: map[string][]control.DeliveryRecord{}, states: map[string][]notify.PolicyState{}}
	recs, err := a.notices.Deliveries(ctx, scope, project, "", a.clock.Now(), 0)
	if err != nil {
		return notificationFacts{}, err
	}
	for _, r := range recs {
		f.deliveries[r.Subject] = append(f.deliveries[r.Subject], r)
	}
	policies, err := a.notices.PolicyRecords(ctx, scope, project)
	if err != nil {
		return notificationFacts{}, err
	}
	for _, p := range policies {
		if notify.IsEventSubject(p.Subject) {
			continue // the event webhook feed cursor is not a notification policy state
		}
		if len(p.State) == 0 || string(p.State) == "null" {
			continue // a retirement erased the opaque state: nothing to read
		}
		var st notify.PolicyState
		if json.Unmarshal(p.State, &st) != nil {
			return notificationFacts{}, model.Fail(model.Corrupt)
		}
		f.states[p.Subject] = append(f.states[p.Subject], st)
	}
	return f, nil
}

func tierRank(t notify.Tier) int {
	switch t {
	case notify.TierUrgent:
		return 2
	case notify.TierQueue:
		return 1
	}
	return 0
}

// apply fills the notification sections of v from the incident's own subject.
func (f notificationFacts) apply(v *IncidentView) {
	n := &v.Notification
	if !f.wired {
		n.Urgency.State, n.Urgency.Reason = StateNotAvailable, ReasonOutboxNotWired
		n.Delivery.State, n.Delivery.Reason = StateNotAvailable, ReasonOutboxNotWired
		n.Digest.State, n.Digest.Reason = StateNotAvailable, ReasonOutboxNotWired
		n.Unread.State, n.Unread.Reason = StateNotAvailable, ReasonOutboxNotWired
		return
	}
	subject := incidentSubject(v.ID)
	applyPolicy(n, f.states[subject])
	applyDeliveries(n, f.deliveries[subject])
}

func applyPolicy(n *NotificationView, states []notify.PolicyState) {
	if len(states) == 0 {
		// No policy has evaluated this incident (for instance no enabled
		// destination exists): there is no tier, and none is invented.
		n.Urgency.State, n.Urgency.Reason = StateEmpty, ReasonNoPolicyState
		n.Digest.State, n.Digest.Reason = StateEmpty, ReasonNoPolicyState
		n.Unread.State, n.Unread.Reason = StateEmpty, ReasonNoPolicyState
		return
	}
	best := states[0]
	for _, s := range states[1:] {
		if tierRank(s.Tier) > tierRank(best.Tier) {
			best = s
		}
	}
	n.Urgency = UrgencyView{State: StateReady, Tier: string(best.Tier), Mode: string(best.Mode), EpisodeOpen: best.EpisodeOpen}
	var next model.UnixNano
	seen, enabled := uint64(0), 0
	for _, r := range best.Recipients {
		if !r.Enabled {
			continue
		}
		if enabled == 0 || r.DigestSeen < seen {
			seen = r.DigestSeen
		}
		enabled++
		if r.DigestNext != 0 && (next == 0 || r.DigestNext < next) {
			next = r.DigestNext
		}
	}
	if enabled == 0 {
		n.Digest.State, n.Digest.Reason = StateEmpty, ReasonNoDigestSchedule
		n.Unread.State, n.Unread.Reason = StateEmpty, ReasonNoDigestSchedule
		return
	}
	changed := best.QueueRevision > seen
	n.Digest = DigestView{State: StateReady, NextAt: model.Int64(next), Pending: changed && best.Tier != notify.TierNone}
	n.Unread = UnreadView{State: StateReady, Changed: changed, QueueRevision: model.Uint64(best.QueueRevision), SeenRevision: model.Uint64(seen)}
}

// deliveryStatus names one delivery in words a reader can act on. A claimed or
// pending delivery that already had an unknown attempt is uncertain, not merely
// pending.
func deliveryStatus(r control.DeliveryRecord) string {
	switch r.Phase {
	case control.DeliveryPending, control.DeliveryClaimed:
		if r.Uncertain {
			return "uncertain"
		}
		if n := len(r.Attempts); n > 0 && r.Attempts[n-1].Outcome == control.DeliveryOutcomeRetry {
			return "retrying"
		}
		if r.Phase == control.DeliveryClaimed {
			return "sending"
		}
		return "pending"
	}
	return r.Phase
}

// attention ranks, lowest first; the summary shows the highest one present.
var attentionOrder = []string{"none", "accepted", "pending", "held", "uncertain", "failed"}

func applyDeliveries(n *NotificationView, recs []control.DeliveryRecord) {
	if len(recs) == 0 {
		n.Delivery = DeliverySummaryView{State: StateEmpty, Reason: ReasonNoDeliveries, Attention: "none"}
		return
	}
	slices.SortStableFunc(recs, func(x, y control.DeliveryRecord) int {
		if x.Eligible != y.Eligible {
			if x.Eligible > y.Eligible {
				return -1
			}
			return 1
		}
		return strings.Compare(y.ID.String(), x.ID.String())
	})
	d := DeliverySummaryView{State: StateReady, Counts: map[string]uint32{}}
	attention := 0
	raise := func(s string) {
		if i := slices.Index(attentionOrder, s); i > attention {
			attention = i
		}
	}
	for i, r := range recs {
		st := deliveryStatus(r)
		d.Counts[st]++
		switch {
		case st == "failed":
			raise("failed")
		case st == "uncertain":
			raise("uncertain")
		case r.Hold != "" && r.Open():
			raise("held")
		case r.Open():
			raise("pending")
		case st == control.DeliveryAccepted:
			raise("accepted")
		}
		if r.Route == control.DeliveryRouteDigest && st == control.DeliveryAccepted {
			n.Digest.Sent++
		}
		if i >= MaxDeliveryEntries {
			d.Truncated = true
			continue
		}
		e := DeliveryEntryView{ID: r.ID, Kind: r.Kind, Route: r.Route, Phase: r.Phase, Status: st, Code: r.Code, Hold: r.Hold, Attempts: uint32(len(r.Attempts)),
			NextAt: model.Int64(r.Next), Eligible: model.Int64(r.Eligible), Recipient: r.Recipient, Uncertain: r.Uncertain, PossibleDuplicate: r.PossibleDuplicate}
		for j := len(r.Attempts) - 1; j >= 0; j-- {
			if a := r.Attempts[j]; a.Outcome != "" {
				e.LastOutcome, e.LastCode, e.LastAt = a.Outcome, a.Code, model.Int64(a.ClosedAt)
				break
			}
		}
		d.Entries = append(d.Entries, e)
	}
	d.Attention = attentionOrder[attention]
	n.Delivery = d
}
