// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"reflect"
	"sort"
	"strings"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// The private notification ledger records what one side actually decided and
// delivered, at delivery-attempt granularity. It is the legacy side's input to
// the policy comparison. Recipients appear only as keyed pseudonyms
// (LedgerRecipientKey): the ledger has no field that can hold an address, and a
// pseudonym is not a public value. Nothing here is a public projection; the
// closed public shapes are LedgerStats and PolicyPublicSummary.

// LedgerOutcome is the closed result of one delivery attempt.
type LedgerOutcome string

const (
	ledgerDelivered  LedgerOutcome = "delivered"
	ledgerSuppressed LedgerOutcome = "suppressed"
	ledgerFailed     LedgerOutcome = "failed"
	// ledgerUnknown: the provider may have accepted the message.
	ledgerUnknown LedgerOutcome = "unknown"
)

// LedgerTrigger is why the old owner decided to notify. The adoption operator
// normalizes the legacy rule that fired into this closed vocabulary.
type LedgerTrigger string

const (
	ledgerTriggerOther             LedgerTrigger = "other"
	ledgerTriggerPerOccurrence     LedgerTrigger = "per_occurrence"
	ledgerTriggerCount             LedgerTrigger = "count"
	ledgerTriggerRate              LedgerTrigger = "rate"
	ledgerTriggerRateNoDenominator LedgerTrigger = "rate_unknown_denominator"
	ledgerTriggerImpact            LedgerTrigger = "impact"
	ledgerTriggerRegression        LedgerTrigger = "regression"
	ledgerTriggerCriticalCode      LedgerTrigger = "critical_code"
	ledgerTriggerReminderTimer     LedgerTrigger = "reminder_timer"
	ledgerTriggerSourceRecovery    LedgerTrigger = "source_recovery"
	ledgerTriggerIncidentResolve   LedgerTrigger = "incident_resolve"
	ledgerTriggerManual            LedgerTrigger = "manual"
)

// LedgerEntry is one delivery attempt of the old owner. AttemptID is the
// delivery idempotency identifier shared by every retry of one delivery;
// Attempt numbers the tries from 1. EventTime is when the evidence happened,
// DeliveredAt when the attempt was made (zero when none was), SourceVersion the
// version of the source evidence the decision was made at.
type LedgerEntry struct {
	Entity         notify.Entity  `json:"entity"`
	Kind           notify.Kind    `json:"kind"`
	ImpactRevision uint64         `json:"impact_revision"`
	Ordinal        uint64         `json:"ordinal"`
	Recipient      *model.ID      `json:"recipient_key,omitempty"`
	AttemptID      string         `json:"attempt_id"`
	Attempt        uint32         `json:"attempt"`
	EventTime      model.UnixNano `json:"event_time_ns"`
	DeliveredAt    model.UnixNano `json:"delivered_at_ns,omitempty"`
	SourceVersion  uint64         `json:"source_version"`
	Outcome        LedgerOutcome  `json:"outcome"`
	Suppression    notify.Code    `json:"suppression,omitempty"`
	Trigger        LedgerTrigger  `json:"trigger"`
}

// LedgerStats are the closed, count-only facts of one ledger reduction.
type LedgerStats struct {
	Entries             int `json:"entries"`
	Deliveries          int `json:"deliveries"`
	Retries             int `json:"retries"`
	Duplicates          int `json:"duplicates"`
	DuplicateDeliveries int `json:"duplicate_deliveries"`
	Late                int `json:"late"`
}

// ledgerRecord is one reduced logical delivery.
type ledgerRecord struct {
	Entry LedgerEntry
}

type ledgerReduction struct {
	Records             []ledgerRecord
	Late                []ledgerRecord
	DuplicateDeliveries []ledgerRecord
	Stats               LedgerStats
	Findings            []PolicyFinding
}

const (
	ledgerMaxEntries    = 100000
	ledgerMinKeyBytes   = 32
	ledgerMaxAttemptLen = 64
)

// LedgerRecipientKey derives the keyed pseudonym of a raw recipient handle:
// HMAC-SHA-256 over a domain label and the handle, truncated to a model.ID. Only
// the returned ID may be stored or reported; the raw handle and the key must
// stay with the operator. Surrounding whitespace is ignored and nothing else is
// normalized, so the operator must hash the same spelling on both sides.
func LedgerRecipientKey(key []byte, raw string) (model.ID, error) {
	raw = strings.TrimSpace(raw)
	if len(key) < ledgerMinKeyBytes || raw == "" {
		return model.ID{}, errors.New("recipient key needs a secret of at least 32 bytes and a non-empty handle")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("soundpost/adoption/ledger-recipient/v1\x00"))
	mac.Write([]byte(raw))
	var id model.ID
	copy(id[:], mac.Sum(nil))
	if id == (model.ID{}) {
		return model.ID{}, errors.New("degenerate recipient key")
	}
	return id, nil
}

func ledgerEntityValid(e notify.Entity) bool {
	switch e.Kind {
	case notify.EntityIssue, notify.EntityCondition, notify.EntityIncident:
		return e.ID != (model.ID{})
	}
	return false
}

func ledgerKindValid(k notify.Kind) bool {
	switch k {
	case notify.KindOpen, notify.KindReminder, notify.KindWorseImpact, notify.KindRecovery, notify.KindResolution, notify.KindCurrent, notify.KindQueue, notify.KindDigest:
		return true
	}
	return false
}

func ledgerTriggerValid(t LedgerTrigger) bool {
	switch t {
	case ledgerTriggerOther, ledgerTriggerPerOccurrence, ledgerTriggerCount, ledgerTriggerRate, ledgerTriggerRateNoDenominator, ledgerTriggerImpact,
		ledgerTriggerRegression, ledgerTriggerCriticalCode, ledgerTriggerReminderTimer, ledgerTriggerSourceRecovery, ledgerTriggerIncidentResolve, ledgerTriggerManual:
		return true
	}
	return false
}

func ledgerSafeName(s string) bool {
	if s == "" || len(s) > ledgerMaxAttemptLen {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '.', r == ':', r == '-':
		default:
			return false
		}
	}
	return true
}

// ledgerValidate refuses a malformed entry outright: closed enums, identifiers
// and the relation between outcome, suppression code and delivery time.
func ledgerValidate(e LedgerEntry) error {
	switch {
	case !ledgerEntityValid(e.Entity):
		return errors.New("ledger entry has an invalid entity")
	case !ledgerKindValid(e.Kind):
		return errors.New("ledger entry has an unknown kind")
	case e.Recipient != nil && *e.Recipient == (model.ID{}):
		return errors.New("ledger entry has a zero recipient key")
	case !ledgerSafeName(e.AttemptID):
		return errors.New("ledger entry has an invalid attempt identifier")
	case e.Attempt == 0:
		return errors.New("ledger attempts are numbered from 1")
	case e.EventTime <= 0:
		return errors.New("ledger entry has no event time")
	case !ledgerTriggerValid(e.Trigger):
		return errors.New("ledger entry has an unknown trigger")
	}
	switch e.Outcome {
	case ledgerDelivered, ledgerFailed, ledgerUnknown:
		if e.DeliveredAt <= 0 || e.Suppression != notify.CodeNone {
			return errors.New("an attempted delivery needs a delivery time and no suppression code")
		}
	case ledgerSuppressed:
		if e.DeliveredAt != 0 {
			return errors.New("a suppressed decision has no delivery time")
		}
		switch e.Suppression {
		case notify.CodeMaintenance, notify.CodeSnoozed, notify.CodeNoDestination:
		default:
			return errors.New("a suppressed decision needs a closed suppression code")
		}
	default:
		return errors.New("ledger entry has an unknown outcome")
	}
	return nil
}

// ledgerKey identifies one decision towards one recipient.
type ledgerKey struct {
	Entity       notify.Entity
	Kind         notify.Kind
	Impact       uint64
	Ordinal      uint64
	Recipient    model.ID
	HasRecipient bool
}

func ledgerKeyOf(e LedgerEntry) ledgerKey {
	k := ledgerKey{Entity: e.Entity, Kind: e.Kind, Impact: e.ImpactRevision, Ordinal: e.Ordinal}
	if e.Recipient != nil {
		k.Recipient, k.HasRecipient = *e.Recipient, true
	}
	return k
}

func ledgerKeyLess(a, b ledgerKey) bool {
	switch {
	case a.Entity.Kind != b.Entity.Kind:
		return a.Entity.Kind < b.Entity.Kind
	case a.Entity.ID != b.Entity.ID:
		return a.Entity.ID.String() < b.Entity.ID.String()
	case a.Kind != b.Kind:
		return a.Kind < b.Kind
	case a.Impact != b.Impact:
		return a.Impact < b.Impact
	case a.Ordinal != b.Ordinal:
		return a.Ordinal < b.Ordinal
	case a.HasRecipient != b.HasRecipient:
		return !a.HasRecipient
	}
	return a.Recipient.String() < b.Recipient.String()
}

// ledgerEntryLess is a total order over entries, so a reduction never depends
// on the order the operator listed them in.
func ledgerEntryLess(a, b LedgerEntry) bool {
	switch {
	case a.AttemptID != b.AttemptID:
		return a.AttemptID < b.AttemptID
	case a.Attempt != b.Attempt:
		return a.Attempt < b.Attempt
	case a.DeliveredAt != b.DeliveredAt:
		return a.DeliveredAt < b.DeliveredAt
	case a.Outcome != b.Outcome:
		return a.Outcome < b.Outcome
	case a.EventTime != b.EventTime:
		return a.EventTime < b.EventTime
	case a.SourceVersion != b.SourceVersion:
		return a.SourceVersion < b.SourceVersion
	case a.Trigger != b.Trigger:
		return a.Trigger < b.Trigger
	case a.Suppression != b.Suppression:
		return a.Suppression < b.Suppression
	}
	ka, kb := ledgerKeyOf(a), ledgerKeyOf(b)
	return ledgerKeyLess(ka, kb)
}

func ledgerClone(e LedgerEntry) LedgerEntry {
	if e.Recipient != nil {
		r := *e.Recipient
		e.Recipient = &r
	}
	return e
}

// ledgerAttempted reports that the provider may have the message.
func ledgerAttempted(e LedgerEntry) bool {
	return e.Outcome == ledgerDelivered || e.Outcome == ledgerUnknown
}

// ledgerImmediate reports that the kind interrupts a person at once.
func ledgerImmediate(k notify.Kind) bool { return k != notify.KindQueue && k != notify.KindDigest }

func ledgerSortFindings(f []PolicyFinding) {
	sort.Slice(f, func(i, j int) bool {
		if f[i].Code != f[j].Code {
			return f[i].Code < f[j].Code
		}
		return f[i].Subject < f[j].Subject
	})
}

// ledgerReduce collapses a delivery-attempt ledger to one record per logical
// decision, by delivery attempt, event time and source version:
//
//   - entries sharing an AttemptID are retries of one delivery; an attempt that
//     reached the provider wins, otherwise the last attempt does;
//   - an identical entry again is a duplicate record, not a second delivery;
//   - a delivery of older source evidence than one the same entity already had
//     delivered is late: it is excluded and is never the current state;
//   - two separate delivery attempts of one decision keep the one that was
//     delivered, then the newest source version; any further delivered copy is
//     a duplicate delivery the recipient actually received.
//
// Defects that make the ledger untrustworthy (one attempt ID for two decisions,
// two outcomes for one attempt, a delivery before its event) are blocker
// findings, never silently repaired. The result does not depend on input order.
func ledgerReduce(entries []LedgerEntry) (ledgerReduction, error) {
	var red ledgerReduction
	if len(entries) > ledgerMaxEntries {
		return red, errors.New("ledger exceeds the entry bound")
	}
	for _, e := range entries {
		if err := ledgerValidate(e); err != nil {
			return red, err
		}
	}
	red.Stats.Entries = len(entries)
	sorted := make([]LedgerEntry, len(entries))
	for i, e := range entries {
		sorted[i] = ledgerClone(e)
	}
	sort.SliceStable(sorted, func(i, j int) bool { return ledgerEntryLess(sorted[i], sorted[j]) })
	seen := map[PolicyFinding]bool{}
	finding := func(code, subject string) {
		f := PolicyFinding{Code: code, Blocker: true, Subject: subject}
		if !seen[f] {
			seen[f] = true
			red.Findings = append(red.Findings, f)
		}
	}

	// 1. One representative per delivery attempt identifier.
	var reps []LedgerEntry
	for lo := 0; lo < len(sorted); {
		hi := lo
		for hi < len(sorted) && sorted[hi].AttemptID == sorted[lo].AttemptID {
			hi++
		}
		group := sorted[lo:hi]
		lo = hi
		base := group[0]
		var attempts []LedgerEntry
		for _, e := range group {
			switch {
			case ledgerKeyOf(e) != ledgerKeyOf(base) || e.SourceVersion != base.SourceVersion || e.EventTime != base.EventTime:
				finding("ledger_attempt_conflict", base.AttemptID)
			case len(attempts) > 0 && attempts[len(attempts)-1].Attempt == e.Attempt:
				if reflect.DeepEqual(attempts[len(attempts)-1], e) {
					red.Stats.Duplicates++
				} else {
					finding("ledger_attempt_conflict", base.AttemptID)
				}
			default:
				attempts = append(attempts, e)
			}
		}
		red.Stats.Retries += len(attempts) - 1
		rep := attempts[len(attempts)-1]
		for i := len(attempts) - 1; i >= 0; i-- {
			if attempts[i].Outcome == ledgerDelivered {
				rep = attempts[i]
				break
			}
		}
		if rep.Outcome != ledgerDelivered {
			for i := len(attempts) - 1; i >= 0; i-- {
				if attempts[i].Outcome == ledgerUnknown {
					rep = attempts[i]
					break
				}
			}
		}
		for _, a := range attempts {
			if a.DeliveredAt > 0 && a.DeliveredAt < a.EventTime {
				finding("ledger_time_inversion", base.AttemptID)
			}
		}
		if ledgerAttempted(rep) {
			red.Stats.Deliveries++
		}
		reps = append(reps, rep)
	}

	// 2. Late deliveries: per entity, in delivery order, an attempted
	// immediate notice of older source evidence than one already delivered.
	order := make([]int, 0, len(reps))
	for i, e := range reps {
		if ledgerAttempted(e) && ledgerImmediate(e.Kind) {
			order = append(order, i)
		}
	}
	sort.SliceStable(order, func(a, b int) bool {
		x, y := reps[order[a]], reps[order[b]]
		if x.DeliveredAt != y.DeliveredAt {
			return x.DeliveredAt < y.DeliveredAt
		}
		if x.SourceVersion != y.SourceVersion {
			return x.SourceVersion < y.SourceVersion
		}
		return x.AttemptID < y.AttemptID
	})
	newest := map[notify.Entity]uint64{}
	late := map[int]bool{}
	for _, i := range order {
		e := reps[i]
		if v, ok := newest[e.Entity]; ok && e.SourceVersion < v {
			late[i] = true
			continue
		}
		newest[e.Entity] = e.SourceVersion
	}
	byKey := map[ledgerKey][]LedgerEntry{}
	for i, e := range reps {
		if late[i] {
			red.Late = append(red.Late, ledgerRecord{Entry: e})
			continue
		}
		k := ledgerKeyOf(e)
		byKey[k] = append(byKey[k], e)
	}
	red.Stats.Late = len(red.Late)

	// 3. One record per logical decision towards one recipient.
	for _, group := range byKey {
		sort.SliceStable(group, func(i, j int) bool {
			a, b := group[i], group[j]
			switch {
			case ledgerAttempted(a) != ledgerAttempted(b):
				return ledgerAttempted(a)
			case a.SourceVersion != b.SourceVersion:
				return a.SourceVersion > b.SourceVersion
			case a.EventTime != b.EventTime:
				return a.EventTime > b.EventTime
			case a.DeliveredAt != b.DeliveredAt:
				return a.DeliveredAt > b.DeliveredAt
			}
			return a.AttemptID > b.AttemptID
		})
		red.Records = append(red.Records, ledgerRecord{Entry: group[0]})
		// The winner sorts first among attempted records: an attempted extra
		// exists only when the winner was attempted too.
		for _, extra := range group[1:] {
			if ledgerAttempted(extra) {
				red.DuplicateDeliveries = append(red.DuplicateDeliveries, ledgerRecord{Entry: extra})
			}
		}
	}
	red.Stats.DuplicateDeliveries = len(red.DuplicateDeliveries)
	for _, list := range []*[]ledgerRecord{&red.Records, &red.Late, &red.DuplicateDeliveries} {
		l := *list
		sort.SliceStable(l, func(i, j int) bool {
			ki, kj := ledgerKeyOf(l[i].Entry), ledgerKeyOf(l[j].Entry)
			if ki != kj {
				return ledgerKeyLess(ki, kj)
			}
			return l[i].Entry.AttemptID < l[j].Entry.AttemptID
		})
	}
	ledgerSortFindings(red.Findings)
	return red, nil
}

// ledgerDecisions expresses the reduced records in the notify package's legacy
// decision vocabulary, so notify.CompareParity can compare them.
func ledgerDecisions(r ledgerReduction) []notify.LegacyDecision {
	out := make([]notify.LegacyDecision, 0, len(r.Records))
	for _, rec := range r.Records {
		e := rec.Entry
		d := notify.LegacyDecision{Entity: e.Entity, Kind: e.Kind, ImpactRevision: e.ImpactRevision, Ordinal: e.Ordinal, Recipient: e.Recipient, SourceVersion: e.SourceVersion, DedupID: e.AttemptID}
		if e.Outcome == ledgerSuppressed {
			d.Suppression = e.Suppression
		}
		out = append(out, d)
	}
	return out
}
