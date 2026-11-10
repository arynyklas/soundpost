// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"soundpost/internal/control"
	"soundpost/internal/model"
)

// This file holds the pure decision logic of the pipeline drills (provider-failure-outage,
// external-deadman, owner-cutover-rollback): verifiers, digest builders and the observer-state
// parser. Nothing here touches a node, a process or the network, so every rule is unit-tested in
// pipeline_test.go; the scenarios themselves (pipeline_scenarios.go: provider-failure-outage and
// owner-cutover-rollback, pipeline_deadman.go: external-deadman, over the node scaffolding of
// pipeline_node.go) only feed them what they observed.

// pipeSend is one provider call as the recording sender saw it. It carries identities, enums and
// closed codes only: never a destination, a template text or any telemetry.
type pipeSend struct {
	Seq            int
	ID             string // the stable delivery id (hex)
	Subject        string // "incident:<id>" / "issue:<id>"
	Kind           string
	ImpactRevision uint64
	Ordinal        uint64
	Recipient      string
	Attempt        uint32
	Outcome        string // accepted | retry | unknown | terminal
	Code           string
	Receipt        string // the provider's receipt, set on accepted only
	Phase          string // the cutover phase the harness was in when the worker ran
}

// ---- one normal owner ----

// pipeOwnerStep is the committed cutover state observed after one step.
type pipeOwnerStep struct {
	Phase  string
	Owners []string
}

// pipeExpectedOwners is the ownership table of the cutover (docs/operations/notification-cutover.md),
// written down independently of the product so the drill does not mirror its implementation.
func pipeExpectedOwners(phase, oldOwner, newOwner string) ([]string, bool) {
	switch phase {
	case "shadow", "quiescing_old", "old_active":
		return []string{oldOwner}, true
	case "new_active":
		return []string{newOwner}, true
	case "barrier_verified", "rollback_quiescing":
		return nil, true
	}
	return nil, false
}

// pipeVerifyOwnerSteps requires that at EVERY observed step exactly the phase's owner is active and
// never more than one.
func pipeVerifyOwnerSteps(steps []pipeOwnerStep, oldOwner, newOwner string) error {
	if len(steps) == 0 {
		return errors.New("no cutover step was observed")
	}
	for i, s := range steps {
		want, ok := pipeExpectedOwners(s.Phase, oldOwner, newOwner)
		if !ok {
			return fmt.Errorf("step %d: unknown phase %q", i+1, s.Phase)
		}
		if len(s.Owners) > 1 {
			return fmt.Errorf("step %d (%s): %d active normal owners %v", i+1, s.Phase, len(s.Owners), s.Owners)
		}
		if len(s.Owners) != len(want) || (len(want) == 1 && s.Owners[0] != want[0]) {
			return fmt.Errorf("step %d (%s): active owners %v, want %v", i+1, s.Phase, s.Owners, want)
		}
	}
	return nil
}

// ---- sends: identity, duplicates, backlog ----

// pipeGroup returns the calls of each delivery id in order, and the ids in first-seen order.
func pipeGroup(calls []pipeSend) (map[string][]pipeSend, []string) {
	by := map[string][]pipeSend{}
	var order []string
	for _, c := range calls {
		if _, ok := by[c.ID]; !ok {
			order = append(order, c.ID)
		}
		by[c.ID] = append(by[c.ID], c)
	}
	return by, order
}

// pipeVerifyRetryIdentity requires that every retry of a delivery keeps its identity and receipt:
// one id, one subject and kind, attempts numbered 1..n without a gap, at most one acceptance and it
// is the last call, the acceptance carries a receipt and no other call of the delivery names a
// different one.
func pipeVerifyRetryIdentity(calls []pipeSend) error {
	by, order := pipeGroup(calls)
	for _, id := range order {
		cs := by[id]
		receipt := ""
		for i, c := range cs {
			if c.Attempt != uint32(i+1) {
				return fmt.Errorf("delivery %s: call %d is attempt %d, want %d (an attempt vanished or a retry got a new number)", id, i+1, c.Attempt, i+1)
			}
			if c.Subject != cs[0].Subject || c.Kind != cs[0].Kind {
				return fmt.Errorf("delivery %s: attempt %d changed identity (%s/%s, was %s/%s)", id, c.Attempt, c.Subject, c.Kind, cs[0].Subject, cs[0].Kind)
			}
			if c.Outcome == "accepted" && c.Receipt == "" {
				return fmt.Errorf("delivery %s: attempt %d accepted without a receipt", id, c.Attempt)
			}
			if c.Receipt != "" {
				if receipt != "" && receipt != c.Receipt {
					return fmt.Errorf("delivery %s: the receipt changed between attempts (%q, then %q)", id, receipt, c.Receipt)
				}
				receipt = c.Receipt
			}
			if c.Outcome == "accepted" && i != len(cs)-1 {
				return fmt.Errorf("delivery %s: attempt %d was sent after the acceptance at attempt %d", id, cs[i+1].Attempt, c.Attempt)
			}
		}
	}
	return nil
}

// pipeLogicalKey is what a recipient perceives as one notification.
func pipeLogicalKey(c pipeSend) string {
	return fmt.Sprintf("%s|%s|%d|%d|%s", c.Subject, c.Kind, c.ImpactRevision, c.Ordinal, c.Recipient)
}

// pipeFindDuplicateAnnouncements lists every way one notification reached the provider as accepted
// more than once: one delivery accepted twice, a send after the acceptance, and one logical
// notification accepted under two delivery ids.
func pipeFindDuplicateAnnouncements(calls []pipeSend) []string {
	var out []string
	by, order := pipeGroup(calls)
	for _, id := range order {
		accepted := 0
		for _, c := range by[id] {
			if accepted > 0 {
				out = append(out, fmt.Sprintf("delivery %s sent again (attempt %d, %s) after it was accepted", id, c.Attempt, c.Outcome))
			}
			if c.Outcome == "accepted" {
				accepted++
			}
		}
		if accepted > 1 {
			out = append(out, fmt.Sprintf("delivery %s was accepted %d times", id, accepted))
		}
	}
	keys := map[string][]string{}
	var keyOrder []string
	for _, c := range calls {
		if c.Outcome != "accepted" {
			continue
		}
		k := pipeLogicalKey(c)
		if _, ok := keys[k]; !ok {
			keyOrder = append(keyOrder, k)
		}
		seen := false
		for _, id := range keys[k] {
			seen = seen || id == c.ID
		}
		if !seen {
			keys[k] = append(keys[k], c.ID)
		}
	}
	for _, k := range keyOrder {
		if len(keys[k]) > 1 {
			out = append(out, fmt.Sprintf("notification %q was accepted under %d delivery ids %v", k, len(keys[k]), keys[k]))
		}
	}
	return out
}

// pipeFindBacklogEmergencies detects retroactive backlog announced as a NEW emergency after a
// recovery. calls[boundary:] happened after the recovery was declared. `outage` holds every delivery
// id that existed during the outage, `expectedNew` the ids of notifications the drill itself caused
// after the recovery (a genuinely new material change). After the boundary the only legitimate
// sends are those ids; an unknown id is an invented emergency, and an outage delivery that was
// already accepted before the boundary and is sent again is the backlog replayed.
func pipeFindBacklogEmergencies(calls []pipeSend, boundary int, outage, expectedNew map[string]bool) []string {
	if boundary < 0 || boundary > len(calls) {
		return []string{fmt.Sprintf("boundary %d is outside the %d recorded calls", boundary, len(calls))}
	}
	acceptedBefore := map[string]bool{}
	for _, c := range calls[:boundary] {
		if c.Outcome == "accepted" {
			acceptedBefore[c.ID] = true
		}
	}
	var out []string
	flagged := map[string]bool{}
	for _, c := range calls[boundary:] {
		switch {
		case !outage[c.ID] && !expectedNew[c.ID]:
			if !flagged[c.ID] {
				out = append(out, fmt.Sprintf("delivery %s (%s, %s) was first sent after the recovery and is not an expected new notification", c.ID, c.Kind, c.Subject))
				flagged[c.ID] = true
			}
		case acceptedBefore[c.ID]:
			if !flagged[c.ID] {
				out = append(out, fmt.Sprintf("delivery %s (%s) was already accepted before the recovery and was sent again after it", c.ID, c.Kind))
				flagged[c.ID] = true
			}
		}
	}
	return out
}

// pipeFindSendsOutsideOwner lists the sends made while the cutover was not in the one phase whose
// owner may send. A call without a phase label is a harness defect and is reported too.
func pipeFindSendsOutsideOwner(calls []pipeSend, activePhase string) []string {
	var out []string
	for _, c := range calls {
		if c.Phase != activePhase {
			out = append(out, fmt.Sprintf("delivery %s attempt %d was sent in phase %q, only %q may send", c.ID, c.Attempt, c.Phase, activePhase))
		}
	}
	return out
}

// ---- the exact semantic content of a delivery ----

type pipeAttemptSemantic struct {
	Number  uint32 `json:"number"`
	Outcome string `json:"outcome"`
	Code    string `json:"code,omitempty"`
}

// pipeSemantic is what a reader must be able to retrieve about one acknowledged delivery: its
// identity, kind and subject, the provider receipt, the digest of the committed body and every
// attempt in order. The harness builds it from what the sender observed and the store gives it back.
type pipeSemantic struct {
	ID         string                `json:"id"`
	Subject    string                `json:"subject"`
	Kind       string                `json:"kind"`
	Receipt    string                `json:"receipt"`
	BodyDigest string                `json:"body_digest"`
	Attempts   []pipeAttemptSemantic `json:"attempts"`
}

func pipeDigest(s pipeSemantic) string {
	if s.Attempts == nil {
		s.Attempts = []pipeAttemptSemantic{}
	}
	raw, _ := json.Marshal(s)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// pipeSemanticFromSends builds the semantic content of an ACKed delivery from what the recording
// sender observed. A delivery that was never sent, or never accepted, has none: it cannot be ACKed.
func pipeSemanticFromSends(id string, calls []pipeSend, bodyDigest string) (pipeSemantic, error) {
	by, _ := pipeGroup(calls)
	cs := by[id]
	if len(cs) == 0 {
		return pipeSemantic{}, fmt.Errorf("delivery %s was never sent", id)
	}
	sem := pipeSemantic{ID: id, Subject: cs[0].Subject, Kind: cs[0].Kind, BodyDigest: bodyDigest}
	for _, c := range cs {
		sem.Attempts = append(sem.Attempts, pipeAttemptSemantic{Number: c.Attempt, Outcome: c.Outcome, Code: c.Code})
		if c.Outcome == "accepted" {
			sem.Receipt = c.Receipt
		}
	}
	if sem.Receipt == "" || cs[len(cs)-1].Outcome != "accepted" {
		return pipeSemantic{}, fmt.Errorf("delivery %s was never accepted by the provider", id)
	}
	return sem, nil
}

// pipeBodyDigest is the committed digest binding the delivery id to its body.
func pipeBodyDigest(rec control.DeliveryRecord) string { return hex.EncodeToString(rec.Digest[:]) }

// pipeSemanticFromRecord is the same content read back from the control store.
func pipeSemanticFromRecord(rec control.DeliveryRecord) pipeSemantic {
	sem := pipeSemantic{ID: rec.ID.String(), Subject: rec.Subject, Kind: rec.Kind, Receipt: rec.Provider, BodyDigest: pipeBodyDigest(rec)}
	for _, a := range rec.Attempts {
		sem.Attempts = append(sem.Attempts, pipeAttemptSemantic{Number: a.Number, Outcome: a.Outcome, Code: a.Code})
	}
	return sem
}

// pipeRetained is the retained map a reconciliation compares with the ledger.
func pipeRetained(recs []control.DeliveryRecord) map[string]string {
	out := make(map[string]string, len(recs))
	for _, r := range recs {
		out[r.ID.String()] = pipeDigest(pipeSemanticFromRecord(r))
	}
	return out
}

// ---- the observer's own record ----

type pipeObsAttempt struct {
	N      int    `json:"n"`
	AtNS   int64  `json:"at_ns"`
	Kind   string `json:"kind"`
	Status int    `json:"status"`
	Error  string `json:"error"`
}

type pipeObsOutage struct {
	ID          string           `json:"id"`
	Component   string           `json:"component"`
	LastOKNS    int64            `json:"last_ok_ns"`
	DetectedNS  int64            `json:"detected_ns"`
	RecoveredNS int64            `json:"recovered_ns"`
	Alerted     bool             `json:"alerted"`
	Recovery    bool             `json:"recovery_notified"`
	Attempts    []pipeObsAttempt `json:"attempts"`
}

type pipeObsComponent struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// pipeObsState is the part of the observer's state.json the drill reads (the observer program is
// the 06.09 fixture, tests/acceptance/observer, and is not forked or imported).
type pipeObsState struct {
	Observer   string             `json:"observer"`
	StartedNS  int64              `json:"started_ns"`
	LastCycle  int64              `json:"last_cycle_ns"`
	Armed      bool               `json:"armed"`
	Components []pipeObsComponent `json:"components"`
	Outages    []pipeObsOutage    `json:"outages"`
}

// pipeParseObserverState decodes one state.json. A truncated or foreign file is an error, never an
// empty state: the drill must not mistake a half-written record for "no outage".
func pipeParseObserverState(raw []byte) (pipeObsState, error) {
	var st pipeObsState
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&st); err != nil {
		return pipeObsState{}, fmt.Errorf("observer state: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return pipeObsState{}, errors.New("observer state: trailing data")
	}
	if st.Observer == "" || st.StartedNS <= 0 {
		return pipeObsState{}, errors.New("observer state: no observer identity or start time")
	}
	return st, nil
}

func pipeAccepted(a pipeObsAttempt) bool { return a.Status >= 200 && a.Status < 300 }

// pipeCountAlertAttempts counts the alert attempts across every outage: the ones the destination
// refused or that never arrived, and the ones it accepted. Recovery notices are not alerts.
func pipeCountAlertAttempts(st pipeObsState) (failed, accepted int) {
	for _, o := range st.Outages {
		for _, a := range o.Attempts {
			switch {
			case a.Kind != "alert":
			case pipeAccepted(a):
				accepted++
			default:
				failed++
			}
		}
	}
	return failed, accepted
}

// pipeVerifyOutageRetained compares the observer's record after a recovery (or a restart) with the
// record before: every outage is still there with the same identity, times and alert flag, every
// earlier attempt (failed ones included) is still there unchanged and in place, an outage has at
// most one accepted alert, and no new outage appeared. A recovery may only append its notice.
func pipeVerifyOutageRetained(before, after pipeObsState) error {
	if before.Observer != after.Observer || before.StartedNS != after.StartedNS {
		return fmt.Errorf("the observer's record is not the same record (observer %q -> %q, started %d -> %d)", before.Observer, after.Observer, before.StartedNS, after.StartedNS)
	}
	if len(after.Outages) != len(before.Outages) {
		return fmt.Errorf("the record holds %d outages, it held %d: an outage was erased or a new emergency appeared", len(after.Outages), len(before.Outages))
	}
	byID := map[string]pipeObsOutage{}
	for _, o := range after.Outages {
		byID[o.ID] = o
	}
	for _, b := range before.Outages {
		a, ok := byID[b.ID]
		switch {
		case !ok:
			return fmt.Errorf("outage %s of %s disappeared", b.ID, b.Component)
		case a.Component != b.Component || a.DetectedNS != b.DetectedNS || a.LastOKNS != b.LastOKNS:
			return fmt.Errorf("outage %s was rewritten (component %s, last ok %d, detected %d -> %s, %d, %d)", b.ID, b.Component, b.LastOKNS, b.DetectedNS, a.Component, a.LastOKNS, a.DetectedNS)
		case b.Alerted && !a.Alerted:
			return fmt.Errorf("outage %s lost its alerted flag", b.ID)
		case b.RecoveredNS != 0 && a.RecoveredNS != b.RecoveredNS:
			return fmt.Errorf("outage %s changed its recovery time", b.ID)
		case len(a.Attempts) < len(b.Attempts):
			return fmt.Errorf("outage %s: %d attempts remain, %d were recorded: an attempt was erased", b.ID, len(a.Attempts), len(b.Attempts))
		}
		for i, x := range b.Attempts {
			if a.Attempts[i] != x {
				return fmt.Errorf("outage %s: attempt %d was rewritten (%+v -> %+v)", b.ID, i+1, x, a.Attempts[i])
			}
		}
		alerts := 0
		for _, x := range a.Attempts {
			if x.Kind == "alert" && pipeAccepted(x) {
				alerts++
			}
		}
		if alerts > 1 {
			return fmt.Errorf("outage %s was alerted %d times: a recovery must not be a second emergency", b.ID, alerts)
		}
	}
	return nil
}

// pipeIsFault reports whether err wraps a model.Fault with that code (and, when given, a detail that
// starts with detail).
func pipeIsFault(err error, code, detail string) bool {
	var f *model.Fault
	if !errors.As(err, &f) || string(f.Code) != code {
		return false
	}
	return detail == "" || strings.HasPrefix(f.SafeDetail, detail)
}

// pipeStoreVsLedger compares the delivery records read back from the store with the ACK ledger and
// returns every disagreement that is NOT a content difference (Reconcile covers content): an
// accepted record nobody ACKed (an acknowledgement the drill lost or an announcement it never
// saw) and a delivery still open (pending or claimed) at the end, i.e. lost.
func pipeStoreVsLedger(recs []control.DeliveryRecord, acks []Ack) []string {
	var out []string
	acked := map[string]bool{}
	for _, a := range acks {
		acked[a.ID] = true
	}
	held := map[string]control.DeliveryRecord{}
	for _, r := range recs {
		held[r.ID.String()] = r
		switch {
		case r.Open():
			out = append(out, fmt.Sprintf("delivery %s is still %s at the end: it was lost", r.ID, r.Phase))
		case r.Phase == control.DeliveryAccepted && !acked[r.ID.String()]:
			out = append(out, fmt.Sprintf("delivery %s is accepted on the store but was never ACKed in the ledger", r.ID))
		}
	}
	for _, a := range acks {
		r, ok := held[a.ID]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("ACKed delivery %s has no record on the store", a.ID))
		case r.Phase != control.DeliveryAccepted:
			out = append(out, fmt.Sprintf("ACKed delivery %s is %s on the store, not accepted", a.ID, r.Phase))
		}
	}
	return out
}

// pipeObsEvent is one entry the drill's outage timeline takes from the observer's own record.
type pipeObsEvent struct {
	At      int64
	Key     string // unique per outage and notice, so a later reading appends only what is new
	Fail    bool
	Subject string
	Detail  string
}

// pipeObserverEvents renders the observer's record as timeline events in time order: every missing
// heartbeat and every failed notice attempt is a failure, every accepted notice a delivery.
func pipeObserverEvents(st pipeObsState) []pipeObsEvent {
	var out []pipeObsEvent
	for _, o := range st.Outages {
		out = append(out, pipeObsEvent{At: o.DetectedNS, Key: o.ID + "/missing", Fail: true, Subject: "heartbeat/" + o.Component,
			Detail: fmt.Sprintf("no healthy heartbeat since %d (outage %s)", o.LastOKNS, o.ID)})
		for _, a := range o.Attempts {
			e := pipeObsEvent{At: a.AtNS, Key: fmt.Sprintf("%s/%s#%d", o.ID, a.Kind, a.N), Fail: !pipeAccepted(a), Subject: a.Kind + "/" + o.Component}
			if e.Fail {
				e.Detail = fmt.Sprintf("status %d %s", a.Status, a.Error)
			} else {
				e.Detail = fmt.Sprintf("status %d", a.Status)
			}
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].At != out[j].At {
			return out[i].At < out[j].At
		}
		// At the same instant a detection comes before the notices it caused.
		if mi, mj := strings.HasSuffix(out[i].Key, "/missing"), strings.HasSuffix(out[j].Key, "/missing"); mi != mj {
			return mi
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// pipeNoticeDigest is the semantic content of one observer notice as its destination must have
// received it: which observer, what kind of notice, for which outage and component.
func pipeNoticeDigest(observer, kind, outage, component string) string {
	raw, _ := json.Marshal([]string{observer, kind, outage, component})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// pipeRequireChecks fails when a check a scenario is defined by is missing from its report or did
// not hold. It exists so that deleting an assertion from a scenario cannot go unnoticed: a drill
// that quietly stops asserting is worthless.
func pipeRequireChecks(checks []Check, required []string) error {
	if len(required) == 0 {
		return errors.New("the scenario defines no required checks")
	}
	ok, seen := map[string]bool{}, map[string]bool{}
	for _, c := range checks {
		if _, dup := ok[c.Name]; dup {
			ok[c.Name] = ok[c.Name] && c.OK
		} else {
			ok[c.Name] = c.OK
		}
	}
	var missing, failed []string
	for _, name := range required {
		if seen[name] {
			return fmt.Errorf("required check %q is listed twice", name)
		}
		seen[name] = true
		held, present := ok[name]
		switch {
		case !present:
			missing = append(missing, name)
		case !held:
			failed = append(failed, name)
		}
	}
	if len(missing) > 0 || len(failed) > 0 {
		return fmt.Errorf("required checks missing %v, not holding %v", missing, failed)
	}
	return nil
}
