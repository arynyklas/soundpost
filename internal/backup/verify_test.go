// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"testing"

	"soundpost/internal/model"
	"soundpost/internal/storage"
)

type gapCase struct {
	group model.ID
	fact  model.EvidenceGap
	att   GapAttestation
	iv    storage.ReplayInterval
	state model.ControlState
	m     BackupManifest
}

// goodGap is one committed control fact, the attestation the backup carried for
// it and the certificate interval it explains.
func goodGap() gapCase {
	c := gapCase{group: model.NewID()}
	c.fact = model.EvidenceGap{ID: model.NewID(), Org: model.NewID(), Project: model.NewID(), Group: c.group, After: 10, Through: 12, Count: 2, Reason: "unprocessed_expiry", RecordedAt: 99}
	c.state = model.ControlState{Installation: model.NewID(), Revision: 500, EvidenceGaps: map[string]model.EvidenceGap{c.fact.ID.String(): c.fact}}
	c.att = GapAttestation{Fact: c.fact.ID, Group: c.group, After: 10, Through: 12, Reason: "unprocessed_expiry", ControlRevision: 500, Digest: GapDigest(c.fact)}
	c.iv = storage.ReplayInterval{Group: c.group, After: 10, Through: 12, Mode: "gap", Count: 2, Reason: "unprocessed_expiry"}
	c.m = BackupManifest{Control: ControlBinding{Revision: 500}, Gaps: []GapAttestation{c.att}}
	return c
}

func TestRestoreRejectsForgedWidenedAndUnbackedGaps(t *testing.T) {
	ok := goodGap()
	if err := verifyGaps(ok.m, []storage.ReplayInterval{ok.iv}, ok.state); err != nil {
		t.Fatalf("an honest gap was rejected: %v", err)
	}
	replay := storage.ReplayInterval{Group: ok.group, After: 0, Through: 10, Mode: "replay", Count: 10}
	if err := verifyGaps(BackupManifest{Control: ControlBinding{Revision: 500}}, []storage.ReplayInterval{replay}, ok.state); err != nil {
		t.Fatalf("a bundle with no gaps was rejected: %v", err)
	}
	cases := map[string]func(c *gapCase, intervals *[]storage.ReplayInterval){
		"certificate gap with no attestation (self-asserted)": func(c *gapCase, _ *[]storage.ReplayInterval) { c.m.Gaps = nil },
		"attestation the certificate never used":              func(c *gapCase, iv *[]storage.ReplayInterval) { *iv = []storage.ReplayInterval{replay} },
		"widened certificate interval": func(c *gapCase, iv *[]storage.ReplayInterval) {
			wide := c.iv
			wide.Through, wide.Count = 15, 5
			*iv = []storage.ReplayInterval{wide}
		},
		"widened attestation and interval over a narrower fact": func(c *gapCase, iv *[]storage.ReplayInterval) {
			c.att.Through = 15
			c.m.Gaps = []GapAttestation{c.att}
			wide := c.iv
			wide.Through, wide.Count = 15, 5
			*iv = []storage.ReplayInterval{wide}
		},
		"shifted start": func(c *gapCase, iv *[]storage.ReplayInterval) {
			c.att.After = 9
			c.m.Gaps = []GapAttestation{c.att}
			shifted := c.iv
			shifted.After, shifted.Count = 9, 3
			*iv = []storage.ReplayInterval{shifted}
		},
		"fact absent from the control state at the cut": func(c *gapCase, _ *[]storage.ReplayInterval) { c.state.EvidenceGaps = map[string]model.EvidenceGap{} },
		"fact altered after it was attested": func(c *gapCase, _ *[]storage.ReplayInterval) {
			f := c.fact
			f.Reason = "different"
			c.state.EvidenceGaps = map[string]model.EvidenceGap{f.ID.String(): f}
		},
		"fact for another group": func(c *gapCase, iv *[]storage.ReplayInterval) {
			other := model.NewID()
			c.att.Group = other
			c.m.Gaps = []GapAttestation{c.att}
			moved := c.iv
			moved.Group = other
			*iv = []storage.ReplayInterval{moved}
		},
		"reason differs between certificate and fact": func(c *gapCase, iv *[]storage.ReplayInterval) {
			changed := c.iv
			changed.Reason = "something else"
			*iv = []storage.ReplayInterval{changed}
		},
		"attested at a revision other than the cut": func(c *gapCase, _ *[]storage.ReplayInterval) {
			c.att.ControlRevision = 501
			c.m.Gaps = []GapAttestation{c.att}
		},
		"attested beyond the state it claims to come from": func(c *gapCase, _ *[]storage.ReplayInterval) {
			c.state.Revision = 400
		},
		"the same fact attested twice": func(c *gapCase, _ *[]storage.ReplayInterval) { c.m.Gaps = []GapAttestation{c.att, c.att} },
		"gap interval with a wrong count": func(c *gapCase, iv *[]storage.ReplayInterval) {
			bad := c.iv
			bad.Count = 1
			*iv = []storage.ReplayInterval{bad}
		},
	}
	for name, mutate := range cases {
		c := goodGap()
		intervals := []storage.ReplayInterval{c.iv}
		mutate(&c, &intervals)
		if err := verifyGaps(c.m, intervals, c.state); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
