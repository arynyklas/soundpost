// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package issues_test

import (
	"soundpost/internal/issues"
	"soundpost/internal/model"
	"testing"
)

func TestFingerprintStableAndScoped(t *testing.T) {
	org, project := model.NewID(), model.NewID()
	code := "checkout_failed"
	occurrence := model.ErrorOccurrence{Class: "TypeError", Mechanism: "manual", Code: &code, Frames: []model.Frame{{Module: "checkout", Function: "submit", Artifact: "src/checkout.ts", Line: 12, InApp: true}}}
	hash := func(version uint16, org, project model.ID, occurrence model.ErrorOccurrence) [32]byte {
		t.Helper()
		h, e := issues.Fingerprint(version, org, project, occurrence)
		if e != nil {
			t.Fatal(e)
		}
		return h
	}
	original := hash(1, org, project, occurrence)
	occurrence.Frames[0].Line = 999
	column := uint32(10)
	occurrence.Frames[0].Column = &column
	occurrence.Build = model.NewID()
	occurrence.Occurrence = model.NewID()
	occurrence.Handled = true
	if got := hash(1, org, project, occurrence); got != original {
		t.Fatal("volatile occurrence metadata changed grouping")
	}
	for _, h := range [][32]byte{hash(1, model.NewID(), project, occurrence), hash(1, org, model.NewID(), occurrence), hash(2, org, project, occurrence)} {
		if h == original {
			t.Fatal("scope/version absent from grouping identity")
		}
	}
	changed := "payment_failed"
	occurrence.Code = &changed
	if hash(1, org, project, occurrence) == original {
		t.Fatal("approved operation code absent from grouping")
	}
	occurrence.Code = &code
	occurrence.Frames = append(occurrence.Frames, model.Frame{Module: "forbidden metadata", Function: "secret", Artifact: "/other/project/secret", InApp: false})
	if hash(1, org, project, occurrence) != original {
		t.Fatal("non-in-app forbidden metadata influenced grouping")
	}
	occurrence.Frames[0].Artifact = "../secret"
	if _, e := issues.Fingerprint(1, org, project, occurrence); e == nil {
		t.Fatal("unsafe in-app identity accepted")
	}
	if _, e := issues.Fingerprint(0, org, project, model.ErrorOccurrence{Class: "Error"}); e == nil {
		t.Fatal("zero grouping version accepted")
	}
	if _, e := issues.Fingerprint(1, model.ID{}, project, model.ErrorOccurrence{Class: "Error"}); e == nil {
		t.Fatal("unscoped grouping accepted")
	}
}

func TestFingerprintEightInnermostAndFallback(t *testing.T) {
	org, project := model.NewID(), model.NewID()
	occurrence := model.ErrorOccurrence{Class: "Error", Mechanism: "manual"}
	for i := range 10 {
		occurrence.Frames = append(occurrence.Frames, model.Frame{Module: "app", Function: string(rune('a' + i)), Artifact: "app.ts", Line: uint32(i + 1), InApp: true})
	}
	original, e := issues.Fingerprint(1, org, project, occurrence)
	if e != nil {
		t.Fatal(e)
	}
	occurrence.Frames[8].Function = "outside_limit"
	if got, _ := issues.Fingerprint(1, org, project, occurrence); got != original {
		t.Fatal("more than eight innermost identities used")
	}
	occurrence.Frames[0], occurrence.Frames[1] = occurrence.Frames[1], occurrence.Frames[0]
	if got, _ := issues.Fingerprint(1, org, project, occurrence); got == original {
		t.Fatal("newest-first order discarded")
	}
	template := "approved_failure"
	occurrence = model.ErrorOccurrence{Class: "Error", Mechanism: "unknown", Template: &template}
	fallback, e := issues.Fingerprint(1, org, project, occurrence)
	if e != nil {
		t.Fatal(e)
	}
	occurrence.Graph = &model.ExceptionGraph{Reasons: []string{"unknown_throw"}}
	if got, _ := issues.Fingerprint(1, org, project, occurrence); got != fallback {
		t.Fatal("unknown mechanism inspected exception graph")
	}
	other := "different_template"
	occurrence.Template = &other
	if got, _ := issues.Fingerprint(1, org, project, occurrence); got == fallback {
		t.Fatal("fallback omitted safe template")
	}
	beforeMechanism, e := issues.Fingerprint(1, org, project, occurrence)
	if e != nil {
		t.Fatal(e)
	}
	occurrence.Mechanism = "manual"
	if got, _ := issues.Fingerprint(1, org, project, occurrence); got == beforeMechanism {
		t.Fatal("fallback omitted mechanism")
	}
}
