// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model_test

import (
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"strings"
	"testing"
)

func TestCanonicalDecimalWireFamiliesRejectAliases(t *testing.T) {
	cases := []struct {
		name, field string
		newValue    func() any
	}{
		{"job", "ordinal", func() any { return &model.JobAttemptEvent{} }},
		{"replay", "sequence", func() any { return &model.ReplayChunk{} }},
		{"profile_sample", "count", func() any { return &model.ProfileSample{} }},
		{"profile_frame", "offset", func() any { return &model.ProfileFrame{} }},
		{"loss", "count", func() any { return &model.LossReport{} }},
		{"condition", "sequence", func() any { return &model.ConditionEvent{} }},
		{"source_policy", "max_bytes", func() any { return &model.SourcePolicy{} }},
		{"reservation", "bytes", func() any { return &model.AdmissionReservation{} }},
		{"quota_change", "max_bytes", func() any { return &auth.AdmissionQuotaChange{} }},
		{"artifact", "size", func() any { return &model.ArtifactManifest{} }},
		{"blob", "size", func() any { return &model.BlobManifest{} }},
		{"evidence", "ordinal", func() any { return &model.GroupingEvidence{} }},
		{"denominator", "count", func() any { return &model.GroupingDenominator{} }},
		{"session", "expires", func() any { return &auth.Session{} }},
		{"server_token", "expires", func() any { return &auth.IssuedServerToken{} }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			good := `{"` + test.field + `":"9007199254740993"}`
			if err := json.NewDecoder(strings.NewReader(good)).Decode(test.newValue()); err != nil {
				t.Fatal("exact canonical integer rejected")
			}
			for _, bad := range []string{`"01"`, `"+1"`, `"-0"`, `"1e0"`, `null`, `1`} {
				raw := `{"` + test.field + `":` + bad + `}`
				if json.Unmarshal([]byte(raw), test.newValue()) == nil {
					t.Fatal("direct decoder accepted numeric alias")
				}
				if model.StrictJSON([]byte(raw), test.newValue()) == nil {
					t.Fatal("strict decoder accepted numeric alias")
				}
			}
		})
	}
}
func TestHistogramAndCursorRequiredDecimalFieldsRemainRequired(t *testing.T) {
	for _, raw := range []string{`{"count":"1"}`, `{"zero_count":"0"}`, `{"count":null,"zero_count":"0"}`, `{"count":"01","zero_count":"0"}`} {
		var value model.IntegerHistogram
		if json.Unmarshal([]byte(raw), &value) == nil {
			t.Fatal("histogram required/canonical count check lost")
		}
	}
	for _, raw := range []string{`{"group":"11111111111111111111111111111111"}`, `{"group":"11111111111111111111111111111111","index":null}`, `{"group":"11111111111111111111111111111111","index":"01"}`} {
		var value model.Cursor
		if json.Unmarshal([]byte(raw), &value) == nil {
			t.Fatal("cursor required/canonical index check lost")
		}
	}
}
