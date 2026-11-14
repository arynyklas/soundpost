// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"github.com/arynyklas/soundpost/internal/model"
	"testing"
)

func TestNativeProfilesFrontierCannotClaimLaterCapabilityScan(t *testing.T) {
	a := model.ID{1}
	b := model.ID{2}
	got := mergeProfileMarks([]model.Cursor{{Group: a, Index: 4}, {Group: b, Index: 8}}, []model.Cursor{{Group: a, Index: 9}, {Group: b, Index: 3}, {Group: model.ID{3}, Index: 99}})
	if len(got) != 2 || got[0].Index != 4 || got[1].Index != 3 {
		t.Fatal("root/capability/loss scans fabricated later root coverage")
	}
}
