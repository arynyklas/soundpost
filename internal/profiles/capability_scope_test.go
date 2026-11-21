// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package profiles

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// 04.04-C11: the profile view hands the capability records of the stored profile to the reader unchanged, including the
// acquisition scope, so a reader can tell a system-wide scheduler read from a target-only capture.
func TestProfileViewExportsTheAcquisitionScopeOfItsCapabilities(t *testing.T) {
	scope := realCursorScope(t)
	profile := model.NewID()
	page := multiChunkPage(scope.ProjectIDs()[0], profile, 1, 2)
	page.Capabilities[0].Value.AcquisitionScope = model.AcquisitionScopeSystemWideScheduler
	service := NewService(pageScanner{page}, allowScope{}, unavailableLinks{})
	view, err := service.Read(context.Background(), scope, profile, Window{Start: 0, End: 1 << 40, MaxSamples: 8})
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Capabilities) != 1 || view.Capabilities[0].Value.AcquisitionScope != model.AcquisitionScopeSystemWideScheduler {
		t.Fatalf("the view dropped the acquisition scope: %+v", view.Capabilities)
	}
	raw, err := json.Marshal(view)
	if err != nil || !strings.Contains(string(raw), `"acquisition_scope":"`+model.AcquisitionScopeSystemWideScheduler+`"`) {
		t.Fatalf("the wire view lacks the acquisition scope: %v", err)
	}
}
