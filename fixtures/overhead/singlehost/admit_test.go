// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// TestProductAdmitsEveryBatchOfTheWorkload provisions one project of the estate in a real in-process product (control, auth, admission,
// storage) exactly as the server role does, and admits several windows of the generated workload through the product's own admission
// service: every batch of every kind must be durably receipted. A batch the product refuses is a defect of the generator.
func TestProductAdmitsEveryBatchOfTheWorkload(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	ctx := context.Background()
	bootstrap, _ := app.Control.BootstrapToken()
	session, err := app.Auth.Bootstrap(ctx, bootstrap, "owner@overhead.invalid", "single host overhead owner password 2026")
	if err != nil {
		t.Fatal(err)
	}
	actor, err := app.Auth.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	cfg := gate()
	pj := NewProject(cfg, 0)
	command := func(kind string, p auth.AdminPayload) {
		t.Helper()
		var revision model.Revision
		app.Control.View(ctx, func(st model.ControlState) error { revision = st.Revision; return nil })
		p.Reason = "overhead test"
		raw, _ := json.Marshal(p)
		if _, err := app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: pj.Org, Kind: kind, Payload: raw}); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
	}
	command("create_org", auth.AdminPayload{Name: "overhead"})
	command("create_project", auth.AdminPayload{ID: pj.Project, Name: "overhead"})
	issued, err := app.Auth.OnboardSource(ctx, actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: pj.Org, Project: pj.Project, Source: pj.Source,
		Expires: model.UnixNano(time.Now().Add(policyCredential).UnixNano()), Policy: pj.Policy, Reason: "overhead test"})
	if err != nil {
		t.Fatal(err)
	}
	if issued.Descriptor.PolicyRevision != 1 || issued.Descriptor.Slots != 64 {
		t.Fatalf("descriptor: %+v", issued.Descriptor)
	}
	cred, err := app.Auth.AuthenticateSource(ctx, issued.Credential, "", false)
	if err != nil {
		t.Fatal(err)
	}
	admitted, total := 0, time.Duration(0)
	start := time.Now().Add(-time.Minute)
	windows := 3
	if v, err := strconv.Atoi(os.Getenv("SINGLEHOST_TEST_WINDOWS")); err == nil && v > 0 {
		windows = v
	}
	for j := 0; j < windows; j++ {
		for _, pr := range pj.Window(j, start.Add(time.Duration(j)*cfg.Window)) {
			var b model.Batch
			if err := json.Unmarshal(pr.Body, &b); err != nil {
				t.Fatal(err)
			}
			grant, err := app.Ingest.ResolveSource(ctx, cred, b)
			if err != nil {
				t.Fatalf("resolve window %d slot %d: %v", j, pr.Slot, err)
			}
			t0 := time.Now()
			receipt, err := app.Ingest.Admit(ctx, grant, b)
			total += time.Since(t0)
			if err != nil {
				t.Fatalf("admit window %d slot %d (%d records, kinds %s): %v", j, pr.Slot, len(pr.Records), string(kindsOf(pr)), err)
			}
			if receipt.BatchID != pr.ID {
				t.Fatalf("receipt for another batch")
			}
			admitted++
			if admitted%50 == 0 {
				t.Logf("%d batches admitted, mean admission %.2f ms", admitted, total.Seconds()*1000/float64(admitted))
			}
		}
	}
	if admitted == 0 {
		t.Fatal("nothing admitted")
	}
}

func kindsOf(pr Prepared) []byte {
	seen := map[byte]bool{}
	var out []byte
	for _, m := range pr.Records {
		if !seen[m.Kind] {
			seen[m.Kind] = true
			out = append(out, m.Kind)
		}
	}
	return out
}
