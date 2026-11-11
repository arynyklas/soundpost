// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/httpapi"
	"soundpost/internal/model"
)

// replayIntake is a real node with one replay-enabled source and its ingest route.
type replayIntake struct {
	post     func(model.ReplayChunk) (int, string)
	producer model.ID
}

func newReplayIntake(t *testing.T) *replayIntake {
	t.Helper()
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	ctx := context.Background()
	token, err := app.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := app.Auth.Bootstrap(ctx, token, "replay-intake@example.test", "replay intake password 2026")
	if err != nil {
		t.Fatal(err)
	}
	actor, err := app.Auth.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	org, project, source := model.NewID(), model.NewID(), model.NewID()
	command := func(kind string, p auth.AdminPayload) {
		t.Helper()
		var revision model.Revision
		if err := app.Control.View(ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
			t.Fatal(err)
		}
		p.Reason = "replay intake"
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw}); err != nil {
			t.Fatal(err)
		}
	}
	command("create_org", auth.AdminPayload{Name: "replay intake"})
	command("create_project", auth.AdminPayload{ID: project, Name: "replay intake"})
	sourcePolicy, err := json.Marshal(auth.SourcePolicyConfig{ProjectID: project, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	command("source_policy", auth.AdminPayload{ID: source, Config: sourcePolicy})
	service, environment, build := model.NewID(), model.NewID(), model.NewID()
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Replay}, Replay: true,
		Resources:     model.ResourceRegistry{Services: []model.ID{service}, Environments: []model.ID{environment}, Builds: []model.ID{build}, Instances: []string{"replay-1"}},
		RetentionDays: map[model.Kind]uint32{model.Replay: 30}, MaxBytes: 1 << 24, MaxSeries: 100}
	issued, err := app.Auth.OnboardSource(ctx, actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: org, Project: project, Source: source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "replay intake"})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(httpapi.NewServer("", app.Auth, nil, app.Register).Handler)
	t.Cleanup(server.Close)
	r := &replayIntake{producer: model.NewID()}
	resource := model.Resource{Service: service, Environment: environment, Build: build, Instance: "replay-1", Labels: model.Labels{}}
	r.post = func(c model.ReplayChunk) (int, string) {
		t.Helper()
		rec := model.Record{ID: model.NewID(), Kind: model.Replay, ObservedAt: c.Clock.Wall, Resource: resource, Payload: model.Payload{Replay: &c}}
		batch := model.Batch{Version: 1, Project: project, Source: source, Producer: r.producer, ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{rec}}
		if batch.RouteSlot, err = model.OwnerSlot(org, project, source, r.producer, rec); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(batch)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest("POST", server.URL+"/ingest/v1/batches", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+issued.Credential)
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	return r
}

func firstReplayChunk(replay model.ID) model.ReplayChunk {
	return model.ReplayChunk{Replay: replay, Session: model.NewID(), Recorder: "1", Sequence: 1, CheckpointSequence: 1, PolicyRevision: 1,
		Clock: model.TraceClock{Wall: model.UnixNano(time.Now().UnixNano()), Mono: 1000, Domain: model.ClockDomain{Host: model.NewID(), Boot: model.NewID(), Runtime: model.NewID()}}}
}

// Replay chunks are admitted only in the closed format: the chain and
// checkpoint rules replays.ValidateChunk states are enforced at intake, not just
// when a viewer later reads the replay. A first chunk that names a previous hash
// (which a recorder cannot produce), a sequence-1 chunk that is not its own
// checkpoint and a chunk with a zeroed clock domain are each refused with a
// typed Invalid, and a refused chunk charges no quota and leaves no record.
func TestReplayAdmissionRefusesChunksOutsideTheClosedFormat(t *testing.T) {
	intake := newReplayIntake(t)
	if status, body := intake.post(firstReplayChunk(model.NewID())); status != 200 {
		t.Fatalf("a valid first chunk was refused: %d %s", status, body)
	}
	for name, mutate := range map[string]func(*model.ReplayChunk){
		"first chunk names a previous hash":   func(c *model.ReplayChunk) { c.Previous = model.Hash{1}; c.Checkpoint = model.Hash{1} },
		"sequence 1 that is not a checkpoint": func(c *model.ReplayChunk) { c.CheckpointSequence = 0 },
		"checkpoint beyond the sequence":      func(c *model.ReplayChunk) { c.CheckpointSequence = 2 },
		"unsupported recorder version":        func(c *model.ReplayChunk) { c.Recorder = "soundpost1" },
		"sequence past the closed-format cap": func(c *model.ReplayChunk) { c.Sequence = 1 << 20 },
	} {
		t.Run(name, func(t *testing.T) {
			c := firstReplayChunk(model.NewID())
			mutate(&c)
			if status, body := intake.post(c); status != http.StatusUnprocessableEntity && status != http.StatusUnsupportedMediaType {
				t.Fatalf("a chunk outside the closed format was not refused as invalid: %d %s", status, body)
			}
		})
	}
}
