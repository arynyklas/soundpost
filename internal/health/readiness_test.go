// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package health

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// secretCanary stands in for a credential, a path or a token that a failing dependency
// might put into its error text. No readiness answer may ever contain it.
const secretCanary = "SOUNDPOST_SECRET_CANARY_7f3a"

type fakeState struct {
	version   string
	restore   bool
	schema    Schema
	schemaErr error
	groups    []Group
	groupsErr error
	fences    uint64
	fencesErr error
	disk      Disk
	diskErr   error
}

func (f *fakeState) Version() string   { return f.version }
func (f *fakeState) RestoreHold() bool { return f.restore }
func (f *fakeState) Schema(context.Context) (Schema, error) {
	return f.schema, f.schemaErr
}
func (f *fakeState) Groups(context.Context) ([]Group, error) { return f.groups, f.groupsErr }
func (f *fakeState) PendingPolicyFences(context.Context) (uint64, error) {
	return f.fences, f.fencesErr
}
func (f *fakeState) Disk(context.Context) (Disk, error) { return f.disk, f.diskErr }

func healthy() *fakeState {
	control, data := model.NewID(), model.NewID()
	return &fakeState{
		version: "1.2.3",
		schema:  Schema{Observed: 1, Supported: 1},
		// The control group is deliberately not first: the reported cursor must be the control
		// group's, not whatever comes first.
		groups: []Group{
			{ID: data, Quorum: true, Commit: 7, Applied: 7, Cursor: model.Cursor{Group: data, Index: 7}},
			{ID: control, Control: true, Quorum: true, Commit: 41, Applied: 41, Cursor: model.Cursor{Group: control, Index: 41}},
		},
	}
}

func TestReadinessRejectsNoQuorumFailedSyncAndOldSchema(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*fakeState)
		want   Reason
	}{
		{"no quorum on a data group", func(s *fakeState) { s.groups[0].Quorum = false }, ReasonNoQuorum},
		{"no quorum on the control group", func(s *fakeState) { s.groups[1].Quorum = false }, ReasonNoQuorum},
		{"failed sync on a data group", func(s *fakeState) { s.groups[0].Failed = true }, ReasonSyncFailed},
		{"failed sync wins over its quorum answer", func(s *fakeState) { s.groups[1].Failed, s.groups[1].Quorum = true, false }, ReasonSyncFailed},
		{"old schema needs a migration", func(s *fakeState) { s.schema = Schema{Observed: 0, Supported: 1} }, ReasonSchemaOld},
		{"newer schema written by a newer binary", func(s *fakeState) { s.schema = Schema{Observed: 2, Supported: 1} }, ReasonSchemaNewer},
		{"policy fence still draining", func(s *fakeState) { s.fences = 1 }, ReasonPolicyStale},
		{"disk denies low priority intake", func(s *fakeState) { s.disk = Disk{Level: DiskDenyLow} }, ReasonDiskPressure},
		{"disk denies all intake", func(s *fakeState) { s.disk = Disk{Level: DiskDenyAll} }, ReasonDiskPressure},
		{"disk meter unreadable", func(s *fakeState) { s.diskErr = errors.New("statfs /var/lib/soundpost token=" + secretCanary) }, ReasonDiskUnknown},
		{"restore not activated", func(s *fakeState) { s.restore = true }, ReasonRestorePending},
		{"apply backlog beyond the bound", func(s *fakeState) { s.groups[0].Commit = s.groups[0].Applied + MaxApplyLag + 1 }, ReasonApplyLag},
		{"no groups reported", func(s *fakeState) { s.groups = nil }, ReasonStateUnavailable},
		{"no control group reported", func(s *fakeState) { s.groups[1].Control = false }, ReasonStateUnavailable},
		{"groups unreadable", func(s *fakeState) { s.groupsErr = errors.New("open /secret/" + secretCanary) }, ReasonStateUnavailable},
		{"schema unreadable", func(s *fakeState) { s.schemaErr = errors.New(secretCanary) }, ReasonStateUnavailable},
		{"policy fences unreadable", func(s *fakeState) { s.fencesErr = errors.New(secretCanary) }, ReasonStateUnavailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := healthy()
			c.mutate(s)
			got, err := Ready(context.Background(), s)
			if err != nil {
				t.Fatalf("Ready returned error %v", err)
			}
			if got.Ready {
				t.Fatalf("state is ready, want unready %q", c.want)
			}
			if got.Reason != c.want {
				t.Fatalf("reason %q, want %q", got.Reason, c.want)
			}
			if !got.Reason.Valid() {
				t.Fatalf("reason %q is not in the closed set", got.Reason)
			}
			if got.Version != "" || got.Applied != nil {
				t.Fatalf("an unready answer exposes version/cursor: %+v", got)
			}
			raw, _ := json.Marshal(got)
			if strings.Contains(string(raw), secretCanary) || strings.Contains(string(raw), "/") {
				t.Fatalf("unready answer leaks error text: %s", raw)
			}
		})
	}

	t.Run("healthy exposes the applied cursor and version only", func(t *testing.T) {
		s := healthy()
		got, err := Ready(context.Background(), s)
		if err != nil || !got.Ready || got.Reason != "" {
			t.Fatalf("healthy state not ready: %+v %v", got, err)
		}
		if got.Version != "1.2.3" {
			t.Fatalf("version %q", got.Version)
		}
		if got.Applied == nil || *got.Applied != s.groups[1].Cursor {
			t.Fatalf("applied cursor %+v is not the control group's %+v", got.Applied, s.groups[1].Cursor)
		}
		raw, _ := json.Marshal(got)
		var keys map[string]json.RawMessage
		if json.Unmarshal(raw, &keys) != nil {
			t.Fatal("answer is not a JSON object")
		}
		for k := range keys {
			if k != "ready" && k != "version" && k != "applied_cursor" {
				t.Fatalf("unexpected field %q in %s", k, raw)
			}
		}
	})
}

// States that must not make a node unready: a warning level, an unmetered platform,
// and a small apply backlog while writes are in flight.
func TestReadinessToleratesWarningUnmeteredAndSmallBacklog(t *testing.T) {
	for name, mutate := range map[string]func(*fakeState){
		"warn level":       func(s *fakeState) { s.disk = Disk{Level: DiskWarn} },
		"unmetered":        func(s *fakeState) { s.disk = Disk{Unmetered: true} },
		"backlog at bound": func(s *fakeState) { s.groups[0].Commit = s.groups[0].Applied + MaxApplyLag },
	} {
		s := healthy()
		mutate(s)
		got, err := Ready(context.Background(), s)
		if err != nil || !got.Ready {
			t.Fatalf("%s: %+v %v", name, got, err)
		}
	}
}

// A cancelled caller gets the cancellation, never a made-up verdict either way.
func TestReadinessReportsCancellationAsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := Ready(ctx, healthy())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %+v, %v; want context.Canceled", got, err)
	}
	if got.Ready {
		t.Fatal("a cancelled evaluation reported ready")
	}
}

func TestReadinessRequiresAState(t *testing.T) {
	if got, err := Ready(context.Background(), nil); err == nil || got.Ready {
		t.Fatalf("nil state: %+v %v", got, err)
	}
}

func TestReasonSetIsClosed(t *testing.T) {
	if Reason("").Valid() || Reason("error: open /etc/passwd").Valid() {
		t.Fatal("free text accepted as a reason")
	}
}
