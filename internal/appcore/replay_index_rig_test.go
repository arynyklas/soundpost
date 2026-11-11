// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"testing"
	"time"

	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/ingest"
	"soundpost/internal/model"
	"soundpost/internal/replays"
	"soundpost/internal/storage"
)

// indexRig is a real node (control store, storage engine, one-voter Raft) with a
// replay-enabled source, a reader and the production ingest service, which a test
// may replace with another ingest service over the same stores. It can be closed
// and reopened on the same directory, which is the restart of a crashed process.
type indexRig struct {
	t        *testing.T
	ctx      context.Context
	dir      string
	app      *appcore.App
	override *ingest.Service
	session  string
	reader   string
	issued   string
	email    string
	password string

	org, project, source, producer model.ID
	resource                       model.Resource
}

func newIndexRig(t *testing.T) *indexRig {
	t.Helper()
	r := &indexRig{t: t, ctx: context.Background(), dir: t.TempDir(), org: model.NewID(), project: model.NewID(), source: model.NewID(), producer: model.NewID(),
		email: "replay-index-reader@example.test", password: "replay index reader password 2026"}
	r.open()
	t.Cleanup(func() { r.app.Close() })
	token, err := r.app.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := r.app.Auth.Bootstrap(r.ctx, token, "replay-index@example.test", "replay index password 2026")
	if err != nil {
		t.Fatal(err)
	}
	r.session = owner.Token
	reader := model.NewID()
	r.command("create_org", auth.AdminPayload{Name: "replay index"})
	r.command("create_project", auth.AdminPayload{ID: r.project, Name: "replay index"})
	sourcePolicy, err := json.Marshal(auth.SourcePolicyConfig{ProjectID: r.project, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	r.command("source_policy", auth.AdminPayload{ID: r.source, Config: sourcePolicy})
	r.command("create_user", auth.AdminPayload{ID: reader, Email: r.email, Password: r.password})
	r.command("membership", auth.AdminPayload{UserID: reader, Enabled: true})
	r.command("grant", auth.AdminPayload{UserID: reader, ProjectID: r.project, Enabled: true, Permissions: []string{string(auth.Read)}})
	login, err := r.app.Auth.Login(r.ctx, r.email, r.password, "")
	if err != nil {
		t.Fatal(err)
	}
	r.reader = login.Token

	service, environment, build := model.NewID(), model.NewID(), model.NewID()
	r.resource = model.Resource{Service: service, Environment: environment, Build: build, Instance: "replay-1", Labels: model.Labels{}}
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Replay, model.Metric}, Replay: true,
		Resources:     model.ResourceRegistry{Services: []model.ID{service}, Environments: []model.ID{environment}, Builds: []model.ID{build}, Instances: []string{"replay-1"}},
		RetentionDays: map[model.Kind]uint32{model.Replay: 30, model.Metric: 30}, MaxBytes: 1 << 24, MaxSeries: 100}
	actor, err := r.app.Auth.Authenticate(r.ctx, r.session)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := r.app.Auth.OnboardSource(r.ctx, actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: r.org, Project: r.project, Source: r.source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "replay index"})
	if err != nil {
		t.Fatal(err)
	}
	r.issued = issued.Credential
	return r
}

func (r *indexRig) open() {
	r.t.Helper()
	app, err := appcore.Open(r.dir)
	if err != nil {
		r.t.Fatal(err)
	}
	r.app, r.override = app, nil
}

// restart is the death and restart of the process on the same directories.
func (r *indexRig) restart() {
	r.t.Helper()
	if err := r.app.Close(); err != nil {
		r.t.Fatal(err)
	}
	r.open()
}

func (r *indexRig) revision() model.Revision {
	r.t.Helper()
	var out model.Revision
	if err := r.app.Control.View(r.ctx, func(st model.ControlState) error { out = st.Revision; return nil }); err != nil {
		r.t.Fatal(err)
	}
	return out
}

func (r *indexRig) command(kind string, p auth.AdminPayload) {
	r.t.Helper()
	actor, err := r.app.Auth.Authenticate(r.ctx, r.session)
	if err != nil {
		r.t.Fatal(err)
	}
	p.Reason = "replay index"
	raw, err := json.Marshal(p)
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err = r.app.Auth.AdminCommand(r.ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: r.revision(), OrgID: r.org, Kind: kind, Payload: raw}); err != nil {
		r.t.Fatal(err)
	}
}

// svc is the ingest service in use: the production one unless a test replaced it.
func (r *indexRig) svc() *ingest.Service {
	if r.override != nil {
		return r.override
	}
	return r.app.Ingest
}

// admit is one authenticated POST of a batch: resolve the source grant, admit.
func (r *indexRig) admit(b model.Batch) (model.Receipt, error) {
	r.t.Helper()
	cred, err := r.app.Auth.AuthenticateSource(r.ctx, r.issued, "", false)
	if err != nil {
		r.t.Fatal(err)
	}
	grant, err := r.svc().ResolveSource(r.ctx, cred, b)
	if err != nil {
		return model.Receipt{}, err
	}
	return r.svc().Admit(r.ctx, grant, b)
}

func (r *indexRig) lookup(b model.Batch, original model.Hash) (model.Receipt, error) {
	r.t.Helper()
	cred, err := r.app.Auth.AuthenticateSource(r.ctx, r.issued, "", false)
	if err != nil {
		r.t.Fatal(err)
	}
	return r.svc().LookupReceipt(r.ctx, cred, model.ReceiptRequest{Source: r.source, Producer: r.producer, RouteSlot: b.RouteSlot, BatchID: b.ID, OriginalHash: original})
}

func (r *indexRig) seal(records ...model.Record) model.Batch {
	r.t.Helper()
	b := model.Batch{Version: 1, Project: r.project, Source: r.source, Producer: r.producer, ID: model.NewID(), PolicyRevision: 1, Records: records}
	var err error
	if b.RouteSlot, err = model.OwnerSlot(r.org, r.project, r.source, r.producer, records[0]); err != nil {
		r.t.Fatal(err)
	}
	return b
}

// replayBatch is one batch of replay chunks of one replay.
func (r *indexRig) replayBatch(chunks ...model.ReplayChunk) model.Batch {
	r.t.Helper()
	records := make([]model.Record, len(chunks))
	for i := range chunks {
		c := chunks[i]
		records[i] = model.Record{ID: model.NewID(), Kind: model.Replay, ObservedAt: c.Clock.Wall, Resource: r.resource, Payload: model.Payload{Replay: &c}}
	}
	return r.seal(records...)
}

func (r *indexRig) metricBatch(name string) model.Batch {
	value := model.FloatBits(0x3ff0000000000000)
	return r.seal(model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: 1, Resource: r.resource,
		Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: &value, Unit: "1", Type: "counter"}}})
}

// The persisted layout of the index (docs/protocol/replay-v1.md): the control
// settings of the organization hold one index per replay and one pin map per project.
type indexedCheckpoint struct {
	Sequence uint64
	Hash     model.Hash
}
type indexedGroup struct {
	Session     model.ID
	Seq         uint64
	Checkpoints []indexedCheckpoint
}
type indexedPin struct {
	Seq         uint64
	RetainUntil model.UnixNano
}

// indexOf reads the checkpoint index and the retention pin of a replay; both are
// nil/zero when the replay has none.
func (r *indexRig) indexOf(replay model.ID) (*indexedGroup, indexedPin) {
	r.t.Helper()
	var group *indexedGroup
	var pin indexedPin
	if err := r.app.Control.View(r.ctx, func(st model.ControlState) error {
		settings := st.Orgs[r.org.String()].Settings
		if raw, ok := settings["replay_index:"+r.project.String()+":"+replay.String()]; ok {
			group = new(indexedGroup)
			if err := json.Unmarshal(raw, group); err != nil {
				return err
			}
		}
		if raw, ok := settings["replay_pins:"+r.project.String()]; ok {
			var pins map[string]indexedPin
			if err := json.Unmarshal(raw, &pins); err != nil {
				return err
			}
			pin = pins[replay.String()]
		}
		return nil
	}); err != nil {
		r.t.Fatal(err)
	}
	return group, pin
}

func (r *indexRig) readScope() auth.Scope {
	r.t.Helper()
	cred, err := r.app.Auth.Authenticate(r.ctx, r.reader)
	if err != nil {
		r.t.Fatal(err)
	}
	scope, err := r.app.Auth.Authorize(r.ctx, cred, r.org, []model.ID{r.project}, auth.Read)
	if err != nil {
		r.t.Fatal(err)
	}
	return scope
}

// storedRows counts the stored rows of one replay, duplicates included.
func (r *indexRig) storedRows(replay model.ID) int {
	r.t.Helper()
	it, err := r.app.Storage.Scan(r.ctx, r.readScope(), storage.ScanRequest{Projects: []model.ID{r.project}, Signal: model.Replay, Start: math.MinInt64, End: math.MaxInt64,
		Selectors: []storage.Matcher{{Target: storage.MatchField, Name: "replay_id", Op: storage.MatchEqual, Literal: storage.Literal{Kind: storage.LiteralString, String: replay.String()}}}})
	if err != nil {
		r.t.Fatal(err)
	}
	defer it.Close()
	rows := 0
	for {
		page, err := it.Next(r.ctx)
		if errors.Is(err, io.EOF) {
			return rows
		}
		if err != nil {
			r.t.Fatal(err)
		}
		for i := range page.Values {
			if c := page.Values[i].Replay; c != nil && c.Replay == replay {
				rows++
			}
		}
	}
}

// reads is the reader's view of a replay as the events it releases, e.g.
// "checkpoint1 delta2 gap3-4".
func (r *indexRig) reads(replay model.ID) string {
	r.t.Helper()
	service, err := appcore.NewReplayService(r.app.Storage, r.app.Auth, r.app.Control)
	if err != nil {
		r.t.Fatal(err)
	}
	stream, err := service.Read(r.ctx, r.readScope(), replay, replays.ReplayWindow{})
	if err != nil {
		r.t.Fatal(err)
	}
	defer stream.Close()
	var out []string
	for {
		ev, err := stream.Next(r.ctx)
		if errors.Is(err, io.EOF) {
			return strings.Join(out, " ")
		}
		if err != nil {
			r.t.Fatal(err)
		}
		switch ev.Kind {
		case replays.EventGap:
			out = append(out, fmt.Sprintf("gap%d-%d", ev.Sequence, ev.Through))
		default:
			out = append(out, fmt.Sprintf("%s%d", ev.Kind, ev.Sequence))
		}
	}
}

// quota is what the source has been charged: bytes and reservations.
func (r *indexRig) quota() (uint64, int) {
	r.t.Helper()
	var bytes uint64
	var reservations int
	if err := r.app.Control.View(r.ctx, func(st model.ControlState) error {
		bytes = uint64(st.Quotas["source:"+r.org.String()+":"+r.project.String()+":"+r.source.String()].Bytes)
		reservations = len(st.Reservations)
		return nil
	}); err != nil {
		r.t.Fatal(err)
	}
	return bytes, reservations
}

// replayRecorder builds chunks the way the SDK recorder chains them: a checkpoint
// repeats the previous hash as its checkpoint hash, a delta names the checkpoint.
type replayRecorder struct {
	replay, session model.ID
	domain          model.ClockDomain
	base            model.UnixNano
	seq, cpSeq      uint64
	prev, cpHash    model.Hash
}

func newReplayRecorder() *replayRecorder {
	return &replayRecorder{replay: model.NewID(), session: model.NewID(), domain: model.ClockDomain{Host: model.NewID(), Boot: model.NewID(), Runtime: model.NewID()}, base: model.UnixNano(time.Now().UnixNano())}
}

func (r *replayRecorder) next(checkpoint bool) model.ReplayChunk {
	r.seq++
	wall := r.base + model.UnixNano(r.seq)*1_000_000
	c := model.ReplayChunk{Replay: r.replay, Session: r.session, Recorder: "1", Sequence: model.Uint64(r.seq), Previous: r.prev, PolicyRevision: 1,
		Clock:  model.TraceClock{Wall: wall, Mono: model.MonoNano(r.seq) * 1000, Domain: r.domain},
		Events: []model.MaskedEvent{{At: model.MonoNano(wall), Kind: "pointer", Node: 1, X: int32(r.seq), Y: 7}}}
	if checkpoint {
		c.CheckpointSequence, c.Checkpoint = model.Uint64(r.seq), r.prev
		c.Nodes = []model.MaskedNode{{ID: 1, Tag: "div", Class: "masked", Text: "[masked]"}, {ID: 2, Parent: 1, Tag: "span", Text: "[masked]"}}
	} else {
		c.CheckpointSequence, c.Checkpoint = model.Uint64(r.cpSeq), r.cpHash
	}
	h, err := replays.ChunkHash(c)
	if err != nil {
		panic(err)
	}
	r.prev = h
	if checkpoint {
		r.cpSeq, r.cpHash = r.seq, h
	}
	return c
}

func (r *replayRecorder) cp() model.ReplayChunk    { return r.next(true) }
func (r *replayRecorder) delta() model.ReplayChunk { return r.next(false) }

// forged is a different chunk at the same sequence and still inside the closed format.
func forged(c model.ReplayChunk) model.ReplayChunk {
	c.Events = []model.MaskedEvent{{At: 1, Kind: "pointer", Node: 1, X: 9, Y: 9}}
	return c
}

func codeOf(err error) model.Code {
	var f *model.Fault
	if errors.As(err, &f) {
		return f.Code
	}
	return ""
}
