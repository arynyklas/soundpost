// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replays

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/policy"
	"github.com/arynyklas/soundpost/internal/replica"
	"github.com/arynyklas/soundpost/internal/retention"
	"github.com/arynyklas/soundpost/internal/storage"
	"io"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fx is a real control store, auth service, source policy service, replicated
// storage engine (one voter, 64 slots), retention service and replay service.
// The only seam that can be substituted is the scanner hook (tamper tests).
type fx struct {
	t      *testing.T
	ctx    context.Context
	clock  atomic.Int64
	store  *control.Store
	auth   *auth.Service
	engine *storage.Engine
	policy *policy.Service
	ret    *retention.Service
	svc    *Service
	scan   *hookScanner
	cred   auth.Credential
	user   model.ID
	main   tenant
}

type tenant struct {
	org, project, source, producer model.ID
	cred                           auth.SourceCredential
	desc                           model.SourceDescriptor
	resource                       model.Resource
}

func (f *fx) now() time.Time       { return time.Unix(0, f.clock.Load()) }
func (f *fx) wall() model.UnixNano { return model.UnixNano(f.clock.Load()) }

func newFx(t *testing.T) *fx {
	t.Helper()
	f := &fx{t: t, ctx: context.Background()}
	f.clock.Store(time.Unix(1_800_000_000, 0).UnixNano())
	dir := t.TempDir()
	var err error
	if f.store, err = control.Open(filepath.Join(dir, "control")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.store.Close() })
	if f.auth, err = auth.NewService(auth.AuthDependencies{Control: f.store, Now: f.now}); err != nil {
		t.Fatal(err)
	}
	if err = f.store.EnableSingle(f.ctx, filepath.Join(dir, "control", "raft")); err != nil {
		t.Fatal(err)
	}
	boot, _ := f.store.BootstrapToken()
	s, err := f.auth.Bootstrap(f.ctx, boot, "owner@example.test", "a long test password 2026")
	if err != nil {
		t.Fatal(err)
	}
	f.user = s.User
	if f.cred, err = f.auth.Authenticate(f.ctx, s.Token); err != nil {
		t.Fatal(err)
	}
	if f.engine, err = storage.Open(filepath.Join(dir, "data"), f.auth); err != nil {
		t.Fatal(err)
	}
	transport := replica.NewLoopback()
	groups, err := f.engine.EnableReplication(replica.Config{ID: 1, Directory: filepath.Join(dir, "data", "raft"), Transport: transport, Members: replica.Members{Revision: 1, Nodes: []replica.Member{{ID: 1, Address: "https://single.invalid", NodeIdentity: "single", FailureDomain: "local-disk"}}}}, nil, f.store)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range groups {
		if err = transport.Register(g); err == nil {
			err = g.Campaign()
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { f.engine.Close(); transport.Close() })
	if err = f.store.BindAdmissionOwner(f.engine); err != nil {
		t.Fatal(err)
	}
	if err = f.engine.BindDeletions(f.store); err != nil {
		t.Fatal(err)
	}
	if f.policy, err = policy.New(f.auth, f.now); err != nil {
		t.Fatal(err)
	}
	f.scan = &hookScanner{inner: f.engine}
	if f.svc, err = New(f.scan, f.auth, f.store); err != nil {
		t.Fatal(err)
	}
	f.svc.now = f.now
	if f.ret, err = retention.New(retention.Config{Control: f.store, Data: f.engine, Base: f.auth.SourceLifecycleGenerations(), References: f.svc, Clock: f.now}); err != nil {
		t.Fatal(err)
	}
	f.main = f.addTenant(model.NewID())
	return f
}

func (f *fx) revision() model.Revision {
	var r model.Revision
	if err := f.store.View(f.ctx, func(st control.State) error { r = st.Revision; return nil }); err != nil {
		f.t.Fatal(err)
	}
	return r
}
func (f *fx) admin(org model.ID, kind string, p auth.AdminPayload) {
	f.t.Helper()
	p.Reason = "fixture"
	raw, _ := json.Marshal(p)
	if _, err := f.auth.AdminCommand(f.ctx, f.cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: f.revision(), OrgID: org, Kind: kind, Payload: raw}); err != nil {
		f.t.Fatal(kind, err)
	}
}

// addTenant creates an organization with one project and one replay-enabled source.
func (f *fx) addTenant(org model.ID) tenant {
	f.t.Helper()
	t := tenant{org: org, project: model.NewID(), source: model.NewID(), producer: model.NewID()}
	f.admin(org, "create_org", auth.AdminPayload{Name: "org-" + org.String()[:6]})
	f.admin(org, "create_project", auth.AdminPayload{ID: t.project, Name: "p"})
	f.admin(org, "membership", auth.AdminPayload{UserID: f.user, Enabled: true})
	svc, env, build := model.NewID(), model.NewID(), model.NewID()
	pol := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Replay}, Replay: true, Resources: model.ResourceRegistry{Services: []model.ID{svc}, Environments: []model.ID{env}, Builds: []model.ID{build}, Instances: []string{"i"}}, RetentionDays: map[model.Kind]uint32{model.Replay: 14}, MaxBytes: 1 << 30, MaxSeries: 100}
	issued, err := f.auth.OnboardSource(f.ctx, f.cred, auth.SourceOnboarding{CommandID: model.NewID(), Org: org, Project: t.project, Source: t.source, Expires: model.UnixNano(f.now().Add(60 * 24 * time.Hour).UnixNano()), Policy: pol, Reason: "fixture"})
	if err != nil {
		f.t.Fatal(err)
	}
	t.desc = issued.Descriptor
	if t.cred, err = f.auth.AuthenticateSource(f.ctx, issued.Credential, "", false); err != nil {
		f.t.Fatal(err)
	}
	t.resource = model.Resource{Service: svc, Environment: env, Build: build, Instance: "i"}
	return t
}

// reader creates a user with a Read grant on the given projects and returns a
// scope for them plus a function that revokes the grant on one project.
func (f *fx) reader(t tenant, projects ...model.ID) (auth.Scope, func()) {
	f.t.Helper()
	cred, revoke := f.readerCred(t, projects...)
	return f.scopeOf(t, cred, projects...), revoke
}

func (f *fx) scopeOf(t tenant, cred auth.Credential, projects ...model.ID) auth.Scope {
	f.t.Helper()
	scope, err := f.auth.Authorize(f.ctx, cred, t.org, projects, auth.Read)
	if err != nil {
		f.t.Fatal(err)
	}
	return scope
}

// readerCred creates the user; admin commands bump the org epoch, so a scope
// must be taken after the last command of a test.
func (f *fx) readerCred(t tenant, projects ...model.ID) (auth.Credential, func()) {
	f.t.Helper()
	user := model.NewID()
	email := fmt.Sprintf("reader-%s@example.test", user.String()[:8])
	f.admin(t.org, "create_user", auth.AdminPayload{ID: user, Email: email, Password: "reader password 2026"})
	f.admin(t.org, "membership", auth.AdminPayload{UserID: user, Enabled: true})
	for _, p := range projects {
		f.admin(t.org, "grant", auth.AdminPayload{UserID: user, ProjectID: p, Enabled: true, Permissions: []string{string(auth.Read)}})
	}
	login, err := f.auth.Login(f.ctx, email, "reader password 2026", "")
	if err != nil {
		f.t.Fatal(err)
	}
	cred, err := f.auth.Authenticate(f.ctx, login.Token)
	if err != nil {
		f.t.Fatal(err)
	}
	return cred, func() {
		f.admin(t.org, "grant", auth.AdminPayload{UserID: user, ProjectID: projects[0], Enabled: false})
	}
}

func (f *fx) grant(t tenant) policy.SourceGrant {
	f.t.Helper()
	g, err := f.policy.ResolveSource(f.ctx, t.cred, t.project, t.source, 1)
	if err != nil {
		f.t.Fatal(err)
	}
	return g
}

// rawAppend runs the real admission path (policy.Normalize, quota reservation,
// durable append) and, when record is set, the post-admission index step. The
// replay Validate gate is the caller's choice, so a test can also store what the
// gate would have rejected.
func (f *fx) rawAppend(t tenant, c model.ReplayChunk, record bool) error {
	g := f.grant(t)
	b := model.Batch{Version: 1, Project: t.project, Source: t.source, Producer: t.producer, ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Replay, ObservedAt: c.Clock.Wall, Resource: t.resource, Payload: model.Payload{Replay: &c}}}}
	b.RouteSlot, _ = model.OwnerSlot(t.org, t.project, t.source, t.producer, b.Records[0])
	n, err := policy.Normalize(g, b)
	if err != nil {
		return err
	}
	scope, err := g.Scope()
	if err != nil {
		return err
	}
	if n.Reservation, err = f.store.ReserveAdmission(f.ctx, scope, n); err != nil {
		return err
	}
	if _, err = f.engine.Append(f.ctx, scope, n); err != nil {
		return err
	}
	if record {
		return f.svc.Record(f.ctx, g, t.project, c, n.Deadlines[0].RetainUntil)
	}
	return nil
}

// admit is production admission order: Validate, durable append, index.
func (f *fx) admit(t tenant, c model.ReplayChunk) error {
	if err := f.svc.Validate(f.grant(t), c); err != nil {
		return err
	}
	return f.rawAppend(t, c, true)
}
func (f *fx) mustAdmit(t tenant, cs ...model.ReplayChunk) {
	f.t.Helper()
	for _, c := range cs {
		if err := f.admit(t, c); err != nil {
			f.t.Fatalf("admit sequence %d: %v", c.Sequence, err)
		}
	}
}

// recorder builds chunks the way the SDK recorder chains them: a checkpoint
// repeats the previous hash as its checkpoint hash, a delta names the checkpoint.
type recorder struct {
	replay, session model.ID
	domain          model.ClockDomain
	base            model.UnixNano
	seq, cpSeq      uint64
	prev, cpHash    model.Hash
}

func newRecorder(base model.UnixNano) *recorder {
	return &recorder{replay: model.NewID(), session: model.NewID(), domain: model.ClockDomain{Host: model.NewID(), Boot: model.NewID(), Runtime: model.NewID()}, base: base}
}
func (r *recorder) next(checkpoint bool) model.ReplayChunk {
	r.seq++
	wall := r.base + model.UnixNano(r.seq)*1_000_000
	c := model.ReplayChunk{Replay: r.replay, Session: r.session, Recorder: "1", Sequence: model.Uint64(r.seq), Previous: r.prev, Clock: model.TraceClock{Wall: wall, Mono: model.MonoNano(r.seq) * 1000, Domain: r.domain}, PolicyRevision: 1,
		Events: []model.MaskedEvent{{At: model.MonoNano(wall), Kind: "pointer", Node: 1, X: int32(r.seq), Y: 7}}}
	if checkpoint {
		c.CheckpointSequence, c.Checkpoint = model.Uint64(r.seq), r.prev
		c.Nodes = []model.MaskedNode{{ID: 1, Tag: "div", Class: "masked", Text: "[masked]"}, {ID: 2, Parent: 1, Tag: "span", Text: "[masked]"}}
	} else {
		c.CheckpointSequence, c.Checkpoint = model.Uint64(r.cpSeq), r.cpHash
	}
	h, err := ChunkHash(c)
	if err != nil {
		panic(err)
	}
	r.prev = h
	if checkpoint {
		r.cpSeq, r.cpHash = r.seq, h
	}
	return c
}
func (r *recorder) cp() model.ReplayChunk    { return r.next(true) }
func (r *recorder) delta() model.ReplayChunk { return r.next(false) }

// chain returns checkpoint, then n deltas.
func (r *recorder) chain(n int) []model.ReplayChunk {
	out := []model.ReplayChunk{r.cp()}
	for i := 0; i < n; i++ {
		out = append(out, r.delta())
	}
	return out
}

// drain reads a stream to EOF and renders it compactly: C<seq> D<seq> G<a>-<b>
// U<seq> R<seq> E<seq>. Chunk bodies are only present on C and D events.
func drain(t *testing.T, s ReplayStream) (string, []Event) {
	t.Helper()
	defer s.Close()
	var out []string
	var evs []Event
	for {
		ev, err := s.Next(context.Background())
		if errors.Is(err, io.EOF) {
			return strings.Join(out, " "), evs
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		evs = append(evs, ev)
		switch ev.Kind {
		case EventCheckpoint:
			out = append(out, fmt.Sprintf("C%d", ev.Sequence))
		case EventDelta:
			out = append(out, fmt.Sprintf("D%d", ev.Sequence))
		case EventGap:
			out = append(out, fmt.Sprintf("G%d-%d", ev.Sequence, ev.Through))
		case EventUnsupported:
			out = append(out, fmt.Sprintf("U%d", ev.Sequence))
		case EventRevoke:
			out = append(out, fmt.Sprintf("R%d", ev.Sequence))
		case EventError:
			out = append(out, fmt.Sprintf("E%d", ev.Sequence))
		}
		if (ev.Kind == EventCheckpoint || ev.Kind == EventDelta) != (ev.Chunk != nil) {
			t.Fatalf("event %s carries chunk=%v", ev.Kind, ev.Chunk != nil)
		}
	}
}

func (f *fx) read(scope auth.Scope, id model.ID, w ReplayWindow) (string, []Event) {
	f.t.Helper()
	s, err := f.svc.Read(f.ctx, scope, id, w)
	if err != nil {
		f.t.Fatalf("Read: %v", err)
	}
	return drain(f.t, s)
}

func code(err error) model.Code { return faultCode(err) }

// hookScanner wraps the real engine so a test can drop, edit or add rows as the
// reader sees them, simulating a damaged or tampered store.
type hookScanner struct {
	inner  ReplayScanner
	drop   func(*model.ReplayChunk) bool
	edit   func(*model.ReplayChunk)
	before func() // runs at the start of every Scan
	end    func() // runs once when the inner iterator is exhausted, before the reader sees EOF
	extra  []extraRow
	scans  atomic.Int64
}
type extraRow struct {
	project model.ID
	chunk   model.ReplayChunk
}

func (h *hookScanner) Scan(ctx context.Context, s auth.Scope, req storage.ScanRequest) (storage.RowIterator, error) {
	h.scans.Add(1)
	if h.before != nil {
		h.before()
	}
	it, err := h.inner.Scan(ctx, s, req)
	if err != nil {
		return nil, err
	}
	return &hookRows{h: h, it: it, id: req.Selectors[0].Literal.String}, nil
}

type hookRows struct {
	h        *hookScanner
	it       storage.RowIterator
	id       string
	extraned bool
}

func (r *hookRows) Next(ctx context.Context) (storage.Page, error) {
	p, err := r.it.Next(ctx)
	if errors.Is(err, io.EOF) && r.h.end != nil {
		end := r.h.end
		r.h.end = nil
		end()
	}
	if errors.Is(err, io.EOF) && !r.extraned {
		r.extraned = true
		var out storage.Page
		for _, e := range r.h.extra {
			c := e.chunk
			if c.Replay.String() != r.id {
				continue
			}
			out.IDs = append(out.IDs, model.NewID())
			out.Projects = append(out.Projects, e.project)
			out.Values = append(out.Values, model.Payload{Replay: &c})
		}
		if len(out.IDs) > 0 {
			return out, nil
		}
	}
	if err != nil {
		return p, err
	}
	var out storage.Page
	for i := range p.Values {
		v := p.Values[i].Replay
		if v == nil {
			continue
		}
		c := *v
		if r.h.drop != nil && r.h.drop(&c) {
			continue
		}
		if r.h.edit != nil {
			r.h.edit(&c)
		}
		out.IDs = append(out.IDs, p.IDs[i])
		out.Projects = append(out.Projects, p.Projects[i])
		out.Values = append(out.Values, model.Payload{Replay: &c})
	}
	return out, nil
}
func (r *hookRows) Watermarks() []model.Cursor { return r.it.Watermarks() }
func (r *hookRows) Close() error               { return r.it.Close() }

func TestReplayCheckpointAndMissingChunk(t *testing.T) {
	t.Run("a missing middle chunk is an explicit gap until the next verified checkpoint", func(t *testing.T) {
		f := newFx(t)
		scope, _ := f.reader(f.main, f.main.project)
		r := newRecorder(f.wall())
		c := r.chain(5)       // 1 cp, 2..6 deltas
		c = append(c, r.cp()) // 7 cp
		c = append(c, r.delta(), r.delta())
		f.mustAdmit(f.main, c[0], c[1], c[2], c[4], c[5], c[6], c[7], c[8]) // sequence 4 (c[3]) never arrives
		got, evs := f.read(scope, r.replay, ReplayWindow{})
		if want := "C1 D2 D3 G4-6 C7 D8 D9"; got != want {
			t.Fatalf("stream %q, want %q", got, want)
		}
		for _, ev := range evs {
			if ev.Kind == EventGap && ev.Reason != ReasonMissingChunk {
				t.Fatalf("gap reason %q", ev.Reason)
			}
			if ev.Kind == EventDelta && (ev.Sequence == 5 || ev.Sequence == 6) {
				t.Fatal("a delta behind the hole was applied")
			}
		}
	})
	t.Run("a staged future chunk never makes the replay look continuous and the late chunk heals it", func(t *testing.T) {
		f := newFx(t)
		scope, _ := f.reader(f.main, f.main.project)
		r := newRecorder(f.wall())
		c := r.chain(4) // 1..5
		f.mustAdmit(f.main, c[0], c[1], c[3], c[4])
		got, _ := f.read(scope, r.replay, ReplayWindow{})
		if want := "C1 D2 G3-5"; got != want {
			t.Fatalf("with the hole %q, want %q", got, want)
		}
		f.mustAdmit(f.main, c[2]) // the missing chunk arrives late, out of order
		got, _ = f.read(scope, r.replay, ReplayWindow{})
		if want := "C1 D2 D3 D4 D5"; got != want {
			t.Fatalf("after arrival %q, want %q", got, want)
		}
	})
	t.Run("a duplicate is applied once and a different chunk at the same sequence is a conflict", func(t *testing.T) {
		f := newFx(t)
		scope, _ := f.reader(f.main, f.main.project)
		r := newRecorder(f.wall())
		c := r.chain(3)
		f.mustAdmit(f.main, c[0], c[1], c[2], c[2], c[3])
		if got, _ := f.read(scope, r.replay, ReplayWindow{}); got != "C1 D2 D3 D4" {
			t.Fatalf("duplicate delivery: %q", got)
		}
		forged := c[2]
		forged.Events = []model.MaskedEvent{{At: 1, Kind: "pointer", Node: 1, X: 99, Y: 99}}
		f.mustAdmit(f.main, forged)
		got, evs := f.read(scope, r.replay, ReplayWindow{})
		if want := "C1 D2 G3-4"; got != want {
			t.Fatalf("conflicting delta: %q, want %q", got, want)
		}
		for _, ev := range evs {
			if ev.Kind == EventGap && ev.Reason != ReasonConflictingChunk {
				t.Fatalf("reason %q", ev.Reason)
			}
		}
	})
	t.Run("an altered previous hash cannot apply its delta or anything chained behind it", func(t *testing.T) {
		f := newFx(t)
		scope, _ := f.reader(f.main, f.main.project)
		r := newRecorder(f.wall())
		c := r.chain(4)
		c[2].Previous[0] ^= 0xff // sequence 3 claims a different predecessor
		f.mustAdmit(f.main, c...)
		got, evs := f.read(scope, r.replay, ReplayWindow{})
		if want := "C1 D2 G3-5"; got != want {
			t.Fatalf("stream %q, want %q", got, want)
		}
		if evs[2].Reason != ReasonHashMismatch {
			t.Fatalf("reason %q", evs[2].Reason)
		}
	})
	t.Run("a delta naming the wrong checkpoint is never applied", func(t *testing.T) {
		f := newFx(t)
		scope, _ := f.reader(f.main, f.main.project)
		r := newRecorder(f.wall())
		c := r.chain(2)
		c[2].Checkpoint[0] ^= 0xff
		f.mustAdmit(f.main, c...)
		got, evs := f.read(scope, r.replay, ReplayWindow{})
		if want := "C1 D2 G3-3"; got != want || evs[2].Reason != ReasonDependencyMismatch {
			t.Fatalf("stream %q reason %q", got, evs[2].Reason)
		}
	})
	t.Run("a checkpoint contradicting its present predecessor is not a recovery point", func(t *testing.T) {
		f := newFx(t)
		scope, _ := f.reader(f.main, f.main.project)
		r := newRecorder(f.wall())
		c := r.chain(1)
		cp := r.cp() // 3
		cp.Previous[0] ^= 0xff
		cp.Checkpoint = cp.Previous
		d := r.delta() // 4
		f.mustAdmit(f.main, c[0], c[1], cp, d)
		got, _ := f.read(scope, r.replay, ReplayWindow{})
		if want := "C1 D2 G3-4"; got != want {
			t.Fatalf("stream %q, want %q", got, want)
		}
	})
	t.Run("a checkpoint after a lost predecessor recovers with an explicit gap", func(t *testing.T) {
		f := newFx(t)
		scope, _ := f.reader(f.main, f.main.project)
		r := newRecorder(f.wall())
		c := r.chain(1)
		r.delta() // 3 lost
		cp := r.cp()
		f.mustAdmit(f.main, c[0], c[1], cp, r.delta())
		got, _ := f.read(scope, r.replay, ReplayWindow{})
		if want := "C1 D2 G3-3 C4 D5"; got != want {
			t.Fatalf("stream %q, want %q", got, want)
		}
	})
	t.Run("recorder gap markers break continuity and a gap-marked checkpoint recovers", func(t *testing.T) {
		f := newFx(t)
		scope, _ := f.reader(f.main, f.main.project)
		r := newRecorder(f.wall())
		c := r.chain(1)
		lossy := r.delta() // 3: the recorder overflowed
		lossy.Gap = true
		after := r.delta() // 4
		recover := r.cp()  // 5
		recover.Gap = true
		last := r.delta() // 6
		f.mustAdmit(f.main, c[0], c[1])
		// Gap flags are part of the hash; rebuild the chain around them.
		fixed := rechain(t, []model.ReplayChunk{c[0], c[1], lossy, after, recover, last})
		f.mustAdmit(f.main, fixed[2:]...)
		got, evs := f.read(scope, r.replay, ReplayWindow{})
		if want := "C1 D2 G3-4 G5-5 C5 D6"; got != want {
			t.Fatalf("stream %q, want %q", got, want)
		}
		if evs[2].Reason != ReasonRecorderGap || evs[3].Reason != ReasonRecorderGap {
			t.Fatalf("reasons %q %q", evs[2].Reason, evs[3].Reason)
		}
	})
	t.Run("a window opening on a delta snaps back to its checkpoint and every step since", func(t *testing.T) {
		f := newFx(t)
		scope, _ := f.reader(f.main, f.main.project)
		r := newRecorder(f.wall())
		c := r.chain(4)
		f.mustAdmit(f.main, c...)
		if got, _ := f.read(scope, r.replay, ReplayWindow{From: 4, To: 5}); got != "C1 D2 D3 D4 D5" {
			t.Fatalf("window %q", got)
		}
		if got, _ := f.read(scope, r.replay, ReplayWindow{From: 1, To: 2}); got != "C1 D2" {
			t.Fatalf("head window %q", got)
		}
		if _, err := f.svc.Read(f.ctx, scope, r.replay, ReplayWindow{From: 4, To: 2}); code(err) != model.Invalid {
			t.Fatalf("inverted window: %v", err)
		}
	})
	t.Run("event metadata carries sequence, hash, policy and clock", func(t *testing.T) {
		f := newFx(t)
		scope, _ := f.reader(f.main, f.main.project)
		r := newRecorder(f.wall())
		c := r.chain(1)
		f.mustAdmit(f.main, c...)
		_, evs := f.read(scope, r.replay, ReplayWindow{})
		h0, _ := ChunkHash(c[0])
		h1, _ := ChunkHash(c[1])
		if evs[0].Hash != h0 || evs[1].Hash != h1 || evs[1].Previous != h0 || evs[1].Checkpoint != h0 || evs[1].CheckpointSequence != 1 || evs[1].Policy != 1 || evs[1].Clock != c[1].Clock || evs[0].Sequence != 1 || evs[1].Sequence != 2 {
			t.Fatalf("metadata %+v", evs[1])
		}
	})
	t.Run("a recorder version this server cannot reconstruct is reported unsupported, never rendered", func(t *testing.T) {
		f := newFx(t)
		scope, _ := f.reader(f.main, f.main.project)
		r := newRecorder(f.wall())
		c := r.chain(2)
		c[2].Recorder = "2"
		if err := f.svc.Validate(f.grant(f.main), c[2]); code(err) != model.Unsupported {
			t.Fatalf("admission gate: %v", err)
		}
		f.mustAdmit(f.main, c[0], c[1])
		if err := f.rawAppend(f.main, c[2], false); err != nil { // stored before a downgrade, say
			t.Fatal(err)
		}
		got, _ := f.read(scope, r.replay, ReplayWindow{})
		if want := "C1 D2 U3"; got != want {
			t.Fatalf("stream %q, want %q", got, want)
		}
	})
}

// rechain recomputes previous/checkpoint hashes so flag edits stay a valid chain.
func rechain(t *testing.T, in []model.ReplayChunk) []model.ReplayChunk {
	t.Helper()
	out := make([]model.ReplayChunk, len(in))
	var prev, cp model.Hash
	for i, c := range in {
		c.Previous = prev
		if c.CheckpointSequence == c.Sequence {
			c.Checkpoint = prev
		} else {
			c.Checkpoint = cp
		}
		h, err := ChunkHash(c)
		if err != nil {
			t.Fatal(err)
		}
		prev = h
		if c.CheckpointSequence == c.Sequence {
			cp = h
		}
		out[i] = c
	}
	return out
}
