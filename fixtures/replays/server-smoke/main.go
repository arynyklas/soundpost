// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Command server-smoke exercises the replay server chain against a real
// in-process Soundpost node: private app state, the real HTTPS ingest route,
// the real storage engine, auth and retention. Chunks are built by this program
// through the closed replay format; it does NOT use the browser recorder, the
// inert renderer or the UI (plan 03 and plan 05 own those), and no HTTP route
// reads replays yet, so the replay service is bound here directly over the
// engine, auth service and control state of the app. It never contacts a
// configured remote endpoint.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/httpapi"
	"soundpost/internal/model"
	"soundpost/internal/policy"
	"soundpost/internal/replays"
	"soundpost/internal/retention"
	"strings"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "replay server smoke failed:", err)
		os.Exit(1)
	}
}

type smoke struct {
	ctx                  context.Context
	app                  *appcore.App
	svc                  *replays.Service
	policies             *policy.Service
	client               *http.Client
	endpoint             string
	owner                auth.Credential
	org, project, source model.ID
	producer             model.ID
	resource             model.Resource
	credential           string
	sourceCredential     auth.SourceCredential
	observed             []string
}

func run() error {
	endpointEnv := flag.String("endpoint-env", "SOUNDPOST_FIXTURE_API", "variable assigned the ephemeral local HTTPS fixture endpoint; must initially be unset")
	dropMiddle := flag.Bool("drop-middle", false, "never deliver one middle chunk and require an explicit gap until the next checkpoint")
	revokeReader := flag.Bool("revoke-reader", false, "revoke a reader between chunks and require a typed revoke before any further chunk")
	deleteRoot := flag.Bool("delete-root", false, "delete the replay root and require the same revoke and a not_found for later readers")
	flag.Parse()
	if *endpointEnv == "" || os.Getenv(*endpointEnv) != "" {
		return errors.New("an unused local endpoint variable is required")
	}
	dir, err := os.MkdirTemp("", "soundpost-replay-smoke-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	s := &smoke{ctx: context.Background()}
	if s.app, err = appcore.Open(dir); err != nil {
		return errors.New("private app state unavailable")
	}
	defer s.app.Close()
	server := httptest.NewTLSServer(httpapi.NewServer("", s.app.Auth, nil, s.app.Register).Handler)
	defer server.Close()
	s.client, s.endpoint = server.Client(), server.URL
	if err = os.Setenv(*endpointEnv, s.endpoint); err != nil {
		return err
	}
	defer os.Unsetenv(*endpointEnv)
	if err = s.setup(); err != nil {
		return err
	}
	if s.svc, err = replays.New(s.app.Storage, s.app.Auth, s.app.Control); err != nil {
		return err
	}
	if s.policies, err = policy.New(s.app.Auth, nil); err != nil {
		return err
	}
	if err = s.rawChannels(); err != nil {
		return err
	}
	if err = s.scenario(*dropMiddle); err != nil {
		return err
	}
	if *revokeReader {
		if err = s.revoke(); err != nil {
			return err
		}
	}
	if *deleteRoot {
		if err = s.deleteRoot(); err != nil {
			return err
		}
	}
	for _, line := range s.observed {
		fmt.Println(line)
	}
	fmt.Println("not covered: browser recorder (03.07), inert renderer (03.08), UI (05.08), group retention through the retention service of the app (it does not wire replays.Service as a References source), SDK pre-buffer masking")
	return nil
}

func (s *smoke) note(format string, args ...any) {
	s.observed = append(s.observed, fmt.Sprintf(format, args...))
}

func (s *smoke) command(kind string, p auth.AdminPayload) error {
	var revision model.Revision
	if err := s.app.Control.View(s.ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		return err
	}
	p.Reason = "replay server smoke"
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = s.app.Auth.AdminCommand(s.ctx, s.owner, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: s.org, Kind: kind, Payload: raw})
	return err
}

func (s *smoke) setup() error {
	boot, err := s.app.Control.BootstrapToken()
	if err != nil {
		return err
	}
	session, err := s.app.Auth.Bootstrap(s.ctx, boot, "replay-smoke-owner@example.test", "replay smoke owner password 2026")
	if err != nil {
		return err
	}
	if s.owner, err = s.app.Auth.Authenticate(s.ctx, session.Token); err != nil {
		return err
	}
	s.org, s.project, s.source, s.producer = model.NewID(), model.NewID(), model.NewID(), model.NewID()
	if err = s.command("create_org", auth.AdminPayload{Name: "replay smoke"}); err != nil {
		return err
	}
	if err = s.command("create_project", auth.AdminPayload{ID: s.project, Name: "web"}); err != nil {
		return err
	}
	svc, env, build := model.NewID(), model.NewID(), model.NewID()
	pol := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Replay}, Replay: true, Resources: model.ResourceRegistry{Services: []model.ID{svc}, Environments: []model.ID{env}, Builds: []model.ID{build}, Instances: []string{"replay-smoke"}}, RetentionDays: map[model.Kind]uint32{model.Replay: 14}, MaxBytes: 1 << 30, MaxSeries: 100}
	issued, err := s.app.Auth.OnboardSource(s.ctx, s.owner, auth.SourceOnboarding{CommandID: model.NewID(), Org: s.org, Project: s.project, Source: s.source, Expires: model.UnixNano(time.Now().Add(24 * time.Hour).UnixNano()), Policy: pol, Reason: "replay server smoke"})
	if err != nil {
		return err
	}
	s.credential = issued.Credential
	if s.sourceCredential, err = s.app.Auth.AuthenticateSource(s.ctx, issued.Credential, "", false); err != nil {
		return err
	}
	s.resource = model.Resource{Service: svc, Environment: env, Build: build, Instance: "replay-smoke"}
	return nil
}

// reader creates a fresh read-only user and returns its scope and a revoke func.
func (s *smoke) reader() (auth.Scope, func() error, error) {
	user := model.NewID()
	email := "reader-" + user.String()[:8] + "@example.test"
	for _, step := range []struct {
		kind string
		p    auth.AdminPayload
	}{
		{"create_user", auth.AdminPayload{ID: user, Email: email, Password: "replay smoke reader 2026"}},
		{"membership", auth.AdminPayload{UserID: user, Enabled: true}},
		{"grant", auth.AdminPayload{UserID: user, ProjectID: s.project, Enabled: true, Permissions: []string{string(auth.Read)}}},
	} {
		if err := s.command(step.kind, step.p); err != nil {
			return auth.Scope{}, nil, err
		}
	}
	login, err := s.app.Auth.Login(s.ctx, email, "replay smoke reader 2026", "")
	if err != nil {
		return auth.Scope{}, nil, err
	}
	cred, err := s.app.Auth.Authenticate(s.ctx, login.Token)
	if err != nil {
		return auth.Scope{}, nil, err
	}
	scope, err := s.app.Auth.Authorize(s.ctx, cred, s.org, []model.ID{s.project}, auth.Read)
	if err != nil {
		return auth.Scope{}, nil, err
	}
	return scope, func() error {
		return s.command("grant", auth.AdminPayload{UserID: user, ProjectID: s.project, Enabled: false})
	}, nil
}

// recorder chains chunks the way the closed format requires.
type recorder struct {
	replay, session model.ID
	domain          model.ClockDomain
	seq, cpSeq      uint64
	prev, cpHash    model.Hash
}

func newRecorder() *recorder {
	return &recorder{replay: model.NewID(), session: model.NewID(), domain: model.ClockDomain{Host: model.NewID(), Boot: model.NewID(), Runtime: model.NewID()}}
}

func (r *recorder) next(checkpoint bool) (model.ReplayChunk, error) {
	r.seq++
	wall := model.UnixNano(time.Now().UnixNano())
	c := model.ReplayChunk{Replay: r.replay, Session: r.session, Recorder: "1", Sequence: model.Uint64(r.seq), Previous: r.prev, Clock: model.TraceClock{Wall: wall, Mono: model.MonoNano(r.seq) * 1000, Domain: r.domain}, PolicyRevision: 1,
		Events: []model.MaskedEvent{{At: model.MonoNano(wall), Kind: "pointer", Node: 1, X: int32(r.seq), Y: 3}}}
	if checkpoint {
		c.CheckpointSequence, c.Checkpoint = model.Uint64(r.seq), r.prev
		c.Nodes = []model.MaskedNode{{ID: 1, Tag: "div", Class: "masked", Text: "[masked]"}, {ID: 2, Parent: 1, Tag: "button", Text: "[masked]"}}
	} else {
		c.CheckpointSequence, c.Checkpoint = model.Uint64(r.cpSeq), r.cpHash
	}
	h, err := replays.ChunkHash(c)
	if err != nil {
		return c, err
	}
	r.prev = h
	if checkpoint {
		r.cpSeq, r.cpHash = r.seq, h
	}
	return c, nil
}

func (s *smoke) grant() (policy.SourceGrant, error) {
	return s.policies.ResolveSource(s.ctx, s.sourceCredential, s.project, s.source, 1)
}

func (s *smoke) batch(c model.ReplayChunk) (model.Batch, error) {
	b := model.Batch{Version: 1, Project: s.project, Source: s.source, Producer: s.producer, ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Replay, ObservedAt: c.Clock.Wall, Resource: s.resource, Payload: model.Payload{Replay: &c}}}}
	var err error
	b.RouteSlot, err = model.OwnerSlot(s.org, s.project, s.source, s.producer, b.Records[0])
	return b, err
}

// send admits one wire chunk the way production should: closed-format
// validation first, then the real HTTPS ingest route, then the index step. It
// returns the HTTP status (0 when validation refused before any request).
func (s *smoke) send(c model.ReplayChunk) (int, error) {
	g, err := s.grant()
	if err != nil {
		return 0, err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return 0, err
	}
	if _, err = s.svc.ValidateJSON(g, raw); err != nil {
		return 0, err
	}
	b, err := s.batch(c)
	if err != nil {
		return 0, err
	}
	status, receipt, err := s.post(b)
	if err != nil || status != 200 {
		return status, err
	}
	for _, d := range receipt.SignalDeadlines {
		if d.Kind == model.Replay {
			return status, s.svc.Record(s.ctx, g, s.project, c, d.RetainUntil)
		}
	}
	return status, errors.New("receipt has no replay deadline")
}

func (s *smoke) post(b model.Batch) (int, model.Receipt, error) {
	body, err := json.Marshal(b)
	if err != nil {
		return 0, model.Receipt{}, err
	}
	req, err := http.NewRequest("POST", s.endpoint+"/ingest/v1/batches", bytes.NewReader(body))
	if err != nil {
		return 0, model.Receipt{}, err
	}
	req.Header.Set("Authorization", "Bearer "+s.credential)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, model.Receipt{}, errors.New("local verified-TLS ingest request failed")
	}
	defer resp.Body.Close()
	reply, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return 0, model.Receipt{}, err
	}
	var receipt model.Receipt
	if resp.StatusCode == 200 {
		err = json.Unmarshal(reply, &receipt)
	}
	return resp.StatusCode, receipt, err
}

// rawChannels requires every raw-content channel to be refused before storage,
// both by the closed-format gate and, for raw node text, by the real route.
func (s *smoke) rawChannels() error {
	r := newRecorder()
	good, err := r.next(true)
	if err != nil {
		return err
	}
	g, err := s.grant()
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(good)
	canary := "RAW-PAGE-CANARY-" + model.NewID().String()
	for _, key := range []string{"html", "text", "attributes", "css", "url", "canvas", "body"} {
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		m[key] = canary
		bad, _ := json.Marshal(m)
		if _, err = s.svc.ValidateJSON(g, bad); err == nil {
			return fmt.Errorf("raw channel %q was accepted by the closed-format gate", key)
		} else if strings.Contains(err.Error(), canary) {
			return errors.New("a validation error echoed page content")
		}
	}
	tainted := good
	tainted.Nodes = []model.MaskedNode{{ID: 1, Tag: "div", Text: canary}}
	b, err := s.batch(tainted)
	if err != nil {
		return err
	}
	status, _, err := s.post(b)
	if err != nil {
		return err
	}
	if status == 200 {
		return errors.New("the real ingest route stored a raw text node")
	}
	s.note("raw channels: 7 unknown-field channels refused by the closed-format gate; raw node text refused by the real route (status %d); none stored", status)
	return nil
}

func (s *smoke) record(dropMiddle bool) (*recorder, error) {
	r := newRecorder()
	for i := 1; i <= 10; i++ {
		c, err := r.next(i == 1 || i == 6)
		if err != nil {
			return nil, err
		}
		if dropMiddle && i == 4 {
			continue // the chunk is lost in transit; later chunks still arrive
		}
		if status, err := s.send(c); err != nil || status != 200 {
			return nil, fmt.Errorf("chunk %d not admitted: status %d: %w", i, status, err)
		}
	}
	return r, nil
}

func render(evs []replays.Event) string {
	var out []string
	for _, ev := range evs {
		switch ev.Kind {
		case replays.EventCheckpoint:
			out = append(out, fmt.Sprintf("C%d", ev.Sequence))
		case replays.EventDelta:
			out = append(out, fmt.Sprintf("D%d", ev.Sequence))
		case replays.EventGap:
			out = append(out, fmt.Sprintf("G%d-%d(%s)", ev.Sequence, ev.Through, ev.Reason))
		default:
			out = append(out, string(ev.Kind))
		}
	}
	return strings.Join(out, " ")
}

func (s *smoke) drain(st replays.ReplayStream) ([]replays.Event, error) {
	defer st.Close()
	var evs []replays.Event
	for {
		ev, err := st.Next(s.ctx)
		if errors.Is(err, io.EOF) {
			return evs, nil
		}
		if err != nil {
			return evs, err
		}
		evs = append(evs, ev)
	}
}

func (s *smoke) scenario(dropMiddle bool) error {
	r, err := s.record(dropMiddle)
	if err != nil {
		return err
	}
	scope, _, err := s.reader()
	if err != nil {
		return err
	}
	st, err := s.svc.Read(s.ctx, scope, r.replay, replays.ReplayWindow{})
	if err != nil {
		return err
	}
	evs, err := s.drain(st)
	if err != nil {
		return err
	}
	want := "C1 D2 D3 D4 D5 C6 D7 D8 D9 D10"
	if dropMiddle {
		want = "C1 D2 D3 G4-5(missing_chunk) C6 D7 D8 D9 D10"
	}
	if got := render(evs); got != want {
		return fmt.Errorf("stream %q, want %q", got, want)
	}
	// Interaction order is the masked pointer sequence of the released chunks.
	last := int32(0)
	for _, ev := range evs {
		if ev.Chunk == nil {
			continue
		}
		if ev.Chunk.Events[0].X <= last {
			return errors.New("released interactions are out of order")
		}
		last = ev.Chunk.Events[0].X
	}
	s.note("authorized read over chunks admitted through the real HTTPS route: %s", render(evs))
	return nil
}

func (s *smoke) revoke() error {
	r, err := s.record(false)
	if err != nil {
		return err
	}
	scope, revoke, err := s.reader()
	if err != nil {
		return err
	}
	st, err := s.svc.Read(s.ctx, scope, r.replay, replays.ReplayWindow{})
	if err != nil {
		return err
	}
	defer st.Close()
	for i := 0; i < 2; i++ {
		if ev, err := st.Next(s.ctx); err != nil || ev.Chunk == nil {
			return errors.New("expected two chunks before the revocation")
		}
	}
	if err = revoke(); err != nil {
		return err
	}
	ev, err := st.Next(s.ctx)
	if err != nil || ev.Kind != replays.EventRevoke || ev.Chunk != nil {
		return fmt.Errorf("after revocation: %+v %v", ev, err)
	}
	if _, err = st.Next(s.ctx); !errors.Is(err, io.EOF) {
		return errors.New("stream continued after the revoke")
	}
	if _, err = s.svc.Read(s.ctx, scope, r.replay, replays.ReplayWindow{}); err == nil {
		return errors.New("a revoked reader opened a stream")
	}
	s.note("revoke: typed revoke at sequence %d after 2 released chunks; no further chunk; reopening is refused", ev.Sequence)
	return nil
}

func (s *smoke) deleteRoot() error {
	r, err := s.record(false)
	if err != nil {
		return err
	}
	scope, _, err := s.reader()
	if err != nil {
		return err
	}
	st, err := s.svc.Read(s.ctx, scope, r.replay, replays.ReplayWindow{})
	if err != nil {
		return err
	}
	defer st.Close()
	if ev, err := st.Next(s.ctx); err != nil || ev.Chunk == nil {
		return errors.New("expected a chunk before the deletion")
	}
	admin, err := s.app.Auth.Authorize(s.ctx, s.owner, s.org, nil, auth.OrgAdmin)
	if err != nil {
		return err
	}
	var revision model.Revision
	if err = s.app.Control.View(s.ctx, func(state model.ControlState) error { revision = state.Revision; return nil }); err != nil {
		return err
	}
	if _, err = s.app.Retention.Delete(s.ctx, admin, retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: revision, Mode: model.DeleteEntity, OrgID: s.org, ProjectIDs: []model.ID{s.project}, EntityIDs: []model.ID{r.replay}, Reason: "replay server smoke"}); err != nil {
		return err
	}
	ev, err := st.Next(s.ctx)
	if err != nil || ev.Kind != replays.EventRevoke || ev.Reason != replays.ReasonDeleted || ev.Chunk != nil {
		return fmt.Errorf("after deletion: %+v %v", ev, err)
	}
	later, _, err := s.reader()
	if err != nil {
		return err
	}
	_, gone := s.svc.Read(s.ctx, later, r.replay, replays.ReplayWindow{})
	_, never := s.svc.Read(s.ctx, later, model.NewID(), replays.ReplayWindow{})
	var a, b *model.Fault
	if !errors.As(gone, &a) || !errors.As(never, &b) || a.Code != model.NotFound || a.SafeDetail != b.SafeDetail {
		return errors.New("a deleted replay is distinguishable from a missing one")
	}
	late, err := r.next(false)
	if err != nil {
		return err
	}
	if status, err := s.send(late); err == nil && status == 200 {
		return errors.New("a late chunk of the deleted root was admitted")
	}
	s.note("delete-root: open stream ended with typed revoke(deleted); later readers get the same not_found as for a missing replay; a late chunk of the root is refused")
	return nil
}
