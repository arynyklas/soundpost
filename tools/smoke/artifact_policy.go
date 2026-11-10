// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"soundpost/internal/appcore"
	"soundpost/internal/artifacts"
	"soundpost/internal/auth"
	"soundpost/internal/httpapi"
	"soundpost/internal/model"
	"soundpost/internal/retention"
	"soundpost/internal/storage"
	"strings"
	"sync/atomic"
	"time"
)

// RunArtifactPolicy drives a real appcore (real control, replicated storage,
// auth, ingest over HTTPS, artifacts, the retention service) through task 09.04:
//
//   - a REAL error occurrence is admitted over HTTPS; the map references it with
//     the batch cursor and the retention deadline of the admission receipt;
//   - a build reference uses the real control cursor of the upload; the map stays
//     until the last of them is released or expires (lifecycle clock advanced);
//   - private source bytes are warm only for the visibility that read them and a
//     grant revoked mid-stream stops the stream before the next byte;
//   - an unreferenced expired map and a map whose references all ended take the GC
//     fence and are then unreadable and unreferenceable;
//   - references survive a process restart, and a rolled-back or edited ledger
//     fails closed;
//   - a real C11 entity deletion removes an artifact with live references, and a
//     restore that brings back control state without the tombstone cannot revive it
//     once the deletion ledger is re-applied.
//
// NOT exercised, and not claimed: profile references (no profile record links to
// artifacts in this build, so no profile reference is created); a real snapshot
// pin source (none exists: pins are an explicit "no pin" implementation and the
// manifest says so); the 01.09 backup restore authority (the restore is a control
// rollback followed by ImportDeletions of the deletion's own predicates); and
// physical expiry by the retention worker (its clock is the real one; expiry here
// advances the lifecycle clock only).
//
// Registered as: case "artifact-policy": return RunArtifactPolicy(os.Args[2:]).
func RunArtifactPolicy(args []string) (result error) {
	p := &policySmoke{stage: "policy_flags", evidence: map[string]any{}}
	defer func() { result = annotateSmokeFailure("artifact_policy", p.stage, model.ID{}, result) }()
	flags := flag.NewFlagSet("artifact-policy", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	artifact := flags.String("artifact-dir", "", "sanitized artifacts")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *artifact == "" {
		return errors.New("artifact directory required")
	}
	if err := os.MkdirAll(*artifact, 0700); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "soundpost-artifact-policy-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	p.ctx, p.dir = context.Background(), dir
	if err = p.run(); err != nil {
		return err
	}
	p.stage = "policy_manifest"
	raw, err := json.MarshalIndent(p.evidence, "", "  ")
	if err != nil {
		return err
	}
	if bytes.Contains(raw, []byte(p.canary)) {
		return p.fail("manifest_leaks_canary")
	}
	return os.WriteFile(filepath.Join(*artifact, "artifact-policy-manifest.json"), raw, 0600)
}

type policySmoke struct {
	ctx      context.Context
	stage    string
	evidence map[string]any
	dir      string
	canary   string

	app                         *appcore.App
	life                        *artifacts.Lifecycle
	token, credential           string
	user                        model.ID
	org, project, source, build model.ID
	offset                      atomic.Int64
	pins                        noPins
}

// noPins is the explicit absence of a snapshot-pin source (see RunArtifactPolicy).
type noPins struct{}

func (noPins) Pinned(context.Context, model.ID, model.ID, model.ID) (bool, error) { return false, nil }

func (p *policySmoke) fail(name string) error {
	return &smokeFailure{Stage: "artifact_policy_" + name, Code: "policy_violation"}
}

// check records a computed outcome and fails the smoke when it is false.
func (p *policySmoke) check(name string, ok bool) error {
	p.evidence[name] = ok
	if !ok {
		return p.fail(name)
	}
	return nil
}
func faultOf(err error) model.Code {
	var fault *model.Fault
	if errors.As(err, &fault) {
		return fault.Code
	}
	return ""
}
func (p *policySmoke) scope(action auth.Permission) (auth.Scope, error) {
	actor, err := p.app.Auth.Authenticate(p.ctx, p.token)
	if err != nil {
		return auth.Scope{}, err
	}
	if action == auth.OrgAdmin {
		return p.app.Auth.Authorize(p.ctx, actor, p.org, nil, action)
	}
	return p.app.Auth.Authorize(p.ctx, actor, p.org, []model.ID{p.project}, action)
}
func (p *policySmoke) command(kind string, payload auth.AdminPayload) error {
	actor, err := p.app.Auth.Authenticate(p.ctx, p.token)
	if err != nil {
		return err
	}
	var revision model.Revision
	if err = p.app.Control.View(p.ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		return err
	}
	payload.Reason = "artifact policy smoke"
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = p.app.Auth.AdminCommand(p.ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: p.org, Kind: kind, Payload: raw})
	return err
}
func (p *policySmoke) now() time.Time { return time.Now().Add(time.Duration(p.offset.Load())) }
func (p *policySmoke) attach() error {
	var err error
	p.life, err = artifacts.NewLifecycle(p.app.Artifacts, artifacts.LifecycleConfig{State: p.app.Control, Deletes: p.app.Retention, Pins: p.pins, CacheBytes: 1 << 20, Now: p.now})
	return err
}
func (p *policySmoke) setReaders(readers ...model.ID) error {
	return p.app.Control.Update(p.ctx, func(st *model.ControlState) error {
		o := st.Orgs[p.org.String()]
		cfg, err := json.Marshal(auth.SourcePolicyConfig{ProjectID: p.project, Enabled: true, Readers: readers})
		if err != nil {
			return err
		}
		o.Settings["source_policy:"+p.source.String()] = cfg
		st.Orgs[p.org.String()] = o
		return nil
	})
}

// setup creates the organization, project, grants, source and the first session.
func (p *policySmoke) setup() error {
	p.stage = "policy_setup"
	app, err := appcore.Open(p.dir)
	if err != nil {
		return err
	}
	p.app = app
	p.org, p.project, p.source, p.build = model.NewID(), model.NewID(), model.NewID(), model.NewID()
	boot, err := app.Control.BootstrapToken()
	if err != nil {
		return err
	}
	session, err := app.Auth.Bootstrap(p.ctx, boot, "artifact-policy-smoke@example.test", "artifact policy smoke password 2026")
	if err != nil {
		return err
	}
	p.token, p.user = session.Token, session.User
	for _, step := range []struct {
		kind string
		p    auth.AdminPayload
	}{{"create_org", auth.AdminPayload{Name: "artifact policy smoke"}}, {"create_project", auth.AdminPayload{ID: p.project, Name: "builds"}}} {
		if err = p.command(step.kind, step.p); err != nil {
			return err
		}
	}
	if err = app.Control.Update(p.ctx, func(st *model.ControlState) error {
		o := st.Orgs[p.org.String()]
		o.Members[p.user.String()] = true
		o.Grants[p.user.String()+":"+p.project.String()] = []string{"artifacts.write", "artifacts.read", "raw.read"}
		st.Orgs[p.org.String()] = o
		return nil
	}); err != nil {
		return err
	}
	if err = p.setReaders(p.user); err != nil {
		return err
	}
	actor, err := app.Auth.Authenticate(p.ctx, p.token)
	if err != nil {
		return err
	}
	issued, err := app.Auth.OnboardSource(p.ctx, actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: p.org, Project: p.project, Source: p.source, Expires: model.UnixNano(time.Now().Add(24 * time.Hour).UnixNano()), Reason: "artifact policy smoke", Policy: model.SourcePolicy{
		Enabled: true, Revision: 1, Class: "structured", Kinds: []model.Kind{model.ErrorKind},
		Resources:     model.ResourceRegistry{Services: []model.ID{model.NewID()}, Environments: []model.ID{model.NewID()}, Builds: []model.ID{p.build}, Instances: []string{"artifact-policy"}},
		RetentionDays: map[model.Kind]uint32{model.ErrorKind: 14}, MaxBytes: 1 << 30, MaxSeries: 1000,
	}})
	if err != nil {
		return err
	}
	p.credential = issued.Credential
	return p.attach()
}

func (p *policySmoke) put(debug string, private bool) (artifacts.Artifact, error) {
	raw := []byte(`{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA","sourcesContent":["` + p.canary + `"]}`)
	generated := []byte("generated " + debug)
	m := artifacts.Manifest{Version: 1, Org: p.org, Project: p.project, Source: p.source, Build: p.build, DebugID: debug, GeneratedSHA256: model.HashCanonical(generated), MapSHA256: model.HashCanonical(raw), Path: "dist/" + debug + ".js", SourceContent: private, Size: model.Uint64(len(raw)), RetainUntil: model.UnixNano(time.Now().Add(time.Hour).UnixNano())}
	w, err := p.scope(auth.ArtifactWrite)
	if err != nil {
		return artifacts.Artifact{}, err
	}
	return p.app.Artifacts.Put(p.ctx, w, m, bytes.NewReader(raw))
}

// ingestError admits one real error occurrence over HTTPS that names the map as
// its frame artifact, and returns the admission receipt.
func (p *policySmoke) ingestError(a artifacts.Artifact) (model.Receipt, model.UnixNano, error) {
	server := httptest.NewTLSServer(httpapi.NewServer("", p.app.Auth, nil, p.app.Register).Handler)
	defer server.Close()
	col := uint32(0)
	record := model.Record{ID: model.NewID(), Kind: model.ErrorKind, ObservedAt: model.UnixNano(time.Now().UnixNano()), Resource: model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: p.build, Instance: "artifact-policy", Labels: model.Labels{}}, Payload: model.Payload{Error: &model.ErrorOccurrence{Occurrence: model.NewID(), Class: "TypeError", Mechanism: "manual", Build: p.build, Handled: true, Frames: []model.Frame{{Module: "fixture", Function: "original", Artifact: a.ID.String(), Line: 1, Column: &col}}}}}
	// The registry holds the real service/environment of the policy.
	if err := p.app.Control.View(p.ctx, func(st model.ControlState) error {
		reg := st.Sources[p.source.String()].Policy.Resources
		record.Resource.Service, record.Resource.Environment = reg.Services[0], reg.Environments[0]
		return nil
	}); err != nil {
		return model.Receipt{}, 0, err
	}
	batch := model.Batch{Version: 1, Project: p.project, Source: p.source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{record}}
	var err error
	if batch.RouteSlot, err = model.OwnerSlot(p.org, p.project, p.source, batch.Producer, record); err != nil {
		return model.Receipt{}, 0, err
	}
	body, err := json.Marshal(batch)
	if err != nil {
		return model.Receipt{}, 0, err
	}
	req, err := http.NewRequest("POST", server.URL+"/ingest/v1/batches", bytes.NewReader(body))
	if err != nil {
		return model.Receipt{}, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+p.credential)
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	if err != nil {
		return model.Receipt{}, 0, err
	}
	defer resp.Body.Close()
	reply, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err = requireSmokeResponse("artifact_policy_ingest", resp.StatusCode, 200, reply, err); err != nil {
		return model.Receipt{}, 0, err
	}
	var receipt model.Receipt
	if err = json.Unmarshal(reply, &receipt); err != nil {
		return model.Receipt{}, 0, err
	}
	for _, d := range receipt.SignalDeadlines {
		if d.Kind == model.ErrorKind {
			return receipt, d.RetainUntil, nil
		}
	}
	return model.Receipt{}, 0, p.fail("no_error_deadline")
}

func (p *policySmoke) run() error {
	if err := p.setup(); err != nil {
		return err
	}
	defer func() {
		if p.app != nil {
			p.app.Close()
		}
	}()
	p.canary = "ARTIFACT-POLICY-CANARY-" + model.NewID().String()
	ctx := p.ctx
	write, err := p.scope(auth.ArtifactWrite)
	if err != nil {
		return err
	}
	read := func() auth.Scope {
		s, e := p.scope(auth.ArtifactRead)
		if e != nil {
			err = e
		}
		return s
	}

	// ---- real references ---------------------------------------------------
	p.stage = "policy_references"
	a, err := p.put("policy-a", true)
	if err != nil {
		return err
	}
	b, err := p.put("policy-b", false)
	if err != nil {
		return err
	}
	receipt, errDeadline, err := p.ingestError(a)
	if err != nil {
		return err
	}
	errorRef := artifacts.OriginCursor{Kind: artifacts.ReferenceError, Cursor: receipt.Cursor}
	if err = p.life.Reference(ctx, write, a.ID, errorRef, errDeadline); err != nil {
		return err
	}
	var buildCursor model.Cursor
	if err = p.app.Control.View(ctx, func(st model.ControlState) error {
		buildCursor = model.Cursor{Group: st.Installation, Index: model.Uint64(a.ControlRevision)}
		return nil
	}); err != nil {
		return err
	}
	buildRef := artifacts.OriginCursor{Kind: artifacts.ReferenceBuild, Cursor: buildCursor}
	if err = p.life.Reference(ctx, write, a.ID, buildRef, 0); err != nil {
		return err
	}
	effective, err := p.life.EffectiveRetention(ctx, read(), a.ID)
	if err != nil {
		return err
	}
	if err = p.check("error_reference_retains_map_past_upload_deadline", effective >= errDeadline && effective > a.Manifest.RetainUntil); err != nil {
		return err
	}
	if err = p.check("unreferenced_map_retained_only_by_upload_deadline", func() bool {
		e, ee := p.life.EffectiveRetention(ctx, read(), b.ID)
		return ee == nil && e == b.Manifest.RetainUntil
	}()); err != nil {
		return err
	}

	// ---- private cache and read revocation ----------------------------------
	p.stage = "policy_private_cache"
	readSources := func(s auth.Scope) ([]byte, error) {
		r, e := p.app.Artifacts.ReadSourcesAuthorized(ctx, s, a.ID, artifacts.Window{})
		if e != nil {
			return nil, e
		}
		defer r.Close()
		return io.ReadAll(r)
	}
	first, err := readSources(read())
	if err != nil {
		return err
	}
	if _, err = readSources(read()); err != nil {
		return err
	}
	warm := p.life.CacheStats()
	other, lerr := p.app.Auth.Login(ctx, "artifact-policy-smoke@example.test", "artifact policy smoke password 2026", "")
	if lerr != nil {
		return lerr
	}
	actor2, err := p.app.Auth.Authenticate(ctx, other.Token)
	if err != nil {
		return err
	}
	scope2, err := p.app.Auth.Authorize(ctx, actor2, p.org, []model.ID{p.project}, auth.ArtifactRead)
	if err != nil {
		return err
	}
	if _, err = readSources(scope2); err != nil {
		return err
	}
	after := p.life.CacheStats()
	if err = p.check("private_sources_released_to_named_reader", bytes.Contains(first, []byte(p.canary))); err != nil {
		return err
	}
	if err = p.check("same_visibility_reuses_warm_bytes", warm.Hits == 1 && warm.Misses == 1); err != nil {
		return err
	}
	if err = p.check("other_visibility_never_reuses_private_bytes", after.Hits == warm.Hits && after.Misses == warm.Misses+1); err != nil {
		return err
	}
	if err = p.setReaders(); err != nil {
		return err
	}
	_, denied := readSources(read())
	if err = p.check("revoked_reader_grant_denies_warm_sources", faultOf(denied) == model.NotFound && p.life.CacheStats().Hits == after.Hits); err != nil {
		return err
	}
	if err = p.setReaders(p.user); err != nil {
		return err
	}
	stream, err := p.app.Artifacts.ReadSourcesAuthorized(ctx, read(), a.ID, artifacts.Window{})
	if err != nil {
		return err
	}
	if n, rerr := stream.Read(make([]byte, 4)); rerr != nil || n != 4 {
		return p.fail("stream_start")
	}
	if err = p.setReaders(); err != nil {
		return err
	}
	probe := bytes.Repeat([]byte{0x7f}, 8)
	n, rerr := stream.Read(probe)
	stream.Close()
	if err = p.check("grant_revoked_mid_stream_stops_before_next_byte", n == 0 && faultOf(rerr) == model.NotFound && bytes.Equal(probe, bytes.Repeat([]byte{0x7f}, 8))); err != nil {
		return err
	}
	if err = p.setReaders(p.user); err != nil {
		return err
	}

	// ---- expiry: the last referencing record decides -------------------------
	p.stage = "policy_expiry"
	candidate := func(x artifacts.Artifact) storage.EraseCandidate {
		m := x.Map.Manifest
		return storage.EraseCandidate{Org: m.Org, Project: m.Project, Blob: &m, Cursor: x.Map.Cursor}
	}
	p.offset.Store(int64(2 * time.Hour)) // the uploads' own hour is over
	heldA, err := p.life.LatestReference(ctx, candidate(a))
	if err != nil {
		return err
	}
	freeB, err := p.life.LatestReference(ctx, candidate(b))
	if err != nil {
		return err
	}
	if err = p.check("expired_upload_without_reference_is_released_and_fenced", freeB == 0); err != nil {
		return err
	}
	_, readB := p.app.Artifacts.Get(ctx, read(), b.ID)
	refB := p.life.Reference(ctx, write, b.ID, artifacts.OriginCursor{Kind: artifacts.ReferenceBuild, Cursor: buildCursor}, 0)
	if err = p.check("fenced_map_is_unreadable_and_unreferenceable", faultOf(readB) == model.NotFound && faultOf(refB) == model.Conflict); err != nil {
		return err
	}
	if err = p.check("referenced_map_pinned_after_upload_deadline", int64(heldA) > p.now().UnixNano()); err != nil {
		return err
	}
	p.offset.Store(int64(time.Until(time.Unix(0, int64(errDeadline)))) + int64(time.Hour)) // the error record has expired
	stillBuild, err := p.life.LatestReference(ctx, candidate(a))
	if err != nil {
		return err
	}
	if err = p.check("expired_error_does_not_release_map_a_live_build_still_needs", int64(stillBuild) > p.now().UnixNano()); err != nil {
		return err
	}
	if err = p.life.Unreference(ctx, write, a.ID, buildRef, 0); err != nil {
		return err
	}
	last, err := p.life.LatestReference(ctx, candidate(a))
	if err != nil {
		return err
	}
	_, readA := p.app.Artifacts.Get(ctx, read(), a.ID)
	if err = p.check("last_reference_released_map_is_fenced_for_erasure", last == 0 && faultOf(readA) == model.NotFound); err != nil {
		return err
	}
	p.offset.Store(0)

	// ---- restart and tampering ----------------------------------------------
	p.stage = "policy_restart"
	c, err := p.put("policy-c", false)
	if err != nil {
		return err
	}
	cursor := model.Cursor{Group: model.NewID(), Index: 7}
	if err = p.life.Reference(ctx, write, c.ID, artifacts.OriginCursor{Kind: artifacts.ReferenceError, Cursor: cursor}, model.UnixNano(time.Now().Add(72*time.Hour).UnixNano())); err != nil {
		return err
	}
	if err = p.app.Close(); err != nil {
		return err
	}
	p.app = nil
	if p.app, err = appcore.Open(p.dir); err != nil {
		return err
	}
	if err = p.attach(); err != nil {
		return err
	}
	write, err = p.scope(auth.ArtifactWrite)
	if err != nil {
		return err
	}
	survived, err := p.life.EffectiveRetention(ctx, read(), c.ID)
	if err != nil {
		return err
	}
	if err = p.check("reference_survives_restart", int64(survived) > time.Now().Add(71*time.Hour).UnixNano()); err != nil {
		return err
	}
	var key string
	var good json.RawMessage
	if err = p.app.Control.View(ctx, func(st model.ControlState) error {
		for k, v := range st.Orgs[p.org.String()].Settings {
			if strings.HasPrefix(k, "artifact_refs:") && strings.HasSuffix(k, c.ID.String()) {
				key, good = k, append(json.RawMessage(nil), v...)
			}
		}
		return nil
	}); err != nil || key == "" {
		return p.fail("ledger_missing")
	}
	var doc map[string]any
	if err = json.Unmarshal(good, &doc); err != nil {
		return err
	}
	doc["Entries"].([]any)[0].(map[string]any)["retain_until_ns"] = float64(1)
	edited, _ := json.Marshal(doc)
	setLedger := func(raw json.RawMessage) error {
		return p.app.Control.Update(ctx, func(st *model.ControlState) error {
			o := st.Orgs[p.org.String()]
			o.Settings[key] = raw
			st.Orgs[p.org.String()] = o
			return nil
		})
	}
	if err = setLedger(edited); err != nil {
		return err
	}
	_, latestErr := p.life.LatestReference(ctx, candidate(c))
	_, gcErr := p.life.GC(ctx, write, c.ID)
	_, readC := p.app.Artifacts.Get(ctx, read(), c.ID)
	if err = p.check("edited_ledger_fails_closed", latestErr != nil && gcErr != nil && readC != nil); err != nil {
		return err
	}
	if err = setLedger(good); err != nil {
		return err
	}
	_, readC = p.app.Artifacts.Get(ctx, read(), c.ID)
	if err = p.check("restored_ledger_serves_again", readC == nil); err != nil {
		return err
	}

	// ---- C11 deletion and restore ---------------------------------------------
	p.stage = "policy_delete_restore"
	d, err := p.put("policy-d", true)
	if err != nil {
		return err
	}
	if err = p.life.Reference(ctx, write, d.ID, artifacts.OriginCursor{Kind: artifacts.ReferenceError, Cursor: model.Cursor{Group: model.NewID(), Index: 9}}, model.UnixNano(time.Now().Add(72*time.Hour).UnixNano())); err != nil {
		return err
	}
	admin, err := p.scope(auth.OrgAdmin)
	if err != nil {
		return err
	}
	var revision model.Revision
	if err = p.app.Control.View(ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		return err
	}
	op, err := p.app.Retention.Delete(ctx, admin, retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: revision, Mode: model.DeleteEntity, OrgID: p.org, ProjectIDs: []model.ID{p.project}, EntityIDs: []model.ID{d.ID}, Reason: "artifact policy smoke"})
	if err != nil {
		return err
	}
	var done retention.DeleteReceipt
	for range 10 {
		if err = p.app.Retention.RunOnce(ctx); err != nil {
			return err
		}
		if admin, err = p.scope(auth.OrgAdmin); err != nil {
			return err
		}
		if done, err = p.app.Retention.PollDelete(ctx, admin, op.OperationID); err != nil {
			return err
		}
		if done.Phase == model.DeletePhaseComplete && done.Physical == retention.PhysicalDone {
			break
		}
	}
	if err = p.check("entity_deletion_completed_physically", done.Phase == model.DeletePhaseComplete && done.Physical == retention.PhysicalDone); err != nil {
		return err
	}
	gone := func() bool {
		w, _ := p.scope(auth.ArtifactWrite)
		_, g := p.app.Artifacts.Get(ctx, read(), d.ID)
		_, r := p.app.Artifacts.ReadAuthorized(ctx, read(), d.ID, artifacts.Window{})
		ref := p.life.Reference(ctx, w, d.ID, artifacts.OriginCursor{Kind: artifacts.ReferenceProfile, Cursor: model.Cursor{Group: model.NewID(), Index: 1}}, 0)
		latest, lerr := p.life.LatestReference(ctx, candidate(d))
		return faultOf(g) == model.NotFound && faultOf(r) == model.NotFound && faultOf(ref) == model.NotFound && lerr == nil && latest == 0
	}
	if err = p.check("deleted_artifact_with_live_reference_is_gone_everywhere", gone()); err != nil {
		return err
	}
	var tombstones []model.DeletePredicate
	if err = p.app.Control.View(ctx, func(st model.ControlState) error {
		for _, o := range st.Deletions {
			tombstones = append(tombstones, o.Predicate)
		}
		return nil
	}); err != nil {
		return err
	}
	if err = p.app.Control.Update(ctx, func(st *model.ControlState) error { st.Deletions = map[string]model.DeletionOperation{}; return nil }); err != nil {
		return err
	}
	if err = p.app.Control.ImportDeletions(ctx, tombstones, model.UnixNano(time.Now().UnixNano())); err != nil {
		return err
	}
	if err = p.check("restore_with_deletion_ledger_cannot_revive_artifact", len(tombstones) == 1 && gone()); err != nil {
		return err
	}
	p.evidence["reference_kinds_exercised"] = []string{"error", "build"}
	p.evidence["reference_kinds_not_exercised"] = []string{"profile"}
	p.evidence["snapshot_pins"] = "explicit no-pin implementation (no snapshot pin source exists)"
	p.evidence["restore"] = "control rollback of the tombstone plus ImportDeletions of the deletion's predicates (backup authority not driven)"
	return nil
}
