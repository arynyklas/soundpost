// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/backup"
	"github.com/arynyklas/soundpost/internal/exports"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/retention"
	"github.com/arynyklas/soundpost/internal/storage"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RunDeletion drives a real appcore (real control, replicated storage, auth,
// ingest, exports, the retention worker and a real signed restore authority)
// through the C11/C12 deletion saga over HTTPS and writes a sanitized manifest:
//
//   - positive controls: the canary is physically present, before the deletion,
//     in every store class the deletion has to clean;
//   - authorized query/cache/export/live releases race Begin: nothing is
//     released by any call that starts after Begin returned;
//   - HTTP denial is byte-equal to a guessed-absent target from Begin on, before
//     any slot has a barrier; an authority outage leaves the operation fencing;
//   - a legal hold makes physical-erasure success impossible (bytes stay,
//     receipt says held) until it is released;
//   - after the worker's passes the canary is found nowhere except in the store
//     the receipt declares (the replication layer's idempotence cache), and
//     apply.db, segments, snapshot files/state and control.db are clean;
//   - the restore authority holds the suppression ledger for the deletion;
//   - disk pressure drives the real ingest path through the 80/90/95 levels with
//     honest transitions and no ACKed data lost or shortened.
//
// Registered as: case "delete-restore-pressure": return RunDeletion(os.Args[2:]).
func RunDeletion(args []string) (result error) {
	d := &deletionSmoke{stage: "deletion_flags", evidence: map[string]any{}}
	defer func() { result = annotateSmokeFailure("delete_restore_pressure", d.stage, model.ID{}, result) }()
	flags := flag.NewFlagSet("delete-restore-pressure", flag.ContinueOnError)
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
	d.ctx = context.Background()
	if err := d.deleteScenario(); err != nil {
		return err
	}
	if err := d.pressureScenario(); err != nil {
		return err
	}
	d.stage = "deletion_manifest"
	raw, err := json.MarshalIndent(d.evidence, "", "  ")
	if err != nil {
		return err
	}
	if bytes.Contains(raw, []byte(d.canaries["doomed"])) || bytes.Contains(raw, []byte(d.canaries["sibling"])) || bytes.Contains(raw, []byte(d.canaries["held"])) {
		return d.fail("manifest_leaks_canary")
	}
	return os.WriteFile(filepath.Join(*artifact, "deletion-manifest.json"), raw, 0600)
}

type deletionSmoke struct {
	ctx      context.Context
	stage    string
	evidence map[string]any
	canaries map[string]string
}

func (d *deletionSmoke) fail(name string) error {
	return &smokeFailure{Stage: "deletion_" + name, Code: "deletion_violation"}
}

// ---- a site: one real application over HTTPS with one organization ----------

type dsite struct {
	app    *appcore.App
	server *httptest.Server
	client *http.Client
	owner  auth.Session
	actor  auth.Credential
	org    model.ID
	dir    string
}
type dproject struct {
	id, source model.ID
	credential string
	resource   model.Resource
}

func (d *deletionSmoke) openSite(open func(dir string) (*appcore.App, error)) (*dsite, func(), error) {
	dir, err := os.MkdirTemp("", "soundpost-deletion-")
	if err != nil {
		return nil, nil, err
	}
	app, err := open(dir)
	if err != nil {
		os.RemoveAll(dir)
		return nil, nil, err
	}
	server := httptest.NewTLSServer(httpapi.NewServer("", app.Auth, nil, app.Register).Handler)
	closer := func() { server.Close(); app.Close(); os.RemoveAll(dir) }
	s := &dsite{app: app, server: server, client: server.Client(), dir: dir, org: model.NewID()}
	boot, err := app.Control.BootstrapToken()
	if err != nil {
		closer()
		return nil, nil, err
	}
	if s.owner, err = app.Auth.Bootstrap(d.ctx, boot, "deletion-smoke-owner@example.test", "deletion smoke owner password 2026"); err != nil {
		closer()
		return nil, nil, err
	}
	if s.actor, err = app.Auth.Authenticate(d.ctx, s.owner.Token); err != nil {
		closer()
		return nil, nil, err
	}
	for _, step := range []struct {
		kind string
		p    auth.AdminPayload
	}{{"create_org", auth.AdminPayload{Name: "deletion smoke"}}, {"membership", auth.AdminPayload{UserID: s.owner.User, Enabled: true}}} {
		if err = s.command(d.ctx, step.kind, step.p); err != nil {
			closer()
			return nil, nil, err
		}
	}
	return s, closer, nil
}

func (s *dsite) command(ctx context.Context, kind string, p auth.AdminPayload) error {
	var revision model.Revision
	if err := s.app.Control.View(ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		return err
	}
	p.Reason = "deletion smoke"
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = s.app.Auth.AdminCommand(ctx, s.actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: s.org, Kind: kind, Payload: raw})
	return err
}

func (s *dsite) revision(ctx context.Context) (model.Revision, error) {
	var revision model.Revision
	err := s.app.Control.View(ctx, func(st model.ControlState) error { revision = st.Revision; return nil })
	return revision, err
}

// project creates a project the owner can read and a structured source for it.
func (s *dsite) project(ctx context.Context, name string) (dproject, error) {
	p := dproject{id: model.NewID(), source: model.NewID()}
	if err := s.command(ctx, "create_project", auth.AdminPayload{ID: p.id, Name: name}); err != nil {
		return p, err
	}
	if err := s.command(ctx, "grant", auth.AdminPayload{UserID: s.owner.User, ProjectID: p.id, Enabled: true, Permissions: []string{string(auth.Read)}}); err != nil {
		return p, err
	}
	cfg, _ := json.Marshal(auth.SourcePolicyConfig{ProjectID: p.id, Enabled: true})
	if err := s.command(ctx, "source_policy", auth.AdminPayload{ID: p.source, Config: cfg}); err != nil {
		return p, err
	}
	service, environment, build := model.NewID(), model.NewID(), model.NewID()
	p.resource = model.Resource{Service: service, Environment: environment, Build: build, Instance: "opaque-instance", Labels: model.Labels{}}
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric, model.SpanKind}, Resources: model.ResourceRegistry{Services: []model.ID{service}, Environments: []model.ID{environment}, Builds: []model.ID{build}, Instances: []string{"opaque-instance"}}, Operations: []string{"operation"}, RetentionDays: map[model.Kind]uint32{model.Metric: 14, model.SpanKind: 14}, MaxBytes: 1 << 20, MaxSeries: 100}
	issued, err := s.app.Auth.OnboardSource(ctx, s.actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: s.org, Project: p.id, Source: p.source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "deletion smoke"})
	p.credential = issued.Credential
	return p, err
}

func (s *dsite) call(method, path string, body any) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, s.server.URL+path, reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Cookie", "__Host-soundpost="+s.owner.Token)
	req.Header.Set("Origin", s.server.URL)
	req.Header.Set("X-CSRF-Token", s.owner.CSRF)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<24))
	return resp.StatusCode, raw, err
}

func (p dproject) metric(at int64, name string) model.Record {
	value := model.FloatBits(math.Float64bits(1))
	return model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(at), Resource: p.resource, Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: &value, Unit: "1", Type: "counter"}}}
}

func (p dproject) span(at int64) model.Record {
	clock := model.TraceClock{Wall: 1, Mono: 1, Domain: model.ClockDomain{Host: model.NewID(), Boot: model.NewID(), Runtime: model.NewID()}}
	end := clock
	end.Mono = 2
	var id model.SpanID
	id[0] = 1
	return model.Record{ID: model.NewID(), Kind: model.SpanKind, ObservedAt: model.UnixNano(at), Resource: p.resource, Payload: model.Payload{Span: &model.Span{Trace: model.NewID(), ID: id, Kind: "internal", Operation: "operation", Start: clock, End: &end, Status: "ok", SampleProbability: model.FloatBits(0x3ff0000000000000), SampleDecision: "keep"}}}
}

// batchBody is one fixed batch: posting the same bytes twice is a retry.
func (s *dsite) batchBody(p dproject, records ...model.Record) ([]byte, error) {
	batch := model.Batch{Version: 1, Project: p.id, Source: p.source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: records}
	var err error
	if batch.RouteSlot, err = model.OwnerSlot(s.org, p.id, p.source, batch.Producer, records[0]); err != nil {
		return nil, err
	}
	return json.Marshal(batch)
}

func (s *dsite) post(credential string, body []byte) (int, http.Header, []byte, error) {
	req, err := http.NewRequest("POST", s.server.URL+"/ingest/v1/batches", bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, resp.Header, raw, err
}

// ingest admits one fresh batch and requires the ACK.
func (s *dsite) ingest(p dproject, records ...model.Record) error {
	body, err := s.batchBody(p, records...)
	if err != nil {
		return err
	}
	status, _, reply, err := s.post(p.credential, body)
	return requireSmokeResponse("deletion_ingest", status, 200, reply, err)
}

func (s *dsite) readScope(ctx context.Context, p dproject) (auth.Scope, error) {
	return s.app.Auth.Authorize(ctx, s.actor, s.org, []model.ID{p.id}, auth.Read)
}

func (s *dsite) adminScope(ctx context.Context) (auth.Scope, error) {
	return s.app.Auth.Authorize(ctx, s.actor, s.org, nil, auth.OrgAdmin)
}

// hold places a legal hold on one project with a fresh admin scope (a scope minted before a
// deletion began is dead at revalidation).
func (s *dsite) hold(ctx context.Context, svc *retention.Service, project model.ID, reason string) (model.ID, error) {
	scope, err := s.adminScope(ctx)
	if err != nil {
		return model.ID{}, err
	}
	revision, err := s.revision(ctx)
	if err != nil {
		return model.ID{}, err
	}
	return svc.PlaceHold(ctx, scope, retention.HoldRequest{CommandID: model.NewID(), ExpectedRevision: revision, ProjectIDs: []model.ID{project}, Reason: reason})
}

func (s *dsite) release(ctx context.Context, svc *retention.Service, hold model.ID) error {
	scope, err := s.adminScope(ctx)
	if err != nil {
		return err
	}
	revision, err := s.revision(ctx)
	if err != nil {
		return err
	}
	return svc.ReleaseHold(ctx, scope, model.NewID(), revision, hold, "deletion smoke released")
}

func (s *dsite) begin(ctx context.Context, svc *retention.Service, project model.ID, reason string) (retention.DeleteReceipt, error) {
	// Admission reservations commit to control, so intake running beside the request moves the
	// revision between reading it and committing; a stale revision is retried with a fresh read.
	var last error
	for range 50 {
		scope, err := s.adminScope(ctx)
		if err != nil {
			return retention.DeleteReceipt{}, err
		}
		revision, err := s.revision(ctx)
		if err != nil {
			return retention.DeleteReceipt{}, err
		}
		receipt, err := svc.Delete(ctx, scope, retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: revision, Mode: model.DeleteRetireProject, OrgID: s.org, ProjectIDs: []model.ID{project}, Reason: reason})
		var fault *model.Fault
		if err == nil || !errors.As(err, &fault) || fault.Code != model.Conflict {
			return receipt, err
		}
		last = err
	}
	return retention.DeleteReceipt{}, last
}

func (s *dsite) poll(ctx context.Context, svc *retention.Service, operation model.ID) (retention.DeleteReceipt, error) {
	scope, err := s.adminScope(ctx)
	if err != nil {
		return retention.DeleteReceipt{}, err
	}
	return svc.PollDelete(ctx, scope, operation)
}

// scanRows counts what an authorized scan releases for the project.
func (s *dsite) scanRows(ctx context.Context, p dproject) (int, error) {
	scope, err := s.readScope(ctx, p)
	if err != nil {
		return 0, err
	}
	it, err := s.app.Storage.Scan(ctx, scope, storage.ScanRequest{Projects: []model.ID{p.id}, Signal: model.Metric, End: model.UnixNano(math.MaxInt64)})
	if err != nil {
		return 0, err
	}
	defer it.Close()
	n := 0
	for {
		page, err := it.Next(ctx)
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		n += page.Len()
	}
}

func exportRequest(op string, s *dsite, project model.ID) httpapi.ExportRequest {
	return httpapi.ExportRequest{Operation: op, Org: s.org, Project: project, Permission: string(auth.Read), Signal: model.Metric, Start: 0, End: model.Int64(math.MaxInt64)}
}

// exportCreate asks for an export and returns the HTTP answer.
func (s *dsite) exportCreate(project model.ID) (exports.Grant, int, []byte, error) {
	status, body, err := s.call("POST", "/api/v1/exports", exportRequest("create", s, project))
	var grant exports.Grant
	if err == nil && status == http.StatusAccepted {
		err = json.Unmarshal(body, &grant)
	}
	return grant, status, body, err
}

func (s *dsite) exportStatus(project, id model.ID) (int, []byte, error) {
	r := exportRequest("status", s, project)
	r.ID = httpapi.OptionalID(id)
	return s.call("POST", "/api/v1/exports", r)
}

func (s *dsite) exportDownload(project model.ID, grant exports.Grant) (int, []byte, error) {
	r := exportRequest("download", s, project)
	r.ID, r.Ticket = httpapi.OptionalID(grant.Operation.ID), grant.Ticket
	return s.call("POST", "/api/v1/exports", r)
}

// exportReady creates an export and waits for it to complete.
func (s *dsite) exportReady(project model.ID) (exports.Grant, error) {
	grant, status, body, err := s.exportCreate(project)
	if err = requireSmokeResponse("deletion_export_create", status, http.StatusAccepted, body, err); err != nil {
		return grant, err
	}
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(25 * time.Millisecond) {
		status, body, err = s.exportStatus(project, grant.Operation.ID)
		if err = requireSmokeResponse("deletion_export_status", status, 200, body, err); err != nil {
			return grant, err
		}
		var op exports.Operation
		if err = json.Unmarshal(body, &op); err != nil {
			return grant, err
		}
		if op.Phase == "failed" {
			return grant, errors.New("export failed")
		}
		if op.Phase == "complete" {
			return grant, nil
		}
	}
	return grant, errors.New("export did not complete")
}

// denial reduces an error answer to what a caller can tell apart.
func denial(status int, body []byte) (string, bool) {
	var f model.Fault
	if json.Unmarshal(body, &f) != nil || f.Code == "" {
		return "", false
	}
	return fmt.Sprintf("%d/%s/%s", status, f.Code, f.SafeDetail), true
}

// ---- physical scanning -----------------------------------------------------

var base64Run = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)

// deepHits counts needle in data and in everything that decodes out of it.
// Journals and snapshots wrap commands in base64 inside JSON inside base64, so
// a plain byte search proves nothing about them. Fragmentary data (free pages
// start mid-string) is tried at all four base64 alignments at the top level.
func deepHits(data, needle []byte, depth int, label string, out map[string]int) {
	if n := bytes.Count(data, needle); n > 0 {
		out[label] += n
	}
	if depth == 0 {
		return
	}
	alignments := 1
	if label == "raw" {
		alignments = 4
	}
	for _, run := range base64Run.FindAll(data, -1) {
		for skip := 0; skip < alignments && skip < len(run); skip++ {
			plain := strings.NewReplacer("-", "+", "_", "/").Replace(string(bytes.TrimRight(run[skip:], "=")))
			if len(plain)%4 == 1 {
				plain = plain[:len(plain)-1]
			}
			decoded, err := base64.RawStdEncoding.DecodeString(plain)
			if err != nil || len(decoded) < len(needle) {
				continue
			}
			deepHits(decoded, needle, depth-1, label+">b64", out)
		}
	}
}

// Store classes. A hit is attributed to the store it sits in, not to a file.
const (
	storeApply     = "apply.db"
	storeSegments  = "segments"
	storeSnapFiles = "snapshot_files"
	storeSnapState = "snapshot_state"
	storeSnapCache = "snapshot_completed_cache"
	storeJournal   = "raft_journal"
	storeControl   = "control.db"
)

// storeHits searches every regular file under dir for every canary and returns
// store -> canary label -> occurrences.
func storeHits(dir string, canaries map[string]string) (map[string]map[string]int, error) {
	out := map[string]map[string]int{}
	add := func(store, label string, n int) {
		if out[store] == nil {
			out[store] = map[string]int{}
		}
		out[store][label] += n
	}
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !info.Mode().IsRegular() {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		for label, canary := range canaries {
			needle := []byte(canary)
			hits := map[string]int{}
			switch {
			case rel == "data/apply.db":
				deepHits(raw, needle, 4, "raw", hits)
				add(storeApply, label, sum(hits))
			case strings.HasPrefix(rel, "data/segments/"):
				deepHits(raw, needle, 4, "raw", hits)
				add(storeSegments, label, sum(hits))
			case rel == "control.db" || strings.HasPrefix(rel, "raft/control/"):
				deepHits(raw, needle, 4, "raw", hits)
				add(storeControl, label, sum(hits))
			case strings.HasPrefix(rel, "raft/data/") && path.Base(rel) == "ready.wal":
				deepHits(raw, needle, 5, "raw", hits)
				add(storeJournal, label, sum(hits))
			case strings.HasPrefix(rel, "raft/data/") && strings.Contains(rel, "/snapshots/") && path.Base(rel) == "envelope.json":
				var env map[string]json.RawMessage
				if err := json.Unmarshal(raw, &env); err != nil {
					return err
				}
				for field, value := range env {
					hits = map[string]int{}
					deepHits(value, needle, 5, "raw", hits)
					store := storeSnapFiles + ":" + "envelope_" + field
					switch field {
					case "state":
						store = storeSnapState
					case "completed":
						store = storeSnapCache
					}
					add(store, label, sum(hits))
				}
			case strings.HasPrefix(rel, "raft/data/") && strings.Contains(rel, "/snapshots/") && strings.Contains(rel, "/files/"):
				deepHits(raw, needle, 4, "raw", hits)
				add(storeSnapFiles, label, sum(hits))
			default:
				deepHits(raw, needle, 5, "raw", hits)
				add("other:"+rel, label, sum(hits))
			}
		}
		return nil
	})
	for _, byLabel := range out { // drop zero entries
		for label, n := range byLabel {
			if n == 0 {
				delete(byLabel, label)
			}
		}
	}
	for store, byLabel := range out {
		if len(byLabel) == 0 {
			delete(out, store)
		}
	}
	return out, err
}

func sum(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func has(hits map[string]map[string]int, store, label string) bool { return hits[store][label] > 0 }

// summarize turns the hit map into store -> total, for the manifest.
func summarize(hits map[string]map[string]int, label string) map[string]int {
	out := map[string]int{}
	for store, byLabel := range hits {
		if n := byLabel[label]; n > 0 {
			out[store] = n
		}
	}
	return out
}

// ---- an authority whose first checkpoints fail -----------------------------

// flakyAuthority is the real signed restore authority with an outage in front of it.
type flakyAuthority struct {
	*backup.Authority
	failures atomic.Int32
	attempts atomic.Int32
}

func (a *flakyAuthority) CheckpointDeletion(ctx context.Context, g retention.LedgerGeneration) (retention.AuthorityReceipt, error) {
	a.attempts.Add(1)
	if a.failures.Add(-1) >= 0 {
		return retention.AuthorityReceipt{}, model.Fail(model.Unavailable)
	}
	return a.Authority.CheckpointDeletion(ctx, g)
}

// ---- the deletion scenario --------------------------------------------------

func (d *deletionSmoke) deleteScenario() error {
	ctx := d.ctx
	d.stage = "deletion_open"
	site, closer, err := d.openSite(appcore.Open)
	if err != nil {
		return err
	}
	defer closer()
	app, svc := site.app, site.app.Retention

	d.stage = "deletion_authority"
	authorityDir, err := os.MkdirTemp("", "soundpost-deletion-authority-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(authorityDir)
	keys, err := backup.GenerateAuthorityKeys("deletion-smoke-authority")
	if err != nil {
		return err
	}
	destination, err := backup.NewLocalDestination(authorityDir)
	if err != nil {
		return err
	}
	real, err := backup.NewAuthority(destination, keys, time.Now)
	if err != nil {
		return err
	}
	var installation model.ID
	if err = app.Control.View(ctx, func(st model.ControlState) error { installation = st.Installation; return nil }); err != nil {
		return err
	}
	if _, err = real.Initialize(ctx, installation); err != nil {
		return err
	}
	authority := &flakyAuthority{Authority: real}
	authority.failures.Store(2)
	if err = svc.UseAuthority(authority); err != nil {
		return err
	}

	d.stage = "deletion_projects"
	doomed, err := site.project(ctx, "doomed")
	if err != nil {
		return err
	}
	sibling, err := site.project(ctx, "sibling")
	if err != nil {
		return err
	}
	held, err := site.project(ctx, "held")
	if err != nil {
		return err
	}
	suffix := func() string { return strings.ReplaceAll(model.NewID().String(), "-", "") }
	d.canaries = map[string]string{"doomed": "deletion_canary_" + suffix(), "sibling": "sibling_marker_" + suffix(), "held": "held_canary_" + suffix()}
	canary := d.canaries["doomed"]

	d.stage = "deletion_seed"
	seed := map[*dproject]string{&doomed: canary, &sibling: d.canaries["sibling"], &held: d.canaries["held"]}
	for project, name := range seed {
		for i := range 3 {
			if err = site.ingest(*project, project.metric(int64(i+1), name)); err != nil {
				return err
			}
		}
	}
	if err = app.Storage.Flush(ctx); err != nil {
		return err
	}
	if _, err = app.Storage.CreateSnapshots(ctx); err != nil { // the routine snapshot, before anyone asked for a deletion
		return err
	}

	d.stage = "deletion_positive_controls"
	before, err := storeHits(site.dir, d.canaries)
	if err != nil {
		return err
	}
	for _, store := range []string{storeApply, storeSegments, storeSnapFiles, storeSnapState, storeSnapCache, storeJournal} {
		if !has(before, store, "doomed") {
			return d.fail("positive_control_missing_" + store)
		}
	}
	if has(before, storeControl, "doomed") {
		return d.fail("telemetry_in_control_store")
	}
	d.evidence["canary_stores_before_deletion"] = summarize(before, "doomed")

	d.stage = "deletion_hold_blocks_begin"
	earlyHold, err := site.hold(ctx, svc, held.id, "deletion smoke legal hold")
	if err != nil {
		return err
	}
	heldReceipt, err := site.begin(ctx, svc, held.id, "deletion smoke held request")
	if err != nil {
		return err
	}
	if heldReceipt.Phase != model.DeletePhaseHeld {
		return d.fail("hold_did_not_block_begin")
	}
	if n, err := site.scanRows(ctx, held); err != nil || n != 3 {
		return d.fail("held_request_denied_reads")
	}
	if err = svc.RunOnce(ctx); err != nil {
		return err
	}
	if n, err := site.scanRows(ctx, held); err != nil || n != 3 {
		return d.fail("held_request_erased_or_denied")
	}
	mid, err := storeHits(site.dir, map[string]string{"held": d.canaries["held"]})
	if err != nil {
		return err
	}
	if !has(mid, storeApply, "held") || !has(mid, storeSegments, "held") {
		return d.fail("held_request_bytes_missing")
	}
	if err = site.release(ctx, svc, earlyHold); err != nil {
		return err
	}
	if again, err := site.poll(ctx, svc, heldReceipt.OperationID); err != nil || again.Phase != model.DeletePhaseHeld {
		return d.fail("release_started_the_deletion_by_itself")
	}
	d.evidence["hold_blocks_begin"] = map[string]any{"phase": heldReceipt.Phase, "reads_still_served": true, "bytes_still_present": true, "release_starts_nothing": true}

	d.stage = "deletion_export_before"
	baseline := func() (map[string]string, error) {
		out := map[string]string{}
		random := model.NewID()
		_, status, body, err := site.exportCreate(random)
		if err != nil {
			return nil, err
		}
		var ok bool
		if out["create"], ok = denial(status, body); !ok {
			return nil, d.fail("baseline_not_a_fault")
		}
		if status, body, err = site.exportStatus(random, model.NewID()); err != nil {
			return nil, err
		}
		if out["status"], ok = denial(status, body); !ok {
			return nil, d.fail("baseline_not_a_fault")
		}
		forged := exports.Grant{Operation: exports.Operation{ID: model.NewID()}, Ticket: "forged"}
		if status, body, err = site.exportDownload(random, forged); err != nil {
			return nil, err
		}
		if out["download"], ok = denial(status, body); !ok {
			return nil, d.fail("baseline_not_a_fault")
		}
		return out, nil
	}
	guessed, err := baseline()
	if err != nil {
		return err
	}
	grant, err := site.exportReady(doomed.id)
	if err != nil {
		return err
	}
	status, body, err := site.exportDownload(doomed.id, grant)
	if err = requireSmokeResponse("deletion_export_before_download", status, 200, body, err); err != nil {
		return err
	}
	if !bytes.Contains(body, []byte(canary)) {
		return d.fail("export_before_missing_rows")
	}
	d.stage = "deletion_race_setup"
	readScope, err := site.readScope(ctx, doomed)
	if err != nil {
		return err
	}
	request := storage.ScanRequest{Projects: []model.ID{doomed.id}, Signal: model.Metric, End: model.UnixNano(math.MaxInt64)}
	preOpened, err := app.Storage.Scan(ctx, readScope, request) // opened before Begin, first page not yet taken
	if err != nil {
		return err
	}
	defer preOpened.Close()
	live, err := app.Storage.Subscribe(ctx, readScope, storage.SubscribeRequest{Projects: []model.ID{doomed.id}, Signal: model.Metric})
	if err != nil {
		return err
	}
	defer live.Close()
	live2, err := app.Storage.Subscribe(ctx, readScope, storage.SubscribeRequest{Projects: []model.ID{doomed.id}, Signal: model.Metric}) // never read before Begin: its pages are pending
	if err != nil {
		return err
	}
	defer live2.Close()
	if err = site.ingest(doomed, doomed.metric(4, canary)); err != nil { // a committed page waits in the live stream
		return err
	}
	fill, err := app.Cache.Lookup(ctx, readScope, "profile", "q", "p")
	if err != nil || fill.Hit {
		return d.fail("cache_not_cold")
	}
	if err = app.Cache.Store(ctx, readScope, fill.Fill, []byte("cached "+canary), false); err != nil {
		return err
	}
	if hit, err := app.Cache.Lookup(ctx, readScope, "profile", "q", "p"); err != nil || !hit.Hit {
		return d.fail("cache_not_warm")
	}

	d.stage = "deletion_race"
	var beginAt atomic.Int64 // unix nanos at which Begin returned; zero until then
	var receipt retention.DeleteReceipt
	begin := func() error {
		var err error
		receipt, err = site.begin(ctx, svc, doomed.id, "deletion smoke")
		beginAt.Store(time.Now().UnixNano())
		return err
	}
	surfaces := map[string]func() bool{
		"scan": func() bool {
			it, err := app.Storage.Scan(ctx, readScope, request)
			if err != nil {
				return false
			}
			defer it.Close()
			page, err := it.Next(ctx)
			return err == nil && page.Len() > 0
		},
		"cache": func() bool {
			hit, err := app.Cache.Lookup(ctx, readScope, "profile", "q", "p")
			return err == nil && hit.Hit && len(hit.Value) > 0
		},
		"export_download": func() bool {
			status, body, err := site.exportDownload(doomed.id, grant)
			return err == nil && status == 200 && bytes.Contains(body, []byte(canary))
		},
		"live": func() bool {
			// Next must not be given a deadline: a cancelled Next closes the stream for good. The
			// writer keeps committing pages, so each call returns within a few milliseconds.
			page, err := live.Next(ctx)
			return err == nil && page.Page.Len() > 0
		},
	}
	writer := func(stop *atomic.Bool) {
		for i := int64(5); !stop.Load(); i++ {
			_ = site.ingest(doomed, doomed.metric(i, canary)) // denied (and ignored) once Begin has committed
			time.Sleep(5 * time.Millisecond)
		}
	}
	stats, violations, err := raceBegin(surfaces, writer, begin, &beginAt, func() { live.Close() })
	if err != nil {
		return err
	}
	if receipt.Phase != model.DeletePhaseFencing || receipt.Physical != retention.PhysicalPending {
		return d.fail("begin_not_fencing")
	}
	if len(violations) != 0 {
		return d.fail("bytes_released_after_fence_" + violations[0])
	}
	for name, st := range stats {
		if st.beforeReleased == 0 {
			return d.fail("race_vacuous_" + name) // the surface never released anything before Begin: nothing was raced
		}
		if st.after == 0 && name != "live" { // a stream with nothing new to deliver stays blocked: nothing released
			return d.fail("race_never_ran_after_" + name)
		}
	}
	raceEvidence := map[string]any{}
	for name, st := range stats {
		raceEvidence[name] = map[string]int{"calls_before_begin": st.before, "released_before_begin": st.beforeReleased, "calls_after_begin": st.after, "released_after_begin": st.afterReleased}
	}
	d.evidence["race_with_begin"] = raceEvidence

	d.stage = "deletion_after_begin"
	// Objects that were open or warm before Begin release nothing afterwards.
	if page, err := preOpened.Next(ctx); err == nil && page.Len() > 0 {
		return d.fail("preopened_scan_released_rows")
	}
	if page, err := live2.Next(ctx); err == nil && page.Page.Len() > 0 {
		return d.fail("live_stream_released_rows")
	}
	if hit, err := app.Cache.Lookup(ctx, readScope, "profile", "q", "p"); err == nil && hit.Hit {
		return d.fail("warm_cache_entry_served")
	}
	_, gone := site.readScope(ctx, doomed)
	_, absent := app.Auth.Authorize(ctx, site.actor, site.org, []model.ID{model.NewID()}, auth.Read)
	if gone == nil || absent == nil || fmt.Sprint(gone) != fmt.Sprint(absent) {
		return d.fail("deleted_project_scope_distinguishable")
	}
	for kind, want := range guessed {
		var status int
		var body []byte
		switch kind {
		case "create":
			_, status, body, err = site.exportCreate(doomed.id)
		case "status":
			status, body, err = site.exportStatus(doomed.id, grant.Operation.ID)
		case "download":
			status, body, err = site.exportDownload(doomed.id, grant)
		}
		if err != nil {
			return err
		}
		if got, ok := denial(status, body); !ok || got != want {
			return d.fail("export_" + kind + "_distinguishable_from_guessed_absent")
		}
		if bytes.Contains(body, []byte(canary)) {
			return d.fail("export_" + kind + "_leaked_rows")
		}
	}
	rejected, _, replyBody, err := site.post(doomed.credential, mustBody(site.batchBody(doomed, doomed.metric(99, canary))))
	if err != nil {
		return err
	}
	unknown, _, unknownBody, err := site.post("sp_unknown_source_key_"+suffix(), mustBody(site.batchBody(doomed, doomed.metric(99, canary))))
	if err != nil {
		return err
	}
	if rejected == 200 {
		return d.fail("ingest_accepted_after_begin")
	}
	deniedAs, ok := denial(rejected, replyBody)
	unknownAs, _ := denial(unknown, unknownBody)
	if !ok {
		return d.fail("ingest_denial_not_a_fault")
	}
	if deniedAs != unknownAs {
		return d.fail("deleted_source_distinguishable_from_unknown_key")
	}
	if err = site.ingest(sibling, sibling.metric(10, d.canaries["sibling"])); err != nil {
		return d.fail("sibling_project_affected_by_begin")
	}
	d.evidence["http_denial"] = map[string]any{"export_create_status_download_equal_guessed_absent": true, "ingest_after_begin": deniedAs, "unknown_key": unknownAs, "begin_phase": receipt.Phase, "begin_progress": receipt.Progress}

	d.stage = "deletion_hold_after_begin"
	lateHold, err := site.hold(ctx, svc, doomed.id, "deletion smoke late legal hold")
	if err != nil {
		return err
	}

	d.stage = "deletion_authority_outage"
	for attempt := 1; attempt <= 2; attempt++ {
		if err = svc.RunOnce(ctx); err == nil {
			return d.fail("authority_outage_was_not_reported")
		}
		current, err := site.poll(ctx, svc, receipt.OperationID)
		if err != nil {
			return err
		}
		// The late hold already overlaps the operation, so the receipt reports physical "held"
		// while it is still fencing; what must never appear is "done" or a completed phase.
		if current.Phase != model.DeletePhaseFencing || current.Progress != "64/64" || current.Physical == retention.PhysicalDone {
			return d.fail("outage_did_not_leave_fencing_" + current.Phase + "_" + strings.ReplaceAll(current.Progress, "/", "of") + "_" + current.Physical)
		}
		stuck, err := storeHits(site.dir, map[string]string{"doomed": canary})
		if err != nil {
			return err
		}
		if !has(stuck, storeApply, "doomed") || !has(stuck, storeSegments, "doomed") {
			return d.fail("fencing_erased_bytes_early")
		}
		if status, body, err = site.exportDownload(doomed.id, grant); err != nil || status == 200 || bytes.Contains(body, []byte(canary)) {
			return d.fail("fencing_not_denying_reads")
		}
	}
	d.evidence["authority_outage"] = map[string]any{"failed_checkpoints": 2, "phase": model.DeletePhaseFencing, "barriers": "64/64", "completed": false}

	d.stage = "deletion_held_physical"
	if err = svc.RunOnce(ctx); err != nil { // authority answers: the operation completes
		return err
	}
	complete, err := site.poll(ctx, svc, receipt.OperationID)
	if err != nil {
		return err
	}
	if complete.Phase != model.DeletePhaseComplete || complete.Physical != retention.PhysicalHeld || len(complete.Residual) != 0 {
		return d.fail("hold_did_not_block_physical_success")
	}
	heldBytes, err := storeHits(site.dir, d.canaries)
	if err != nil {
		return err
	}
	if !has(heldBytes, storeApply, "doomed") || !has(heldBytes, storeSegments, "doomed") {
		return d.fail("held_deletion_erased_bytes")
	}
	if !has(heldBytes, storeApply, "sibling") {
		return d.fail("sibling_bytes_missing_while_held")
	}
	if status, body, err = site.exportDownload(doomed.id, grant); err != nil || status == 200 || bytes.Contains(body, []byte(canary)) {
		return d.fail("held_deletion_serves_reads")
	}
	if svc.Status().HeldByLegal == 0 {
		return d.fail("hold_veto_not_reported")
	}
	d.evidence["held_deletion"] = map[string]any{"phase": complete.Phase, "physical": complete.Physical, "bytes_present_while_held": summarize(heldBytes, "doomed"), "reads_denied": true}

	d.stage = "deletion_release_hold"
	if err = site.release(ctx, svc, lateHold); err != nil {
		return err
	}
	var done retention.DeleteReceipt
	deadline := time.Now().Add(4 * time.Minute)
	for {
		if err = svc.RunOnce(ctx); err != nil && time.Now().After(deadline) {
			return err
		}
		if done, err = site.poll(ctx, svc, receipt.OperationID); err != nil {
			return err
		}
		if done.Phase == model.DeletePhaseComplete && done.Physical == retention.PhysicalDone {
			break
		}
		if time.Now().After(deadline) {
			return d.fail("physical_cleanup_not_done")
		}
		time.Sleep(200 * time.Millisecond)
	}

	d.stage = "deletion_physical_scan"
	after, err := storeHits(site.dir, d.canaries)
	if err != nil {
		return err
	}
	// The receipt and the engine declare exactly what the scan can still find: nothing. A
	// declaration that was not empty would be a physical "done" with copies still on the host.
	declared := app.Storage.ResidualStores()
	if len(declared) != 0 || len(done.Residual) != 0 {
		return d.fail("residual_stores_declared_after_physical_done")
	}
	for store, byLabel := range after {
		for label, n := range byLabel {
			if n == 0 || label != "doomed" {
				continue
			}
			return d.fail("erased_bytes_survived_in_" + strings.NewReplacer("/", "_", ".", "_", ":", "_").Replace(store))
		}
	}
	for _, store := range []string{storeApply, storeSegments} {
		if !has(after, store, "sibling") {
			return d.fail("sibling_bytes_lost_from_" + store)
		}
	}
	if has(after, storeApply, "held") == false {
		return d.fail("held_project_bytes_lost")
	}
	st := svc.Status()
	if st.ScrubPending || st.PhysicalLagOps != 0 || st.ErasedRecords == 0 {
		return d.fail("worker_status_not_clean")
	}
	if n, err := site.scanRows(ctx, sibling); err != nil || n < 4 {
		return d.fail("sibling_rows_lost")
	}
	d.evidence["physical_cleanup"] = map[string]any{"physical": done.Physical, "residual_stores_declared": done.Residual, "canary_stores_after_cleanup": summarize(after, "doomed"), "sibling_stores_after_cleanup": summarize(after, "sibling"), "worker": map[string]any{"erased_records": st.ErasedRecords, "scrub_pending": st.ScrubPending, "snapshots": st.Snapshots, "held_vetoes": st.HeldByLegal}}

	d.stage = "deletion_manifest_ledger"
	current, err := real.Current(ctx)
	if err != nil {
		return err
	}
	if len(current.Tombstones) != 1 || len(current.Ledger.Entries) != 1 || current.Ledger.Entries[0].Hash != current.Tombstones[0].Digest() || current.Tombstones[0].Operation != receipt.OperationID {
		return d.fail("authority_ledger_does_not_hold_the_deletion")
	}
	if authority.attempts.Load() < 3 {
		return d.fail("authority_outage_not_exercised")
	}
	d.evidence["backup_suppression_manifest"] = map[string]any{
		"operation": receipt.OperationID, "mode": done.Mode, "phase": done.Phase, "physical": done.Physical,
		"generation": done.Generation, "backup_expiry_not_after_ns": done.BackupDeadline,
		"authority_head": current.Head, "ledger": current.Ledger, "tombstones": current.Tombstones,
		"authority_checkpoint_attempts": authority.attempts.Load(),
	}
	return nil
}

func mustBody(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

type raceStat struct{ before, beforeReleased, after, afterReleased int }

// raceBegin runs every surface in a tight loop, lets them release for a while, calls begin, and
// keeps them running afterwards. A call that STARTED after begin returned must not have released
// anything; the violations returned are the surfaces where one did.
func raceBegin(surfaces map[string]func() bool, writer func(*atomic.Bool), begin func() error, beginAt *atomic.Int64, unblock func()) (map[string]*raceStat, []string, error) {
	type call struct {
		surface  string
		start    int64
		released bool
	}
	var mu sync.Mutex
	var calls []call
	var stop atomic.Bool
	var wg sync.WaitGroup
	for name, fn := range surfaces {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				start := time.Now().UnixNano()
				released := fn()
				mu.Lock()
				calls = append(calls, call{name, start, released})
				mu.Unlock()
				time.Sleep(time.Millisecond)
			}
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); writer(&stop) }()
	time.Sleep(250 * time.Millisecond)
	err := begin()
	time.Sleep(600 * time.Millisecond)
	stop.Store(true)
	if unblock != nil {
		unblock() // a Next blocked waiting for an event is released by closing its stream
	}
	wg.Wait()
	if err != nil {
		return nil, nil, err
	}
	at := beginAt.Load()
	stats := map[string]*raceStat{}
	bad := map[string]bool{}
	for name := range surfaces {
		stats[name] = &raceStat{}
	}
	for _, c := range calls {
		st := stats[c.surface]
		if c.start > at {
			st.after++
			if c.released {
				st.afterReleased++
				bad[c.surface] = true
			}
		} else {
			st.before++
			if c.released {
				st.beforeReleased++
			}
		}
	}
	violations := make([]string, 0, len(bad))
	for name := range bad {
		violations = append(violations, name)
	}
	sort.Strings(violations)
	return stats, violations, nil
}

// ---- the disk-pressure scenario ---------------------------------------------

// smokeMeter is the disk accounting the admission gate reads: fixed capacity,
// usage set to exact percentages, so the 80/90/95 boundaries are crossed
// deterministically through the real ingest path.
type smokeMeter struct {
	total uint64
	used  atomic.Uint64
}

func (m *smokeMeter) set(percent uint64) { m.used.Store(m.total / 100 * percent) }
func (m *smokeMeter) Usage(string) (storage.DiskUsage, error) {
	return storage.DiskUsage{TotalBytes: m.total, UsedBytes: m.used.Load()}, nil
}

func (d *deletionSmoke) pressureScenario() error {
	ctx := d.ctx
	d.stage = "pressure_open"
	meter := &smokeMeter{total: 100 << 30} // a multiple of 100, so every percentage below is exact
	meter.set(50)
	cfg := storage.DefaultPressureConfig()
	cfg.Interval = 0 // sample on every admission: a level change is visible to the very next request
	site, closer, err := d.openSite(func(dir string) (*appcore.App, error) { return appcore.OpenWithPressure(dir, meter, cfg) })
	if err != nil {
		return err
	}
	defer closer()
	app := site.app
	p, err := site.project(ctx, "pressure")
	if err != nil {
		return err
	}
	victim, err := site.project(ctx, "freed-by-deletion")
	if err != nil {
		return err
	}

	d.stage = "pressure_seed"
	type acked struct {
		body   []byte
		reply  []byte
		header string
	}
	var ackedBatches []acked
	ack := func(records ...model.Record) error {
		body, err := site.batchBody(p, records...)
		if err != nil {
			return err
		}
		status, header, reply, err := site.post(p.credential, body)
		if err = requireSmokeResponse("pressure_ack", status, 200, reply, err); err != nil {
			return err
		}
		ackedBatches = append(ackedBatches, acked{body, reply, header.Get("X-Soundpost-Receipt")})
		return nil
	}
	for i := range 3 {
		if err = ack(p.metric(int64(i+1), "pressure_acked_total")); err != nil {
			return err
		}
	}
	for i := range 2 {
		if err = site.ingest(victim, victim.metric(int64(i+1), "victim_total")); err != nil {
			return err
		}
	}
	rows, err := site.scanRows(ctx, p)
	if err != nil || rows != 3 {
		return d.fail("pressure_seed_rows")
	}
	retained := string(ackedBatches[0].reply)

	// admit posts a fresh batch of the class and returns the HTTP answer.
	admit := func(low bool) (int, http.Header, []byte, error) {
		record := p.metric(time.Now().UnixNano()%1_000_000+100, "pressure_probe_total")
		if low {
			record = p.span(time.Now().UnixNano()%1_000_000 + 100)
		}
		body, err := site.batchBody(p, record)
		if err != nil {
			return 0, nil, nil, err
		}
		return site.post(p.credential, body)
	}
	type step struct {
		percent     uint64
		level       storage.PressureLevel
		metricOK    bool
		lowOK       bool
		warningCode string
	}
	var transitions []map[string]any
	observe := func(s step) error {
		meter.set(s.percent)
		status, err := app.Storage.ObservePressure(ctx)
		if err != nil {
			return err
		}
		if status.Level != s.level {
			return d.fail(fmt.Sprintf("level_at_%d_is_%d", s.percent, status.Level))
		}
		st, header, reply, err := admit(false)
		if err != nil {
			return err
		}
		if (st == 200) != s.metricOK {
			return d.fail(fmt.Sprintf("metric_admission_at_%d_was_%d", s.percent, st))
		}
		if st != 200 {
			if got, ok := denial(st, reply); !ok || got != "503/unavailable/capacity" || header.Get("Retry-After") == "" {
				return d.fail(fmt.Sprintf("metric_rejection_at_%d_is_not_a_retryable_capacity_fault", s.percent))
			}
		}
		lowStatus, lowHeader, lowReply, err := admit(true)
		if err != nil {
			return err
		}
		if (lowStatus == 200) != s.lowOK {
			return d.fail(fmt.Sprintf("low_priority_admission_at_%d_was_%d", s.percent, lowStatus))
		}
		if lowStatus != 200 {
			if got, ok := denial(lowStatus, lowReply); !ok || got != "503/unavailable/capacity" || lowHeader.Get("Retry-After") == "" {
				return d.fail(fmt.Sprintf("low_rejection_at_%d_is_not_a_retryable_capacity_fault", s.percent))
			}
		}
		if err = app.Retention.RunOnce(ctx); err != nil && s.percent != 95 {
			return err
		}
		if got := app.Retention.Status().Pressure.Level; got != s.level {
			return d.fail("worker_does_not_surface_the_level")
		}
		transitions = append(transitions, map[string]any{"used_percent": s.percent, "level": status.Level, "metric_admitted": st == 200, "low_priority_admitted": lowStatus == 200})
		return nil
	}
	steps := []step{
		{50, storage.PressureNormal, true, true, ""},
		{80, storage.PressureWarn, true, true, "disk_warn"},
		{90, storage.PressureDenyLow, true, false, "disk_deny_low"},
		{95, storage.PressureDenyAll, false, false, "disk_deny_all"},
		{94, storage.PressureDenyAll, false, false, ""}, // hysteresis: still denying until usage falls below 93%
		{91, storage.PressureDenyLow, true, false, "disk_deny_low"},
		{50, storage.PressureNormal, true, true, "disk_recovered"},
	}
	d.stage = "pressure_levels"
	for _, s := range steps {
		if err = observe(s); err != nil {
			return err
		}
		if s.percent == 95 {
			// At full disk: the ACKed batches still answer with their original receipt, byte for byte,
			// and deleting to free space is not refused.
			for i, a := range ackedBatches[:3] {
				st, header, reply, err := site.post(p.credential, a.body)
				if err != nil {
					return err
				}
				if st != 200 || !bytes.Equal(reply, a.reply) || header.Get("X-Soundpost-Receipt") != a.header {
					return d.fail(fmt.Sprintf("acked_retry_%d_changed_under_pressure", i))
				}
			}
			receipt, err := site.begin(ctx, app.Retention, victim.id, "free space at full disk")
			if err != nil {
				return d.fail("delete_refused_at_full_disk")
			}
			for deadline := time.Now().Add(4 * time.Minute); ; time.Sleep(200 * time.Millisecond) {
				_ = app.Retention.RunOnce(ctx)
				if receipt, err = site.poll(ctx, app.Retention, receipt.OperationID); err != nil {
					return err
				}
				if receipt.Phase == model.DeletePhaseComplete && receipt.Physical == retention.PhysicalDone {
					break
				}
				if time.Now().After(deadline) {
					return d.fail("delete_did_not_complete_at_full_disk")
				}
			}
			if _, err := site.scanRows(ctx, victim); err == nil {
				return d.fail("freed_project_still_readable")
			}
		}
	}

	d.stage = "pressure_honesty"
	status := app.Storage.PressureStatus()
	var codes []string
	for _, w := range status.Warnings {
		codes = append(codes, w.Code)
	}
	wantCodes := []string{"disk_warn", "disk_deny_low", "disk_deny_all", "disk_deny_low", "disk_recovered"}
	if fmt.Sprint(codes) != fmt.Sprint(wantCodes) {
		return d.fail("warning_sequence_is_" + strings.Join(codes, ","))
	}
	if status.DeniedAll == 0 || status.DeniedLow == 0 {
		return d.fail("denial_counters_not_counting")
	}
	if rows, err = site.scanRows(ctx, p); err != nil {
		return err
	}
	// Every ACKed metric record is still there (the probes admitted at the permissive levels are
	// extra), and no receipt time moved: pressure never shortens retention.
	if rows < 3 {
		return d.fail("acked_data_disappeared_under_pressure")
	}
	for i, a := range ackedBatches[:3] {
		st, _, reply, err := site.post(p.credential, a.body)
		if err != nil || st != 200 || !bytes.Equal(reply, a.reply) {
			return d.fail(fmt.Sprintf("acked_receipt_%d_changed_after_pressure", i))
		}
	}
	if string(ackedBatches[0].reply) != retained {
		return d.fail("receipt_deadline_moved")
	}
	d.evidence["disk_pressure"] = map[string]any{"transitions": transitions, "warning_codes": codes, "denied_low": status.DeniedLow, "denied_all": status.DeniedAll, "acked_batches_retried_identically": 3, "rows_after": rows, "delete_at_full_disk": "completed"}
	return nil
}
