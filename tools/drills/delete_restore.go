// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/backup"
	"soundpost/internal/control"
	"soundpost/internal/ingest"
	"soundpost/internal/jobs"
	"soundpost/internal/model"
	"soundpost/internal/policy"
	"soundpost/internal/replica"
	"soundpost/internal/retention"
	"soundpost/internal/storage"
)

// ---- pure verifiers (no I/O; unit-tested in delete_restore_test.go) ----

// drFenceSample is one observation of a deletion receipt while the saga runs.
type drFenceSample struct {
	Seq        int    `json:"seq"`
	Phase      string `json:"phase"`
	Generation uint64 `json:"generation"`
	Revision   uint64 `json:"revision"`
	Barriers   int    `json:"barriers"`
	Physical   string `json:"physical"`
}

// drVerifyFence checks the receipt/fence samples of one deletion: generation, control revision
// and the number of recorded slot barriers never go back, the phase never leaves complete, a
// physical "done" never reverts, "complete" is reported only with every slot barrier recorded,
// held/failed are never success, and the LAST sample is the completed all-slot fence.
func drVerifyFence(samples []drFenceSample, slots int) error {
	if len(samples) == 0 {
		return errors.New("fence: no receipt was ever observed")
	}
	rank := map[string]int{model.DeletePhaseFencing: 1, model.DeletePhaseComplete: 2}
	for i, s := range samples {
		r, ok := rank[s.Phase]
		switch {
		case !ok:
			return fmt.Errorf("fence: sample %d has phase %q (only fencing and complete are phases of a successful barrier)", i, s.Phase)
		case s.Barriers < 0 || s.Barriers > slots:
			return fmt.Errorf("fence: sample %d records %d barriers for %d slots", i, s.Barriers, slots)
		case s.Phase == model.DeletePhaseComplete && s.Barriers != slots:
			return fmt.Errorf("fence: sample %d is complete with %d/%d slot barriers", i, s.Barriers, slots)
		}
		if i == 0 {
			continue
		}
		p := samples[i-1]
		switch {
		case s.Generation < p.Generation:
			return fmt.Errorf("fence: generation went back %d -> %d at sample %d", p.Generation, s.Generation, i)
		case s.Revision < p.Revision:
			return fmt.Errorf("fence: control revision went back %d -> %d at sample %d", p.Revision, s.Revision, i)
		case s.Barriers < p.Barriers:
			return fmt.Errorf("fence: recorded barriers went back %d -> %d at sample %d", p.Barriers, s.Barriers, i)
		case rank[p.Phase] > r:
			return fmt.Errorf("fence: phase went back %s -> %s at sample %d", p.Phase, s.Phase, i)
		case p.Physical == retention.PhysicalDone && s.Physical != retention.PhysicalDone:
			return fmt.Errorf("fence: physical cleanup reverted from done to %q at sample %d", s.Physical, i)
		}
	}
	if last := samples[len(samples)-1]; last.Phase != model.DeletePhaseComplete || last.Barriers != slots {
		return fmt.Errorf("fence: the last sample is %s with %d/%d barriers, not a completed all-slot fence", last.Phase, last.Barriers, slots)
	}
	return nil
}

// drVerifyBarrierCoverage requires exactly one recorded barrier cursor per slot, each in a
// distinct, non-zero data group with a non-zero index: a group is never skipped or counted twice.
func drVerifyBarrierCoverage(barriers []model.Cursor, slots int) error {
	if len(barriers) != slots {
		return fmt.Errorf("barriers: %d recorded for %d slots", len(barriers), slots)
	}
	seen := map[model.ID]bool{}
	for i, c := range barriers {
		switch {
		case c.Group == (model.ID{}) || c.Index == 0:
			return fmt.Errorf("barriers: entry %d has no group or cursor", i)
		case seen[c.Group]:
			return fmt.Errorf("barriers: group %s appears twice (another group has no barrier)", c.Group)
		}
		seen[c.Group] = true
	}
	return nil
}

// drSend is the outcome of one send attempt. Stale marks a send built under a policy revision
// that had already been superseded when the send began.
type drSend struct {
	Label string     `json:"label"`
	Batch string     `json:"batch"`
	Built uint64     `json:"built_revision"`
	Stale bool       `json:"stale"`
	Acked bool       `json:"acked"`
	Fault model.Code `json:"fault,omitempty"`
}

// drVerifyStaleSends requires that every stale send was refused with the typed `stale` fault and
// never acknowledged (a stale send that succeeded, or that was refused with any other code, was
// silently remapped or failed for an unrelated reason), and that at least minStale were made.
func drVerifyStaleSends(outcomes []drSend, minStale int) error {
	n := 0
	for _, o := range outcomes {
		if !o.Stale {
			continue
		}
		n++
		switch {
		case o.Acked:
			return fmt.Errorf("stale send %q (built under revision %d) was acknowledged", o.Label, o.Built)
		case o.Fault != model.Stale:
			return fmt.Errorf("stale send %q (built under revision %d) was refused with %q, want %q", o.Label, o.Built, o.Fault, model.Stale)
		}
	}
	if n < minStale {
		return fmt.Errorf("only %d stale sends were made, at least %d are needed for the drill to mean anything", n, minStale)
	}
	return nil
}

// drPolicyStep is one completed policy change.
type drPolicyStep struct {
	Revision   uint64 `json:"revision"`
	Phase      string `json:"phase"`
	Barriers   int    `json:"barriers"`
	ControlRev uint64 `json:"control_revision"`
	Digest     string `json:"policy_digest"`
}

// drVerifyPolicyTimeline requires consecutive revisions, each fence complete across every slot,
// strictly growing control revisions and a distinct policy digest per revision.
func drVerifyPolicyTimeline(steps []drPolicyStep, slots int) error {
	if len(steps) == 0 {
		return errors.New("policy timeline: empty")
	}
	digests := map[string]uint64{}
	for i, s := range steps {
		switch {
		case s.Phase != "complete":
			return fmt.Errorf("policy timeline: revision %d fence is %q, not complete", s.Revision, s.Phase)
		case s.Barriers != slots:
			return fmt.Errorf("policy timeline: revision %d fence reached %d/%d slots", s.Revision, s.Barriers, slots)
		case s.Digest == "":
			return fmt.Errorf("policy timeline: revision %d has no policy digest", s.Revision)
		}
		if prev, dup := digests[s.Digest]; dup {
			return fmt.Errorf("policy timeline: revisions %d and %d carry one identical policy", prev, s.Revision)
		}
		digests[s.Digest] = s.Revision
		if i == 0 {
			continue
		}
		p := steps[i-1]
		switch {
		case s.Revision != p.Revision+1:
			return fmt.Errorf("policy timeline: revision %d follows %d", s.Revision, p.Revision)
		case s.ControlRev <= p.ControlRev:
			return fmt.Errorf("policy timeline: control revision did not grow between revision %d and %d", p.Revision, s.Revision)
		}
	}
	return nil
}

// drRow is one retained row read back from the system, with the batch it belongs to.
type drRow struct {
	BatchID string
	Org     model.ID
	Project model.ID
	Record  model.Record
}

// drDetectResurrection returns, sorted, the batch IDs of every retained row that a deletion
// tombstone covers. It uses the very predicate the engine and the restore ledger use
// (model.DeletePredicate.CoversRecord), so the detector and the system cannot disagree on what a
// tombstone means. An empty result is the only acceptable one after a restore.
func drDetectResurrection(rows []drRow, tombstones []model.DeletePredicate) []string {
	set := map[string]bool{}
	for _, r := range rows {
		for _, t := range tombstones {
			if t.CoversRecord(r.Org, r.Project, r.Record) {
				set[r.BatchID] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// drAcked is one ACKed batch of the drill.
type drAcked struct {
	ID      string
	Org     model.ID
	Project model.ID
	Record  model.Record
	Cursor  model.Cursor
	Digest  string
	Label   string
}

// drPartition splits ACKed batches into those outside every tombstone (they must be retained
// exactly) and those inside one (they were acknowledged and then legitimately deleted).
func drPartition(acks []drAcked, tombstones []model.DeletePredicate) (outside, inside []drAcked) {
	for _, a := range acks {
		covered := false
		for _, t := range tombstones {
			if t.CoversRecord(a.Org, a.Project, a.Record) {
				covered = true
				break
			}
		}
		if covered {
			inside = append(inside, a)
		} else {
			outside = append(outside, a)
		}
	}
	return outside, inside
}

// drRefusal is what a drill observed after a restore step that had to fail closed.
type drRefusal struct {
	Err           error
	RootCreated   bool
	StageLeftover int
	ObjectsOpened int
	Activated     bool
	ReadsServed   int
	Admitted      int
}

// drClassifyRefusal returns nil only for a closed failure: the step returned a TYPED fault
// (a *model.Fault) whose code is in the allowed set, and nothing was created, read, activated,
// served or admitted. A nil error, an untyped error or any residue is a failure of the drill.
func drClassifyRefusal(o drRefusal, allowed ...model.Code) error {
	if len(allowed) == 0 {
		return errors.New("refusal: no allowed fault codes were given")
	}
	if o.Err == nil {
		return errors.New("refusal: the step succeeded; it had to fail closed")
	}
	var fault *model.Fault
	if !errors.As(o.Err, &fault) {
		return fmt.Errorf("refusal: the failure is not a typed fault: %v", o.Err)
	}
	if !slices.Contains(allowed, fault.Code) {
		return fmt.Errorf("refusal: typed fault %q is not one of %v", fault.Code, allowed)
	}
	switch {
	case o.RootCreated:
		return errors.New("refusal: a restore root exists after the refusal")
	case o.StageLeftover != 0:
		return fmt.Errorf("refusal: %d staging leftovers", o.StageLeftover)
	case o.ObjectsOpened != 0:
		return fmt.Errorf("refusal: %d backup objects were read before the refusal", o.ObjectsOpened)
	case o.Activated:
		return errors.New("refusal: the installation reports activation")
	case o.ReadsServed != 0:
		return fmt.Errorf("refusal: %d rows were served", o.ReadsServed)
	case o.Admitted != 0:
		return fmt.Errorf("refusal: %d writes were admitted", o.Admitted)
	}
	return nil
}

// drVerdict classifies one ACKed evidence batch after retention expiry.
type drVerdict string

const (
	drRetained         drVerdict = "retained"
	drGapDeclared      drVerdict = "gap_declared"
	drProcessedExpired drVerdict = "processed_then_expired"
	drSilentlyMissing  drVerdict = "silently_missing"
	drChangedContent   drVerdict = "retained_with_other_content"
	drOverDeclared     drVerdict = "retained_inside_declared_gap"
)

type drEvidenceResult struct {
	ID      string    `json:"id"`
	Verdict drVerdict `json:"verdict"`
	Gap     string    `json:"gap,omitempty"`
	Reason  string    `json:"reason,omitempty"`
}

func drGapCovers(g model.EvidenceGap, a drAcked) bool {
	if g.Group != a.Cursor.Group || g.Org != a.Org || g.Project != a.Project || uint64(a.Cursor.Index) <= uint64(g.After) || uint64(a.Cursor.Index) > uint64(g.Through) {
		return false
	}
	return len(g.Signals) == 0 || slices.Contains(g.Signals, a.Record.Kind)
}

// drClassifyEvidence explains what happened to every ACKed evidence batch after retention
// expiry. A batch is exactly one of: retained with its exact content; covered by a gap the
// retention WORKER declared with a reason (the only gap that authorizes expiry); already applied
// to the lifecycle projection (its effect lives in the state, the raw record may expire); or
// silently missing, which is an error, as are a retained batch whose content changed and a
// retained batch inside a declared gap (an over-declaration). The error lists every violation.
func drClassifyEvidence(acks []drAcked, retained map[string]string, gaps []model.EvidenceGap, processed map[model.ID]uint64) ([]drEvidenceResult, error) {
	out := make([]drEvidenceResult, 0, len(acks))
	var bad []string
	for _, a := range acks {
		res := drEvidenceResult{ID: a.ID}
		var cover *model.EvidenceGap
		for i := range gaps {
			if gaps[i].DeclaredBy == "worker" && gaps[i].Reason != "" && drGapCovers(gaps[i], a) {
				cover = &gaps[i]
				break
			}
		}
		if got, ok := retained[a.ID]; ok {
			switch {
			case got != a.Digest:
				res.Verdict = drChangedContent
			case cover != nil:
				res.Verdict, res.Gap = drOverDeclared, cover.ID.String()
			default:
				res.Verdict = drRetained
			}
		} else if cover != nil {
			res.Verdict, res.Gap, res.Reason = drGapDeclared, cover.ID.String(), cover.Reason
		} else if uint64(a.Cursor.Index) <= processed[a.Cursor.Group] {
			res.Verdict = drProcessedExpired
		} else {
			res.Verdict = drSilentlyMissing
		}
		if res.Verdict == drChangedContent || res.Verdict == drOverDeclared || res.Verdict == drSilentlyMissing {
			bad = append(bad, a.ID+"="+string(res.Verdict))
		}
		out = append(out, res)
	}
	if len(bad) > 0 {
		return out, fmt.Errorf("evidence: %d of %d acknowledged batches are not explained: %s", len(bad), len(acks), strings.Join(bad, ", "))
	}
	return out, nil
}

// drVerifyHealthReportsGap checks the read path's answer after the evidence expired unprocessed:
// the verdict is unknown and incomplete (never a success), names the evidence gap as a reason,
// and lists every declared gap both as evidence and as an annotated incomplete interval.
func drVerifyHealthReportsGap(r jobs.Report, gaps []model.EvidenceGap) error {
	if len(gaps) == 0 {
		return errors.New("health: no declared gap to expect")
	}
	h := r.Health
	if h.Status != jobs.StatusUnknown {
		return fmt.Errorf("health: status is %q after the evidence expired; an empty success would hide the loss", h.Status)
	}
	if h.Complete {
		return errors.New("health: reported complete although evidence expired unprocessed")
	}
	if !slices.Contains(h.Reasons, jobs.ReasonEvidenceGap) {
		return fmt.Errorf("health: reasons %v do not name %q", h.Reasons, jobs.ReasonEvidenceGap)
	}
	for _, g := range gaps {
		if len(g.Signals) != 0 && !slices.Contains(g.Signals, model.JobAttempt) {
			continue
		}
		if !slices.Contains(h.Evidence.Gaps, g.ID) {
			return fmt.Errorf("health: declared gap %s is not part of the verdict's evidence", g.ID)
		}
		found := false
		for _, iv := range r.Intervals {
			if iv.ID == g.ID {
				found = iv.Reason == "evidence_expired"
				break
			}
		}
		if !found {
			return fmt.Errorf("health: declared gap %s is not an incomplete interval with reason evidence_expired", g.ID)
		}
	}
	return nil
}

// ---- semantic digests ----

// drPageRowDigest is the digest of the exact semantic content of one row: project, source,
// record identity, signal, time, resource and payload, in the canonical encoding. The digest of a
// record before ACK and the digest of the row read back after recovery are computed by the same
// function, so equal digests mean equal semantic content, not equal counts.
func drPageRowDigest(project, source, id model.ID, kind model.Kind, observed model.UnixNano, res model.Resource, payload model.Payload) string {
	raw, err := model.CanonicalJSON(model.Record{ID: id, Kind: kind, ObservedAt: observed, Resource: res, Payload: payload})
	if err != nil {
		return "unencodable:" + err.Error()
	}
	h := sha256.New()
	h.Write(project[:])
	h.Write(source[:])
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}

func drRecordDigest(project, source model.ID, r model.Record) string {
	return drPageRowDigest(project, source, r.ID, r.Kind, r.ObservedAt, r.Resource, r.Payload)
}

// drRequireRecorded fails unless every named check was recorded in the report and passed. A
// scenario ends with it, so an assertion that was silently deleted or skipped (a refactor, an
// early return) makes the scenario fail instead of pass with less evidence.
func drRequireRecorded(rep *Report, names ...string) error {
	ok := map[string]bool{}
	for _, c := range rep.Checks {
		if c.OK {
			ok[c.Name] = true
		} else {
			return fmt.Errorf("check %s did not pass", c.Name)
		}
	}
	var missing []string
	for _, n := range names {
		if !ok[n] {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("required checks were never recorded: %s", strings.Join(missing, ", "))
	}
	return nil
}

func init() {
	register("stale-policy-delete-barrier", drStalePolicyDeleteBarrier)
	register("backup-predates-deletion", drBackupPredatesDeletion)
	register("restore-authority-unavailable", drRestoreAuthorityUnavailable)
	register("evidence-gap-after-retention", drEvidenceGapAfterRetention)
}

// ---- physical scanning (copied pattern of tools/smoke/deletion.go, multi-needle) ----

var drBase64Run = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)

type drNeedle struct {
	Label string
	Bytes []byte
}

// drDeepHits counts every needle in data and in everything that decodes out of it. Journals and
// snapshots wrap commands in base64 inside JSON inside base64, so a plain byte search proves
// nothing about them. Fragmentary data (free pages start mid-string) is tried at all four base64
// alignments at the top level. Counts are added to out by needle label.
func drDeepHits(data []byte, needles []drNeedle, depth int, top bool, out map[string]int) {
	minLen := math.MaxInt
	for _, n := range needles {
		if c := bytes.Count(data, n.Bytes); c > 0 {
			out[n.Label] += c
		}
		minLen = min(minLen, len(n.Bytes))
	}
	if depth == 0 {
		return
	}
	alignments := 1
	if top {
		alignments = 4
	}
	for _, run := range drBase64Run.FindAll(data, -1) {
		for skip := 0; skip < alignments && skip < len(run); skip++ {
			plain := strings.NewReplacer("-", "+", "_", "/").Replace(string(bytes.TrimRight(run[skip:], "=")))
			if len(plain)%4 == 1 {
				plain = plain[:len(plain)-1]
			}
			decoded, err := base64.RawStdEncoding.DecodeString(plain)
			if err != nil || len(decoded) < minLen {
				continue
			}
			drDeepHits(decoded, needles, depth-1, false, out)
		}
	}
}

// drStoreOf attributes a file (path relative to the installation root) to the store class that
// holds it, so a hit is reported against the store, not a file name.
func drStoreOf(rel string) string {
	rel = filepath.ToSlash(rel)
	switch {
	case rel == "data/apply.db":
		return "apply.db"
	case strings.HasPrefix(rel, "data/segments/"):
		return "segments"
	case rel == "control.db" || strings.HasPrefix(rel, "raft/control/") || strings.HasPrefix(rel, "control/"):
		return "control"
	case strings.Contains(rel, "/snapshots/"):
		return "snapshots"
	case strings.HasSuffix(rel, "ready.wal"):
		return "raft_journal"
	}
	return "other:" + rel
}

// drStoreHits searches every regular file under dir for every needle: store -> label -> hits.
func drStoreHits(dir string, needles []drNeedle) (map[string]map[string]int, error) {
	out := map[string]map[string]int{}
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !info.Mode().IsRegular() {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		hits := map[string]int{}
		drDeepHits(raw, needles, 5, true, hits)
		store := drStoreOf(rel)
		for label, n := range hits {
			if out[store] == nil {
				out[store] = map[string]int{}
			}
			out[store][label] += n
		}
		return nil
	})
	return out, err
}

func drHitTotal(hits map[string]map[string]int, label string) int {
	n := 0
	for _, byLabel := range hits {
		n += byLabel[label]
	}
	return n
}

func drHitStores(hits map[string]map[string]int, label string) []string {
	var out []string
	for store, byLabel := range hits {
		if byLabel[label] > 0 {
			out = append(out, store)
		}
	}
	sort.Strings(out)
	return out
}

// ---- one real application with an organization (in process) ----

const (
	drOwnerEmail    = "drill-owner@example.test"
	drOwnerPassword = "drill owner password 2026"
)

func drFault(err error) model.Code {
	var f *model.Fault
	if errors.As(err, &f) {
		return f.Code
	}
	return ""
}

type drSite struct {
	env   *Env
	app   *appcore.App
	dir   string
	owner auth.Session
	actor auth.Credential
	// recovery is the one-time recovery administrator of a restored installation
	recovery auth.Credential
	org      model.ID
}

// drOpenSite opens the real application (replicated storage, control, auth, ingest, retention
// worker) in an approved directory and bootstraps its owner and one organization.
func drOpenSite(env *Env, name string) (*drSite, error) {
	dir := filepath.Join(env.Work, name)
	if err := env.Approve([]string{dir}, nil); err != nil {
		return nil, err
	}
	app, err := appcore.Open(dir)
	if err != nil {
		return nil, err
	}
	s := &drSite{env: env, app: app, dir: dir, org: model.NewID()}
	boot, err := app.Control.BootstrapToken()
	if err == nil {
		s.owner, err = app.Auth.Bootstrap(env.Ctx, boot, drOwnerEmail, drOwnerPassword)
	}
	if err == nil {
		s.actor, err = app.Auth.Authenticate(env.Ctx, s.owner.Token)
	}
	if err == nil {
		err = s.command("create_org", auth.AdminPayload{Name: "delete restore drill"})
	}
	if err == nil {
		err = s.command("membership", auth.AdminPayload{UserID: s.owner.User, Enabled: true})
	}
	if err != nil {
		app.Close()
		return nil, err
	}
	return s, nil
}

func (s *drSite) close() { s.app.Close() }

// command submits one admin command, re-reading the control revision on a conflict (admission
// reservations move the revision while intake runs; a refused command committed nothing).
func (s *drSite) command(kind string, p auth.AdminPayload) error {
	p.Reason = "delete restore drill"
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	for range 50 {
		var revision model.Revision
		if err = s.app.Control.View(s.env.Ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
			return err
		}
		if _, err = s.app.Auth.AdminCommand(s.env.Ctx, s.actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: s.org, Kind: kind, Payload: raw}); drFault(err) != model.Conflict {
			return err
		}
	}
	return err
}

// fresh logs the owner in again: policy changes need a fresh credential.
func (s *drSite) fresh() (auth.Credential, error) {
	session, err := s.app.Auth.Login(s.env.Ctx, drOwnerEmail, drOwnerPassword, "")
	if err != nil {
		return auth.Credential{}, err
	}
	return s.app.Auth.Authenticate(s.env.Ctx, session.Token)
}

func (s *drSite) adminScope() (auth.Scope, error) {
	return s.app.Auth.Authorize(s.env.Ctx, s.actor, s.org, nil, auth.OrgAdmin)
}

func (s *drSite) readScope(project model.ID) (auth.Scope, error) {
	return s.app.Auth.Authorize(s.env.Ctx, s.actor, s.org, []model.ID{project}, auth.Read)
}

func (s *drSite) revision() (model.Revision, error) {
	var r model.Revision
	err := s.app.Control.View(s.env.Ctx, func(st model.ControlState) error { r = st.Revision; return nil })
	return r, err
}

// drProject is a project with one structured source whose policy revision starts at 1.
type drProject struct {
	id, source model.ID
	raw        string // the source secret; never written to a report
	cred       auth.SourceCredential
	resource   model.Resource
	policy     model.SourcePolicy
}

func (s *drSite) addProject(name string, kinds []model.Kind, days map[model.Kind]uint32) (*drProject, error) {
	p := &drProject{id: model.NewID(), source: model.NewID()}
	if err := s.command("create_project", auth.AdminPayload{ID: p.id, Name: name}); err != nil {
		return nil, err
	}
	if err := s.command("grant", auth.AdminPayload{UserID: s.owner.User, ProjectID: p.id, Enabled: true, Permissions: []string{string(auth.Read), string(auth.PolicyWrite)}}); err != nil {
		return nil, err
	}
	service, environment, build := model.NewID(), model.NewID(), model.NewID()
	p.resource = model.Resource{Service: service, Environment: environment, Build: build, Instance: "drill-instance", Labels: model.Labels{}}
	p.policy = model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: kinds, Resources: model.ResourceRegistry{Services: []model.ID{service}, Environments: []model.ID{environment}, Builds: []model.ID{build}, Instances: []string{"drill-instance"}}, RetentionDays: days, MaxBytes: 1 << 30, MaxSeries: 100000}
	issued, err := s.app.Auth.OnboardSource(s.env.Ctx, s.actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: s.org, Project: p.id, Source: p.source, Expires: model.UnixNano(time.Now().Add(48 * time.Hour).UnixNano()), Policy: p.policy, Reason: "delete restore drill"})
	if err != nil {
		return nil, err
	}
	p.raw = issued.Credential
	p.cred, err = s.app.Auth.AuthenticateSource(s.env.Ctx, p.raw, "", false)
	return p, err
}

// metric builds a one-record batch under policy `rev`. The route slot of a metric follows its
// series identity, so slot >= 0 searches name suffixes until the series hashes to that slot
// (every one of the 64 data groups can be targeted deterministically).
func (p *drProject) metric(org model.ID, rev model.Revision, at int64, base string, value uint64, slot int) (model.Batch, model.Record, error) {
	v := model.FloatBits(math.Float64bits(float64(value)))
	for k := 0; k < 100000; k++ {
		name := fmt.Sprintf("%s_%d", base, k)
		rec := model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(at), Resource: p.resource, Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: &v, Unit: "1", Type: "counter"}}}
		got, err := model.OwnerSlot(org, p.id, p.source, model.ID{}, rec)
		if err != nil {
			return model.Batch{}, model.Record{}, err
		}
		if slot >= 0 && int(got) != slot {
			continue
		}
		b := model.Batch{Version: 1, Project: p.id, Source: p.source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: rev, RouteSlot: got, Records: []model.Record{rec}}
		return b, rec, nil
	}
	return model.Batch{}, model.Record{}, fmt.Errorf("no series name hashes to slot %d", slot)
}

// send admits one batch through the real ingest pipeline (source resolution against the policy
// revision, normalization, admission reservation, replicated append, finalize, revalidation).
func (s *drSite) send(p *drProject, b model.Batch) (model.Receipt, error) {
	g, err := s.app.Ingest.ResolveSource(s.env.Ctx, p.cred, b)
	if err != nil {
		return model.Receipt{}, err
	}
	return s.app.Ingest.Admit(s.env.Ctx, g, b)
}

func (s *drSite) lookup(p *drProject, b model.Batch, r model.Receipt) (model.Receipt, error) {
	return s.app.Ingest.LookupReceipt(s.env.Ctx, p.cred, model.ReceiptRequest{Source: b.Source, Producer: b.Producer, RouteSlot: b.RouteSlot, BatchID: b.ID, OriginalHash: r.Hash})
}

// lookupBatch asks for the receipt of a batch by identity and content hash, as a sender that did
// not see its ACK does.
func (s *drSite) lookupBatch(p *drProject, b model.Batch) (model.Receipt, error) {
	raw, err := model.CanonicalJSON(b)
	if err != nil {
		return model.Receipt{}, err
	}
	return s.lookup(p, b, model.Receipt{Hash: model.HashCanonical(raw)})
}

// drSameReceipt compares the historical fact of an ACK; the Historical marker only says how the
// lookup was authorized, not what was acknowledged.
func drSameReceipt(a, b model.Receipt) bool {
	a.Historical, b.Historical = false, false
	x, err1 := model.CanonicalJSON(a)
	y, err2 := model.CanonicalJSON(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

// drScanned is one row read back from the engine.
type drScanned struct {
	Digest string
	Origin model.Cursor
}

// drScan reads every row of (project, kind) through an authorized scope and digests its exact
// semantic content. Rows are keyed by record ID.
func drScan(ctx context.Context, eng *storage.Engine, scope auth.Scope, project model.ID, kind model.Kind) (map[model.ID]drScanned, error) {
	it, err := eng.Scan(ctx, scope, storage.ScanRequest{Projects: []model.ID{project}, Signal: kind, End: model.UnixNano(math.MaxInt64)})
	if err != nil {
		return nil, err
	}
	defer it.Close()
	out := map[model.ID]drScanned{}
	for {
		page, err := it.Next(ctx)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		for i := 0; i < page.Len(); i++ {
			out[page.IDs[i]] = drScanned{Digest: drPageRowDigest(page.Projects[i], page.Sources[i], page.IDs[i], kind, page.ObservedTimes[i], page.Resources[i], page.Values[i]), Origin: page.Origins[i]}
		}
	}
}

// ---- ACK bookkeeping shared by the scenarios ----

// drLedgers separates what must be retained (outside every tombstone; recorded in the report's
// ACK ledger and reconciled exactly) from what was acknowledged and then legitimately deleted
// (recorded in a second ledger and asserted ABSENT). Both are acknowledged writes.
type drLedgers struct {
	mu    sync.Mutex
	rep   *Report
	pred  model.DeletePredicate // the deletion's predicate (Operation is not needed to evaluate coverage)
	keep  []drAcked
	gone  []drAcked
	gone2 *Ledger
	byRec map[model.ID]string
	rcpt  map[string]model.Receipt
	batch map[string]model.Batch
	proj  map[string]*drProject
	sends []drSend
	tried map[model.ID]string // record -> the unacknowledged send that carried it
}

func newDrLedgers(rep *Report, pred model.DeletePredicate) *drLedgers {
	return &drLedgers{rep: rep, pred: pred, gone2: &Ledger{}, byRec: map[model.ID]string{}, rcpt: map[string]model.Receipt{}, batch: map[string]model.Batch{}, proj: map[string]*drProject{}, tried: map[model.ID]string{}}
}

// ack records one acknowledged batch on the right side of the predicate.
func (l *drLedgers) ack(label string, org model.ID, p *drProject, b model.Batch, rec model.Record, r model.Receipt) error {
	a := drAcked{ID: b.ID.String(), Org: org, Project: p.id, Record: rec, Cursor: r.Cursor, Digest: drRecordDigest(p.id, p.source, rec), Label: label}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.byRec[rec.ID] = a.ID
	l.rcpt[a.ID] = r
	l.batch[a.ID] = b
	l.proj[a.ID] = p
	entry := Ack{ID: a.ID, Group: r.Cursor.Group.String(), Index: uint64(r.Cursor.Index), Digest: a.Digest, Label: label}
	if l.pred.CoversRecord(org, p.id, rec) {
		l.gone = append(l.gone, a)
		return l.gone2.Record(entry)
	}
	l.keep = append(l.keep, a)
	return l.rep.Ledger().Record(entry)
}

// attempt records a send that was not acknowledged.
func (l *drLedgers) attempt(b model.Batch, label string, code model.Code, stale bool) {
	l.rep.Ledger().Attempted(Attempt{ID: b.ID.String(), Outcome: "refused:" + string(code), Detail: label})
	l.mu.Lock()
	l.sends = append(l.sends, drSend{Label: label, Batch: b.ID.String(), Built: uint64(b.PolicyRevision), Stale: stale, Fault: code})
	if len(b.Records) > 0 {
		l.tried[b.Records[0].ID] = fmt.Sprintf("%s (fault %q, stale=%v, built under revision %d)", label, code, stale, b.PolicyRevision)
	}
	l.mu.Unlock()
}

// describe names the unacknowledged send a retained "unknown-record:<id>" key came from.
func (l *drLedgers) describe(key string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	id, ok := strings.CutPrefix(key, "unknown-record:")
	if !ok {
		return key
	}
	rec, err := model.ParseID(id)
	if err != nil {
		return key
	}
	if d, ok := l.tried[rec]; ok {
		return key + " <- " + d
	}
	return key + " <- no recorded send"
}

func (l *drLedgers) acked(b model.Batch, label string, stale bool) {
	l.mu.Lock()
	l.sends = append(l.sends, drSend{Label: label, Batch: b.ID.String(), Built: uint64(b.PolicyRevision), Stale: stale, Acked: true})
	l.mu.Unlock()
}

// retained maps every row read back to its batch ID; a row whose record was never acknowledged
// keeps an "unknown-record:" key so the exact reconciliation reports it.
func (l *drLedgers) retained(rows map[model.ID]drScanned, into map[string]string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for rec, row := range rows {
		if id, ok := l.byRec[rec]; ok {
			into[id] = row.Digest
		} else {
			into["unknown-record:"+rec.String()] = row.Digest
		}
	}
}

func (l *drLedgers) ackedFacts(list []drAcked) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for _, a := range list {
		out = append(out, map[string]any{"id": a.ID, "label": a.Label, "cursor_group": a.Cursor.Group.String(), "cursor_index": uint64(a.Cursor.Index), "semantic_digest": a.Digest})
	}
	return out
}

func drParseProgress(s string) int {
	n, _, _ := strings.Cut(s, "/")
	v, _ := strconv.Atoi(n)
	return v
}

func drSample(seq int, r retention.DeleteReceipt) drFenceSample {
	return drFenceSample{Seq: seq, Phase: r.Phase, Generation: r.Generation, Revision: uint64(r.Revision), Barriers: drParseProgress(r.Progress), Physical: r.Physical}
}

func drPolicyDigest(p model.SourcePolicy) string {
	raw, err := model.CanonicalJSON(p)
	if err != nil {
		return ""
	}
	return model.HashCanonical(raw).String()
}

// ---- scenario 1: stale policy revision against the all-shard delete barrier ----

type drRaceCounters struct{ legit, inrange, staleFresh, staleReplay, cached atomic.Int64 }

func (c *drRaceCounters) snapshot() map[string]int64 {
	return map[string]int64{"legit_writers": c.legit.Load(), "in_range_writers": c.inrange.Load(), "stale_fresh_senders": c.staleFresh.Load(), "stale_replay_senders": c.staleReplay.Load(), "cached_policy_workers": c.cached.Load()}
}

// drStalePolicyDeleteBarrier races, on one real installation: ingest under policy revisions that
// change underneath it, workers holding stale revisions (fresh batches, replays of ACKed
// batches, a cached-policy worker) and an all-shard deletion barrier. After the barrier it
// proves no stale send was acknowledged or remapped, the deleted range is gone from every shard
// (logically and physically), every ACKed batch outside the predicate is retained with exactly
// the acknowledged content, and the receipt/fence evidence is monotone and complete.
func drStalePolicyDeleteBarrier(env *Env, rep *Report) error {
	ctx := env.Ctx
	s, err := drOpenSite(env, "site")
	if err != nil {
		return err
	}
	defer s.close()
	kinds, days := []model.Kind{model.Metric}, map[model.Kind]uint32{model.Metric: 30}
	doom, err := s.addProject("doomed", kinds, days)
	if err != nil {
		return err
	}
	sib, err := s.addProject("sibling", kinds, days)
	if err != nil {
		return err
	}
	const lo, hi = 1000, 2000
	pred := model.DeletePredicate{Org: s.org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{doom.id}, Signals: []model.Kind{model.Metric}, Start: lo, End: hi}
	led := newDrLedgers(rep, pred)
	nonce := strings.ReplaceAll(model.NewID().String(), "-", "")[:12]
	doomedName, keptName, inrangeName, refusedName := "drill_doomed_"+nonce, "drill_kept_"+nonce, "drill_inrange_"+nonce, "drill_refused_"+nonce
	var curRev atomic.Uint64
	curRev.Store(1)

	put := func(label string, p *drProject, rev model.Revision, at int64, base string, slot int) error {
		b, rec, err := p.metric(s.org, rev, at, base, uint64(at), slot)
		if err != nil {
			return err
		}
		r, err := s.send(p, b)
		if err != nil {
			led.attempt(b, label, drFault(err), false)
			return fmt.Errorf("%s: %w", label, err)
		}
		led.acked(b, label, false)
		return led.ack(label, s.org, p, b, rec, r)
	}

	// ---- 1. ACKed batches under policy revision 1, one per data group in each class ----
	for slot := range drSlots {
		if err = put("seed in-range (will be deleted)", doom, 1, lo+int64(slot), doomedName, slot); err != nil {
			return err
		}
		if err = put("seed outside the range, same project", doom, 1, 5000+int64(slot), keptName, slot); err != nil {
			return err
		}
		if err = put("seed sibling project, same time range", sib, 1, lo+int64(slot), keptName, slot); err != nil {
			return err
		}
	}
	if err = s.app.Storage.Flush(ctx); err != nil {
		return err
	}
	needles := []drNeedle{{"doomed_prefix", []byte(doomedName)}, {"kept_prefix", []byte(keptName)}}
	before, err := drStoreHits(s.dir, needles)
	if err != nil {
		return err
	}
	if err = rep.Require("physical_positive_control", drHitTotal(before, "doomed_prefix") > 0 && drHitTotal(before, "kept_prefix") > 0,
		fmt.Sprintf("before the deletion the scanner finds the doomed canary in %v and the kept canary in %v", drHitStores(before, "doomed_prefix"), drHitStores(before, "kept_prefix"))); err != nil {
		return err
	}
	seeded := len(led.gone) + len(led.keep)
	rep.Fact("seed_acks", map[string]int{"total": seeded, "inside_predicate": len(led.gone), "outside_predicate": len(led.keep), "data_groups": len(drDistinctGroups(led.gone))})

	// ---- 2. advance the policy 1 -> 2 (a fenced change across every data group) ----
	var timeline []drPolicyStep
	var timelineFacts []map[string]any
	var timelineMu sync.Mutex
	advance := func(rev model.Revision) error {
		cred, err := s.fresh()
		if err != nil {
			return err
		}
		var cur model.SourceAuthority
		if err = s.app.Control.View(ctx, func(st model.ControlState) error { cur = st.Sources[doom.source.String()]; return nil }); err != nil {
			return err
		}
		next := cur.Policy
		next.Revision = rev
		next.MaxBytes = cur.Policy.MaxBytes - 1
		op, err := s.app.Auth.ChangeSourcePolicy(ctx, cred, auth.SourcePolicyChange{CommandID: model.NewID(), Source: doom.source, ExpectedRevision: rev - 1, Policy: next, Reason: "delete restore drill policy advance"})
		if err != nil {
			return fmt.Errorf("policy %d: %w", rev, err)
		}
		if err = s.app.Auth.DrainSourceFences(ctx); err != nil {
			return fmt.Errorf("policy %d fence: %w", rev, err)
		}
		done, err := s.app.Auth.SourceOperation(ctx, cred, op.Operation)
		if err != nil {
			return err
		}
		var controlRev model.Revision
		var after model.SourceAuthority
		if err = s.app.Control.View(ctx, func(st model.ControlState) error {
			controlRev = st.Revision
			after = st.Sources[doom.source.String()]
			return nil
		}); err != nil {
			return err
		}
		if err = drVerifyBarrierCoverage(done.Barriers, drSlots); err != nil {
			return fmt.Errorf("policy %d fence: %w", rev, err)
		}
		if after.Policy.Revision != rev || after.Closing {
			return fmt.Errorf("policy %d: control reports revision %d closing=%v", rev, after.Policy.Revision, after.Closing)
		}
		step := drPolicyStep{Revision: uint64(rev), Phase: done.Phase, Barriers: len(done.Barriers), ControlRev: uint64(controlRev), Digest: drPolicyDigest(after.Policy)}
		timelineMu.Lock()
		timeline = append(timeline, step)
		timelineFacts = append(timelineFacts, map[string]any{"revision": step.Revision, "fence_operation": op.Operation.String(), "phase": step.Phase, "barriers": step.Barriers, "control_revision": step.ControlRev, "policy_digest": step.Digest, "at": time.Now().UTC().Format(time.RFC3339Nano)})
		timelineMu.Unlock()
		curRev.Store(uint64(rev))
		return nil
	}
	if err = advance(2); err != nil {
		return err
	}
	srcDigest := func() (string, error) {
		var d string
		err := s.app.Control.View(ctx, func(st model.ControlState) error {
			d = drPolicyDigest(st.Sources[doom.source.String()].Policy)
			return nil
		})
		return d, err
	}
	digestAt2, err := srcDigest()
	if err != nil {
		return err
	}

	// ---- 3. a burst of stale sends against revision 2: replays of every ACKed revision-1 batch
	// and fresh revision-1 batches. None may be acknowledged, remapped or change the source. ----
	var replays []model.Batch
	led.mu.Lock()
	for _, a := range append(append([]drAcked{}, led.keep...), led.gone...) {
		if led.proj[a.ID] == doom {
			replays = append(replays, led.batch[a.ID])
		}
	}
	led.mu.Unlock()
	burst := 0
	for _, b := range replays {
		_, err := s.send(doom, b)
		burst++
		if err == nil {
			led.acked(b, "pre-race replay of an ACKed revision-1 batch", true)
		} else {
			led.attempt(b, "pre-race replay of an ACKed revision-1 batch", drFault(err), true)
		}
	}
	for i := range 32 {
		b, _, err := doom.metric(s.org, 1, 9000+int64(i), refusedName, 1, -1)
		if err != nil {
			return err
		}
		_, err = s.send(doom, b)
		burst++
		if err == nil {
			led.acked(b, "pre-race fresh revision-1 batch", true)
		} else {
			led.attempt(b, "pre-race fresh revision-1 batch", drFault(err), true)
		}
	}
	digestAfterBurst, err := srcDigest()
	if err != nil {
		return err
	}
	if err = rep.Require("no_source_state_remap_by_stale_sends", digestAt2 == digestAfterBurst && digestAt2 != "", fmt.Sprintf("source policy digest %s before and %s after %d stale sends", digestAt2, digestAfterBurst, burst)); err != nil {
		return err
	}

	// ---- 4. the race: writers of every kind run while the delete barrier AND a second policy
	// fence (2 -> 3) are driven across the same 64 data groups ----
	var (
		stop  atomic.Bool
		wg    sync.WaitGroup
		count drRaceCounters
		seq   atomic.Int64
		fatal atomic.Value
	)
	fail := func(err error) {
		if err != nil {
			fatal.CompareAndSwap(nil, err)
		}
	}
	var recovered atomic.Int64
	record := func(label string, p *drProject, b model.Batch, rec model.Record, r model.Receipt, err error, stale bool) {
		if err == nil {
			led.acked(b, label, stale)
			fail(led.ack(label, s.org, p, b, rec, r))
			return
		}
		code := drFault(err)
		if !stale && code != model.Conflict {
			// A refusal that is not a permanent one may have come AFTER the append (the control
			// finalize or the closing source's final revalidation fails once the data is durable).
			// The sender's protocol is to look the batch up by identity: a receipt found is the
			// ACK it would have received and the row it names is an acknowledged row.
			if got, lerr := s.lookupBatch(p, b); lerr == nil {
				recovered.Add(1)
				led.acked(b, label+" (receipt found by lookup after a "+string(code)+" refusal)", false)
				fail(led.ack(label+" (receipt found by lookup after a "+string(code)+" refusal)", s.org, p, b, rec, got))
				return
			}
		}
		led.attempt(b, label, code, stale)
	}
	spawn := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}
	// Writers hold the read side of the gate around every send. The deletion's Begin is an
	// optimistic control commit keyed on the control revision, which intake advances on every
	// admission: under full intake it can starve. Begin is therefore tried under full load first
	// (the conflict count is reported) and then under a short write lock that only pauses NEW
	// sends for the duration of that single commit; the barriers, the policy fence and the
	// apply-time rejection all still run under full concurrent load.
	var gate sync.RWMutex
	gsend := func(p *drProject, b model.Batch) (model.Receipt, error) {
		gate.RLock()
		defer gate.RUnlock()
		return s.send(p, b)
	}
	// legitimate writers: the sibling project and the doomed project OUTSIDE the range
	spawn(func() {
		for i := 0; i < 600 && !stop.Load(); i++ {
			p, rev, at := sib, model.Revision(1), lo+seq.Add(1)
			if i%2 == 1 {
				p, rev, at = doom, model.Revision(curRev.Load()), 6000+seq.Add(1)
			}
			b, rec, err := p.metric(s.org, rev, at, fmt.Sprintf("%s_w%d", keptName, seq.Add(1)), uint64(at), -1)
			if err != nil {
				fail(err)
				return
			}
			r, err := gsend(p, b)
			record("race: legitimate writer outside the predicate", p, b, rec, r, err, false)
			count.legit.Add(1)
			time.Sleep(5 * time.Millisecond)
		}
	})
	// in-range writers: inside the predicate until the barrier, refused after it
	spawn(func() {
		for i := 0; i < 600 && !stop.Load(); i++ {
			at := lo + seq.Add(1)%(hi-lo)
			b, rec, err := doom.metric(s.org, model.Revision(curRev.Load()), at, fmt.Sprintf("%s_%d", inrangeName, seq.Add(1)), uint64(at), -1)
			if err != nil {
				fail(err)
				return
			}
			r, err := gsend(doom, b)
			record("race: in-range writer", doom, b, rec, r, err, false)
			count.inrange.Add(1)
			time.Sleep(5 * time.Millisecond)
		}
	})
	// stale senders: fresh revision-1 batches, replays of ACKed batches, and a worker that cached
	// revision 2 and keeps sending it after revision 3 took over
	staleLoop := func(counter *atomic.Int64, f func(i int) (model.Batch, model.Record, bool)) {
		for i := 0; i < 300 && !(i >= 60 && stop.Load()); i++ {
			b, rec, stale := f(i)
			r, err := gsend(doom, b)
			record("race: stale sender", doom, b, rec, r, err, stale)
			counter.Add(1)
			time.Sleep(8 * time.Millisecond)
		}
	}
	spawn(func() {
		staleLoop(&count.staleFresh, func(i int) (model.Batch, model.Record, bool) {
			b, rec, err := doom.metric(s.org, 1, 9000+seq.Add(1), refusedName, 1, -1)
			fail(err)
			return b, rec, true
		})
	})
	spawn(func() {
		staleLoop(&count.staleReplay, func(i int) (model.Batch, model.Record, bool) {
			b := replays[i%len(replays)]
			return b, b.Records[0], true
		})
	})
	spawn(func() {
		cached := curRev.Load()
		staleLoop(&count.cached, func(i int) (model.Batch, model.Record, bool) {
			stale := curRev.Load() > cached
			b, rec, err := doom.metric(s.org, model.Revision(cached), 7000+seq.Add(1), keptName+"_cached", 1, -1)
			fail(err)
			return b, rec, stale
		})
	})
	for deadline := time.Now().Add(time.Minute); count.legit.Load() < 5 || count.inrange.Load() < 5 || count.staleFresh.Load() < 5 || count.cached.Load() < 5; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			stop.Store(true)
			wg.Wait()
			return errors.New("the racing writers did not start")
		}
	}
	atBegin := count.snapshot()

	// begin the deletion (a revision conflict means intake moved the control revision: re-read)
	beginOnce := func(gated bool) (retention.DeleteReceipt, error) {
		if gated {
			gate.Lock()
			defer gate.Unlock()
		}
		scope, err := s.adminScope()
		if err != nil {
			return retention.DeleteReceipt{}, err
		}
		rev, err := s.revision()
		if err != nil {
			return retention.DeleteReceipt{}, err
		}
		return s.app.Retention.Delete(ctx, scope, retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: rev, Mode: pred.Mode, OrgID: s.org, ProjectIDs: pred.Projects, Signals: pred.Signals, Start: pred.Start, End: pred.End, Reason: "delete restore drill: all-shard barrier race"})
	}
	var receipt retention.DeleteReceipt
	beginConflicts := 0
	for attempt := 0; attempt < 400; attempt++ {
		r, err := beginOnce(attempt >= 60)
		if drFault(err) == model.Conflict {
			beginConflicts++
			continue
		}
		if err != nil {
			stop.Store(true)
			wg.Wait()
			return err
		}
		receipt = r
		break
	}
	rep.Fact("delete_begin", map[string]any{"conflicts_before_begin_committed": beginConflicts, "attempts_under_full_intake_before_the_gate": 60})
	if receipt.OperationID == (model.ID{}) {
		stop.Store(true)
		wg.Wait()
		return errors.New("the deletion could not begin")
	}
	var (
		samples  = []drFenceSample{drSample(1, receipt)}
		sampleMu sync.Mutex
	)
	// sample polls the receipt and appends the observation under one lock, so the samples are in
	// the order they were observed (the fence verifier compares neighbours).
	sample := func() (retention.DeleteReceipt, error) {
		sampleMu.Lock()
		defer sampleMu.Unlock()
		scope, err := s.adminScope()
		if err != nil {
			return retention.DeleteReceipt{}, err
		}
		r, err := s.app.Retention.PollDelete(ctx, scope, receipt.OperationID)
		if err == nil {
			samples = append(samples, drSample(len(samples)+1, r))
		}
		return r, err
	}
	pollStop, pollDone := make(chan struct{}), make(chan struct{})
	go func() { // watches the fence while the worker drives it
		defer close(pollDone)
		for {
			select {
			case <-pollStop:
				return
			case <-time.After(2 * time.Millisecond):
				_, _ = sample()
			}
		}
	}()
	stopPoller := func() { close(pollStop); <-pollDone }
	policy3 := make(chan error, 1)
	go func() { policy3 <- advance(3) }()
	var runErrs int
	var done retention.DeleteReceipt
	for deadline := time.Now().Add(5 * time.Minute); ; time.Sleep(25 * time.Millisecond) {
		if err = s.app.Retention.RunOnce(ctx); err != nil {
			runErrs++
		}
		r, err := sample()
		if err != nil {
			stopPoller()
			stop.Store(true)
			wg.Wait()
			return err
		}
		if r.Phase == model.DeletePhaseComplete && r.Physical == retention.PhysicalDone {
			done = r
			break
		}
		if time.Now().After(deadline) {
			stopPoller()
			stop.Store(true)
			wg.Wait()
			return fmt.Errorf("the deletion did not finish: phase %s progress %s physical %s", r.Phase, r.Progress, r.Physical)
		}
	}
	stopPoller()
	if err = <-policy3; err != nil {
		stop.Store(true)
		wg.Wait()
		return err
	}
	atEnd := count.snapshot()
	stop.Store(true)
	wg.Wait()
	if v := fatal.Load(); v != nil {
		return v.(error)
	}
	concurrent := map[string]int64{}
	for k, v := range atEnd {
		concurrent[k] = v - atBegin[k]
	}
	rep.Fact("writers_running_during_barrier", concurrent)
	for k, v := range concurrent {
		if err = rep.Require("race_overlapped_"+k, v > 0, fmt.Sprintf("%d sends of this kind were made between the delete begin and its completion", v)); err != nil {
			return err
		}
	}

	// ---- 5. after the barrier: every data group refuses the range and keeps accepting the rest ----
	finalRev := model.Revision(curRev.Load())
	refusedCodes := map[string]int{}
	var lateAcked []string
	for slot := range drSlots {
		b, rec, err := doom.metric(s.org, finalRev, lo+500+int64(slot), refusedName+"_late", 1, slot)
		if err != nil {
			return err
		}
		r, err := s.send(doom, b)
		if err == nil {
			lateAcked = append(lateAcked, b.ID.String())
			record("after the barrier: in-range write", doom, b, rec, r, nil, false)
			continue
		}
		refusedCodes[string(drFault(err))]++
		led.attempt(b, "after the barrier: in-range write", drFault(err), false)
	}
	if err = rep.Require("barrier_refuses_the_range_in_every_slot", len(lateAcked) == 0 && refusedCodes[""] == 0 && len(refusedCodes) > 0, fmt.Sprintf("64 in-range writes, one per data group, after the barrier: refused with %v, acknowledged %d", refusedCodes, len(lateAcked))); err != nil {
		return err
	}
	for slot := range drSlots {
		if err = put("after the barrier: outside the range", doom, finalRev, 8000+int64(slot), keptName+"_after", slot); err != nil {
			return fmt.Errorf("data outside the predicate stopped flowing in slot %d: %w", slot, err)
		}
	}
	if err = rep.Require("data_outside_the_predicate_keeps_flowing", true, "64 writes outside the range, one per data group, were acknowledged after the barrier"); err != nil {
		return err
	}

	// ---- 6. fences, policy timeline, stale sends ----
	var op model.DeletionOperation
	var final model.SourceAuthority
	if err = s.app.Control.View(ctx, func(st model.ControlState) error {
		op = st.Deletions[receipt.OperationID.String()]
		final = st.Sources[doom.source.String()]
		return nil
	}); err != nil {
		return err
	}
	if err = rep.Require("delete_fence_monotone_and_complete", drVerifyFence(samples, drSlots) == nil, fmt.Sprintf("%d receipt samples; %v", len(samples), drVerifyFence(samples, drSlots))); err != nil {
		return err
	}
	if err = rep.Require("delete_barrier_in_every_data_group", drVerifyBarrierCoverage(op.Barriers, drSlots) == nil, fmt.Sprintf("%d recorded barrier cursors; %v", len(op.Barriers), drVerifyBarrierCoverage(op.Barriers, drSlots))); err != nil {
		return err
	}
	seedGroups := map[model.ID]bool{}
	for _, g := range drDistinctGroups(led.gone) {
		seedGroups[g] = true
	}
	barrierGroups := map[model.ID]bool{}
	for _, c := range op.Barriers {
		barrierGroups[c.Group] = true
	}
	sameGroups := len(seedGroups) == drSlots && len(barrierGroups) == drSlots
	for g := range seedGroups {
		sameGroups = sameGroups && barrierGroups[g]
	}
	if err = rep.Require("barrier_groups_are_the_groups_that_served_the_acks", sameGroups, "the 64 groups that acknowledged the seeded in-range batches are exactly the 64 groups with a recorded barrier"); err != nil {
		return err
	}
	timelineMu.Lock()
	steps := append([]drPolicyStep(nil), timeline...)
	timelineMu.Unlock()
	if err = rep.Require("policy_timeline_consecutive_and_fenced", drVerifyPolicyTimeline(steps, drSlots) == nil && len(steps) == 2, fmt.Sprintf("%d policy changes; %v", len(steps), drVerifyPolicyTimeline(steps, drSlots))); err != nil {
		return err
	}
	if err = rep.Require("source_policy_is_the_last_advance", final.Policy.Revision == 3 && !final.Closing && drPolicyDigest(final.Policy) == steps[len(steps)-1].Digest, fmt.Sprintf("control source policy revision %d, closing %v: nothing remapped it after the last fenced change", final.Policy.Revision, final.Closing)); err != nil {
		return err
	}
	// a policy CHANGE built against a stale revision is a stale control command: it is refused,
	// not merged into the current policy
	staleNext := final.Policy
	staleNext.Revision = 2
	staleNext.MaxBytes = final.Policy.MaxBytes + 1000
	staleCred, err := s.fresh()
	if err != nil {
		return err
	}
	_, staleErr := s.app.Auth.ChangeSourcePolicy(ctx, staleCred, auth.SourcePolicyChange{CommandID: model.NewID(), Source: doom.source, ExpectedRevision: 1, Policy: staleNext, Reason: "delete restore drill: stale policy command"})
	var afterStale model.SourceAuthority
	if err = s.app.Control.View(ctx, func(st model.ControlState) error { afterStale = st.Sources[doom.source.String()]; return nil }); err != nil {
		return err
	}
	if err = rep.Require("stale_policy_command_refused_not_merged", drFault(staleErr) == model.Conflict && drPolicyDigest(afterStale.Policy) == drPolicyDigest(final.Policy) && afterStale.Policy.Revision == 3 && !afterStale.Closing,
		fmt.Sprintf("a policy change expecting revision 1 while revision 3 is in force was refused with %q; the source policy digest and revision are unchanged", drFault(staleErr))); err != nil {
		return err
	}
	led.mu.Lock()
	sends := append([]drSend(nil), led.sends...)
	led.mu.Unlock()
	staleCount, staleCodes := 0, map[string]int{}
	for _, o := range sends {
		if o.Stale {
			staleCount++
			staleCodes[string(o.Fault)]++
		}
	}
	if err = rep.Require("stale_sends_never_acknowledged_always_typed_stale", drVerifyStaleSends(sends, 100) == nil, fmt.Sprintf("%d stale sends, refusal codes %v; %v", staleCount, staleCodes, drVerifyStaleSends(sends, 100))); err != nil {
		return err
	}

	// ---- 7. exact reconciliation against what the system retains ----
	retained := map[string]string{}
	for _, p := range []*drProject{doom, sib} {
		scope, err := s.readScope(p.id)
		if err != nil {
			return err
		}
		rows, err := drScan(ctx, s.app.Storage, scope, p.id, model.Metric)
		if err != nil {
			return err
		}
		led.retained(rows, retained)
	}
	if err = rep.Reconcile(retained); err != nil {
		return err
	}
	var unackedWhy []string
	for _, id := range rep.Reconciliation.UnackedRetained {
		unackedWhy = append(unackedWhy, led.describe(id))
	}
	if err = rep.Require("no_unacknowledged_row_retained", len(rep.Reconciliation.UnackedRetained) == 0, fmt.Sprintf("%d retained rows were never acknowledged or recovered by receipt lookup (a stale or refused send that left a row would show here) %v", len(rep.Reconciliation.UnackedRetained), unackedWhy)); err != nil {
		return err
	}
	var rows []drRow
	led.mu.Lock()
	for id := range retained {
		if b, ok := led.batch[id]; ok {
			rows = append(rows, drRow{BatchID: id, Org: s.org, Project: b.Project, Record: b.Records[0]})
		}
	}
	gone := append([]drAcked(nil), led.gone...)
	keep := append([]drAcked(nil), led.keep...)
	led.mu.Unlock()
	resurrected := drDetectResurrection(rows, []model.DeletePredicate{op.Predicate})
	stillThere := 0
	for _, a := range gone {
		if _, ok := retained[a.ID]; ok {
			stillThere++
		}
	}
	if err = rep.Require("deleted_data_gone_from_every_shard", len(resurrected) == 0 && stillThere == 0, fmt.Sprintf("%d acknowledged in-range batches across %d data groups; %d still readable, %d resurrected", len(gone), len(drDistinctGroups(gone)), stillThere, len(resurrected))); err != nil {
		return err
	}
	if err = rep.Require("tombstone_is_the_requested_predicate", op.Predicate.Mode == pred.Mode && op.Predicate.Start == pred.Start && op.Predicate.End == pred.End && len(op.Predicate.Projects) == 1 && op.Predicate.Projects[0] == doom.id, "the recorded tombstone is the predicate every ACK was classified against"); err != nil {
		return err
	}

	// ---- 8. an ACK issued before the delete still shows its status afterwards ----
	identical, deletedIdentical := 0, 0
	for _, group := range [][]drAcked{keep, gone} {
		for _, a := range group {
			got, err := s.lookup(led.proj[a.ID], led.batch[a.ID], led.rcpt[a.ID])
			if err != nil || !drSameReceipt(got, led.rcpt[a.ID]) {
				return rep.Require("ack_status_after_delete", false, fmt.Sprintf("batch %s: receipt lookup after the deletion returned %v / %v", a.ID, got.Cursor, err))
			}
			identical++
			if led.pred.CoversRecord(a.Org, a.Project, a.Record) {
				deletedIdentical++
			}
		}
	}
	if err = rep.Require("ack_status_after_delete", true, fmt.Sprintf("%d receipt lookups after the deletion returned the original receipt byte for byte (%d of them for deleted batches: an ACK is a historical fact, the rows are what the deletion removed)", identical, deletedIdentical)); err != nil {
		return err
	}

	// ---- 9. physical: the deleted bytes are gone from every store, the kept bytes are not ----
	acked := []drNeedle{}
	for _, a := range gone {
		if m := a.Record.Payload.Metric; m != nil {
			acked = append(acked, drNeedle{Label: "acked_deleted:" + a.ID, Bytes: []byte(m.Name)})
		}
	}
	after, err := drStoreHits(s.dir, append([]drNeedle{{"doomed_prefix", []byte(doomedName)}, {"kept_prefix", []byte(keptName)}, {"refused_in_range", []byte(inrangeName)}, {"stale_refused", []byte(refusedName)}}, acked...))
	if err != nil {
		return err
	}
	declared := map[string]bool{}
	for _, st := range done.Residual {
		declared[st] = true
	}
	undeclared := map[string]int{}
	for store, byLabel := range after {
		for label, n := range byLabel {
			if (label == "doomed_prefix" || strings.HasPrefix(label, "acked_deleted:")) && n > 0 && !declared[store] {
				undeclared[store] += n
			}
		}
	}
	if err = rep.Require("physical_cleanup_done", done.Physical == retention.PhysicalDone && len(s.app.Storage.ResidualStores()) == 0, fmt.Sprintf("receipt physical=%s, residual stores declared by the engine %v and by the receipt %v", done.Physical, s.app.Storage.ResidualStores(), done.Residual)); err != nil {
		return err
	}
	if err = rep.Require("physical_deleted_bytes_gone", len(undeclared) == 0, fmt.Sprintf("the acknowledged-then-deleted batches left bytes in undeclared stores %v (declared residual: %v)", undeclared, done.Residual)); err != nil {
		return err
	}
	if err = rep.Require("physical_kept_bytes_present", drHitTotal(after, "kept_prefix") > 0, fmt.Sprintf("the retained data is still physically present in %v, so the scanner is not blind", drHitStores(after, "kept_prefix"))); err != nil {
		return err
	}
	if err = rep.Require("stale_sends_leave_no_bytes", drHitTotal(after, "stale_refused") == 0, fmt.Sprintf("the canary names carried only by refused sends (the fresh stale batches before and during the race, and the 64 in-range probes refused by the barrier) are found %d times in any store: a refused send leaves no row and no journal residue, and a stale send is refused before it reaches the engine instead of being remapped into a row", drHitTotal(after, "stale_refused"))); err != nil {
		return err
	}
	if err = rep.Require("refused_and_deleted_in_range_sends_leave_no_bytes", drHitTotal(after, "refused_in_range") == 0, fmt.Sprintf("the in-range canary names (acknowledged-then-deleted and refused) are found %d times in any store after the physical cleanup", drHitTotal(after, "refused_in_range"))); err != nil {
		return err
	}

	if err = drRetireRace(s, rep, kinds, days); err != nil {
		return err
	}

	// ---- report ----
	cursors := make([]string, 0, len(op.Barriers))
	for _, c := range op.Barriers {
		cursors = append(cursors, c.Group.String()+":"+strconv.FormatUint(uint64(c.Index), 10))
	}
	rep.Cursor("delete_barrier_cursors", cursors)
	rep.Cursor("delete_operation", receipt.OperationID.String())
	rep.Fences = append(rep.Fences, map[string]any{"kind": "delete_barrier", "operation": receipt.OperationID.String(), "mode": op.Predicate.Mode, "begin_generation": receipt.Generation, "final_generation": done.Generation, "barriers_recorded": len(op.Barriers), "receipt_samples": samples, "retention_run_errors_while_fencing": runErrs})
	rep.PolicyTimeline = timelineFacts
	rep.Fact("acks_outside_predicate_retained_exactly", len(keep))
	rep.Fact("acks_inside_predicate_deleted", led.ackedFacts(gone))
	rep.Fact("stale_sends", map[string]any{"total": staleCount, "refusal_codes": staleCodes})
	rep.Fact("receipts_recovered_by_lookup", map[string]any{"count": recovered.Load(), "note": "a legitimate send refused after its append (finalize or the closing source's final revalidation) is not lost: the sender looks the batch up by identity and the original receipt is the ACK; each such batch is an acknowledged row in the ledger"})
	rep.Fact("sends_after_the_barrier", map[string]any{"in_range_refused_codes": refusedCodes, "outside_range_acked": drSlots})
	rep.Fact("ledger_scope", "ack_ledger holds every acknowledged batch OUTSIDE the deletion predicate (must be retained exactly); acknowledged batches INSIDE it are listed in acks_inside_predicate_deleted and asserted absent")
	return drRequireRecorded(rep, "physical_positive_control", "no_source_state_remap_by_stale_sends", "race_overlapped_legit_writers", "race_overlapped_in_range_writers", "race_overlapped_stale_fresh_senders", "race_overlapped_stale_replay_senders", "race_overlapped_cached_policy_workers",
		"barrier_refuses_the_range_in_every_slot", "data_outside_the_predicate_keeps_flowing", "delete_fence_monotone_and_complete", "delete_barrier_in_every_data_group", "barrier_groups_are_the_groups_that_served_the_acks",
		"policy_timeline_consecutive_and_fenced", "source_policy_is_the_last_advance", "stale_policy_command_refused_not_merged", "stale_sends_never_acknowledged_always_typed_stale",
		"exact_reconciliation", "no_unacknowledged_row_retained", "deleted_data_gone_from_every_shard", "tombstone_is_the_requested_predicate", "ack_status_after_delete",
		"physical_cleanup_done", "physical_deleted_bytes_gone", "physical_kept_bytes_present", "stale_sends_leave_no_bytes", "refused_and_deleted_in_range_sends_leave_no_bytes",
		"retire_physical_positive_control", "retired_source_stays_retired_and_unmapped", "retire_race_overlapped", "retire_fence_monotone_and_complete", "retire_barrier_in_every_data_group", "retired_project_unreadable", "retired_project_bytes_gone_from_every_store")
}

func drDistinctGroups(acks []drAcked) []model.ID {
	seen := map[model.ID]bool{}
	var out []model.ID
	for _, a := range acks {
		if !seen[a.Cursor.Group] {
			seen[a.Cursor.Group] = true
			out = append(out, a.Cursor.Group)
		}
	}
	return out
}

const drSlots = model.DeleteSlots

// ---- scenarios 2 and 3: a backup that predates a completed deletion ----

// drRig is a live installation with the real signed restore authority (an append-only, signed,
// hash-chained journal on a local directory standing in for the independent off-host store) and
// an encrypted backup destination.
type drRig struct {
	site         *drSite
	authDir      string
	authKeys     backup.AuthorityKeys
	authority    *backup.Authority
	keys         backup.StaticKeys
	dest         *backup.LocalDestination
	destDir      string
	svc          *backup.Service
	installation model.ID
}

func drOpenRig(env *Env, tag string) (*drRig, error) {
	s, err := drOpenSite(env, filepath.Join(tag, "live"))
	if err != nil {
		return nil, err
	}
	r := &drRig{site: s, authDir: filepath.Join(env.Work, tag, "authority"), destDir: filepath.Join(env.Work, tag, "offhost"), keys: backup.StaticKeys{}}
	attempts := filepath.Join(env.Work, tag, "attempts")
	if err = env.Approve([]string{r.authDir, r.destDir, attempts}, nil); err != nil {
		s.close()
		return nil, err
	}
	fail := func(err error) (*drRig, error) { s.close(); return nil, err }
	for _, id := range []string{"drill-data-kek", "drill-secret-kek"} {
		k, err := backup.GenerateKey(id)
		if err != nil {
			return fail(err)
		}
		r.keys[id] = k
	}
	if r.authKeys, err = backup.GenerateAuthorityKeys("drill-authority"); err != nil {
		return fail(err)
	}
	authDest, err := backup.NewLocalDestination(r.authDir)
	if err != nil {
		return fail(err)
	}
	if r.authority, err = backup.NewAuthority(authDest, r.authKeys, time.Now); err != nil {
		return fail(err)
	}
	if err = s.app.Control.View(env.Ctx, func(st model.ControlState) error { r.installation = st.Installation; return nil }); err != nil {
		return fail(err)
	}
	if _, err = r.authority.Initialize(env.Ctx, r.installation); err != nil {
		return fail(err)
	}
	if err = s.app.Retention.UseAuthority(r.authority); err != nil {
		return fail(err)
	}
	if r.dest, err = backup.NewLocalDestination(r.destDir); err != nil {
		return fail(err)
	}
	plane := backup.EngineDataPlane(s.app.Storage)
	if r.svc, err = backup.New(backup.Config{Control: s.app.Control, Data: plane, Processed: backup.AppliedProcessed(plane), Authority: r.authority, Authorizer: s.app.Auth, Keys: r.keys, DataKEK: "drill-data-kek", SecretKEK: "drill-secret-kek", Attempts: backup.DirAttempts(attempts), Clock: time.Now}); err != nil {
		return fail(err)
	}
	return r, nil
}

func (r *drRig) backupNow(reason string) (backup.BackupManifest, error) {
	cred, err := r.site.fresh()
	if err != nil {
		return backup.BackupManifest{}, err
	}
	scope, err := r.site.app.Auth.InstanceScope(r.site.env.Ctx, cred, reason)
	if err != nil {
		return backup.BackupManifest{}, err
	}
	return r.svc.Run(r.site.env.Ctx, scope, r.dest)
}

// deleteRange runs one historical-range deletion through the real retention service until it is
// complete (every slot barrier plus the authority checkpoint) and its physical cleanup is done.
func (r *drRig) deleteRange(pred model.DeletePredicate) (retention.DeleteReceipt, error) {
	s, ctx := r.site, r.site.env.Ctx
	var receipt retention.DeleteReceipt
	var err error
	for range 50 {
		var scope auth.Scope
		if scope, err = s.adminScope(); err != nil {
			return receipt, err
		}
		var rev model.Revision
		if rev, err = s.revision(); err != nil {
			return receipt, err
		}
		receipt, err = s.app.Retention.Delete(ctx, scope, retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: rev, Mode: pred.Mode, OrgID: s.org, ProjectIDs: pred.Projects, Signals: pred.Signals, Start: pred.Start, End: pred.End, Reason: "delete restore drill: completed deletion"})
		if drFault(err) != model.Conflict {
			break
		}
	}
	if err != nil {
		return receipt, err
	}
	for deadline := time.Now().Add(5 * time.Minute); ; time.Sleep(50 * time.Millisecond) {
		_ = s.app.Retention.RunOnce(ctx)
		scope, err := s.adminScope()
		if err != nil {
			return receipt, err
		}
		if receipt, err = s.app.Retention.PollDelete(ctx, scope, receipt.OperationID); err != nil {
			return receipt, err
		}
		if receipt.Phase == model.DeletePhaseComplete && receipt.Physical == retention.PhysicalDone {
			return receipt, nil
		}
		if time.Now().After(deadline) {
			return receipt, fmt.Errorf("deletion did not finish: phase %s progress %s physical %s", receipt.Phase, receipt.Progress, receipt.Physical)
		}
	}
}

func drCopyTree(from, to string) error {
	return filepath.Walk(from, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		target := filepath.Join(to, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, info.Mode().Perm())
	})
}

// drCountingDest counts the backup data objects a restore opens: a refusal that happens before
// any backup byte is read opens none.
type drCountingDest struct {
	backup.Destination
	mu    sync.Mutex
	opens []string
}

func (c *drCountingDest) Open(ctx context.Context, name string) (io.ReadCloser, error) {
	c.mu.Lock()
	c.opens = append(c.opens, name)
	c.mu.Unlock()
	return c.Destination.Open(ctx, name)
}

func (c *drCountingDest) dataOpens() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, name := range c.opens {
		if strings.Contains(name, "/obj/") {
			n++
		}
	}
	return n
}

// drLyingLedger is the real authority read with one fact altered at the authority boundary
// (fault injection): it is what a ledger that forgot a deletion looks like to a restore.
type drLyingLedger struct {
	real   backup.DeletionLedger
	mutate func(cur *backup.CurrentDeletion)
}

func (l *drLyingLedger) Current(ctx context.Context) (backup.CurrentDeletion, error) {
	cur, err := l.real.Current(ctx)
	if err != nil {
		return cur, err
	}
	cur.Chain = append([]model.Hash(nil), cur.Chain...)
	cur.Tombstones = append([]model.DeletePredicate(nil), cur.Tombstones...)
	cur.Ledger.Entries = append([]replica.LedgerEntry(nil), cur.Ledger.Entries...)
	l.mutate(&cur)
	return cur, nil
}

// drFixture is the common history of scenarios 2 and 3: ACKed batches outside and inside a
// deletion range, an encrypted backup taken BEFORE the deletion, the deletion completed with an
// independent authority checkpoint, optionally a second backup taken AFTER it, and the disaster
// (the live installation is closed).
type drFixture struct {
	rig        *drRig
	doom, sib  *drProject
	led        *drLedgers
	pred       model.DeletePredicate
	op         model.DeletionOperation
	receipt    retention.DeleteReceipt
	before     backup.BackupManifest
	after      backup.BackupManifest
	staleAuth  string // copy of the authority directory taken before the deletion completed
	headBefore backup.AuthorityHead
	headAfter  backup.CurrentDeletion
	needles    []drNeedle
	owner      model.ID
}

const drFixtureLo, drFixtureHi = 1000, 2000

func (f *drFixture) put(label string, p *drProject, at int64, base string, slot int) error {
	b, rec, err := p.metric(f.rig.site.org, 1, at, base, uint64(at), slot)
	if err != nil {
		return err
	}
	r, err := f.rig.site.send(p, b)
	if err != nil {
		f.led.attempt(b, label, drFault(err), false)
		return fmt.Errorf("%s: %w", label, err)
	}
	f.led.acked(b, label, false)
	return f.led.ack(label, f.rig.site.org, p, b, rec, r)
}

// drFixtureOpts selects the history of a fixture: After takes a second backup once the deletion
// completed; ShareSeries makes every deleted row share its metric series with a retained row
// (otherwise each deleted row carries a series no retained row has).
type drFixtureOpts struct {
	After, ShareSeries bool
	Tag                string // subdirectory of the work directory ("" = the work directory itself)
}

func drBuildFixture(env *Env, rep *Report, opts drFixtureOpts) (*drFixture, error) {
	ctx := env.Ctx
	rig, err := drOpenRig(env, opts.Tag)
	if err != nil {
		return nil, err
	}
	f := &drFixture{rig: rig}
	ok := false
	defer func() {
		if !ok {
			rig.site.close()
		}
	}()
	s := rig.site
	kinds, days := []model.Kind{model.Metric}, map[model.Kind]uint32{model.Metric: 30}
	if f.doom, err = s.addProject("doomed", kinds, days); err != nil {
		return nil, err
	}
	if f.sib, err = s.addProject("sibling", kinds, days); err != nil {
		return nil, err
	}
	f.owner = s.owner.User
	sender := model.NewID()
	if err = s.command("destination", auth.AdminPayload{ID: sender, Config: json.RawMessage(`{"type":"webhook","endpoint":"https://hooks.example.test/notify","enabled":true}`), Secret: "synthetic drill sender secret"}); err != nil {
		return nil, err
	}
	f.pred = model.DeletePredicate{Org: s.org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.doom.id}, Signals: []model.Kind{model.Metric}, Start: drFixtureLo, End: drFixtureHi}
	f.led = newDrLedgers(rep, f.pred)
	nonce := strings.ReplaceAll(model.NewID().String(), "-", "")[:12]
	doomedName, keptName := "drill_doomed_"+nonce, "drill_kept_"+nonce
	f.needles = []drNeedle{{"doomed_prefix", []byte(doomedName)}, {"kept_prefix", []byte(keptName)}}
	for i := range 16 {
		if err = f.put("outside the range, same project", f.doom, 5000+int64(i), keptName, i*4); err != nil {
			return nil, err
		}
		doomedBase, doomedSlot := doomedName, i*4+1
		if opts.ShareSeries {
			doomedBase, doomedSlot = keptName, i*4
		}
		if err = f.put("in the range, same project (will be deleted)", f.doom, drFixtureLo+int64(i), doomedBase, doomedSlot); err != nil {
			return nil, err
		}
	}
	for i := range 8 {
		if err = f.put("sibling project, inside the numeric range", f.sib, drFixtureLo+int64(i), keptName, i*8+2); err != nil {
			return nil, err
		}
	}
	if err = s.app.Control.ReconcileAdmissions(ctx); err != nil {
		return nil, err
	}
	if err = s.app.Storage.Flush(ctx); err != nil {
		return nil, err
	}
	if f.before, err = rig.backupNow("delete restore drill: backup before the deletion"); err != nil {
		return nil, fmt.Errorf("backup before the deletion: %w", err)
	}
	cur, err := rig.authority.Current(ctx)
	if err != nil {
		return nil, err
	}
	f.headBefore = cur.Head
	f.staleAuth = filepath.Join(env.Work, opts.Tag, "authority-before-deletion")
	if err = env.Approve([]string{f.staleAuth}, nil); err != nil {
		return nil, err
	}
	if err = drCopyTree(rig.authDir, f.staleAuth); err != nil {
		return nil, err
	}
	if f.receipt, err = rig.deleteRange(f.pred); err != nil {
		return nil, fmt.Errorf("deletion: %w", err)
	}
	if err = s.app.Control.View(ctx, func(st model.ControlState) error { f.op = st.Deletions[f.receipt.OperationID.String()]; return nil }); err != nil {
		return nil, err
	}
	if f.headAfter, err = rig.authority.Current(ctx); err != nil {
		return nil, err
	}
	if opts.After {
		if f.after, err = rig.backupNow("delete restore drill: backup after the deletion"); err != nil {
			return nil, fmt.Errorf("backup after the deletion: %w", err)
		}
	}
	ok = true
	return f, nil
}

func (f *drFixture) restorer(src backup.Destination) (*backup.Restorer, error) {
	return backup.NewRestorer(backup.RestoreConfig{Keys: f.rig.keys, Source: src, Clock: time.Now})
}

// openRestored starts the restored installation the way `backup activate` does.
func (f *drFixture) openRestored(env *Env, root string) (*drSite, error) {
	if err := env.Approve([]string{root}, nil); err != nil {
		return nil, err
	}
	app, err := appcore.OpenForActivation(root)
	if err != nil {
		return nil, err
	}
	return &drSite{env: env, app: app, dir: root, org: f.rig.site.org, owner: auth.Session{User: f.owner}}, nil
}

// reinstate bootstraps the one-time recovery administrator the restore armed and reauthorizes
// exactly the owner's account, membership and read grants (nothing else comes back by itself).
func (f *drFixture) reinstate(rs *drSite, projects ...*drProject) error {
	ctx := rs.env.Ctx
	token, err := rs.app.Control.BootstrapToken()
	if err != nil {
		return err
	}
	session, err := rs.app.Auth.Bootstrap(ctx, token, "drill-recovery@example.test", "drill recovery password 2026")
	if err != nil {
		return err
	}
	recovery, err := rs.app.Auth.Authenticate(ctx, session.Token)
	if err != nil {
		return err
	}
	items := []auth.Reconciliation{{Kind: auth.ReconcileAccount, User: f.owner}, {Kind: auth.ReconcileMembership, Org: rs.org, User: f.owner}}
	for _, p := range projects {
		items = append(items, auth.Reconciliation{Kind: auth.ReconcileGrant, Org: rs.org, User: f.owner, Project: p.id})
	}
	for _, it := range items {
		it.Reason = "delete restore drill: verified against the original administrator"
		if _, err = rs.app.Auth.Reconcile(ctx, recovery, it); err != nil {
			return err
		}
	}
	login, err := rs.app.Auth.Login(ctx, drOwnerEmail, drOwnerPassword, "")
	if err != nil {
		return err
	}
	rs.actor, err = rs.app.Auth.Authenticate(ctx, login.Token)
	if err == nil {
		rs.recovery = recovery
	}
	return err
}

// reissue reconciles the source of p: the old secret is never revived, a NEW credential is
// returned once.
func (f *drFixture) reissue(rs *drSite, p *drProject) (*drProject, error) {
	issued, err := rs.app.Auth.Reconcile(rs.env.Ctx, rs.recovery, auth.Reconciliation{Kind: auth.ReconcileSource, Source: p.source, Reason: "delete restore drill: source credential reissued"})
	if err != nil {
		return nil, err
	}
	np := *p
	np.raw = issued.Credential
	np.cred, err = rs.app.Auth.AuthenticateSource(rs.env.Ctx, np.raw, "", false)
	return &np, err
}

// restoredRows reads every row of the projects through the reinstated reader.
func (f *drFixture) restoredRows(rs *drSite, projects ...*drProject) (map[string]string, int, error) {
	retained := map[string]string{}
	total := 0
	for _, p := range projects {
		scope, err := rs.readScope(p.id)
		if err != nil {
			return nil, 0, err
		}
		rows, err := drScan(rs.env.Ctx, rs.app.Storage, scope, p.id, model.Metric)
		if err != nil {
			return retained, total, err
		}
		total += len(rows)
		f.led.retained(rows, retained)
	}
	return retained, total, nil
}

func drDestinations(st model.ControlState) int {
	n := 0
	for _, o := range st.Orgs {
		for key := range o.Settings {
			if strings.HasPrefix(key, "destination:") {
				n++
			}
		}
	}
	return n
}

func (s *drSite) senders() (destinations, pending int, err error) {
	err = s.app.Control.View(s.env.Ctx, func(st model.ControlState) error {
		destinations, pending = drDestinations(st), auth.RestorePending(st)
		return nil
	})
	return
}

// resurrection builds the rows read back and runs the tombstone detector over them.
func (f *drFixture) resurrection(retained map[string]string, tombstones []model.DeletePredicate) []string {
	var rows []drRow
	f.led.mu.Lock()
	defer f.led.mu.Unlock()
	for id := range retained {
		if b, ok := f.led.batch[id]; ok {
			rows = append(rows, drRow{BatchID: id, Org: f.rig.site.org, Project: b.Project, Record: b.Records[0]})
		}
	}
	return drDetectResurrection(rows, tombstones)
}

func drManifestFacts(m backup.BackupManifest) map[string]any {
	return map[string]any{"backup_id": m.ID.String(), "authority_sequence": uint64(m.Deletion.Sequence), "authority_generation": uint64(m.Deletion.Generation), "authority_tombstones": uint64(m.Deletion.Tombstones), "objects": len(m.Objects), "control_revision": uint64(m.Control.Revision)}
}

func drHeadFacts(h backup.AuthorityHead) map[string]any {
	return map[string]any{"sequence": h.Sequence, "generation": h.Generation, "digest": h.Digest.String()}
}

func (f *drFixture) factsOfHistory(rep *Report) {
	f.led.mu.Lock()
	gone := append([]drAcked(nil), f.led.gone...)
	f.led.mu.Unlock()
	rep.Fact("backup_before_deletion", drManifestFacts(f.before))
	rep.Fact("authority_head_when_backup_was_taken", drHeadFacts(f.headBefore))
	rep.Fact("authority_head_after_deletion", drHeadFacts(f.headAfter.Head))
	rep.Fact("acks_inside_predicate_deleted", f.led.ackedFacts(gone))
	rep.Fact("deletion", map[string]any{"operation": f.receipt.OperationID.String(), "phase": f.receipt.Phase, "physical": f.receipt.Physical, "generation": f.receipt.Generation, "barriers": len(f.op.Barriers), "authority_generation": f.op.Authority})
	rep.Fact("ledger_scope", "ack_ledger holds every acknowledged batch OUTSIDE the deletion predicate (must be retained exactly after restore); acknowledged batches INSIDE it are listed in acks_inside_predicate_deleted and asserted absent")
	if f.after.ID != (model.ID{}) {
		rep.Fact("backup_after_deletion", drManifestFacts(f.after))
	}
}

// activationState reads restore.json's activation marker.
func drActivated(root string) bool {
	raw, err := os.ReadFile(filepath.Join(root, "restore.json"))
	if err != nil {
		return false
	}
	var st struct {
		Activated model.UnixNano `json:"activated_ns"` // C01: a decimal string on the wire
	}
	return json.Unmarshal(raw, &st) == nil && st.Activated != 0
}

// drBackupPredatesDeletion restores the OLD backup (taken before the deletion completed) with the
// authority's CURRENT head and proves the deleted rows do not come back, the restored installation
// serves nothing until the tombstones are re-applied, senders and sources stay disabled, and every
// acknowledged batch outside the deletion is retained with exactly the acknowledged content.
func drBackupPredatesDeletion(env *Env, rep *Report) error {
	ctx := env.Ctx
	f, err := drBuildFixture(env, rep, drFixtureOpts{})
	if err != nil {
		return err
	}
	liveClosed := false
	closeLive := func() {
		if !liveClosed {
			f.rig.site.close()
			liveClosed = true
		}
	}
	defer closeLive()
	f.factsOfHistory(rep)
	live, err := drStoreHits(f.rig.site.dir, f.needles)
	if err != nil {
		return err
	}
	// the history the scenario is about
	if err = rep.Require("backup_predates_the_deletion", f.before.Deletion.Sequence == 0 && f.before.Deletion.Tombstones == 0 && f.headAfter.Head.Sequence > uint64(f.before.Deletion.Sequence) && len(f.headAfter.Tombstones) == 1 && f.receipt.Phase == model.DeletePhaseComplete && f.op.Authority != nil,
		fmt.Sprintf("the backup binds authority sequence %d with %d tombstones; the completed deletion advanced the independent authority to sequence %d with %d tombstone(s)", f.before.Deletion.Sequence, f.before.Deletion.Tombstones, f.headAfter.Head.Sequence, len(f.headAfter.Tombstones))); err != nil {
		return err
	}
	if err = rep.Require("authority_ledger_names_the_deletion", len(f.headAfter.Ledger.Entries) == 1 && f.headAfter.Ledger.Entries[0].Hash == f.op.Predicate.Digest() && f.headAfter.Tombstones[0].Operation == f.receipt.OperationID, "the independent authority holds the tombstone of the completed deletion"); err != nil {
		return err
	}
	enc, err := drStoreHits(f.rig.destDir, f.needles)
	if err != nil {
		return err
	}
	if err = rep.Require("physical_positive_control", drHitTotal(live, "kept_prefix") > 0, fmt.Sprintf("the scanner finds the kept canary in the live stores %v, so an empty backup result is not a blind scanner", drHitStores(live, "kept_prefix"))); err != nil {
		return err
	}
	if err = rep.Require("backup_destination_holds_no_plaintext_telemetry", len(enc) == 0, fmt.Sprintf("the destination holds %d backup objects and none contains the canary names", len(f.before.Objects))); err != nil {
		return err
	}
	closeLive() // the disaster

	// ---- restore the OLD backup with the authority's current head ----
	root := filepath.Join(env.Work, "restored")
	src := &drCountingDest{Destination: f.rig.dest}
	restorer, err := f.restorer(src)
	if err != nil {
		return err
	}
	report, err := restorer.Restore(ctx, f.before, backup.DestinationRoot(root), f.rig.authority)
	if err != nil {
		return fmt.Errorf("restore of the old backup: %w", err)
	}
	if err = rep.Require("restore_applied_the_current_authority_head", report.AuthoritySequence == f.headAfter.Head.Sequence && report.Tombstones == 1 && report.AuthorityGeneration == f.headAfter.Head.Generation,
		fmt.Sprintf("restore verified authority sequence %d generation %d with %d tombstone(s) (the backup itself bound sequence %d)", report.AuthoritySequence, report.AuthorityGeneration, report.Tombstones, f.before.Deletion.Sequence)); err != nil {
		return err
	}
	rs, err := f.openRestored(env, root)
	if err != nil {
		return err
	}
	defer rs.close()
	if err = rep.Require("restored_engine_closed_until_activation", rs.app.Storage.RestoreReady() != nil && !drActivated(root), "the engine reports its restore hold armed and restore.json records no activation"); err != nil {
		return err
	}
	destinations, pending, err := rs.senders()
	if err != nil {
		return err
	}
	if err = rep.Require("senders_disabled_and_reauthorization_pending", destinations == 0 && pending > 0, fmt.Sprintf("restored control holds %d sender destinations and %d items awaiting administrator reauthorization", destinations, pending)); err != nil {
		return err
	}
	if _, err = rs.app.Auth.AuthenticateSource(ctx, f.doom.raw, "", false); err == nil {
		return rep.Require("old_source_credential_refused", false, "the restored installation accepted a source credential of the old installation")
	}
	if err = f.reinstate(rs, f.doom, f.sib); err != nil {
		return err
	}
	// an authorized reader still gets nothing before activation
	_, served, readErr := f.restoredRows(rs, f.doom, f.sib)
	if err = rep.Require("no_data_served_before_the_tombstones_are_applied", readErr != nil && served == 0, fmt.Sprintf("a fully authorized reader's scan before activation: %d rows, error %v", served, readErr)); err != nil {
		return err
	}
	// a ledger that forgot the deletion cannot activate the installation
	lying := &drLyingLedger{real: f.rig.authority, mutate: func(cur *backup.CurrentDeletion) { cur.Tombstones, cur.Ledger.Entries = nil, nil }}
	if _, err = backup.Activate(ctx, backup.DestinationRoot(root), rs.app, lying, time.Now); err == nil {
		return rep.Require("activation_refused_without_the_tombstone", false, "activation succeeded under a ledger that forgot the completed deletion")
	}
	_, served, readErr = f.restoredRows(rs, f.doom, f.sib)
	if err = rep.Require("activation_refused_without_the_tombstone", drFault(err) == model.Conflict && rs.app.Storage.RestoreReady() != nil && !drActivated(root) && readErr != nil && served == 0,
		fmt.Sprintf("activation under a ledger without the deletion: %q; engine ready=%v; activated marker=%v; rows served %d", drFault(err), rs.app.Storage.RestoreReady() == nil, drActivated(root), served)); err != nil {
		return err
	}
	// the honest activation re-applies the authority's tombstones
	activation, err := backup.Activate(ctx, backup.DestinationRoot(root), rs.app, f.rig.authority, time.Now)
	if err != nil {
		return fmt.Errorf("activation: %w", err)
	}
	var imported model.DeletionOperation
	if err = rs.app.Control.View(ctx, func(st model.ControlState) error { imported = st.Deletions[f.receipt.OperationID.String()]; return nil }); err != nil {
		return err
	}
	if err = rep.Require("tombstones_reapplied_on_activation", activation.Tombstones == 1 && rs.app.Storage.RestoreReady() == nil && imported.Phase == model.DeletePhaseComplete && imported.Predicate.Digest() == f.op.Predicate.Digest(),
		fmt.Sprintf("activation applied %d tombstone(s) at authority generation %d; the restored control state holds the deletion %s in phase %s", activation.Tombstones, activation.AuthorityGeneration, f.receipt.OperationID, imported.Phase)); err != nil {
		return err
	}
	// the source is reissued by an administrator; writes inside the tombstone are refused, others flow
	np, err := f.reissue(rs, f.doom)
	if err != nil {
		return err
	}
	inB, _, err := np.metric(rs.org, 1, drFixtureLo+3, "drill_late_inside", 7, -1)
	if err != nil {
		return err
	}
	_, inErr := rs.send(np, inB)
	f.led.attempt(inB, "restored installation: late write inside the tombstone", drFault(inErr), false)
	if err = rep.Require("late_write_inside_the_tombstone_refused", inErr != nil && drFault(inErr) != "", fmt.Sprintf("a new write inside the deleted range after activation: refused with %q", drFault(inErr))); err != nil {
		return err
	}
	outB, outRec, err := np.metric(rs.org, 1, 7000, "drill_late_outside", 8, -1)
	if err != nil {
		return err
	}
	outR, err := rs.send(np, outB)
	if err != nil {
		return rep.Require("restored_installation_accepts_writes_outside_the_tombstone", false, fmt.Sprintf("refused: %v", err))
	}
	f.led.acked(outB, "restored installation: write outside the tombstone", false)
	if err = f.led.ack("restored installation: write outside the tombstone", rs.org, np, outB, outRec, outR); err != nil {
		return err
	}
	// the retry of an acknowledged batch inside the tombstone must not bring its rows back
	f.led.mu.Lock()
	var firstGone drAcked
	if len(f.led.gone) > 0 {
		firstGone = f.led.gone[0]
	}
	retryBatch := f.led.batch[firstGone.ID]
	f.led.mu.Unlock()
	retryR, retryErr := rs.send(np, retryBatch)
	retryFacts := map[string]any{"batch": firstGone.ID, "fault": string(drFault(retryErr)), "acknowledged": retryErr == nil}
	if retryErr == nil {
		retryFacts["same_receipt_as_the_original"] = drSameReceipt(retryR, f.led.rcpt[firstGone.ID])
	}
	rep.Fact("retry_of_a_deleted_acknowledged_batch", retryFacts)

	// ---- exact reconciliation ----
	retained, total, err := f.restoredRows(rs, f.doom, f.sib)
	if err != nil {
		return err
	}
	if err = rep.Reconcile(retained); err != nil {
		return err
	}
	if err = rep.Require("no_unacknowledged_row_retained", len(rep.Reconciliation.UnackedRetained) == 0, fmt.Sprintf("%d rows read back, %d retained rows were never acknowledged", total, len(rep.Reconciliation.UnackedRetained))); err != nil {
		return err
	}
	tombstones := f.headAfter.Tombstones
	resurrected := f.resurrection(retained, tombstones)
	f.led.mu.Lock()
	stillThere := 0
	for _, a := range f.led.gone {
		if _, ok := retained[a.ID]; ok {
			stillThere++
		}
	}
	goneN := len(f.led.gone)
	f.led.mu.Unlock()
	if err = rep.Require("deleted_data_not_resurrected", len(resurrected) == 0 && stillThere == 0, fmt.Sprintf("%d acknowledged batches were deleted after the backup was taken; %d are readable after the restore, the tombstone detector flags %d", goneN, stillThere, len(resurrected))); err != nil {
		return err
	}
	nowDestinations, nowPending, err := rs.senders()
	if err != nil {
		return err
	}
	if err = rep.Require("senders_still_disabled_after_activation", nowDestinations == 0, fmt.Sprintf("after activation and the owner's reauthorization the restored installation has %d sender destinations and %d items still awaiting reauthorization", nowDestinations, nowPending)); err != nil {
		return err
	}
	if _, err = rs.app.Auth.AuthenticateSource(ctx, f.doom.raw, "", false); err == nil {
		return rep.Require("old_source_credential_refused", false, "the old source credential works after activation")
	}
	if err = rep.Require("old_source_credential_refused", true, "the source credential of the old installation is refused before activation, after activation and after reauthorization (a new credential was issued)"); err != nil {
		return err
	}
	// ---- negative control: the same OLD backup under an authority that does not know the
	// deletion (a copy of the journal from before it). Its binding (sequence 0) cannot tell such
	// an authority from the current one, so this restore is accepted and the deleted rows DO come
	// back: it proves the detector and the scenario can see a resurrection, and that the only
	// protection is the independent CURRENT head used above. ----
	staleDest, err := backup.NewLocalDestination(f.staleAuth)
	if err != nil {
		return err
	}
	staleAuthority, err := backup.NewAuthority(staleDest, f.rig.authKeys.Restricted(), time.Now)
	if err != nil {
		return err
	}
	rootNeg := filepath.Join(env.Work, "restored-negative-control")
	if err = env.Approve([]string{rootNeg}, nil); err != nil {
		return err
	}
	_, negErr := restorer.Restore(ctx, f.before, backup.DestinationRoot(rootNeg), staleAuthority)
	negative := map[string]any{"authority": "journal copy from before the deletion (sequence 0)", "restore_refused": negErr != nil, "fault": string(drFault(negErr))}
	if negErr == nil {
		ns, err := f.openRestored(env, rootNeg)
		if err != nil {
			return err
		}
		defer ns.close()
		if err = f.reinstate(ns, f.doom, f.sib); err != nil {
			return err
		}
		if _, err = backup.Activate(ctx, backup.DestinationRoot(rootNeg), ns.app, staleAuthority, time.Now); err != nil {
			return fmt.Errorf("negative control activation: %w", err)
		}
		negRetained, _, err := f.restoredRows(ns, f.doom, f.sib)
		if err != nil {
			return err
		}
		flagged := f.resurrection(negRetained, tombstones)
		negative["rows_resurrected"] = len(flagged)
		if err = rep.Require("negative_control_detector_flags_the_resurrection", len(flagged) == goneN, fmt.Sprintf("restoring the same backup under a journal that never saw the deletion brings %d of the %d deleted rows back and the tombstone detector flags %d: the check above is not vacuous", len(flagged), goneN, len(flagged))); err != nil {
			return err
		}
	}
	rep.Fact("negative_control_stale_authority", negative)
	rep.Cursor("authority_head_applied", drHeadFacts(f.headAfter.Head))
	rep.Fences = append(rep.Fences, map[string]any{"kind": "authority_head", "applied_at_restore": drHeadFacts(f.headAfter.Head), "tombstones_reapplied": activation.Tombstones, "deletion_operation": f.receipt.OperationID.String(), "backup_bound_sequence": uint64(f.before.Deletion.Sequence), "restore_data_objects_opened": src.dataOpens()})
	return drRequireRecorded(rep, "backup_predates_the_deletion", "authority_ledger_names_the_deletion", "physical_positive_control", "backup_destination_holds_no_plaintext_telemetry", "restore_applied_the_current_authority_head",
		"restored_engine_closed_until_activation", "senders_disabled_and_reauthorization_pending", "no_data_served_before_the_tombstones_are_applied", "activation_refused_without_the_tombstone", "tombstones_reapplied_on_activation",
		"late_write_inside_the_tombstone_refused", "exact_reconciliation", "no_unacknowledged_row_retained", "deleted_data_not_resurrected", "senders_still_disabled_after_activation", "old_source_credential_refused", "negative_control_detector_flags_the_resurrection")
}

// drRestoreAuthorityUnavailable restores with the authority unreachable, uninitialised, foreign,
// wrongly keyed or rolled back, at the restore step and at the activation step. Every refusal
// must be typed and leave nothing created, read, activated, served or admitted; then the same
// restore, with the authority available, succeeds and retains every acknowledged batch exactly.
func drRestoreAuthorityUnavailable(env *Env, rep *Report) error {
	ctx := env.Ctx
	f, err := drBuildFixture(env, rep, drFixtureOpts{After: true, ShareSeries: true})
	if err != nil {
		return err
	}
	f.rig.site.close() // the disaster
	f.factsOfHistory(rep)
	if err = rep.Require("authority_has_moved_past_the_stale_copy", f.after.Deletion.Sequence >= 1 && f.headAfter.Head.Sequence >= uint64(f.after.Deletion.Sequence), fmt.Sprintf("the post-deletion backup binds authority sequence %d; the live authority is at %d; the stale copy is at the pre-deletion head %d", f.after.Deletion.Sequence, f.headAfter.Head.Sequence, f.headBefore.Sequence)); err != nil {
		return err
	}
	root := filepath.Join(env.Work, "restored")
	if err = env.Approve([]string{root, root + ".restore-x"}, nil); err != nil {
		return err
	}
	authAway := f.rig.authDir + ".away"
	if err = env.Approve([]string{authAway}, nil); err != nil {
		return err
	}
	type caseResult struct {
		Name  string `json:"name"`
		Stage string `json:"stage"`
		Code  string `json:"fault"`
		Note  string `json:"note,omitempty"`
	}
	var cases []caseResult

	// ---- restore-time refusals: the authority is consulted before any backup byte is read ----
	restoreRefused := func(name string, allowed []model.Code, ledger backup.DeletionLedger) error {
		src := &drCountingDest{Destination: f.rig.dest}
		restorer, err := f.restorer(src)
		if err != nil {
			return err
		}
		_, rerr := restorer.Restore(ctx, f.after, backup.DestinationRoot(root), ledger)
		left, _ := filepath.Glob(root + ".restore-*")
		_, statErr := os.Stat(root)
		obs := drRefusal{Err: rerr, RootCreated: statErr == nil, StageLeftover: len(left), ObjectsOpened: src.dataOpens(), Activated: drActivated(root)}
		cerr := drClassifyRefusal(obs, allowed...)
		cases = append(cases, caseResult{Name: name, Stage: "restore", Code: string(drFault(rerr))})
		return rep.Require("restore_fails_closed:"+name, cerr == nil, fmt.Sprintf("typed refusal %q (allowed %v); root created=%v, staging leftovers=%d, backup data objects opened=%d; %v", drFault(rerr), allowed, obs.RootCreated, obs.StageLeftover, obs.ObjectsOpened, cerr))
	}
	// a. unreachable: the directory the authority lives in is gone
	if err = os.Rename(f.rig.authDir, authAway); err != nil {
		return err
	}
	err = restoreRefused("authority_unreachable", []model.Code{model.Unavailable}, f.rig.authority)
	if rerr := os.Rename(authAway, f.rig.authDir); rerr != nil {
		return rerr
	}
	if err != nil {
		return err
	}
	// b. uninitialised: an empty journal with the right keys
	emptyDir := filepath.Join(env.Work, "authority-empty")
	if err = env.Approve([]string{emptyDir}, nil); err != nil {
		return err
	}
	emptyDest, err := backup.NewLocalDestination(emptyDir)
	if err != nil {
		return err
	}
	empty, err := backup.NewAuthority(emptyDest, f.rig.authKeys.Restricted(), time.Now)
	if err != nil {
		return err
	}
	if err = restoreRefused("authority_uninitialised", []model.Code{model.Unavailable}, empty); err != nil {
		return err
	}
	// c. wrong key: the real journal read with another installation's keys
	otherKeys, err := backup.GenerateAuthorityKeys("not-the-authority-key")
	if err != nil {
		return err
	}
	realDest, err := backup.NewLocalDestination(f.rig.authDir)
	if err != nil {
		return err
	}
	wrongKey, err := backup.NewAuthority(realDest, otherKeys.Restricted(), time.Now)
	if err != nil {
		return err
	}
	if err = restoreRefused("authority_with_wrong_keys", []model.Code{model.Unavailable}, wrongKey); err != nil {
		return err
	}
	// d. a different installation's authority
	foreignDir := filepath.Join(env.Work, "authority-foreign")
	if err = env.Approve([]string{foreignDir}, nil); err != nil {
		return err
	}
	foreignDest, err := backup.NewLocalDestination(foreignDir)
	if err != nil {
		return err
	}
	foreign, err := backup.NewAuthority(foreignDest, otherKeys, time.Now)
	if err != nil {
		return err
	}
	if _, err = foreign.Initialize(ctx, model.NewID()); err != nil {
		return err
	}
	if err = restoreRefused("authority_of_another_installation", []model.Code{model.Conflict, model.Unavailable}, foreign); err != nil {
		return err
	}
	// e. rolled back: a valid older prefix of the real journal (it predates the deletion)
	staleDest, err := backup.NewLocalDestination(f.staleAuth)
	if err != nil {
		return err
	}
	stale, err := backup.NewAuthority(staleDest, f.rig.authKeys.Restricted(), time.Now)
	if err != nil {
		return err
	}
	if err = restoreRefused("authority_rolled_back_below_the_backup_binding", []model.Code{model.Conflict}, stale); err != nil {
		return err
	}
	// f. no authority at all
	if err = restoreRefused("no_authority", []model.Code{model.Unavailable}, nil); err != nil {
		return err
	}

	// ---- the same restore, authority available ----
	src := &drCountingDest{Destination: f.rig.dest}
	restorer, err := f.restorer(src)
	if err != nil {
		return err
	}
	report, err := restorer.Restore(ctx, f.after, backup.DestinationRoot(root), f.rig.authority)
	if err != nil {
		return rep.Require("same_restore_succeeds_with_the_authority_available", false, fmt.Sprintf("restore with the authority available failed: %v", err))
	}
	if err = rep.Require("same_restore_succeeds_with_the_authority_available", report.Tombstones == 1 && report.AuthoritySequence == f.headAfter.Head.Sequence && src.dataOpens() > 0,
		fmt.Sprintf("restore into the very path the refusals left empty succeeded at authority sequence %d with %d tombstone(s), reading %d backup data objects", report.AuthoritySequence, report.Tombstones, src.dataOpens())); err != nil {
		return err
	}
	rs, err := f.openRestored(env, root)
	if err != nil {
		return err
	}
	defer rs.close()
	if err = f.reinstate(rs, f.doom, f.sib); err != nil {
		return err
	}

	// ---- activation-time refusals: the root exists but the engine must stay closed ----
	refusedActivations := 0
	activateRefused := func(name string, allowed []model.Code, ledger backup.DeletionLedger) error {
		_, aerr := backup.Activate(ctx, backup.DestinationRoot(root), rs.app, ledger, time.Now)
		_, served, readErr := f.restoredRows(rs, f.doom, f.sib)
		admitted := 0
		inB, _, err := f.doom.metric(rs.org, 1, 7000, "drill_probe_before_activation", 1, -1)
		if err != nil {
			return err
		}
		if _, serr := rs.send(f.doom, inB); serr == nil { // the old source credential: must be refused on the closed root
			admitted++
		}
		obs := drRefusal{Err: aerr, Activated: drActivated(root) || rs.app.Storage.RestoreReady() == nil, ReadsServed: served, Admitted: admitted}
		cerr := drClassifyRefusal(obs, allowed...)
		if cerr == nil && readErr == nil {
			cerr = errors.New("a scan on the closed engine returned no error")
		}
		refusedActivations++
		cases = append(cases, caseResult{Name: name, Stage: "activate", Code: string(drFault(aerr))})
		return rep.Require("activation_fails_closed:"+name, cerr == nil, fmt.Sprintf("typed refusal %q (allowed %v); engine ready=%v, activated marker=%v, rows served=%d (scan error %v), writes admitted=%d; %v", drFault(aerr), allowed, rs.app.Storage.RestoreReady() == nil, drActivated(root), served, drFault(readErr), admitted, cerr))
	}
	if err = os.Rename(f.rig.authDir, authAway); err != nil {
		return err
	}
	err = activateRefused("authority_unreachable", []model.Code{model.Unavailable}, f.rig.authority)
	if rerr := os.Rename(authAway, f.rig.authDir); rerr != nil {
		return rerr
	}
	if err != nil {
		return err
	}
	if err = activateRefused("authority_uninitialised", []model.Code{model.Unavailable}, empty); err != nil {
		return err
	}
	if err = activateRefused("authority_rolled_back_below_what_restore_verified", []model.Code{model.Conflict}, stale); err != nil {
		return err
	}
	if err = activateRefused("ledger_that_forgot_the_deletion", []model.Code{model.Conflict}, &drLyingLedger{real: f.rig.authority, mutate: func(cur *backup.CurrentDeletion) { cur.Tombstones, cur.Ledger.Entries = nil, nil }}); err != nil {
		return err
	}
	if err = activateRefused("no_authority", []model.Code{model.Unavailable}, nil); err != nil {
		return err
	}
	// ---- activation with the authority available ----
	activation, err := backup.Activate(ctx, backup.DestinationRoot(root), rs.app, f.rig.authority, time.Now)
	if err != nil {
		return rep.Require("activation_succeeds_with_the_authority_available", false, fmt.Sprintf("activation failed: %v", err))
	}
	if err = rep.Require("activation_succeeds_with_the_authority_available", activation.Tombstones == 1 && rs.app.Storage.RestoreReady() == nil && drActivated(root), fmt.Sprintf("after %d refused activations the same installation activated at authority generation %d with %d tombstone(s)", refusedActivations, activation.AuthorityGeneration, activation.Tombstones)); err != nil {
		return err
	}
	retained, total, err := f.restoredRows(rs, f.doom, f.sib)
	if err != nil {
		return err
	}
	if err = rep.Reconcile(retained); err != nil {
		return err
	}
	if err = rep.Require("no_unacknowledged_row_retained", len(rep.Reconciliation.UnackedRetained) == 0, fmt.Sprintf("%d rows read back after the successful restore, %d never acknowledged", total, len(rep.Reconciliation.UnackedRetained))); err != nil {
		return err
	}
	resurrected := f.resurrection(retained, f.headAfter.Tombstones)
	if err = rep.Require("deleted_data_not_resurrected", len(resurrected) == 0, fmt.Sprintf("the tombstone detector flags %d resurrected rows", len(resurrected))); err != nil {
		return err
	}
	// ---- a finding of this drill, recorded not asserted: a backup taken AFTER a deletion whose
	// erased rows carried a series no retained row has ----
	g, err := drBuildFixture(env, &Report{}, drFixtureOpts{After: true, Tag: "finding"})
	if err != nil {
		return fmt.Errorf("finding probe fixture: %w", err)
	}
	g.rig.site.close()
	rootF := filepath.Join(env.Work, "finding-restored")
	if err = env.Approve([]string{rootF}, nil); err != nil {
		return err
	}
	fr, err := g.restorer(g.rig.dest)
	if err != nil {
		return err
	}
	finding := map[string]any{"backup": "taken after the deletion completed; every deleted row carried a series no retained row carries"}
	if _, rerr := fr.Restore(ctx, g.after, backup.DestinationRoot(rootF), g.rig.authority); rerr != nil {
		finding["restore_fault"] = string(drFault(rerr))
	} else if fs, oerr := g.openRestored(env, rootF); oerr != nil {
		finding["open_fault"] = string(drFault(oerr))
	} else {
		_, aerr := backup.Activate(ctx, backup.DestinationRoot(rootF), fs.app, g.rig.authority, time.Now)
		finding["activation_fault"] = string(drFault(aerr))
		finding["engine_ready_after"] = fs.app.Storage.RestoreReady() == nil
		finding["activated_marker"] = drActivated(rootF)
		fs.close()
		if aerr != nil {
			rep.NotRun("restore + activation of a backup taken after a deletion whose erased rows carried a series no retained row carries",
				"activation fails closed with typed `corrupt` from storage.(*Engine).CommitQuotaReconciliation: the series set recomputed from the surviving rows of the restored index differs from the quota certificate's series digest, which (storage.ReconcileQuota) still lists the series of the erased batches; found by this drill, the restore authority flow above therefore uses a post-deletion backup whose erased rows share their series with retained rows")
		}
	}
	rep.Fact("finding_post_deletion_backup_with_erased_only_series", finding)
	rep.Fact("refusal_cases", cases)
	rep.Fact("successful_restore", map[string]any{"authority_sequence": report.AuthoritySequence, "tombstones": report.Tombstones, "objects": report.Objects})
	rep.Cursor("authority_head_current", drHeadFacts(f.headAfter.Head))
	rep.Cursor("authority_head_stale_copy", drHeadFacts(f.headBefore))
	return drRequireRecorded(rep, "authority_has_moved_past_the_stale_copy",
		"restore_fails_closed:authority_unreachable", "restore_fails_closed:authority_uninitialised", "restore_fails_closed:authority_with_wrong_keys", "restore_fails_closed:authority_of_another_installation", "restore_fails_closed:authority_rolled_back_below_the_backup_binding", "restore_fails_closed:no_authority",
		"same_restore_succeeds_with_the_authority_available",
		"activation_fails_closed:authority_unreachable", "activation_fails_closed:authority_uninitialised", "activation_fails_closed:authority_rolled_back_below_what_restore_verified", "activation_fails_closed:ledger_that_forgot_the_deletion", "activation_fails_closed:no_authority",
		"activation_succeeds_with_the_authority_available", "exact_reconciliation", "no_unacknowledged_row_retained", "deleted_data_not_resurrected")
}

// ---- scenario 4: evidence after retention expiry ----

// drProcessed is the lifecycle projection's checkpoint: per data group, the highest index whose
// evidence the projection has fully processed.
type drProcessed struct {
	mu  sync.Mutex
	idx map[model.ID]uint64
}

func (p *drProcessed) Processed(_ context.Context, group model.ID) (uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.idx[group], nil
}

func (p *drProcessed) mark(group model.ID, index uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.idx[group] = max(p.idx[group], index)
}

func (p *drProcessed) snapshot() map[model.ID]uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[model.ID]uint64, len(p.idx))
	for k, v := range p.idx {
		out[k] = v
	}
	return out
}

// drClockStack is the real engine built the way the retention package's own tests build it (one
// voter, 64 replicated data groups, real control, auth, ingest, retention worker and job
// service) on ONE clock that drives admission deadlines, sessions and the retention worker, so
// "after retention expiry" is reached by advancing the clock, never by editing a deadline.
type drClockStack struct {
	env      *Env
	clock    atomic.Int64
	store    *control.Store
	auth     *auth.Service
	engine   *storage.Engine
	loop     *replica.Loopback
	svc      *retention.Service
	ing      *ingest.Service
	jobs     *jobs.Service
	proc     *drProcessed
	owner    model.ID
	actor    auth.Credential
	org      model.ID
	project  model.ID
	source   model.ID
	cred     auth.SourceCredential
	resource model.Resource
	policy   model.SourcePolicy
}

func (s *drClockStack) now() time.Time { return time.Unix(0, s.clock.Load()) }

type drJobClock struct{ s *drClockStack }

func (c drJobClock) Now() model.UnixNano { return model.UnixNano(c.s.clock.Load()) }

func (s *drClockStack) advance(d time.Duration) { s.clock.Add(int64(d)) }

func (s *drClockStack) close() {
	s.svc.Close()
	s.engine.Close()
	s.loop.Close()
	s.store.Close()
}

// login starts a new session at the stack's clock (sessions expire when the clock moves on).
func (s *drClockStack) login() error {
	session, err := s.auth.Login(s.env.Ctx, drOwnerEmail, drOwnerPassword, "")
	if err != nil {
		return err
	}
	s.actor, err = s.auth.Authenticate(s.env.Ctx, session.Token)
	return err
}

func (s *drClockStack) command(kind string, p auth.AdminPayload) error {
	p.Reason = "delete restore drill"
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	for range 50 {
		var revision model.Revision
		if err = s.store.View(s.env.Ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
			return err
		}
		if _, err = s.auth.AdminCommand(s.env.Ctx, s.actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: s.org, Kind: kind, Payload: raw}); drFault(err) != model.Conflict {
			return err
		}
	}
	return err
}

func drOpenClockStack(env *Env) (*drClockStack, error) {
	ctx := env.Ctx
	dir := filepath.Join(env.Work, "stack")
	if err := env.Approve([]string{dir}, nil); err != nil {
		return nil, err
	}
	s := &drClockStack{env: env, proc: &drProcessed{idx: map[model.ID]uint64{}}, org: model.NewID(), project: model.NewID(), source: model.NewID()}
	s.clock.Store(time.Now().UnixNano())
	var err error
	if s.store, err = control.Open(filepath.Join(dir, "control")); err != nil {
		return nil, err
	}
	fail := func(err error) (*drClockStack, error) {
		if s.engine != nil {
			s.engine.Close()
		}
		if s.loop != nil {
			s.loop.Close()
		}
		s.store.Close()
		return nil, err
	}
	if s.auth, err = auth.NewService(auth.AuthDependencies{Control: s.store, Now: s.now}); err != nil {
		return fail(err)
	}
	if err = s.store.EnableSingle(ctx, filepath.Join(dir, "control", "raft")); err != nil {
		return fail(err)
	}
	boot, err := s.store.BootstrapToken()
	if err != nil {
		return fail(err)
	}
	session, err := s.auth.Bootstrap(ctx, boot, drOwnerEmail, drOwnerPassword)
	if err != nil {
		return fail(err)
	}
	s.owner = session.User
	if s.actor, err = s.auth.Authenticate(ctx, session.Token); err != nil {
		return fail(err)
	}
	for _, step := range []struct {
		kind string
		p    auth.AdminPayload
	}{
		{"create_org", auth.AdminPayload{Name: "evidence drill"}},
		{"create_project", auth.AdminPayload{ID: s.project, Name: "evidence"}},
		{"membership", auth.AdminPayload{UserID: s.owner, Enabled: true}},
		{"grant", auth.AdminPayload{UserID: s.owner, ProjectID: s.project, Enabled: true, Permissions: []string{string(auth.Read), string(auth.PolicyWrite)}}},
	} {
		if err = s.command(step.kind, step.p); err != nil {
			return fail(err)
		}
	}
	service, environment, build := model.NewID(), model.NewID(), model.NewID()
	s.resource = model.Resource{Service: service, Environment: environment, Build: build, Instance: "drill-instance", Labels: model.Labels{}}
	// Lifecycle evidence (job attempts) is kept one day by this source; metrics thirty.
	s.policy = model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric, model.JobAttempt}, Resources: model.ResourceRegistry{Services: []model.ID{service}, Environments: []model.ID{environment}, Builds: []model.ID{build}, Instances: []string{"drill-instance"}}, RetentionDays: map[model.Kind]uint32{model.Metric: 30, model.JobAttempt: 1}, MaxBytes: 1 << 30, MaxSeries: 100000}
	issued, err := s.auth.OnboardSource(ctx, s.actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: s.org, Project: s.project, Source: s.source, Expires: model.UnixNano(s.now().Add(90 * 24 * time.Hour).UnixNano()), Policy: s.policy, Reason: "delete restore drill"})
	if err != nil {
		return fail(err)
	}
	if s.cred, err = s.auth.AuthenticateSource(ctx, issued.Credential, "", false); err != nil {
		return fail(err)
	}
	if s.engine, err = storage.Open(filepath.Join(dir, "data"), s.auth); err != nil {
		return fail(err)
	}
	s.loop = replica.NewLoopback()
	groups, err := s.engine.EnableReplication(replica.Config{ID: 1, Directory: filepath.Join(dir, "data", "raft"), Transport: s.loop, Members: replica.Members{Revision: 1, Nodes: []replica.Member{{ID: 1, Address: "https://single.invalid", NodeIdentity: "single", FailureDomain: "local-disk"}}}}, nil, s.store)
	if err != nil {
		return fail(err)
	}
	for _, g := range groups {
		if err = s.loop.Register(g); err == nil {
			err = g.Campaign()
		}
		if err != nil {
			return fail(err)
		}
	}
	if err = s.store.BindAdmissionOwner(s.engine); err != nil {
		return fail(err)
	}
	if err = s.engine.BindDeletions(s.store); err != nil {
		return fail(err)
	}
	if s.svc, err = retention.New(retention.Config{Control: s.store, Data: s.engine, Base: s.auth.SourceLifecycleGenerations(), Processed: s.proc, Clock: s.now}); err != nil {
		return fail(err)
	}
	if err = s.store.BindJobUpdate(); err != nil {
		return fail(err)
	}
	jobStore, err := jobs.NewControlStore(s.store)
	if err != nil {
		return fail(err)
	}
	if s.jobs, err = jobs.New(jobStore, s.auth, drJobClock{s}); err != nil {
		return fail(err)
	}
	pol, err := policy.New(s.auth, s.now)
	if err != nil {
		return fail(err)
	}
	if s.ing, err = ingest.New(s.auth, pol, s.store, s.engine); err != nil {
		return fail(err)
	}
	return s, nil
}

func (s *drClockStack) send(rec model.Record) (model.Batch, model.Receipt, error) {
	slot, err := model.OwnerSlot(s.org, s.project, s.source, model.ID{}, rec)
	if err != nil {
		return model.Batch{}, model.Receipt{}, err
	}
	b := model.Batch{Version: 1, Project: s.project, Source: s.source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, RouteSlot: slot, Records: []model.Record{rec}}
	g, err := s.ing.ResolveSource(s.env.Ctx, s.cred, b)
	if err != nil {
		return b, model.Receipt{}, err
	}
	r, err := s.ing.Admit(s.env.Ctx, g, b)
	return b, r, err
}

func (s *drClockStack) metric(at model.UnixNano, name string, value uint64) model.Record {
	v := model.FloatBits(math.Float64bits(float64(value)))
	return model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: at, Resource: s.resource, Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: &v, Unit: "1", Type: "counter"}}}
}

// attempt is one succeeded attempt of a job run (the lifecycle evidence kind).
func (s *drClockStack) attempt(job, epoch model.ID, sequence uint64, at model.UnixNano) model.Record {
	run, attempt := model.NewID(), model.NewID()
	terminal := at + model.UnixNano(time.Second)
	ev := &model.JobAttemptEvent{Job: job, Run: run, Attempt: attempt, Schedule: "manual.drill." + run.String()[:8], Ordinal: 1, Epoch: epoch, Sequence: model.Uint64(sequence), State: "succeeded", Observed: at, Terminal: &terminal}
	return model.Record{ID: model.NewID(), Kind: model.JobAttempt, ObservedAt: at, Resource: s.resource, Payload: model.Payload{Job: ev}}
}

func (s *drClockStack) readScope() (auth.Scope, error) {
	return s.auth.Authorize(s.env.Ctx, s.actor, s.org, []model.ID{s.project}, auth.Read)
}

func (s *drClockStack) writeScope() (auth.Scope, error) {
	return s.auth.Authorize(s.env.Ctx, s.actor, s.org, []model.ID{s.project}, auth.PolicyWrite)
}

func (s *drClockStack) health(job model.ID) (jobs.Report, error) {
	scope, err := s.readScope()
	if err != nil {
		return jobs.Report{}, err
	}
	return s.jobs.Health(s.env.Ctx, scope, s.project, job)
}

// drEvidenceGapAfterRetention ACKs lifecycle evidence (job attempts) and ordinary telemetry,
// applies part of the evidence to the job projection, lets the clock run past the evidence's
// retention and runs the real retention worker. The previously ACKed evidence that was neither
// applied nor retained must be an explicit, typed, worker-declared evidence gap with its reason
// on the read path (control gaps and the job health verdict), never an empty success and never
// silently omitted; everything still inside retention reconciles exactly.
func drEvidenceGapAfterRetention(env *Env, rep *Report) error {
	ctx := env.Ctx
	s, err := drOpenClockStack(env)
	if err != nil {
		return err
	}
	defer s.close()
	t0 := s.now()
	hours := func() float64 { return s.now().Sub(t0).Hours() }
	var timeline []map[string]any
	mark := func(event string) {
		timeline = append(timeline, map[string]any{"event": event, "clock_offset_hours": math.Round(hours()*100) / 100})
	}
	job, epoch := model.NewID(), model.NewID()
	nonce := strings.ReplaceAll(model.NewID().String(), "-", "")[:12]
	var evidence []drAcked // every ACKed lifecycle-evidence batch
	byRec := map[model.ID]string{}
	batches := map[string]model.Batch{}
	ack := func(label string, b model.Batch, rec model.Record, r model.Receipt) drAcked {
		a := drAcked{ID: b.ID.String(), Org: s.org, Project: s.project, Record: rec, Cursor: r.Cursor, Digest: drRecordDigest(s.project, s.source, rec), Label: label}
		byRec[rec.ID] = a.ID
		batches[a.ID] = b
		return a
	}
	live := func(label string, rec model.Record) error { // inside retention: reconciled exactly
		b, r, err := s.send(rec)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		a := ack(label, b, rec, r)
		if rec.Kind == model.JobAttempt {
			evidence = append(evidence, a)
		}
		return rep.Ledger().Record(Ack{ID: a.ID, Group: r.Cursor.Group.String(), Index: uint64(r.Cursor.Index), Digest: a.Digest, Label: label})
	}
	expiring := &Ledger{} // acknowledged evidence that will expire (listed in the report, classified below)
	exp := func(label string, rec model.Record) (drAcked, error) {
		b, r, err := s.send(rec)
		if err != nil {
			return drAcked{}, fmt.Errorf("%s: %w", label, err)
		}
		a := ack(label, b, rec, r)
		evidence = append(evidence, a)
		return a, expiring.Record(Ack{ID: a.ID, Group: r.Cursor.Group.String(), Index: uint64(r.Cursor.Index), Digest: a.Digest, Label: label})
	}

	// ---- day 0: the first attempt is ACKed AND applied to the job projection ----
	mark("first attempt ACKed")
	first := s.attempt(job, epoch, 1, model.UnixNano(t0.UnixNano()))
	a1, err := exp("attempt 1 (applied to the job projection)", first)
	if err != nil {
		return err
	}
	s.advance(10 * time.Second)
	if err = s.login(); err != nil {
		return err
	}
	writer, err := s.writeScope()
	if err != nil {
		return err
	}
	if _, outcome, err := s.jobs.ApplyAttempt(ctx, writer, jobs.AttemptEvidence{Project: s.project, Cursor: a1.Cursor, Record: first.ID, Event: *first.Payload.Job}); err != nil || outcome != jobs.Applied {
		return fmt.Errorf("applying attempt 1: %v %v", outcome, err)
	}
	s.proc.mark(a1.Cursor.Group, uint64(a1.Cursor.Index))
	baseline, err := s.health(job)
	if err != nil {
		return err
	}
	if err = rep.Require("baseline_health_before_expiry_is_a_complete_success", baseline.Health.Status == jobs.StatusSucceeded && baseline.Health.Complete && len(baseline.Intervals) == 0,
		fmt.Sprintf("before any evidence is lost the job is %s, complete=%v, %d incomplete intervals", baseline.Health.Status, baseline.Health.Complete, len(baseline.Intervals))); err != nil {
		return err
	}

	// ---- hour 1: four more attempts are ACKed; the projection has not processed them ----
	s.advance(time.Hour)
	if err = s.login(); err != nil {
		return err
	}
	mark("four attempts ACKed, not yet processed by the projection")
	for i := range 4 {
		at := model.UnixNano(s.now().Add(time.Duration(i) * time.Minute).UnixNano())
		if _, err = exp(fmt.Sprintf("attempt %d (ACKed, never processed)", i+2), s.attempt(job, epoch, uint64(i+2), at)); err != nil {
			return err
		}
	}
	for i := range 3 {
		if err = live(fmt.Sprintf("metric %d (30-day retention)", i+1), s.metric(model.UnixNano(s.now().Add(time.Duration(i)*time.Second).UnixNano()), "drill_evidence_metric_"+nonce, uint64(i+1))); err != nil {
			return err
		}
	}

	// ---- hour 47: an unprocessed attempt and more metrics, still inside their retention ----
	s.advance(46 * time.Hour)
	if err = s.login(); err != nil {
		return err
	}
	mark("late attempt and metrics ACKed (inside retention at the expiry pass)")
	if err = live("attempt 7 (ACKed, unprocessed, still inside its one-day retention)", s.attempt(job, epoch, 7, model.UnixNano(s.now().UnixNano()))); err != nil {
		return err
	}
	for i := range 3 {
		if err = live(fmt.Sprintf("metric %d (30-day retention)", i+4), s.metric(model.UnixNano(s.now().Add(time.Duration(i)*time.Second).UnixNano()), "drill_evidence_metric_"+nonce, uint64(i+4))); err != nil {
			return err
		}
	}
	if err = s.store.ReconcileAdmissions(ctx); err != nil {
		return err
	}

	// ---- hour 49: the one-day retention of attempts 1-5 has passed; the worker runs ----
	s.advance(2 * time.Hour)
	if err = s.login(); err != nil {
		return err
	}
	mark("retention expiry pass")
	var runErr error
	for range 5 {
		if runErr = s.svc.RunOnce(ctx); runErr == nil {
			break
		}
	}
	if runErr != nil {
		return fmt.Errorf("retention worker: %w", runErr)
	}
	status := s.svc.Status()

	// ---- the read path after expiry ----
	scope, err := s.readScope()
	if err != nil {
		return err
	}
	gaps, err := s.store.EvidenceGaps(ctx, s.org, s.project)
	if err != nil {
		return err
	}
	scoped, err := s.store.JobGaps(ctx, scope, s.project)
	if err != nil {
		return err
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i].ID.String() < gaps[j].ID.String() })
	sort.Slice(scoped, func(i, j int) bool { return scoped[i].ID.String() < scoped[j].ID.String() })
	if err = rep.Require("gaps_declared_by_the_worker_with_a_reason", len(gaps) > 0 && status.GapsRecorded > 0 && !status.EvidenceHeld && func() bool {
		for _, g := range gaps {
			if g.DeclaredBy != control.GapDeclaredByWorker || g.Reason != "unprocessed_expiry" || g.Count == 0 || uint64(g.Through)-uint64(g.After) != uint64(g.Count) {
				return false
			}
		}
		return true
	}(), fmt.Sprintf("%d committed gap(s); worker status: %d recorded, evidence held=%v; every gap is worker-declared, reason unprocessed_expiry, and counts every entry it covers", len(gaps), status.GapsRecorded, status.EvidenceHeld)); err != nil {
		return err
	}
	sameGaps := len(gaps) == len(scoped)
	for i := range gaps {
		sameGaps = sameGaps && i < len(scoped) && gaps[i].ID == scoped[i].ID
	}
	if err = rep.Require("scoped_gap_read_equals_the_control_gaps", sameGaps, fmt.Sprintf("control reports %d gaps for the project; the authorized job-gap read reports %d, the same ids", len(gaps), len(scoped))); err != nil {
		return err
	}
	report, err := s.health(job)
	if err != nil {
		return err
	}
	verr := drVerifyHealthReportsGap(report, gaps)
	if err = rep.Require("read_path_reports_the_gap_not_an_empty_success", verr == nil, fmt.Sprintf("job health after expiry: status %s, complete=%v, reasons %v, %d gap(s) in the evidence, %d annotated intervals (before expiry: %s, complete=%v); %v", report.Health.Status, report.Health.Complete, report.Health.Reasons, len(report.Health.Evidence.Gaps), len(report.Intervals), baseline.Health.Status, baseline.Health.Complete, verr)); err != nil {
		return err
	}
	if _, ok := report.State.Attempts[first.Payload.Job.Attempt]; !ok {
		return rep.Require("applied_attempt_survives_in_the_projection", false, "the applied attempt 1 is gone from the job state although only its raw record expired")
	}
	if err = rep.Require("applied_attempt_survives_in_the_projection", true, "the processed attempt's effect lives in the job state after its raw record expired (no gap was declared for it)"); err != nil {
		return err
	}

	// ---- every ACKed evidence batch is retained, declared a gap, or processed: never silent ----
	retained := map[string]string{}
	scanned := map[string]int{}
	for _, kind := range []model.Kind{model.JobAttempt, model.Metric} {
		rows, err := drScan(ctx, s.engine, scope, s.project, kind)
		if err != nil {
			return fmt.Errorf("scan %s: %w", kind, err)
		}
		scanned[string(kind)] = len(rows)
		for rec, row := range rows {
			if id, ok := byRec[rec]; ok {
				retained[id] = row.Digest
			} else {
				retained["unknown-record:"+rec.String()] = row.Digest
			}
		}
	}
	results, cerr := drClassifyEvidence(evidence, drOnly(retained, evidence), gaps, s.proc.snapshot())
	verdicts := map[drVerdict]int{}
	for _, r := range results {
		verdicts[r.Verdict]++
	}
	if err = rep.Require("every_acked_evidence_batch_is_retained_or_an_explicit_gap", cerr == nil, fmt.Sprintf("%d ACKed lifecycle-evidence batches: %v; %v", len(evidence), verdicts, cerr)); err != nil {
		return err
	}
	if err = rep.Require("expected_verdicts", verdicts[drGapDeclared] == 4 && verdicts[drProcessedExpired] == 1 && verdicts[drRetained] == 1,
		fmt.Sprintf("attempts 2-5 (ACKed, never processed, expired) are %d gap-declared, attempt 1 (processed) %d processed-then-expired, attempt 7 (inside retention) %d retained", verdicts[drGapDeclared], verdicts[drProcessedExpired], verdicts[drRetained])); err != nil {
		return err
	}
	if err = rep.Reconcile(retained); err != nil {
		return err
	}
	if err = rep.Require("no_unacknowledged_row_retained", len(rep.Reconciliation.UnackedRetained) == 0, fmt.Sprintf("%d retained rows were never acknowledged", len(rep.Reconciliation.UnackedRetained))); err != nil {
		return err
	}

	// ---- report ----
	intervals := make([]map[string]any, 0, len(gaps))
	for _, g := range gaps {
		intervals = append(intervals, map[string]any{"gap": g.ID.String(), "group": g.Group.String(), "after": uint64(g.After), "through": uint64(g.Through), "count": uint64(g.Count), "reason": g.Reason, "declared_by": g.DeclaredBy, "signals": g.Signals, "start_ns": int64(g.Start), "end_ns": int64(g.End)})
	}
	rep.Cursor("evidence_gap_intervals", intervals)
	rep.Cursor("processed_checkpoints", func() map[string]uint64 {
		out := map[string]uint64{}
		for g, v := range s.proc.snapshot() {
			out[g.String()] = v
		}
		return out
	}())
	rep.Fact("raw_scan_after_expiry", map[string]any{"rows_by_signal": scanned, "job_attempts_acked": len(evidence), "note": "the raw scan returns no error and no marker for the expired attempts; only the declared gaps (control and job-health read path) say that evidence is missing"})
	rep.Fact("clock_timeline", timeline)
	rep.Fact("evidence_verdicts", results)
	rep.Fact("job_health_before_expiry", map[string]any{"status": baseline.Health.Status, "complete": baseline.Health.Complete, "reasons": baseline.Health.Reasons})
	rep.Fact("job_health_after_expiry", map[string]any{"status": report.Health.Status, "complete": report.Health.Complete, "reasons": report.Health.Reasons, "gaps_in_evidence": len(report.Health.Evidence.Gaps), "intervals": report.Intervals})
	rep.Fact("expired_acked_evidence", map[string]any{"count": expiring.Len(), "ack_ledger_note": "these ACKed batches are classified above; they are not in ack_ledger because ack_ledger holds what must still be retained"})
	rep.Fact("retention_worker", map[string]any{"gaps_recorded": status.GapsRecorded, "evidence_held": status.EvidenceHeld, "expiry_erased": status.ExpiryErased})
	return drRequireRecorded(rep, "baseline_health_before_expiry_is_a_complete_success", "gaps_declared_by_the_worker_with_a_reason", "scoped_gap_read_equals_the_control_gaps", "read_path_reports_the_gap_not_an_empty_success", "applied_attempt_survives_in_the_projection",
		"every_acked_evidence_batch_is_retained_or_an_explicit_gap", "expected_verdicts", "exact_reconciliation", "no_unacknowledged_row_retained")
}

// drOnly restricts retained rows to the evidence batches that were ACKed (the metric rows are
// reconciled by the exact reconciliation; unknown rows stay so they are reported).
func drOnly(retained map[string]string, evidence []drAcked) map[string]string {
	ids := map[string]bool{}
	for _, a := range evidence {
		ids[a.ID] = true
	}
	out := map[string]string{}
	for id, d := range retained {
		if ids[id] {
			out[id] = d
		}
	}
	return out
}

// drRetireRace is the scenario's second all-shard barrier: retire_project, raced by senders that
// hold the project's policy revision and by a stale policy command. A retired source must stay
// retired (never remapped by a policy command or a send), every send after the retirement began
// is refused, every data group gets a barrier, and the project's bytes are gone from every store.
func drRetireRace(s *drSite, rep *Report, kinds []model.Kind, days map[model.Kind]uint32) error {
	ctx := s.env.Ctx
	proj, err := s.addProject("retired", kinds, days)
	if err != nil {
		return err
	}
	pred := model.DeletePredicate{Org: s.org, Mode: model.DeleteRetireProject, Projects: []model.ID{proj.id}}
	led := newDrLedgers(&Report{}, pred) // every ACK of a retired project is inside the predicate
	name := "drill_retired_" + strings.ReplaceAll(model.NewID().String(), "-", "")[:12]
	for slot := range 16 {
		b, rec, err := proj.metric(s.org, 1, 3000+int64(slot), name, uint64(slot), slot*4)
		if err != nil {
			return err
		}
		r, err := s.send(proj, b)
		if err != nil {
			return fmt.Errorf("retired project seed: %w", err)
		}
		if err = led.ack("retired project seed", s.org, proj, b, rec, r); err != nil {
			return err
		}
	}
	if err = s.app.Storage.Flush(ctx); err != nil {
		return err
	}
	needle := []drNeedle{{"retired", []byte(name)}}
	before, err := drStoreHits(s.dir, needle)
	if err != nil {
		return err
	}
	if err = rep.Require("retire_physical_positive_control", drHitTotal(before, "retired") > 0, fmt.Sprintf("before the retirement the scanner finds the project's canary in %v", drHitStores(before, "retired"))); err != nil {
		return err
	}
	var policyBefore model.SourceAuthority
	if err = s.app.Control.View(ctx, func(st model.ControlState) error { policyBefore = st.Sources[proj.source.String()]; return nil }); err != nil {
		return err
	}

	type outcome struct {
		after bool // the call started after the retirement's Begin had returned
		acked bool
		code  model.Code
	}
	var (
		mu       sync.Mutex
		sends    []outcome
		policies []outcome
		begun    atomic.Bool
		stop     atomic.Bool
		wg       sync.WaitGroup
		seq      atomic.Int64
	)
	count := func(list *[]outcome, after bool) int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, o := range *list {
			if o.after == after {
				n++
			}
		}
		return n
	}
	// As in the range-deletion race, Begin is an optimistic control commit keyed on the control
	// revision that every admission (and every login) advances: it is tried under full load first
	// and then under a short write lock that pauses only NEW racer iterations for that one commit.
	var gate sync.RWMutex
	wg.Add(2)
	go func() { // a sender holding the project's current policy revision
		defer wg.Done()
		for !stop.Load() {
			func() {
				gate.RLock()
				defer gate.RUnlock()
				after := begun.Load()
				b, rec, err := proj.metric(s.org, 1, 4000+seq.Add(1), name+"_race", 1, -1)
				if err != nil {
					return
				}
				r, err := s.send(proj, b)
				if err == nil {
					_ = led.ack("retired project race", s.org, proj, b, rec, r)
				}
				mu.Lock()
				sends = append(sends, outcome{after, err == nil, drFault(err)})
				mu.Unlock()
			}()
			time.Sleep(3 * time.Millisecond)
		}
	}()
	go func() { // a policy command built against a revision that was never current
		defer wg.Done()
		for !stop.Load() {
			func() {
				gate.RLock()
				defer gate.RUnlock()
				after := begun.Load()
				cred, err := s.fresh()
				if err != nil {
					return
				}
				next := proj.policy
				next.Revision = 2
				next.MaxBytes++
				_, err = s.app.Auth.ChangeSourcePolicy(ctx, cred, auth.SourcePolicyChange{CommandID: model.NewID(), Source: proj.source, ExpectedRevision: 7, Policy: next, Reason: "delete restore drill: stale policy command against a retiring source"})
				mu.Lock()
				policies = append(policies, outcome{after, err == nil, drFault(err)})
				mu.Unlock()
			}()
			time.Sleep(3 * time.Millisecond)
		}
	}()
	halt := func() { stop.Store(true); wg.Wait() }
	for deadline := time.Now().Add(time.Minute); count(&sends, false) < 3 || count(&policies, false) < 3; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			halt()
			return errors.New("the retirement racers did not start")
		}
	}
	beginOnce := func(gated bool) (retention.DeleteReceipt, error) {
		if gated {
			gate.Lock()
			defer gate.Unlock()
		}
		scope, err := s.adminScope()
		if err != nil {
			return retention.DeleteReceipt{}, err
		}
		rev, err := s.revision()
		if err != nil {
			return retention.DeleteReceipt{}, err
		}
		r, err := s.app.Retention.Delete(ctx, scope, retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: rev, Mode: pred.Mode, OrgID: s.org, ProjectIDs: pred.Projects, Reason: "delete restore drill: retire a project under racing senders"})
		if err == nil {
			begun.Store(true) // before the gate opens: every iteration that starts later is "after Begin"
		}
		return r, err
	}
	var receipt retention.DeleteReceipt
	beginConflicts := 0
	for attempt := 0; attempt < 200; attempt++ {
		receipt, err = beginOnce(attempt >= 20)
		if drFault(err) != model.Conflict {
			break
		}
		beginConflicts++
	}
	if err != nil {
		halt()
		return fmt.Errorf("retire begin: %w", err)
	}
	rep.Fact("retire_begin", map[string]any{"conflicts_before_begin_committed": beginConflicts, "attempts_under_full_load_before_the_gate": 20})
	samples := []drFenceSample{drSample(1, receipt)}
	var done retention.DeleteReceipt
	for deadline := time.Now().Add(5 * time.Minute); ; time.Sleep(25 * time.Millisecond) {
		_ = s.app.Retention.RunOnce(ctx)
		scope, err := s.adminScope()
		if err != nil {
			halt()
			return err
		}
		r, err := s.app.Retention.PollDelete(ctx, scope, receipt.OperationID)
		if err != nil {
			halt()
			return err
		}
		samples = append(samples, drSample(len(samples)+1, r))
		if r.Phase == model.DeletePhaseComplete && r.Physical == retention.PhysicalDone {
			done = r
			break
		}
		if time.Now().After(deadline) {
			halt()
			return fmt.Errorf("the retirement did not finish: phase %s progress %s physical %s", r.Phase, r.Progress, r.Physical)
		}
	}
	for deadline := time.Now().Add(time.Minute); count(&sends, true) < 20 || count(&policies, true) < 20; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			break
		}
	}
	halt()

	ackedAfter, policyAppliedAny, nSendsAfter, nPoliciesAfter := 0, 0, 0, 0
	sendCodes, policyCodes := map[string]int{}, map[string]int{}
	mu.Lock()
	for _, o := range sends {
		if o.after {
			nSendsAfter++
			sendCodes[string(o.code)]++
			if o.acked {
				ackedAfter++
			}
		}
	}
	for _, o := range policies {
		if o.acked {
			policyAppliedAny++
		}
		if o.after {
			nPoliciesAfter++
			policyCodes[string(o.code)]++
		}
	}
	mu.Unlock()
	var op model.DeletionOperation
	var after model.SourceAuthority
	if err = s.app.Control.View(ctx, func(st model.ControlState) error {
		op = st.Deletions[receipt.OperationID.String()]
		after = st.Sources[proj.source.String()]
		return nil
	}); err != nil {
		return err
	}
	if err = rep.Require("retired_source_stays_retired_and_unmapped", after.Retired && !after.Closing && ackedAfter == 0 && policyAppliedAny == 0 && drPolicyDigest(after.Policy) == drPolicyDigest(policyBefore.Policy) && after.Policy.Revision == policyBefore.Policy.Revision,
		fmt.Sprintf("after the retirement the source is retired=%v closing=%v with its original policy revision %d; %d sends after Begin all refused (%v), %d stale policy commands after Begin all refused (%v), %d policy commands applied in total", after.Retired, after.Closing, after.Policy.Revision, nSendsAfter, sendCodes, nPoliciesAfter, policyCodes, policyAppliedAny)); err != nil {
		return err
	}
	if err = rep.Require("retire_race_overlapped", nSendsAfter >= 20 && nPoliciesAfter >= 20, fmt.Sprintf("%d sends and %d policy commands were made after Begin returned, while the barriers were recorded and the physical cleanup ran", nSendsAfter, nPoliciesAfter)); err != nil {
		return err
	}
	if err = rep.Require("retire_fence_monotone_and_complete", drVerifyFence(samples, drSlots) == nil, fmt.Sprintf("%d receipt samples; %v", len(samples), drVerifyFence(samples, drSlots))); err != nil {
		return err
	}
	if err = rep.Require("retire_barrier_in_every_data_group", drVerifyBarrierCoverage(op.Barriers, drSlots) == nil, fmt.Sprintf("%d recorded barrier cursors; %v", len(op.Barriers), drVerifyBarrierCoverage(op.Barriers, drSlots))); err != nil {
		return err
	}
	_, readErr := s.readScope(proj.id)
	if err = rep.Require("retired_project_unreadable", readErr != nil, fmt.Sprintf("an authorized read scope for the retired project is refused with %q", drFault(readErr))); err != nil {
		return err
	}
	hits, err := drStoreHits(s.dir, needle)
	if err != nil {
		return err
	}
	declared := map[string]bool{}
	for _, st := range done.Residual {
		declared[st] = true
	}
	undeclared := 0
	for store, byLabel := range hits {
		if !declared[store] {
			undeclared += byLabel["retired"]
		}
	}
	if err = rep.Require("retired_project_bytes_gone_from_every_store", undeclared == 0 && done.Physical == retention.PhysicalDone, fmt.Sprintf("physical=%s; the retired project's canary (%d ACKed batches) is found %d times outside declared residual stores %v", done.Physical, len(led.gone), undeclared, done.Residual)); err != nil {
		return err
	}
	rep.Fact("retire_race", map[string]any{"operation": receipt.OperationID.String(), "acked_before_begin": len(led.gone), "sends_after_begin": nSendsAfter, "send_refusal_codes": sendCodes, "policy_commands_after_begin": nPoliciesAfter, "policy_refusal_codes": policyCodes, "barriers": len(op.Barriers), "receipt_samples": len(samples)})
	return nil
}
