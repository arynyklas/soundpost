// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/arynyklas/soundpost/internal/gitlab/gitlabtest"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
)

const (
	d92Title = "Checkout fails after deploy"
	d92Note  = "Rolled the deploy back; watching the error rate."
)

// writes performs every D92 write over HTTP as the organization administrator, in the order of the
// documentation (the GitLab connection is an organization setting both releases accept; it is not a D92 record).
func (d *d92Install) writes() map[string]d92Answer {
	out := map[string]d92Answer{}
	out["issue_assign"] = d.assignIssue()
	out["incident_title"] = d.titleIncident()
	out["incident_note"] = d.noteIncident()
	out["gitlab_connect"] = d.connectGitLab()
	out["gitlab_create_incident"] = d.createGitLab("incident", d.incident)
	out["gitlab_create_issue"] = d.createGitLab("issue", d.issue)
	return out
}

func timelineTypes(v httpapi.IncidentView) []string {
	var out []string
	for _, e := range v.Timeline {
		out = append(out, e.Type)
	}
	return out
}

// requireCommitted requires a 200 committed action whose body decodes.
func requireCommitted(t *testing.T, what string, ans d92Answer) httpapi.ActionResponse {
	t.Helper()
	r := mustJSON[httpapi.ActionResponse](t, what, ans)
	if r.State != httpapi.ActionCommitted {
		t.Fatalf("%s: not committed: %s", what, ans)
	}
	return r
}

func requireLinked(t *testing.T, what string, ans d92Answer, created bool, iid string) httpapi.GitLabResultView {
	t.Helper()
	r := mustJSON[httpapi.GitLabResultView](t, what, ans)
	if r.State != "linked" || r.Created != created || r.IID == nil || strconv.FormatUint(uint64(*r.IID), 10) != iid {
		t.Fatalf("%s: want linked created=%v iid=%s, got %s", what, created, iid, ans)
	}
	return r
}

// d92Records is what the candidate's reads must show once every D92 write was made.
func (d *d92Install) requireRecords(t *testing.T, label string, issueRecords bool) {
	t.Helper()
	inc := mustJSON[httpapi.IncidentView](t, label+" incident get", d.incidentGet())
	if inc.Title != d92Title || len(inc.External) != 1 || inc.External[0].State != "linked" || !strings.HasPrefix(inc.External[0].URL, d.stub.URL+"/shop/web/-/issues/") ||
		!reflect.DeepEqual(timelineTypes(inc), []string{"open", "title", "note", "external_begin", "external_end"}) || inc.Timeline[2].Note != d92Note || inc.Timeline[1].Title != d92Title {
		t.Errorf("%s: the incident does not hold its title, note and link: %s", label, d.incidentGet())
	}
	md := mustJSON[struct{ Markdown string }](t, label+" markdown", d.markdown("/api/v1/incidents/markdown", d.incident))
	if !strings.Contains(md.Markdown, d92Title) || !strings.Contains(md.Markdown, "Rolled the deploy back") { // the export escapes punctuation of the note
		t.Errorf("%s: the timeline export lacks the title or note", label)
	}
	pi := mustJSON[httpapi.GitLabPreviewView](t, label+" incident preview", d.gitlabPreview("incident", d.incident))
	if pi.Existing == nil || pi.Existing.State != "linked" || !strings.HasPrefix(pi.Existing.URL, d.stub.URL+"/shop/web/-/issues/") {
		t.Errorf("%s: the incident preview does not show its link: %+v", label, pi.Existing)
	}
	iss := mustJSON[httpapi.IssueView](t, label+" issue evidence", d.issueEvidence())
	pj := mustJSON[httpapi.GitLabPreviewView](t, label+" issue preview", d.gitlabPreview("issue", d.issue))
	if issueRecords {
		if iss.Grouping == nil || iss.Grouping.Owner == nil || *iss.Grouping.Owner != d.admin.id || len(iss.Grouping.External) != 1 || iss.Grouping.External[0].State != "linked" ||
			pj.Existing == nil || pj.Existing.State != "linked" {
			t.Errorf("%s: the issue does not hold its owner and link: %s", label, d.issueEvidence())
		}
	} else if iss.Grouping == nil || iss.Grouping.Owner != nil || len(iss.Grouping.External) != 0 || pj.Existing != nil {
		t.Errorf("%s: the issue still shows an owner or a link: %s", label, d.issueEvidence())
	}
}

// requireOnlyOwnerAndExternalDropped requires the stored issue records of after to be those of before without
// their owner and external members, and nothing else changed.
func requireOnlyOwnerAndExternalDropped(t *testing.T, before, after string) {
	t.Helper()
	var b, a map[string]map[string]any
	if json.Unmarshal([]byte(before), &b) != nil || json.Unmarshal([]byte(after), &a) != nil || len(b) == 0 {
		t.Fatal("the stored issue records do not decode")
	}
	for _, rec := range b {
		if rec["owner"] == nil || rec["external"] == nil {
			t.Fatal("the stored issue record did not hold the owner and the link before the previous release ran")
		}
		delete(rec, "owner")
		delete(rec, "external")
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("the previous release changed the stored issue records by more than the owner and the external link:\n before %v\n after  %v", b, a)
	}
}

// storedMarker is the control-state format marker in the stored state of the data directory.
func (d *d92Install) storedMarker() uint8 {
	d.t.Helper()
	state, _, err := readControlState(d.oldHost.dir)
	if err != nil {
		d.t.Fatal(err)
	}
	var st struct{ BearerHashKeyVersion uint8 }
	if err = json.Unmarshal(state, &st); err != nil {
		d.t.Fatal(err)
	}
	return st.BearerHashKeyVersion
}

// writtenInstall makes a fresh installation with the candidate (born contracted), makes every D92 write over HTTP as
// an organization administrator, checks every record, stops the candidate and returns its reads. requireMarker says
// the format marker must be up afterwards (D94); the test that puts it back by hand does not need to ask.
func (d *d92Install) writtenInstall(t *testing.T, requireMarker bool) []d92Named {
	t.Helper()
	run := d.start(d.newHost)
	d.provision(run)
	if orgMark, born := d.contracted(); !orgMark || !born {
		t.Fatalf("a fresh data directory started by the candidate is not born contracted (organization %v, installation %v)", orgMark, born)
	}
	if m := d.storedMarker(); m != model.FormatMarkerBase {
		t.Fatalf("the format marker is %d before any D92 record, want %d", m, model.FormatMarkerBase)
	}

	// ---- every D92 write succeeds on a contracted installation ----
	w := d.writes()
	if r := requireCommitted(t, "issue assign", w["issue_assign"]); r.Issue == nil || r.Issue.Owner == nil || *r.Issue.Owner != d.admin.id {
		t.Fatalf("issue assign: %s", w["issue_assign"])
	}
	if r := requireCommitted(t, "incident title", w["incident_title"]); r.Incident == nil || r.Incident.Title != d92Title {
		t.Fatalf("incident title: %s", w["incident_title"])
	}
	if r := requireCommitted(t, "incident note", w["incident_note"]); r.Incident == nil || len(r.Incident.Timeline) == 0 || r.Incident.Timeline[len(r.Incident.Timeline)-1].Note != d92Note {
		t.Fatalf("incident note: %s", w["incident_note"])
	}
	if v := mustJSON[httpapi.GitLabSettingsView](t, "gitlab connect", w["gitlab_connect"]); v.State != httpapi.ActionCommitted || !v.Connected {
		t.Fatalf("gitlab connect: %s", w["gitlab_connect"])
	}
	requireLinked(t, "gitlab create incident", w["gitlab_create_incident"], true, "1")
	requireLinked(t, "gitlab create issue", w["gitlab_create_issue"], true, "2")
	if d.stub.Posts() != 2 {
		t.Fatalf("the stub GitLab received %d issue creations, want 2", d.stub.Posts())
	}
	if m := d.storedMarker(); requireMarker && m != model.FormatMarkerRecords {
		t.Errorf("the D92 records are written but the format marker is %d, want %d (the previous release must refuse to start)", m, model.FormatMarkerRecords)
	}
	d.requireRecords(t, "new binary", true)
	reads := d.candidateReads()
	if err := run.stop(); err != nil {
		t.Fatal(err)
	}
	return reads
}

// TestD92RollbackWithoutTheMarker records what the previous release does on D92 records when the format marker
// is NOT up (the marker put back to the previous release's value on the stopped directory): the hazard the marker exists to
// prevent. It starts, reads, and drops the records. Asserted exactly.
func TestD92RollbackWithoutTheMarker(t *testing.T) {
	d92Releases(t)
	d := newD92Install(t, gitlabtest.New(t))
	reads := d.writtenInstall(t, false)
	versionNew := mustJSON[httpapi.IncidentView](t, "incident reads", reads[0].ans).Version
	if _, err := setSchemaMarker(d.oldHost.dir, model.FormatMarkerBase); err != nil {
		t.Fatal(err)
	}
	stateNew := d.storedKeys(d.oldHost.dir)

	// ---- the previous release on that very directory ----
	// It starts and is ready (no refusal), and a few worker passes later (before any request) it has already rewritten the stored issue records.
	r, obs := d.observe(d.oldHost)
	d.report("old_binary", obs)
	if r == nil || obs.Exited || !obs.Ready {
		t.Fatalf("the previous release did not start and become ready on the contracted data: %+v\n%s", obs, lastLines(obs.LogTail, 8))
	}
	time.Sleep(12 * time.Second) // two passes of the default 5 s worker interval
	mid := d.storedKeys(d.oldHost.dir)
	issuesRewrittenWithoutRequests := mid["GroupingIssues"] != stateNew["GroupingIssues"]
	d.report("old_rewrites_issue_records_before_any_request", issuesRewrittenWithoutRequests)
	if err := d.admin.login(d.site); err != nil {
		t.Fatal(err)
	}
	oldReads := d.previousReads()
	for _, x := range oldReads {
		d.report("old_read_"+x.name, x.ans.Full())
	}
	// it answers the incident reads (the unknown members are ignored: no title, no note text, no link; the
	// timeline entries are listed by type) and the issue read (no owner, no link) with 200s, never a typed refusal.
	byName := map[string]d92Answer{}
	for _, x := range oldReads {
		byName[x.name] = x.ans
	}
	oldInc := mustJSON[httpapi.IncidentView](t, "old incident get", byName["incident_get"])
	if oldInc.Version != versionNew || oldInc.Title != "" || len(oldInc.External) != 0 || !reflect.DeepEqual(timelineTypes(oldInc), []string{"open", "title", "note", "external_begin", "external_end"}) {
		t.Errorf("old incident read: %s", byName["incident_get"])
	}
	for _, e := range oldInc.Timeline {
		if e.Title != "" || e.Note != "" || e.External != nil {
			t.Errorf("the previous release shows the text of a D92 timeline entry: %+v", e)
		}
	}
	if byName["queue"].Status != 200 {
		t.Errorf("old queue: %s", byName["queue"])
	}
	if oldIssue := mustJSON[httpapi.IssueView](t, "old issue evidence", byName["issue_evidence"]); oldIssue.Grouping == nil || oldIssue.Grouping.Owner != nil || len(oldIssue.Grouping.External) != 0 {
		t.Errorf("old issue read shows an owner or a link: %s", byName["issue_evidence"])
	}
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	stateOld := d.storedKeys(d.oldHost.dir)
	changed := differing(stateNew, stateOld)
	d.report("old_changed_state", changed)
	// Stored by the previous release: the incident records are byte for byte what the candidate wrote (their title, notes and link stay in
	// the control state); the organizations, the settings (the GitLab connection and its sealed token) and every other member are untouched.
	// The stored issue records are rewritten WITHOUT their owner and external link, the revision unchanged.
	// The rest is ordinary activity of the previous release's workers and sessions (delivery books, command records, the revision).
	for _, k := range changed {
		switch k {
		case "GroupingIssues", "Revision", "Sessions", "authority_revision", "Commands", "CommandOwners", "DeliveryBooks":
		default:
			t.Errorf("the previous release changed the stored control state member %s", k)
		}
	}
	if stateNew["IncidentBooks"] != stateOld["IncidentBooks"] || !strings.Contains(stateOld["IncidentBooks"], d92Title) || !strings.Contains(stateOld["IncidentBooks"], d92Note) {
		t.Errorf("the incident records were changed by the previous release")
	}
	if !issuesRewrittenWithoutRequests {
		t.Errorf("the previous release rewrote the issue records only when asked, not on its own")
	}
	requireOnlyOwnerAndExternalDropped(t, stateNew["GroupingIssues"], stateOld["GroupingIssues"])

	// ---- an ordinary write of the previous release on a COPY: an incident ack with the title, note and link in place ----
	probeDir := t.TempDir() + "/copy"
	if err := copyDataDir(d.oldHost.dir, probeDir); err != nil {
		t.Fatal(err)
	}
	probe := &binaryHost{path: d.oldHost.path, dir: probeDir, holdDir: d.oldHost.holdDir, logs: d.oldHost.logs, args: d.oldHost.args}
	pr, pobs := d.observe(probe)
	if pr == nil || !pobs.Ready {
		t.Fatalf("the previous release on the copy: %+v", pobs)
	}
	if err := d.admin.login(d.site); err != nil {
		t.Fatal(err)
	}
	ack := d.incidentAction(httpapi.ActionAck, httpapi.ActionPayload{})
	d.report("old_ack_on_copy", ack.Full())
	_ = pr.stop()
	probed := d.storedKeys(probeDir)
	// Measured, asserted exactly: the previous release answers the ack 400 incident_action_invalid, yet commits it (version 6, an ack) and
	// stores the incident WITHOUT its title and external links and with the title, note and link transitions of its timeline stripped of their
	// content: the title and the note text are gone from the control state. This is the one-way loss of rolling back after a D92 record.
	if code, detail := ack.typed(); ack.Status != 400 || code != "invalid" || detail != "incident_action_invalid" {
		t.Errorf("the previous release's ack on an incident with D92 records: want 400 invalid incident_action_invalid, got %s", ack)
	}
	var books map[string]struct {
		Version string
		State   map[string]any
	}
	if err := json.Unmarshal([]byte(probed["IncidentBooks"]), &books); err != nil || len(books) != 1 {
		t.Fatalf("the stored incident books of the copy do not decode: %v", err)
	}
	for _, b := range books {
		timeline, _ := b.State["timeline"].([]any)
		if b.Version != "6" || b.State["ack"] == nil || b.State["title"] != nil || b.State["external"] != nil || len(timeline) != 6 {
			t.Errorf("the incident the previous release stored: version %s ack %v title %v external %v timeline %d", b.Version, b.State["ack"], b.State["title"], b.State["external"], len(timeline))
		}
	}
	if strings.Contains(probed["IncidentBooks"], d92Title) || strings.Contains(probed["IncidentBooks"], "Rolled the deploy back") || strings.Contains(probed["IncidentBooks"], "soundpost-ref-") {
		t.Errorf("the title, the note or the link marker survived the previous release's write")
	}
	d.report("old_ack_incident_books", probed["IncidentBooks"])

	// ---- the candidate again on the original directory ----
	run := d.start(d.newHost)
	defer run.stop()
	after := d.candidateReads()
	requireSameReads(t, "the incident records after the previous release ran", pick(reads, "incident_get", "queue", "incident_timeline_markdown", "gitlab_preview_incident", "gitlab_settings"),
		pick(after, "incident_get", "queue", "incident_timeline_markdown", "gitlab_preview_incident", "gitlab_settings"))
	// The issue records are what the previous release left: no owner and no link. The link is recovered from GitLab by its marker (recheck
	// never creates), the owner by assigning again; the GitLab issue is not created a second time.
	d.requireRecords(t, "after the previous release", false)
	re := d.post("/api/v1/gitlab/issues", map[string]any{"op": httpapi.GitLabOpRecheck, "org": d.fx.org, "project_id": d.fx.project, "entity": map[string]any{"kind": "issue", "id": d.issue}})
	requireLinked(t, "recheck of the issue", re, false, "2")
	requireCommitted(t, "assign again", d.assignIssue())
	if d.stub.Posts() != 2 {
		t.Errorf("the stub GitLab received %d issue creations after the round trip, want still 2", d.stub.Posts())
	}
	d.requireRecords(t, "after recovery", true)
}

// pick selects reads by name.
func pick(all []d92Named, names ...string) []d92Named {
	var out []d92Named
	for _, n := range names {
		for _, r := range all {
			if r.name == n {
				out = append(out, r)
			}
		}
	}
	return out
}

func TestD92RollbackNotContracted(t *testing.T) {
	d92Releases(t)
	d := newD92Install(t, gitlabtest.New(t))
	run := d.start(d.oldHost)
	d.provision(run)
	oldBefore := d.previousReads()
	if err := run.stop(); err != nil {
		t.Fatal(err)
	}
	stateBefore := d.storedKeys(d.oldHost.dir)

	run = d.start(d.newHost)
	if orgMark, born := d.contracted(); orgMark || born {
		t.Fatalf("an installation the previous release bootstrapped is contracted (organization %v, installation %v)", orgMark, born)
	}
	newBefore := d.previousReads()
	w := d.writes()
	// every D92 write is refused, typed, and the GitLab connection (an organization setting the previous release ignores) is not a D92 record
	for _, name := range []string{"issue_assign", "incident_title", "incident_note", "gitlab_create_incident", "gitlab_create_issue"} {
		if !w[name].uncontracted() {
			t.Errorf("%s on a non-contracted installation: want 501 unsupported needs_contracted_installation, got %s", name, w[name])
		}
	}
	if v := mustJSON[httpapi.GitLabSettingsView](t, "gitlab connect", w["gitlab_connect"]); v.State != httpapi.ActionCommitted || !v.Connected {
		t.Errorf("gitlab connect: %s", w["gitlab_connect"])
	}
	// nothing was written: the same reads, and GitLab was never called (the refusal comes before the lease)
	requireSameReads(t, "the candidate after the refused writes", newBefore, d.previousReads())
	if n := len(d.stub.Tokens()); n != 0 || d.stub.Posts() != 0 {
		t.Errorf("the stub GitLab saw %d requests and %d creations, want none", n, d.stub.Posts())
	}
	inc := mustJSON[httpapi.IncidentView](t, "incident get", d.incidentGet())
	iss := mustJSON[httpapi.IssueView](t, "issue evidence", d.issueEvidence())
	if inc.Title != "" || len(inc.External) != 0 || !reflect.DeepEqual(timelineTypes(inc), []string{"open"}) || iss.Grouping == nil || iss.Grouping.Owner != nil || len(iss.Grouping.External) != 0 {
		t.Errorf("a refused D92 write left a record: %s / %s", d.incidentGet(), d.issueEvidence())
	}
	if err := run.stop(); err != nil {
		t.Fatal(err)
	}
	stateAfter := d.storedKeys(d.oldHost.dir)
	for _, k := range []string{"IncidentBooks", "GroupingIssues", "BearerHashKeyVersion"} {
		if stateBefore[k] != stateAfter[k] {
			t.Errorf("the candidate changed the stored %s although every D92 write was refused", k)
		}
	}
	if stateAfter["BearerHashKeyVersion"] != "1" {
		t.Errorf("the format marker is %s after refused D92 writes, want 1 (a refused write must not close the rollback)", stateAfter["BearerHashKeyVersion"])
	}

	// the previous release then reads everything as before (the GitLab connection is an unknown organization setting it ignores)
	run = d.start(d.oldHost)
	defer run.stop()
	requireSameReads(t, "the previous release after the refusals", oldBefore, d.previousReads())
}

// d92Tree is the content of a data directory: every entry by relative path with its mode and the SHA-256 of its bytes.
func d92Tree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		info, err := e.Info()
		if err != nil {
			return err
		}
		if e.IsDir() {
			out[filepath.ToSlash(rel)+"/"] = info.Mode().String()
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		out[filepath.ToSlash(rel)] = fmt.Sprintf("%s %d %x", info.Mode(), len(raw), sum[:8])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// requireSameTree requires two trees to be identical: nothing changed, nothing added, nothing removed.
func requireSameTree(t *testing.T, what string, before, after map[string]string) {
	t.Helper()
	var diffs []string
	for k, v := range before {
		if w, ok := after[k]; !ok {
			diffs = append(diffs, "removed "+k)
		} else if w != v {
			diffs = append(diffs, "changed "+k+" ("+v+" -> "+w+")")
		}
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			diffs = append(diffs, "added "+k)
		}
	}
	sort.Strings(diffs)
	if len(diffs) > 0 {
		t.Errorf("%s: the data directory is not byte-identical:\n  %s", what, strings.Join(diffs, "\n  "))
	}
}

// TestD92RollbackFailsClosed (D94): once the first D92 record is written the format marker is up, and the previous release REFUSES to
// start on the data directory (readiness reason schema_newer, nothing served, the process stays up until stopped); the directory is
// byte-identical afterwards, and the candidate started again reads every D92 record, issue owner and links included.
func TestD92RollbackFailsClosed(t *testing.T) {
	d92Releases(t)
	d := newD92Install(t, gitlabtest.New(t))
	reads := d.writtenInstall(t, true)
	before := d92Tree(t, d.oldHost.dir)
	controlPath := findDataFile(d.oldHost.dir, "control.db")
	controlRel, _ := filepath.Rel(d.oldHost.dir, controlPath)
	controlRel = filepath.ToSlash(controlRel)
	rawBefore, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatal(err)
	}
	dumpBefore := d92Dump(t, controlPath)

	r, obs := d.observe(d.oldHost)
	d.report("old_binary", obs)
	d.report("old_log", obs.LogTail)
	if r == nil || obs.Exited || obs.Ready || obs.Reason != "schema_newer" {
		t.Fatalf("the previous release on D92 data: want a live process, unready with schema_newer, got %+v\n%s", obs, lastLines(obs.LogTail, 8))
	}
	const want = "schema_newer: the control-state format marker of this data directory (2) is newer than the one this binary supports (1); nothing is served"
	if !strings.Contains(obs.LogTail, want) {
		t.Errorf("the previous release's refusal line is not %q:\n%s", want, lastLines(obs.LogTail, 8))
	}
	if code, raw, err := d.site.get("/readyz"); err != nil || code != 503 || !strings.Contains(string(raw), `"reason":"schema_newer"`) {
		t.Errorf("/readyz of the previous release: %d %s %v", code, raw, err)
	}
	if code, raw, err := d.site.post("/api/v1/login", map[string]string{"Email": d.admin.email, "Password": d.admin.password, "Code": ""}, "", ""); err != nil || code == 200 {
		t.Errorf("the previous release served a login on D92 data: %d %s %v", code, raw, err)
	}
	if err := r.stop(); err != nil {
		t.Errorf("the previous release did not stop cleanly: %v", err)
	}
	// Nothing was written: every file is byte-identical but control.db, which bbolt opens read-write and commits an empty
	// transaction into (the two meta pages, 0 and 1: transaction ID and checksum, and the freelist page it rewrites); every bucket,
	// key and value of it is the same.
	after := d92Tree(t, d.oldHost.dir)
	rawAfter, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatal(err)
	}
	pages := differingPages(rawBefore, rawAfter)
	d.report("old_control_db_differing_pages", pages)
	free := freelistPages(rawBefore)
	for p := range freelistPages(rawAfter) {
		free[p] = true
	}
	for _, p := range pages {
		if p != 0 && p != 1 && !free[p] {
			t.Errorf("the previous release changed page %d of control.db, which is neither a meta page nor a freelist page: %v (freelist %v)", p, pages, free)
		}
	}
	if dumpAfter := d92Dump(t, controlPath); !reflect.DeepEqual(dumpBefore, dumpAfter) {
		t.Errorf("the previous release changed the content of control.db")
	}
	delete(before, controlRel)
	delete(after, controlRel)
	requireSameTree(t, "after the previous release refused", before, after)

	run := d.start(d.newHost)
	defer run.stop()
	requireSameReads(t, "the candidate after the refused rollback", reads, d.candidateReads())
	d.requireRecords(t, "after the refused rollback", true)
	if ans := d.incidentAction(httpapi.ActionNote, httpapi.ActionPayload{Note: "after the refused rollback"}); ans.Status != 200 {
		t.Errorf("a D92 write after the refused rollback: %s", ans)
	}
}

// d92Dump is every bucket, key and value (as a SHA-256) of a bbolt file, read from a private copy.
func d92Dump(t *testing.T, path string) map[string]string {
	t.Helper()
	db, closeDB, err := copyForRead(path)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()
	out := map[string]string{}
	var walk func(prefix string, b *bolt.Bucket)
	walk = func(prefix string, b *bolt.Bucket) {
		_ = b.ForEach(func(k, v []byte) error {
			if v == nil {
				walk(prefix+string(k)+"/", b.Bucket(k))
				return nil
			}
			sum := sha256.Sum256(v)
			out[prefix+string(k)] = fmt.Sprintf("%d %x", len(v), sum[:8])
			return nil
		})
	}
	if err = db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			walk(string(name)+"/", b)
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// differingPages lists the pages of two versions of one bbolt file that differ (-1: the sizes differ). A read-write open that commits
// an empty transaction rewrites the two meta pages (0 and 1: transaction ID and checksum) and nothing else.
func differingPages(before, after []byte) []int {
	if len(before) != len(after) {
		return []int{-1}
	}
	pageSize := int(binary.LittleEndian.Uint32(before[16+8:]))
	var out []int
	for p := 0; p*pageSize < len(before); p++ {
		lo, hi := p*pageSize, min((p+1)*pageSize, len(before))
		if !bytes.Equal(before[lo:hi], after[lo:hi]) {
			out = append(out, p)
		}
	}
	return out
}

// freelistPages is the freelist page of each of the two meta pages of a bbolt file (meta: magic, version, page size, flags, root
// bucket (pgid, sequence), freelist pgid, high-water pgid, transaction ID, checksum, after the 16-byte page header).
func freelistPages(raw []byte) map[int]bool {
	pageSize := int(binary.LittleEndian.Uint32(raw[16+8:]))
	out := map[int]bool{}
	for p := range 2 {
		out[int(binary.LittleEndian.Uint64(raw[p*pageSize+16+32:]))] = true
	}
	return out
}
