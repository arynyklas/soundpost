// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
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

// TestD92RollbackWithoutTheMarker is what stops the previous release on a contracted installation when the format marker is NOT
// what stops it (the marker put back to the previous release's value by hand on the stopped directory). The one-way point of the
// contraction is not only the marker: the data engine's file moves off the layout the previous release reads when the installation
// is contracted (upgrade.md, "Layout of apply.db"), and the previous release refuses such a file in initStorage as `corrupt` and
// exits. So on a contracted single-host data directory the previous release never reaches the records the marker protects: it
// exits with reason=corrupt (waited for, asserted), serves nothing, and writes nothing; the candidate then resumes with every D92
// record. The hazard the marker alone prevents (the previous release running on D92 records and dropping them) needs a previous-release
// process whose own apply.db is in its layout, which a single-host data directory of a contracted installation never is.
func TestD92RollbackWithoutTheMarker(t *testing.T) {
	d92Releases(t)
	d := newD92Install(t, gitlabtest.New(t))
	reads := d.writtenInstall(t, false)
	if _, err := setSchemaMarker(d.oldHost.dir, model.FormatMarkerBase); err != nil {
		t.Fatal(err)
	}
	layout := d.applyLayout()
	d.report("apply_layout", layout)
	if layout == 1 {
		t.Fatal("the apply.db of a contracted installation is in the previous release's layout: the previous release would run on the D92 records with only the marker to stop it; this test no longer describes the product")
	}
	frozen := freezeD92Dir(t, d.oldHost.dir)

	// ---- the previous release on that very directory ----
	h := d.oldHost
	logStart := len(h.logs.String())
	r, obs := d.observe(h)
	var exit error
	switch {
	case r != nil:
		done := r.(*binaryRun).done
		select {
		case exit = <-done:
		case <-time.After(60 * time.Second):
			_ = r.kill()
			t.Fatalf("the previous release is still running on a contracted data directory (marker %d, apply.db layout %d): %+v", model.FormatMarkerBase, layout, obs)
		}
	case obs.Exited:
		exit = errors.New(obs.Exit)
	default:
		t.Fatalf("the previous release neither started nor exited: %+v", obs)
	}
	log := h.logs.String()[logStart:]
	d.report("old_exit", fmt.Sprint(exit))
	d.report("old_log", log)
	var ee *exec.ExitError
	if exit == nil || (errors.As(exit, &ee) && ee.ExitCode() == 0) {
		t.Errorf("the previous release exited cleanly on a contracted data directory: %v\n%s", exit, lastLines(log, 8))
	}
	if !strings.Contains(log, "soundpost: startup or service failed (reason=corrupt)") {
		t.Errorf("the previous release's refusal is not reason=corrupt:\n%s", lastLines(log, 8))
	}
	if strings.Contains(log, "schema_newer") {
		t.Errorf("the previous release stopped on the format marker, which this test put back to %d:\n%s", model.FormatMarkerBase, lastLines(log, 8))
	}
	if got := d.applyLayout(); got != layout {
		t.Errorf("the previous release changed meta/scan_index_version of apply.db: %d -> %d", layout, got)
	}
	frozen.requireUnchanged(t, d, "after the previous release exited")

	// ---- the candidate again on the original directory ----
	run := d.start(d.newHost)
	defer run.stop()
	requireSameReads(t, "the candidate after the previous release exited", reads, d.candidateReads())
	d.requireRecords(t, "after the previous release exited", true)
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
	frozen := freezeD92Dir(t, d.oldHost.dir)

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
	frozen.requireUnchanged(t, d, "after the previous release refused")

	run := d.start(d.newHost)
	defer run.stop()
	requireSameReads(t, "the candidate after the refused rollback", reads, d.candidateReads())
	d.requireRecords(t, "after the refused rollback", true)
	if ans := d.incidentAction(httpapi.ActionNote, httpapi.ActionPayload{Note: "after the refused rollback"}); ans.Status != 200 {
		t.Errorf("a D92 write after the refused rollback: %s", ans)
	}
}

// d92BoltFiles are the bbolt files of a data directory that a release opens read-write: opening one commits an empty transaction
// (the two meta pages, 0 and 1: transaction ID and checksum, and the freelist page it rewrites) and changes nothing else.
var d92BoltFiles = []string{"control.db", "apply.db"}

// d92Frozen is a stopped data directory as it was at one moment: every file by content, and each bbolt file also bucket by bucket.
type d92Frozen struct {
	tree  map[string]string
	bolts map[string]d92FrozenBolt
}

type d92FrozenBolt struct {
	path, rel string
	raw       []byte
	dump      map[string]string
}

func freezeD92Dir(t *testing.T, dir string) d92Frozen {
	t.Helper()
	f := d92Frozen{tree: d92Tree(t, dir), bolts: map[string]d92FrozenBolt{}}
	for _, name := range d92BoltFiles {
		b := d92FrozenBolt{path: findDataFile(dir, name)}
		rel, _ := filepath.Rel(dir, b.path)
		b.rel = filepath.ToSlash(rel)
		raw, err := os.ReadFile(b.path)
		if err != nil {
			t.Fatal(err)
		}
		b.raw, b.dump = raw, d92Dump(t, b.path)
		f.bolts[name] = b
	}
	return f
}

// requireUnchanged requires that nothing was written since the freeze: every file is byte-identical but the bbolt files, whose
// differing pages are meta or freelist pages only and whose every bucket, key and value is the same.
func (f d92Frozen) requireUnchanged(t *testing.T, d *d92Install, what string) {
	t.Helper()
	before, after := maps.Clone(f.tree), d92Tree(t, d.oldHost.dir)
	for name, b := range f.bolts {
		rawAfter, err := os.ReadFile(b.path)
		if err != nil {
			t.Fatal(err)
		}
		pages := differingPages(b.raw, rawAfter)
		d.report("old_"+name+"_differing_pages", pages)
		free := freelistPages(b.raw)
		for p := range freelistPages(rawAfter) {
			free[p] = true
		}
		for _, p := range pages {
			if p != 0 && p != 1 && !free[p] {
				t.Errorf("the previous release changed page %d of %s, which is neither a meta page nor a freelist page: %v (freelist %v)", p, name, pages, free)
			}
		}
		if dumpAfter := d92Dump(t, b.path); !reflect.DeepEqual(b.dump, dumpAfter) {
			t.Errorf("the previous release changed the content of %s", name)
		}
		delete(before, b.rel)
		delete(after, b.rel)
	}
	requireSameTree(t, what, before, after)
}

// applyLayout is meta/scan_index_version of the data engine's apply.db in the stopped data directory (1 is the layout the previous
// release reads and writes; an installation moves off it when it is contracted, upgrade.md "Layout of apply.db").
func (d *d92Install) applyLayout() byte {
	d.t.Helper()
	db, closeDB, err := copyForRead(findDataFile(d.oldHost.dir, "apply.db"))
	if err != nil {
		d.t.Fatal(err)
	}
	defer closeDB()
	var v []byte
	if err = db.View(func(tx *bolt.Tx) error {
		v = append(v, tx.Bucket([]byte("meta")).Get([]byte("scan_index_version"))...)
		return nil
	}); err != nil || len(v) != 1 {
		d.t.Fatalf("meta/scan_index_version of apply.db: %v %v", v, err)
	}
	return v[0]
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

// freelistPages is the pages of the freelist of each of the two meta pages of a bbolt file (meta: magic, version, page size, flags, root
// bucket (pgid, sequence), freelist pgid, high-water pgid, transaction ID, checksum, after the 16-byte page header; a freelist that
// does not fit one page continues in the pages after it, the overflow count of its page header).
func freelistPages(raw []byte) map[int]bool {
	pageSize := int(binary.LittleEndian.Uint32(raw[16+8:]))
	out := map[int]bool{}
	for p := range 2 {
		free := int(binary.LittleEndian.Uint64(raw[p*pageSize+16+32:]))
		if free < 0 || (free+1)*pageSize > len(raw) { // bbolt's "no freelist stored" sentinel (all ones)
			continue
		}
		out[free] = true
		for o := 1; o <= int(binary.LittleEndian.Uint32(raw[free*pageSize+12:])); o++ {
			out[free+o] = true
		}
	}
	return out
}
