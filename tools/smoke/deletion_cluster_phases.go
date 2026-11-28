// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/backup"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

var dcNodes = []uint64{1, 2, 3}

const dcSiblingBatches = 3

func dcKey(id uint64) string { return strconv.FormatUint(id, 10) }

// ---- the sibling project ----

// dcSibling is a second project of the same organization, with its own source, reader grant and
// data, that the deletion of the first project must leave alone.
type dcSibling struct {
	project, source model.ID
	credential      string
	marker          string  // the metric name of its samples
	last            float64 // the value of the latest acknowledged sample
	queryTime       string  // the evaluation time of the query that sees that sample
}

func dcSiblingPolicy(fx *installFixture) model.SourcePolicy {
	var approved model.Scalar
	_ = json.Unmarshal([]byte(`503`), &approved)
	return model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: append([]model.Kind{model.Metric, model.Log, model.ErrorKind, model.SpanKind}, installKinds...), Replay: true,
		Resources:     model.ResourceRegistry{Services: []model.ID{fx.service}, Environments: []model.ID{fx.environment}, Builds: []model.ID{fx.build}, Instances: []string{"instance"}},
		Templates:     []model.LogTemplate{{ID: "failed", Revision: 1, Line: "operation failed: {status}", Severity: "error", Fields: []model.TemplateField{{Name: "status", Type: "int64", MaxBytes: 16, Sensitivity: "metadata", Values: []model.Scalar{approved}}}}},
		Operations:    []string{"operation"},
		RetentionDays: map[model.Kind]uint32{model.Metric: 30, model.Log: 14, model.ErrorKind: 30, model.SpanKind: 14, model.JobAttempt: 30, model.Replay: 14, model.Profile: 7, model.CapabilityKind: 30, model.Loss: 30}, MaxBytes: 1 << 30, MaxSeries: 1000}
}

// admin runs one audited administrator command through a node as the organization owner. A moved
// revision or an unavailable node is retried under the same command id.
func (r *dcRun) admin(id uint64, kind string, p auth.AdminPayload) error {
	command := model.NewID()
	p.Reason = "deletion-cluster smoke sibling project"
	payload, err := json.Marshal(p)
	if err != nil {
		return r.wrap(err)
	}
	return r.until("admin_"+kind, 90*time.Second, time.Second, func() (bool, string, error) {
		view, err := r.adminRead(id, "organizations", model.ID{})
		if err != nil {
			return false, "admin_read", nil
		}
		status, raw, err := r.ownerSite[id].post("/api/v1/admin/commands", auth.AdminCommandRequest{CommandID: command, ExpectedRevision: view.Revision, OrgID: r.fx.org, Kind: kind, Payload: payload}, r.owner[id].CSRF, "")
		if err != nil {
			return false, "transport", nil
		}
		switch status {
		case http.StatusOK:
			return true, "ok", nil
		case http.StatusConflict, http.StatusServiceUnavailable:
			return false, "status_" + strconv.Itoa(status), nil
		default:
			return false, "", httpSmokeFailure("admin_"+kind, status, http.StatusOK, raw)
		}
	})
}

// adminRead is the organization owner's administrator read of one kind through one node. The
// "organizations" kind needs no organization; the others name it.
func (r *dcRun) adminRead(id uint64, kind string, org model.ID) (auth.AdminView, error) {
	var view auth.AdminView
	var status int
	var raw []byte
	var err error
	if kind == "organizations" {
		status, raw, err = r.ownerSite[id].post("/api/v1/admin/read", struct {
			Kind string `json:"kind"`
		}{kind}, r.owner[id].CSRF, "")
	} else {
		status, raw, err = r.ownerSite[id].post("/api/v1/admin/read", auth.AdminReadRequest{OrgID: org, Kind: kind}, r.owner[id].CSRF, "")
	}
	if err = requireSmokeResponse("admin_read_"+kind, status, http.StatusOK, raw, err); err != nil {
		return view, err
	}
	return view, json.Unmarshal(raw, &view)
}

// createSibling creates the sibling project, grants the reader on it and onboards its source,
// all through one node, then keeps the credential for its own ingest.
func (r *dcRun) createSibling(id uint64) error {
	fx := r.fx
	r.sib = dcSibling{project: model.NewID(), source: model.NewID(), marker: "deletion_cluster_sibling_" + strings.ReplaceAll(model.NewID().String(), "-", "")}
	if err := r.admin(id, "create_project", auth.AdminPayload{ID: r.sib.project, Name: "sibling"}); err != nil {
		return err
	}
	if err := r.admin(id, "grant", auth.AdminPayload{UserID: r.reader[id].User, ProjectID: r.sib.project, Enabled: true, Permissions: []string{string(auth.Read)}}); err != nil {
		return err
	}
	command := model.NewID()
	var issued auth.SourceOnboarded
	err := r.until("onboard_sibling_source", 90*time.Second, time.Second, func() (bool, string, error) {
		status, raw, err := r.ownerSite[id].post("/api/v1/sources", auth.SourceOnboarding{CommandID: command, Org: fx.org, Project: r.sib.project, Source: r.sib.source,
			Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: dcSiblingPolicy(fx), Reason: "deletion-cluster smoke sibling project"}, r.owner[id].CSRF, "")
		if err != nil {
			return false, "transport", nil
		}
		switch status {
		case http.StatusOK:
			return true, "ok", json.Unmarshal(raw, &issued)
		case http.StatusConflict, http.StatusServiceUnavailable:
			return false, "status_" + strconv.Itoa(status), nil
		default:
			return false, "", httpSmokeFailure("onboard_sibling_source", status, http.StatusOK, raw)
		}
	})
	if err != nil {
		return err
	}
	r.sib.credential = issued.Credential
	return r.check("sibling_project_onboarded", issued.Credential != "", "project, reader grant and source created through node "+dcKey(id))
}

// dcSiblingBatch is one acknowledged-or-not sample of the sibling project: the metric the
// sibling's source policy admits, one record observed at `at`.
func dcSiblingBatch(fx *installFixture, sib dcSibling, value float64, at time.Time) (model.Batch, error) {
	bits := model.FloatBits(math.Float64bits(value))
	record := model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(at.UnixNano()), Resource: model.Resource{Service: fx.service, Environment: fx.environment, Build: fx.build, Instance: "instance", Labels: model.Labels{}},
		Payload: model.Payload{Metric: &model.MetricPoint{Name: sib.marker, Labels: model.Labels{}, SampleKind: "float", Value: &bits, Unit: "1", Type: "gauge"}}}
	batch := model.Batch{Version: 1, Project: sib.project, Source: sib.source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{record}}
	var err error
	batch.RouteSlot, err = model.OwnerSlot(fx.org, sib.project, sib.source, batch.Producer, record)
	return batch, err
}

// siblingIngest acknowledges one sample of the sibling project through a node and moves the
// evaluation time of the sibling's query to just after it.
func (r *dcRun) siblingIngest(id uint64, value float64) error {
	batch, err := dcSiblingBatch(r.fx, r.sib, value, time.Now())
	if err != nil {
		return r.wrap(err)
	}
	status, raw, _, err := retryIngest(r.sites[id], batch, r.sib.credential, 120*time.Second)
	if err != nil || status != http.StatusOK {
		return r.wrap(requireSmokeResponse("ingest_sibling", status, http.StatusOK, raw, err))
	}
	r.sib.last = value
	r.sib.queryTime = fmt.Sprint(time.Now().Add(time.Minute).UnixNano())
	return nil
}

// siblingFixture is the query fixture of the sibling project as read through one node.
func (r *dcRun) siblingFixture(id uint64) *installFixture {
	c := r.nodeFixture(id)
	c.project, c.queryTime = r.sib.project, r.sib.queryTime
	return c
}

// dcSiblingRows is what the control plane says about the sibling and the retired project.
type dcSiblingRows struct {
	ProjectNamed bool   `json:"project_named"`
	ReaderGrant  bool   `json:"reader_grant"`
	SourceLive   bool   `json:"source_live"`
	RetiredState string `json:"retired_project_source"`
}

func (s dcSiblingRows) ok() bool { return s.ProjectNamed && s.ReaderGrant && s.SourceLive }

// siblingRows reads the sibling's control rows (project, reader grant, source) through the real
// administrator read API of one node.
func (r *dcRun) siblingRows(id uint64) (dcSiblingRows, error) {
	var rows dcSiblingRows
	org, err := r.adminRead(id, "organization", r.fx.org)
	if err != nil {
		return rows, err
	}
	if len(org.Organizations) == 1 {
		o := org.Organizations[0]
		rows.ProjectNamed = o.Projects[r.sib.project.String()] == "sibling"
		rows.ReaderGrant = slices.Contains(o.Grants[r.reader[id].User.String()+":"+r.sib.project.String()], string(auth.Read))
	}
	src, err := r.adminRead(id, "source", r.fx.org)
	if err != nil {
		return rows, err
	}
	rows.RetiredState = "absent"
	for _, s := range src.Sources {
		switch s.ID {
		case r.sib.source:
			rows.SourceLive = s.Project == r.sib.project && !s.Revoked && !s.Retired && !s.Closing
		case r.fx.source:
			rows.RetiredState = fmt.Sprintf("retired=%v closing=%v revoked=%v", s.Retired, s.Closing, s.Revoked)
		}
	}
	return rows, nil
}

// checkSibling requires, through each listed node, that the sibling project is untouched: its
// data is served by the real query API at the latest acknowledged value, and its control rows are
// present and live in the real administrator read API.
func (r *dcRun) checkSibling(label string, ids ...uint64) error {
	for _, id := range ids {
		key := dcKey(id)
		var body []byte
		err := r.until("sibling_data_node_"+key, 120*time.Second, time.Second, func() (bool, string, error) {
			status, raw, err := queryExpr(r.sites[id], r.siblingFixture(id), r.sib.marker)
			if err != nil {
				return false, "transport", nil
			}
			body = raw
			return dcServedLatest(status, raw, r.sib.last), dcServedWhat(status, raw), nil
		})
		if err != nil {
			return err
		}
		if err = r.check(label+"_sibling_data_served_node_"+key, bytes.Contains(body, []byte(r.sib.marker)), "complete answer with the latest sibling value "+strconv.FormatFloat(r.sib.last, 'f', -1, 64)); err != nil {
			return err
		}
		var rows dcSiblingRows
		err = r.until("sibling_control_node_"+key, 60*time.Second, time.Second, func() (bool, string, error) {
			var err error
			if rows, err = r.siblingRows(id); err != nil {
				var sf *smokeFailure
				if errors.As(err, &sf) && sf.Actual >= 500 {
					return false, "status_" + strconv.Itoa(sf.Actual), nil
				}
				return false, "", err
			}
			return rows.ok(), fmt.Sprintf("%+v", rows), nil
		})
		if err != nil {
			return err
		}
		if err = r.check(label+"_sibling_control_rows_node_"+key, rows.ok(), fmt.Sprintf("%+v", rows)); err != nil {
			return err
		}
	}
	return nil
}

// scanMarker scans one node's data directory for a name other than the canary.
func (r *dcRun) scanMarker(id uint64, marker string) (dcScan, error) { return r.scanFor(id, marker) }

// ---- journals, receipts sampled while the lagging voter comes back ----

func (r *dcRun) journals(id uint64) (map[string]dcJournal, error) {
	j, err := dcJournals(r.dir(id))
	if err != nil {
		r.detail = "journals of node " + dcKey(id) + ": " + err.Error()
		return nil, r.wrap(err)
	}
	return j, nil
}

// dcCleanTrack is what the receipt polling after the lagging voter's restart observed.
type dcCleanTrack struct {
	cleanAt  map[uint64]int64
	own      map[string]dcScan // a node's own directory the moment its receipt first read clean
	lagging  map[string]dcScan // the lagging voter's directory the moment each node's receipt first read clean
	trail    map[string][]string
	samples  map[string]int
	notClean map[string]int
}

func newDCCleanTrack() *dcCleanTrack {
	return &dcCleanTrack{cleanAt: map[uint64]int64{}, own: map[string]dcScan{}, lagging: map[string]dcScan{}, trail: map[string][]string{}, samples: map[string]int{}, notClean: map[string]int{}}
}

// sample reads the receipt through each listed node once. A receipt that reads clean while the
// lagging voter's own directory still holds the canary is a false clean and the typed failure; it
// is checked at every clean answer, not only the first. It returns what is still not clean.
func (r *dcRun) sample(t *dcCleanTrack, ids ...uint64) ([]string, error) {
	progress := make([]string, 0, len(ids))
	for _, id := range ids {
		key := dcKey(id)
		op, err := r.poll(id)
		if err != nil {
			var sf *smokeFailure
			if errors.As(err, &sf) && sf.Actual >= 500 {
				progress = append(progress, key+":status_"+strconv.Itoa(sf.Actual))
				continue
			}
			return nil, err
		}
		t.samples[key]++
		seen := "[" + strings.Join(op.ResidualStores, "+") + "]"
		if tr := t.trail[key]; len(tr) == 0 || tr[len(tr)-1] != seen {
			t.trail[key] = append(tr, seen)
		}
		if !(op.Phase == model.DeletePhaseComplete && op.Physical == "done" && len(op.ResidualStores) == 0) {
			t.notClean[key]++
			progress = append(progress, key+":"+strings.Join(op.ResidualStores, "+"))
			continue
		}
		first := t.cleanAt[id] == 0
		if first {
			t.cleanAt[id] = r.since()
			r.mark("receipt_first_clean_node_" + key + "_ms")
			own, err := r.scan(id)
			if err != nil {
				return nil, err
			}
			t.own[key] = own
		}
		lagging, err := r.scanWatch()
		if err != nil {
			return nil, err
		}
		detail := fmt.Sprintf("%d hits in %d files, by store %v", lagging.Hits, lagging.Files, lagging.ByStore)
		name := "no_false_clean_node_" + key + "_" + map[bool]string{false: "lagging_voter", true: "replacement_voter"}[r.replace] + "_directory_holds_no_canary"
		if first {
			t.lagging[key] = lagging
			if err = r.check(name, lagging.Hits == 0, detail); err != nil {
				return nil, err
			}
		} else if lagging.Hits > 0 {
			return nil, r.check(name+"_later_sample", false, detail)
		}
	}
	return progress, nil
}

// installEvidence runs after every node is stopped. The lagging voter's own journals must start
// beyond every cut the live voters made while it was down (only an installed snapshot gets a voter
// past entries nobody holds any more), and the replicated erase notice that names the voter, which
// a sender commits before it announces a snapshot to it, must be in every node's apply.db.
func (r *dcRun) installEvidence(who string, lag uint64, stranded []string, cut map[string]dcJournal, requireNotice bool) error {
	r.enter("dc_snapshot_install_evidence")
	after, err := r.journals(lag)
	if err != nil {
		return err
	}
	passed := dcInstalledPast(stranded, cut, after)
	if err = r.check(who+"_journals_start_past_every_cut_after_stop", len(stranded) > 0 && len(passed) == len(stranded), fmt.Sprintf("%d of %d journals the voter was stranded on start beyond the live voters' cut", len(passed), len(stranded))); err != nil {
		return err
	}
	r.art.Evidence[who+"_journals_after_catch_up"] = after
	facts := map[string]dcFacts{}
	for _, id := range r.members {
		f, err := dcReadFacts(r.dir(id))
		if err != nil {
			r.detail = "erase facts of node " + dcKey(id) + ": " + err.Error()
			return r.wrap(err)
		}
		facts[dcKey(id)] = f
		if requireNotice {
			if err = r.check("erase_notice_names_"+who+"_node_"+dcKey(id), f.NoticeByNode[dcKey(lag)] > 0, fmt.Sprintf("notice index %d; notices %v; install epoch %d", f.NoticeByNode[dcKey(lag)], f.NoticeByNode, f.InstallEpoch)); err != nil {
				return err
			}
		}
	}
	r.art.Evidence["erase_protocol_facts_after_stop"] = facts
	return nil
}

// stopRestartVerify is the end both scenarios share. It stops every running node and scans the
// whole data directories; reads the install evidence of the voter that came back (or joined)
// fresh; restarts the cluster and requires the retired project denied through every member, the
// receipt still clean, the sibling intact and still accepting writes through fresh; then stops once
// more and scans again. requireNotice says whether the erase notice naming fresh must be in every
// apply.db (it is for a restarted voter; a joining learner is announced no snapshot before it has
// declared the protocol).
func (r *dcRun) stopRestartVerify(started time.Time, who string, stranded []string, cut map[string]dcJournal, fresh uint64, requireNotice bool) error {
	cl, fx := r.cluster, r.fx
	r.enter("dc_stop_all_nodes")
	if err := cl.stop(r.art.Evidence); err != nil {
		return r.wrap(err)
	}
	r.mark("all_stopped_ms")
	if err := r.scanAll("stopped_scan", "dc_scan_stopped_data_directories"); err != nil {
		return err
	}
	if who != "" {
		if err := r.installEvidence(who, fresh, stranded, cut, requireNotice); err != nil {
			return err
		}
	}

	// ---- restart: denied through each node, still clean, still zero ----
	r.enter("dc_restart_all_nodes")
	if err := r.start(r.members...); err != nil {
		return r.wrap(err)
	}
	if err := r.refreshSites(r.members...); err != nil {
		return err
	}
	if err := r.ready(240*time.Second, r.members...); err != nil {
		return err
	}
	r.mark("all_restarted_ready_ms")
	for _, id := range r.members {
		if err := r.login(id); err != nil {
			return err
		}
	}
	r.enter("dc_denied_through_every_node")
	denied := map[string]any{}
	for _, id := range r.members {
		key := dcKey(id)
		status, raw, err := r.query(id)
		if err != nil {
			return r.wrap(err)
		}
		if err = r.check("read_denied_after_restart_node_"+key, dcDenied(status, raw) && !bytes.Contains(raw, []byte(r.canary)), fmt.Sprintf("status %d code %s", status, dcFaultCode(raw))); err != nil {
			return err
		}
		istatus, iraw, err := r.sites[id].ingest(r.freshBatch(), fx.credential)
		if err != nil {
			return r.wrap(err)
		}
		if err = r.check("ingest_denied_after_restart_node_"+key, istatus >= 400 && istatus < 500, fmt.Sprintf("status %d code %s", istatus, dcFaultCode(iraw))); err != nil {
			return err
		}
		// A restart may leave a receipt naming a store for a moment without anything being wrong: a voter
		// whose control.db was replaced by an installed snapshot while the cluster went down owes one more
		// scrub, and a restarted voter judges itself unproven until its first worker pass has attested again
		// (control.Store.ClusterOperationResidual: its own record AND `settled`; docs/privacy/retention.md,
		// the control stores' install interval). That is the conservative direction and the receipt must be
		// clean once the pass ran, so it is waited for, bounded like every wait; what is never waited out is a
		// receipt that is not complete and done. One run in 30 named control_state on node 1 0.9 s after
		// the restart of all three nodes; the files of every stopped node had been scanned clean before.
		op, err := r.poll(id)
		if err != nil {
			return r.wrap(err)
		}
		notClean := 0
		err = r.until("receipt_clean_after_restart_node_"+key, r.wait, dcPollInterval, func() (bool, string, error) {
			if notClean > 0 {
				o, err := r.poll(id)
				if err != nil {
					return false, "", err
				}
				op = o
			}
			complete := op.Phase == model.DeletePhaseComplete && op.Physical == "done"
			if complete && len(op.ResidualStores) != 0 {
				notClean++
			}
			return !complete || len(op.ResidualStores) == 0, fmt.Sprintf("phase %s physical %s residual %v", safeToken(op.Phase), safeToken(op.Physical), op.ResidualStores), nil
		})
		if err != nil {
			return err
		}
		if err = r.check("receipt_still_clean_after_restart_node_"+key, op.Phase == model.DeletePhaseComplete && op.Physical == "done" && len(op.ResidualStores) == 0, fmt.Sprintf("phase %s physical %s residual %v after %d answer(s) that named a store", safeToken(op.Phase), safeToken(op.Physical), op.ResidualStores, notClean)); err != nil {
			return err
		}
		denied[key] = map[string]any{"read_status": status, "read_code": dcFaultCode(raw), "ingest_status": istatus, "ingest_code": dcFaultCode(iraw), "receipt_answers_naming_a_store": notClean}
	}
	r.art.Evidence["denied_after_restart"] = denied
	r.enter("dc_sibling_untouched_after_restart")
	if err := r.checkSibling("after_restart", r.members...); err != nil {
		return err
	}
	if err := r.siblingIngest(fresh, float64(dcSiblingBatches+2)); err != nil {
		return err
	}
	if err := r.check("sibling_ingest_accepted_through_the_returned_voter_after_restart", true, "a new sample for the sibling project acknowledged through node "+dcKey(fresh)); err != nil {
		return err
	}
	if err := r.checkSibling("after_restart_ingest", r.members...); err != nil {
		return err
	}
	r.enter("dc_stop_final")
	if err := cl.stop(r.art.Evidence); err != nil {
		return r.wrap(err)
	}
	if err := r.scanAll("stopped_scan_after_restart", "dc_scan_after_restart"); err != nil {
		return err
	}
	if r.auth != nil {
		if err := r.restoreOlderBackup(); err != nil {
			return err
		}
	}
	r.art.Evidence["scenario_wall_clock_ms"] = time.Since(started).Milliseconds()
	return nil
}

// ---- starting and stopping voters, with the restore authority ----

func (r *dcRun) nodeFile(id uint64) string {
	return filepath.Join(r.cluster.root, fmt.Sprintf("node-%d.json", id))
}

// start starts voters exactly as the shared process cluster does, plus the restore authority flags
// when the run has an authority (every voter, including a replacement, is given them).
func (r *dcRun) start(ids ...uint64) error {
	c := r.cluster
	for _, id := range ids {
		cmd := exec.Command(c.binary, dcServeArgs(id, r.nodeFile(id), c.data[id], c.public[id], r.auth)...)
		cmd.Stdout, cmd.Stderr = c.logs[id], c.logs[id]
		cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
		if err := cmd.Start(); err != nil {
			return err
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		c.mu.Lock()
		c.cmds[id], c.done[id] = cmd, done
		c.mu.Unlock()
	}
	return nil
}

// stopNode stops one running voter with SIGTERM (the operator's stop, which a backup of its
// directory asks for) and waits for it to exit.
func (r *dcRun) stopNode(id uint64) error {
	c := r.cluster
	c.mu.Lock()
	cmd, done := c.cmds[id], c.done[id]
	c.mu.Unlock()
	if cmd == nil {
		return errors.New("member not running")
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		return &smokeFailure{Stage: "graceful_stop", Code: "timeout"}
	}
	c.mu.Lock()
	delete(c.cmds, id)
	c.mu.Unlock()
	return nil
}

// dcScanIfPresent is dcScanDir for a directory that may not exist yet (a fresh voter's): a
// directory that is not there holds nothing.
func dcScanIfPresent(dir, canary string) (dcScan, error) {
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return dcScan{ByStore: map[string]int{}, HitFiles: map[string]int{}}, nil
	}
	return dcScanDir(dir, canary)
}

// scanWatch scans the directory of the voter whose directory must hold no canary whenever a
// receipt reads clean.
func (r *dcRun) scanWatch() (dcScan, error) {
	if r.scanner != nil {
		return r.scanFor(r.watch, r.canary) // the remote scan counts a directory that is not there as holding nothing
	}
	s, err := dcScanIfPresent(r.dir(r.watch), r.canary)
	if err != nil {
		return s, r.wrap(err)
	}
	return s, nil
}

// dcWithin reports whether child is parent or lies below it.
func dcWithin(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// dcOutsideAll reports whether no path lies inside any of the directories and no directory lies
// inside any of the paths: the authority and its keys share no tree with a node's data.
func dcOutsideAll(paths, dirs []string) bool {
	for _, p := range paths {
		for _, d := range dirs {
			if dcWithin(d, p) || dcWithin(p, d) {
				return false
			}
		}
	}
	return len(paths) > 0 && len(dirs) > 0
}

const (
	dcDataKEK   = "data-kek-1"
	dcSecretKEK = "secret-kek-1"
)

// setupAuthority creates the authority keys, initialises the authority for the installation the
// cluster is seeded from (the stopped bootstrap installation), and creates the two key-encryption
// keys a backup needs. The authority is a directory of its own, outside every node's data
// directory; every serve process is then started with its full keys and that directory.
func (r *dcRun) setupAuthority(work string) error {
	host, ok := r.cluster.boot.(*binaryHost)
	if !ok {
		return r.wrap(errors.New("bootstrap host"))
	}
	a := &dcAuthority{Keys: filepath.Join(work, "authority.keys"), Restricted: filepath.Join(work, "authority.restricted.keys"), Dir: filepath.Join(work, "authority"), KeyDir: filepath.Join(work, "backup-keys"), BackupDir: filepath.Join(work, "backups")}
	if r.authSpot != nil { // the journal is somewhere the operator named (a bucket, or a directory every voter reaches), not a directory of this host
		a.Dir, a.S3 = r.authSpot.Dir, r.authSpot.S3
	}
	if err := os.MkdirAll(a.KeyDir, 0o700); err != nil {
		return r.wrap(err)
	}
	for _, step := range [][]string{
		{"backup", "authority-keygen", "--out", a.Keys, "--restricted-out", a.Restricted, "--id", "dc-authority-1"},
		append([]string{"backup", "authority-init", "--data-dir", host.dir, "--authority-keys", a.Keys}, a.flags()...),
		{"backup", "keygen", "--key-dir", a.KeyDir, "--id", dcDataKEK},
		{"backup", "keygen", "--key-dir", a.KeyDir, "--id", dcSecretKEK},
	} {
		if _, line, err := dcCLI(r.cluster.binary, a.env(), 2*time.Minute, step...); err != nil {
			r.detail = line
			return r.wrap(err)
		}
	}
	paths := []string{a.Keys, a.Restricted, a.KeyDir, a.BackupDir}
	if a.S3 == nil {
		paths = append(paths, a.Dir)
	}
	dirs := make([]string, 0, len(dcNodes))
	for _, id := range dcNodes {
		dirs = append(dirs, r.cluster.data[id])
	}
	outside := dcOutsideAll(paths, dirs)
	r.auth = a
	kind := "the product's local directory destination on this host, own signing keys"
	if a.S3 != nil {
		kind = "an S3-compatible bucket (HTTPS), own signing keys"
	} else if r.authSpot != nil {
		kind = "a directory every voter reaches (named by the operator), own signing keys"
	}
	r.art.Evidence["authority"] = map[string]any{"kind": kind, "configured_on_every_serve_process": "--authority-keys (full keys) and the journal destination flags", "restore_operator_holds": "restricted keys only (read and verify, never write)"}
	return r.check("authority_directory_outside_every_node_data_directory", outside, "the authority, its keys and the backup destination are not inside any node's data directory; every serve process is started with the authority")
}

// backupWhileDown stops the lagging voter (SIGTERM, as the operator's runbook asks) and takes a
// distributed backup of the cluster THROUGH its directory (`backup create --mode distributed`:
// the process joins the two running voters, which keep the quorum) before any deletion exists.
func (r *dcRun) backupWhileDown(lag uint64) error {
	if err := r.stopNode(lag); err != nil {
		r.detail = "stop voter " + dcKey(lag) + ": " + dcSafeLine(err.Error()) + " | its log ends: " + dcSafeLine(r.cluster.logs[lag].String())
		return r.wrap(err)
	}
	a := r.auth
	started := time.Now()
	out, line, err := dcCLI(r.cluster.binary, []string{"SOUNDPOST_ADMIN_PASSWORD=" + r.fx.password}, 8*time.Minute, "backup", "create", "--mode", "distributed", "--node-id", dcKey(lag), "--cluster-config", r.nodeFile(lag), "--data-dir", r.dir(lag),
		"--admin-email", dcOwnerEmail, "--key-dir", a.KeyDir, "--data-kek", dcDataKEK, "--secret-kek", dcSecretKEK, "--authority-keys", a.Keys, "--authority-dir", a.Dir, "--dest-dir", a.BackupDir, "--reason", "deletion-cluster smoke older backup")
	if err != nil {
		r.detail = line
		return r.wrap(err)
	}
	info, err := dcParseBackupCreate(out)
	if err != nil {
		r.detail = dcSafeLine(err.Error())
		return r.wrap(err)
	}
	r.backup, r.backupSibling, r.backupAt = info, r.sib.last, r.sib.queryTime
	r.art.Evidence["backup_before_deletion"] = map[string]any{"backup_id": info.ID, "taken_through_voter": lag, "voters": info.Voters, "objects": info.Objects, "control_revision": info.ControlRevision,
		"authority_sequence": info.AuthoritySequence, "authority_generation": info.AuthorityGeneration, "duration_ms": time.Since(started).Milliseconds(), "canary_ingested_before": true}
	r.mark("older_backup_taken_ms")
	return r.check("older_backup_taken_before_the_deletion_through_a_stopped_voter", info.Voters == 3 && info.Objects > 0, fmt.Sprintf("backup %s of a three-voter cluster, %d objects, authority sequence %d", info.ID, info.Objects, info.AuthoritySequence))
}

// checkAuthority reads the authority directly with the restricted keys a restore operator holds,
// after the deletion completed: it must hold the tombstone of this deletion (retiring exactly the
// retired project and nothing else) at a head past the one the older backup was taken under.
func (r *dcRun) checkAuthority() error {
	cur, err := r.readAuthority()
	if err != nil {
		return err
	}
	tomb, found := dcTombstoneOf(cur.Tombstones, r.op)
	if err = r.check("authority_holds_the_tombstone_of_the_completed_deletion", found, fmt.Sprintf("%d tombstones at authority sequence %d", len(cur.Tombstones), cur.Head.Sequence)); err != nil {
		return err
	}
	if err = r.check("authority_tombstone_retires_exactly_the_retired_project", dcRetiresOnly(tomb, r.fx.org, r.fx.project), "mode "+safeToken(tomb.Mode)+", "+strconv.Itoa(len(tomb.Projects))+" project(s), the sibling project is not named"); err != nil {
		return err
	}
	if err = r.check("authority_head_advanced_past_the_older_backup", cur.Head.Sequence > uint64(r.backup.AuthoritySequence), fmt.Sprintf("head sequence %d, backup taken under %d", cur.Head.Sequence, r.backup.AuthoritySequence)); err != nil {
		return err
	}
	r.authHead, r.authTombstones = cur.Head, len(cur.Tombstones)
	r.art.Evidence["authority_after_deletion"] = map[string]any{"head_sequence": cur.Head.Sequence, "generation": cur.Head.Generation, "tombstones": len(cur.Tombstones), "backup_taken_under_sequence": r.backup.AuthoritySequence}
	return nil
}

// readAuthority is one verified read of the authority journal with the restricted keys.
func (r *dcRun) readAuthority() (backup.CurrentDeletion, error) {
	keys, err := backup.ReadAuthorityKeys(r.auth.Restricted)
	if err != nil {
		return backup.CurrentDeletion{}, r.wrap(err)
	}
	dest, err := r.auth.destination()
	if err != nil {
		return backup.CurrentDeletion{}, r.wrap(err)
	}
	reader, err := backup.NewAuthority(dest, keys, time.Now)
	if err != nil {
		return backup.CurrentDeletion{}, r.wrap(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cur, err := reader.Current(ctx)
	if err != nil {
		return cur, r.wrap(err)
	}
	return cur, nil
}

// restoreOlderBackup is the disaster path with the OLDER backup (taken before the deletion, so it
// holds the canary): `backup restore` into a clean root against the CURRENT authority, `backup
// activate`, and then the restored installation is served by a real process. The completed
// deletion must not come back: the whole root holds no canary after activation (and the older
// backup did hold it before), the reader the operator reinstates is denied the retired project
// and cannot be re-granted it, and the sibling project is served as of the backup.
func (r *dcRun) restoreOlderBackup() error {
	a, c := r.auth, r.cluster
	root := filepath.Join(c.root, "restored-root")
	r.enter("dc_restore_older_backup")
	out, line, err := dcCLI(c.binary, a.env(), 10*time.Minute, append([]string{"backup", "restore", "--backup-id", r.backup.ID, "--root", root, "--key-dir", a.KeyDir, "--authority-keys", a.Restricted, "--dest-dir", a.BackupDir}, a.flags()...)...)
	if err != nil {
		r.detail = line
		return r.wrap(err)
	}
	rest, err := dcParseRestore(out)
	if err != nil {
		return r.wrap(err)
	}
	if err = r.check("restore_of_the_older_backup_verified_the_current_authority_head", rest.ID == r.backup.ID && uint64(rest.AuthoritySequence) == r.authHead.Sequence && rest.AuthoritySequence > r.backup.AuthoritySequence, fmt.Sprintf("restored backup taken under authority sequence %d against head %d", r.backup.AuthoritySequence, rest.AuthoritySequence)); err != nil {
		return err
	}
	if err = r.check("restore_carries_the_deletion_tombstone", rest.Tombstones == r.authTombstones && rest.Tombstones > 0, fmt.Sprintf("%d tombstones (authority holds %d)", rest.Tombstones, r.authTombstones)); err != nil {
		return err
	}
	before, err := dcScanDir(root, r.canary)
	if err != nil {
		return r.wrap(err)
	}
	if err = r.check("older_backup_holds_the_canary_before_activation", before.Hits > 0, fmt.Sprintf("%d hits in %d files, by store %v", before.Hits, before.Files, before.ByStore)); err != nil {
		return err
	}
	r.enter("dc_activate_restored_root")
	out, line, err = dcCLI(c.binary, a.env(), 10*time.Minute, append([]string{"backup", "activate", "--root", root, "--authority-keys", a.Restricted}, a.flags()...)...)
	if err != nil {
		r.detail = line
		return r.wrap(err)
	}
	act, err := dcParseActivate(out)
	if err != nil {
		return r.wrap(err)
	}
	if err = r.check("activation_applies_the_authority_ledger", act.Ready && act.Tombstones == r.authTombstones, fmt.Sprintf("ready %v, %d tombstones applied, authority generation %d", act.Ready, act.Tombstones, act.AuthorityGeneration)); err != nil {
		return err
	}
	after, err := dcScanDir(root, r.canary)
	if err != nil {
		return r.wrap(err)
	}
	marker, err := dcScanDir(root, r.sib.marker)
	if err != nil {
		return r.wrap(err)
	}
	// Activation records the tombstones (control import, a barrier in every slot) and opens the
	// engine, which installs the restored snapshots: the bytes of the deleted data are on this disk
	// again, denied by the barriers. Whether they stay is what the restored installation's own
	// retention worker decides below; this scan is evidence of the window, not an assertion.
	r.art.Evidence["restored_root_scan"] = map[string]any{"canary_before_activation": before, "canary_after_activation": after, "sibling_marker_after_activation": marker}
	if err = r.check("restored_root_still_holds_the_sibling_marker", marker.Hits > 0, fmt.Sprintf("%d hits in %d files; by store %v", marker.Hits, marker.Files, marker.ByStore)); err != nil {
		return err
	}

	r.enter("dc_serve_restored_root")
	host := &binaryHost{path: c.binary, dir: root, logs: &syncBuffer{}}
	if host.holdDir, err = os.MkdirTemp("", "soundpost-hold-"); err != nil {
		return r.wrap(err)
	}
	defer os.RemoveAll(host.holdDir)
	run, err := host.start()
	if err != nil {
		return r.wrap(err)
	}
	defer run.kill()
	cert, err := run.waitCertificate()
	if err != nil {
		return r.wrap(err)
	}
	site := newInstallSite(run.url(), cert)
	if err = run.release(); err != nil {
		return r.wrap(err)
	}
	if err = run.waitReady(120 * time.Second); err != nil {
		return r.wrap(err)
	}
	served := r.since()
	token, err := run.bootstrapToken()
	if err != nil {
		return r.wrap(err)
	}
	if err = r.reconcileAndRead(site, token); err != nil {
		return err
	}

	// The restored installation's retention worker finds the imported deletion without a physical
	// pass and erases the restored copy (it passes once a minute): the canary must leave the disk.
	r.enter("dc_restored_installation_erases_its_copy")
	type observation struct {
		AtMS int64 `json:"at_ms_after_ready"`
		Hits int   `json:"hits"`
	}
	var seen []observation
	err = r.until("restored_root_canary_erased", r.wait, dcPollInterval, func() (bool, string, error) {
		s, err := dcScanDir(root, r.canary)
		if err != nil {
			return false, "", err
		}
		if len(seen) == 0 || seen[len(seen)-1].Hits != s.Hits {
			seen = append(seen, observation{AtMS: r.since() - served, Hits: s.Hits})
		}
		return s.Hits == 0, fmt.Sprintf("%d_hits_by_store_%v", s.Hits, s.ByStore), nil
	})
	r.art.Evidence["restored_root_canary_hits_while_served"] = seen
	if err != nil {
		return err
	}
	if err = r.check("restored_installation_erased_its_copy_of_the_deleted_data", len(seen) > 0 && seen[len(seen)-1].Hits == 0, fmt.Sprintf("canary hits while the restored installation was served: %v", seen)); err != nil {
		return err
	}

	r.enter("dc_stop_restored_root")
	if err = run.stop(); err != nil {
		return r.wrap(err)
	}
	final, err := dcScanDir(root, r.canary)
	if err != nil {
		return r.wrap(err)
	}
	finalMarker, err := dcScanDir(root, r.sib.marker)
	if err != nil {
		return r.wrap(err)
	}
	r.art.Evidence["restored_root_scan_after_serving"] = map[string]any{"canary": final, "sibling_marker": finalMarker}
	if err = r.check("restored_root_holds_no_canary_after_it_was_served", final.Hits == 0, fmt.Sprintf("%d hits in %d files; by store %v; files %v", final.Hits, final.Files, final.ByStore, final.HitFiles)); err != nil {
		return err
	}
	return r.check("restored_root_still_holds_the_sibling_marker_after_it_was_served", finalMarker.Hits > 0, fmt.Sprintf("%d hits in %d files; by store %v", finalMarker.Hits, finalMarker.Files, finalMarker.ByStore))
}

// reconcileAndRead is what the operator of a restored installation does: bootstrap the recovery
// administrator with the one-time token, reinstate the reader's account, membership and its grant
// on the sibling project (and try, and fail, to reinstate its grant on the retired project), then
// read as that reader. fx is the original installation's fixture.
func (r *dcRun) reconcileAndRead(site *installSite, token string) error {
	fx := r.fx
	r.enter("dc_recovery_admin_reconciles_reader")
	status, raw, err := site.post("/api/v1/bootstrap", map[string]string{"Token": token, "Email": "recovery@deletion-cluster.invalid", "Password": "deletion cluster recovery password 2026"}, "", "")
	if err = requireSmokeResponse("restored_bootstrap", status, 200, raw, err); err != nil {
		return r.wrap(err)
	}
	var recovery auth.Session
	if err = json.Unmarshal(raw, &recovery); err != nil {
		return r.wrap(err)
	}
	reader := r.reader[1].User
	status, raw, err = site.post("/api/v1/restore/items", struct{}{}, recovery.CSRF, "")
	if err = requireSmokeResponse("restored_items", status, 200, raw, err); err != nil {
		return r.wrap(err)
	}
	var view auth.RestoreView
	if err = json.Unmarshal(raw, &view); err != nil {
		return r.wrap(err)
	}
	kinds := map[string]int{}
	var readerQuarantined, retiredGrantListed bool
	for _, item := range view.Items {
		kinds[string(item.Kind)]++
		readerQuarantined = readerQuarantined || item.Kind == auth.ReconcileAccount && item.User == reader.String()
		retiredGrantListed = retiredGrantListed || item.Kind == auth.ReconcileGrant && item.Project == fx.project.String()
	}
	r.art.Evidence["restored_installation_quarantine"] = map[string]any{"pending": view.Pending, "items_by_kind": kinds, "retired_project_grant_listed": retiredGrantListed}
	if err = r.check("restored_installation_quarantines_the_reader", readerQuarantined && view.Pending > 0, fmt.Sprintf("%d items awaiting reconciliation, by kind %v", view.Pending, kinds)); err != nil {
		return err
	}
	reconcile := func(kind auth.ReconcileKind, project model.ID) (int, []byte, error) {
		body := map[string]string{"Kind": string(kind), "User": reader.String(), "Reason": "deletion-cluster smoke restore leg"}
		if kind != auth.ReconcileAccount {
			body["Org"] = fx.org.String()
		}
		if kind == auth.ReconcileGrant {
			body["Project"] = project.String()
		}
		return site.post("/api/v1/restore/reconcile", body, recovery.CSRF, "")
	}
	for _, step := range []struct {
		kind    auth.ReconcileKind
		project model.ID
	}{{auth.ReconcileAccount, model.ID{}}, {auth.ReconcileMembership, model.ID{}}, {auth.ReconcileGrant, r.sib.project}} {
		status, raw, err = reconcile(step.kind, step.project)
		if err = requireSmokeResponse("restored_reconcile_"+string(step.kind), status, 200, raw, err); err != nil {
			return r.wrap(err)
		}
	}
	status, raw, err = reconcile(auth.ReconcileGrant, fx.project)
	if err != nil {
		return r.wrap(err)
	}
	if err = r.check("restored_grant_on_the_retired_project_cannot_be_reinstated", status >= 400 && status < 500, fmt.Sprintf("status %d code %s", status, dcFaultCode(raw))); err != nil {
		return err
	}

	r.enter("dc_read_restored_installation")
	jar, err := cookiejar.New(nil)
	if err != nil {
		return r.wrap(err)
	}
	client := *site.client
	client.Jar = jar
	readerSite := &installSite{base: site.base, client: &client}
	session, err := loginReader(readerSite, fx)
	if err != nil {
		return r.wrap(err)
	}
	rfx := *fx
	rfx.reader = session
	rfx.queryTime = fmt.Sprint(time.Now().Add(time.Minute).UnixNano())
	status, raw, err = queryExpr(readerSite, &rfx, r.canary)
	if err != nil {
		return r.wrap(err)
	}
	if err = r.check("restored_read_of_the_retired_project_denied", dcDenied(status, raw) && !bytes.Contains(raw, []byte(r.canary)), fmt.Sprintf("status %d code %s", status, dcFaultCode(raw))); err != nil {
		return err
	}
	denied := map[string]any{"read_status": status, "read_code": dcFaultCode(raw)}
	istatus, iraw, err := readerSite.ingest(r.freshBatch(), fx.credential)
	if err != nil {
		return r.wrap(err)
	}
	if err = r.check("restored_ingest_into_the_retired_project_denied", istatus >= 400 && istatus < 500, fmt.Sprintf("status %d code %s", istatus, dcFaultCode(iraw))); err != nil {
		return err
	}
	denied["ingest_status"], denied["ingest_code"] = istatus, dcFaultCode(iraw)
	r.art.Evidence["restored_installation_denial"] = denied
	rfx.project, rfx.queryTime = r.sib.project, r.restoredSiblingTime()
	var body []byte
	err = r.until("restored_sibling_data", 60*time.Second, time.Second, func() (bool, string, error) {
		status, raw, err := queryExpr(readerSite, &rfx, r.sib.marker)
		if err != nil {
			return false, "transport", nil
		}
		body = raw
		return dcServedLatest(status, raw, r.backupSibling), dcServedWhat(status, raw), nil
	})
	if err != nil {
		return err
	}
	return r.check("restored_sibling_project_served_as_of_the_older_backup", bytes.Contains(body, []byte(r.sib.marker)), "complete answer with the sibling value "+strconv.FormatFloat(r.backupSibling, 'f', -1, 64)+" the older backup held")
}

// ---- replacing the lagging voter by a fresh identity ----

// dcFreshNode is the identity of the replacement voter: a new raft id, node identity, peer
// address, failure domain, certificate and an empty data directory.
var dcFreshNode = distNode{4, "d", "node-d"}

// prepareFresh lays out the replacement voter: its addresses, directory, log, certificate (from
// the cluster CA) and node file, whose member list names it as a learner (docs/operations/
// distributed.md, "Replacing a voter").
func (r *dcRun) prepareFresh() (replica.Member, error) {
	c := r.cluster
	id := dcFreshNode.id
	pub, e1 := freeAddress()
	peer, e2 := freeAddress()
	if e1 != nil || e2 != nil {
		return replica.Member{}, errors.Join(e1, e2)
	}
	c.public[id], c.peer[id] = pub, peer
	c.data[id] = filepath.Join(c.root, "node-"+dcFreshNode.name)
	c.logs[id] = &syncBuffer{}
	certPEM, keyPEM, err := c.pki.ca.issue(dcFreshNode, c.pki.nextSerial())
	if err != nil {
		return replica.Member{}, err
	}
	cert, key := filepath.Join(c.pki.dir, dcFreshNode.name+".pem"), filepath.Join(c.pki.dir, dcFreshNode.name+".key")
	if err = errors.Join(os.WriteFile(cert, certPEM, 0o600), os.WriteFile(key, keyPEM, 0o600)); err != nil {
		return replica.Member{}, err
	}
	raw, err := os.ReadFile(r.nodeFile(1))
	if err != nil {
		return replica.Member{}, err
	}
	var node appcore.NodeConfig
	if model.StrictJSON(raw, &node) != nil {
		return replica.Member{}, model.Fail(model.Invalid)
	}
	learner := replica.Member{ID: id, Address: "https://" + peer, NodeIdentity: dcFreshNode.identity, FailureDomain: "process-directory-" + dcFreshNode.name, Learner: true}
	node.NodeID, node.PeerListen, node.PeerSourceIP = id, peer, ""
	node.Certificate, node.PrivateKey = cert, key
	node.Members = replica.Members{Revision: node.Members.Revision + 1, Nodes: append(slices.Clone(node.Members.Nodes), learner)}
	encoded, err := json.MarshalIndent(node, "", "  ")
	if err != nil {
		return replica.Member{}, err
	}
	return learner, os.WriteFile(r.nodeFile(id), append(encoded, '\n'), 0o600)
}

// membershipCLI runs `soundpost membership ...` of the produced binary against one running voter's
// data directory and returns its output and whether it exited 0.
func (r *dcRun) membershipCLI(id uint64, args ...string) (string, bool) {
	cmd := exec.Command(r.cluster.binary, append([]string{"membership"}, append(args, "--data-dir", r.dir(id))...)...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

// dcFreshWatch is what the periodic scans of the replacement's directory saw. While the deletion is
// pending the leaders' state still holds the canary, so it lands on the fresh directory with the
// state the voter catches up to; its own erasure must remove it before any receipt reads clean.
type dcFreshWatch struct {
	scans             int
	firstHit, lastHit int64 // milliseconds since the run started; 0: never seen
	maxHits           int
	last              time.Time
}

// dcErasedBefore reports whether the canary was last seen on the replacement's directory no later
// than the first clean receipt (or never seen).
func dcErasedBefore(lastHit, firstClean int64) bool {
	return lastHit == 0 || lastHit <= firstClean
}

// observeFresh scans the replacement's directory (at most four times a second) and records when the
// canary was on it.
func (r *dcRun) observeFresh() error {
	if time.Since(r.fresh.last) < 250*time.Millisecond {
		return nil
	}
	s, err := r.scanWatch()
	if err != nil {
		return err
	}
	r.fresh.last = time.Now()
	r.fresh.scans++
	if s.Hits > 0 {
		if r.fresh.firstHit == 0 {
			r.fresh.firstHit = max(r.since(), 1)
		}
		r.fresh.lastHit = max(r.since(), 1)
		r.fresh.maxHits = max(r.fresh.maxHits, s.Hits)
	}
	return nil
}

// membershipUntilDone runs one step on each live voter in turn until one exits 0 (every group is
// in the requested configuration). The receipt is sampled on the live voters between the runs, so a
// clean answer while the membership changes is checked against the replacement's directory.
func (r *dcRun) membershipUntilDone(track *dcCleanTrack, limit time.Duration, args ...string) (string, error) {
	deadline := time.Now().Add(limit)
	last := ""
	for time.Now().Before(deadline) {
		for _, id := range r.live {
			out, ok := r.membershipCLI(id, args...)
			last = out
			if ok {
				return out, nil
			}
			if err := r.observeFresh(); err != nil {
				return out, err
			}
			if r.op == (model.ID{}) { // an early learner joins before any deletion exists: no receipt to sample yet
				continue
			}
			if _, err := r.sample(track, r.live...); err != nil {
				return out, err
			}
		}
		time.Sleep(time.Second)
	}
	r.detail = "membership " + args[0] + ": " + dcSafeLine(last)
	return last, &smokeFailure{Smoke: dcSmoke, Stage: r.stage, Code: "timeout_membership_" + strings.ReplaceAll(args[0], "-", "_")}
}

// replaceWhilePending is the second ending of the scenario. The lagging voter stays dead and is
// REPLACED by a fresh identity through the product's membership path (add-learner, start the new
// node on an empty directory, replace) while the deletion is still pending: it was just begun, the
// leaders' state still holds the canary and no receipt can be clean. The receipt is sampled from
// before the learner exists until it is clean on every member of the new configuration; a clean
// answer while the replacement's directory holds the canary is a false clean, and the replacement's
// directory is scanned throughout to show when the canary landed on it and that it was erased
// before the first clean answer. The retired voter's directory is never started again.
func (r *dcRun) replaceWhilePending(started time.Time) error {
	lag, fresh := r.lag, dcFreshNode.id
	for _, id := range r.live {
		if id != r.live[0] { // the begin node was logged in again just before the deletion
			if err := r.login(id); err != nil {
				return err
			}
		}
	}
	if !r.early {
		if err := r.joinFresh(true); err != nil {
			return err
		}
	}
	track := r.track
	var err error

	r.enter("dc_replace_lagging_voter_by_fresh_identity")
	if _, err = r.membershipUntilDone(track, 240*time.Second, "replace", "--remove", dcKey(lag), "--promote", dcKey(fresh)); err != nil {
		return err
	}
	want := map[uint64]string{}
	for _, id := range dcReplacementMembers(r.members, lag, fresh) {
		for _, n := range append(slices.Clone(distNodes), dcFreshNode) {
			if n.id == id {
				want[id] = n.identity
			}
		}
	}
	listing, _ := r.membershipCLI(r.live[0], "status")
	if err = r.check("replacement_leaves_every_group_with_the_fresh_voter_and_without_the_lagging_one", dcStatusShowsVoters(listing, want, 65), fmt.Sprintf("voters %v in all 65 groups, no learner", want)); err != nil {
		return err
	}
	r.members = dcReplacementMembers(r.members, lag, fresh)
	r.mark("lagging_voter_replaced_ms")
	if err = r.login(fresh); err != nil {
		return err
	}

	r.enter("dc_wait_receipt_clean_all_members_after_replacement")
	err = r.until("receipt_clean_all_members", r.wait, dcPollInterval, func() (bool, string, error) {
		if err := r.observeFresh(); err != nil {
			return false, "", err
		}
		progress, err := r.sample(track, r.members...)
		if err != nil {
			return false, "", err
		}
		return len(track.cleanAt) == len(r.members) && len(progress) == 0, "not_clean " + strings.Join(progress, " "), nil
	})
	if err != nil {
		return err
	}
	r.mark("receipt_clean_all_members_ms")
	r.art.Evidence["live_scan_at_first_clean_receipt"] = track.own
	r.art.Evidence["replacement_voter_scan_at_first_clean_receipt"] = track.lagging
	r.art.Evidence["receipt_residual_trail_with_replacement"] = track.trail
	r.art.Evidence["receipt_samples_with_replacement"] = track.samples
	r.art.Evidence["receipt_not_clean_samples_with_replacement"] = track.notClean
	r.art.Evidence["replacement_voter_directory_watch"] = map[string]any{"scans": r.fresh.scans, "canary_first_seen_ms": r.fresh.firstHit, "canary_last_seen_ms": r.fresh.lastHit, "max_hits_in_one_scan": r.fresh.maxHits}
	if err = r.check("receipt_clean_on_every_member_after_replacement", true, "phase complete, physical done, no residual store on nodes "+fmt.Sprint(r.members)); err != nil {
		return err
	}
	firstClean := int64(0)
	for _, at := range track.cleanAt {
		if firstClean == 0 || at < firstClean {
			firstClean = at
		}
	}
	if err = r.check("replacement_voter_erased_the_canary_before_any_receipt_read_clean", dcErasedBefore(r.fresh.lastHit, firstClean), fmt.Sprintf("canary last seen on the replacement's directory at %d ms (0: never), first clean receipt at %d ms, %d scans", r.fresh.lastHit, firstClean, r.fresh.scans)); err != nil {
		return err
	}
	for _, id := range r.members {
		key := dcKey(id)
		if err = r.check("live_scan_zero_when_receipt_first_clean_node_"+key, track.own[key].Hits == 0, fmt.Sprintf("%d hits in %d files, by store %v", track.own[key].Hits, track.own[key].Files, track.own[key].ByStore)); err != nil {
			return err
		}
	}
	if r.auth != nil {
		r.enter("dc_authority_checkpointed_deletion")
		if err = r.checkAuthority(); err != nil {
			return err
		}
	}

	// The sibling project is untouched by the deletion and by the replacement.
	r.enter("dc_sibling_untouched_after_replacement")
	if err = r.siblingIngest(r.live[0], float64(dcSiblingBatches+1)); err != nil {
		return err
	}
	if err = r.check("sibling_ingest_accepted_after_replacement", true, "a new sample for the sibling project acknowledged through node "+dcKey(r.live[0])); err != nil {
		return err
	}
	if err = r.checkSibling("after_replacement", r.members...); err != nil {
		return err
	}

	// The retired voter's directory is outside the membership and outside the receipt: it was killed
	// before the deletion and still holds the canary. The operator must destroy it (docs/operations/
	// distributed.md step 5); the smoke shows the scan sees it, so a clean receipt is not about it.
	r.enter("dc_retired_voter_directory")
	retired, err := r.scan(lag)
	if err != nil {
		return err
	}
	r.art.Evidence["retired_voter_directory_scan"] = retired
	if err = r.check("retired_voter_directory_still_holds_the_canary_outside_the_receipt", retired.Hits > 0, fmt.Sprintf("%d hits in %d files, by store %v: the receipt of the current voters cannot speak for a disk that left the membership", retired.Hits, retired.Files, retired.ByStore)); err != nil {
		return err
	}
	return r.stopRestartVerify(started, "", nil, nil, fresh, false)
}

// joinFreshEarly is the early-learner run's join: the fresh identity is added and started while the
// canary is live and the run continues only once the learner's own directory holds the canary.
func (r *dcRun) joinFreshEarly() error {
	if err := r.joinFresh(false); err != nil {
		return err
	}
	// The learner replicates the live data: wait until its own directory holds the canary, so the
	// deletion begins with a replacement that holds it (the case the late join cannot show: by then the
	// canary is already erased on the leaders and the replacement only ever receives erased state).
	if err := r.until("fresh_learner_holds_the_canary", 240*time.Second, 250*time.Millisecond, func() (bool, string, error) {
		if err := r.observeFresh(); err != nil {
			return false, "", err
		}
		return r.fresh.firstHit > 0, "canary_not_on_the_learner_yet", nil
	}); err != nil {
		return err
	}
	return r.check("replacement_learner_holds_the_canary_before_the_deletion", r.fresh.firstHit > 0, fmt.Sprintf("canary on the fresh learner's directory at %d ms (max %d hits in one scan) while the deletion has not begun", r.fresh.firstHit, r.fresh.maxHits))
}

// joinFresh prepares the fresh identity (new raft id, node identity, address, certificate, failure
// domain), adds it as a learner to every group and starts it on an empty directory until it is
// ready. The receipt of the deletion is sampled meanwhile only when sample says an operation exists.
func (r *dcRun) joinFresh(sample bool) error {
	fresh := dcFreshNode.id
	r.enter("dc_prepare_fresh_identity")
	learner, err := r.prepareFresh()
	if err != nil {
		return r.wrap(err)
	}
	r.watch = fresh
	track := newDCCleanTrack()
	r.track = track

	if sample {
		r.enter("dc_add_learner_while_deletion_pending")
	} else {
		r.enter("dc_add_learner_before_deletion")
	}
	out, err := r.membershipUntilDone(track, 120*time.Second, "add-learner", "--id", dcKey(fresh), "--address", learner.Address, "--identity", learner.NodeIdentity, "--failure-domain", learner.FailureDomain)
	if err != nil {
		return err
	}
	if err = r.check("learner_added_to_every_group", strings.Contains(out, "groups="), "add-learner exits 0 on a surviving voter: every group has the fresh identity as a learner"); err != nil {
		return err
	}
	r.mark("learner_added_ms")

	r.enter("dc_start_fresh_voter")
	if err = r.start(fresh); err != nil {
		return r.wrap(err)
	}
	if err = r.refreshSites(fresh); err != nil {
		return err
	}
	err = r.until("fresh_voter_ready", 240*time.Second, 10*time.Millisecond, func() (bool, string, error) {
		if err := r.observeFresh(); err != nil {
			return false, "", err
		}
		if sample {
			if _, err := r.sample(track, r.live...); err != nil {
				return false, "", err
			}
		}
		if err := waitNodeReady(r.sites[fresh], time.Second); err != nil {
			return false, "not_ready", nil
		}
		return true, "", nil
	})
	if err != nil {
		return err
	}
	r.mark("fresh_voter_ready_ms")
	return nil
}
