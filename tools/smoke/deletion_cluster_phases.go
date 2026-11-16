// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
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

// siblingIngest acknowledges one sample of the sibling project through a node and moves the
// evaluation time of the sibling's query to just after it.
func (r *dcRun) siblingIngest(id uint64, value float64) error {
	fx := r.fx
	bits := model.FloatBits(math.Float64bits(value))
	record := model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(time.Now().UnixNano()), Resource: model.Resource{Service: fx.service, Environment: fx.environment, Build: fx.build, Instance: "instance", Labels: model.Labels{}},
		Payload: model.Payload{Metric: &model.MetricPoint{Name: r.sib.marker, Labels: model.Labels{}, SampleKind: "float", Value: &bits, Unit: "1", Type: "gauge"}}}
	batch := model.Batch{Version: 1, Project: r.sib.project, Source: r.sib.source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{record}}
	var err error
	if batch.RouteSlot, err = model.OwnerSlot(fx.org, r.sib.project, r.sib.source, batch.Producer, record); err != nil {
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
			return dcServedLatest(status, raw, r.sib.last), "status_" + strconv.Itoa(status), nil
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
func (r *dcRun) scanMarker(id uint64, marker string) (dcScan, error) {
	s, err := dcScanDir(r.dir(id), marker)
	if err != nil {
		return s, r.wrap(err)
	}
	return s, nil
}

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
		lagging, err := r.scan(r.watch)
		if err != nil {
			return nil, err
		}
		detail := fmt.Sprintf("%d hits in %d files, by store %v", lagging.Hits, lagging.Files, lagging.ByStore)
		name := "no_false_clean_node_" + key + "_lagging_voter_directory_holds_no_canary"
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
func (r *dcRun) installEvidence(lag uint64, stranded []string, cut map[string]dcJournal, requireNotice bool) error {
	r.enter("dc_snapshot_install_evidence")
	after, err := r.journals(lag)
	if err != nil {
		return err
	}
	passed := dcInstalledPast(stranded, cut, after)
	if err = r.check("lagging_voter_journals_start_past_every_cut_after_stop", len(stranded) > 0 && len(passed) == len(stranded), fmt.Sprintf("%d of %d journals the voter was stranded on start beyond the live voters' cut", len(passed), len(stranded))); err != nil {
		return err
	}
	r.art.Evidence["lagging_voter_journals_after_catch_up"] = after
	facts := map[string]dcFacts{}
	for _, id := range r.members {
		f, err := dcReadFacts(r.dir(id))
		if err != nil {
			r.detail = "erase facts of node " + dcKey(id) + ": " + err.Error()
			return r.wrap(err)
		}
		facts[dcKey(id)] = f
		if requireNotice {
			if err = r.check("erase_notice_names_lagging_voter_node_"+dcKey(id), f.NoticeByNode[dcKey(lag)] > 0, fmt.Sprintf("notice index %d; notices %v; install epoch %d", f.NoticeByNode[dcKey(lag)], f.NoticeByNode, f.InstallEpoch)); err != nil {
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
func (r *dcRun) stopRestartVerify(started time.Time, stranded []string, cut map[string]dcJournal, fresh uint64, requireNotice bool) error {
	cl, fx := r.cluster, r.fx
	r.enter("dc_stop_all_nodes")
	if err := cl.stop(r.art.Evidence); err != nil {
		return r.wrap(err)
	}
	r.mark("all_stopped_ms")
	if err := r.scanAll("stopped_scan", "dc_scan_stopped_data_directories"); err != nil {
		return err
	}
	if err := r.installEvidence(fresh, stranded, cut, requireNotice); err != nil {
		return err
	}

	// ---- restart: denied through each node, still clean, still zero ----
	r.enter("dc_restart_all_nodes")
	if err := cl.start(r.members...); err != nil {
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
		op, err := r.poll(id)
		if err != nil {
			return r.wrap(err)
		}
		if err = r.check("receipt_still_clean_after_restart_node_"+key, op.Phase == model.DeletePhaseComplete && op.Physical == "done" && len(op.ResidualStores) == 0, fmt.Sprintf("phase %s physical %s residual %v", safeToken(op.Phase), safeToken(op.Physical), op.ResidualStores)); err != nil {
			return err
		}
		denied[key] = map[string]any{"read_status": status, "read_code": dcFaultCode(raw), "ingest_status": istatus, "ingest_code": dcFaultCode(iraw)}
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
	r.art.Evidence["scenario_wall_clock_ms"] = time.Since(started).Milliseconds()
	return nil
}
