// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/privacy/privnode"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
	"github.com/arynyklas/soundpost/internal/policy"
	"github.com/arynyklas/soundpost/internal/profiles"
	"github.com/arynyklas/soundpost/internal/retention"
)

// These tests drive the real native exporter into the real node: the exporter's
// batches reach the real POST /ingest/v1/batches route (gzip, bearer source
// credential, TLS) of an in-process appcore+httpapi server, profiles are read
// back through the real C05 reader and the canonical POST /api/v1/profiles/view
// route, and erasure is the product's own retention.Service operation. The
// captured events are synthetic numeric samples: the real-kernel rows are the
// export fixture's (fixtures/nativeperf/export).

type rlLease struct{}

func (rlLease) Bytes() uint64 { return 2 << 20 }
func (rlLease) Close() error  { return nil }

// rlAdmitter forwards every exporter batch to the real route, records the batch
// the exporter froze, and (when loseProfile is set) drops the durable response
// of the first batch that carries a profile record AFTER the node committed it.
type rlAdmitter struct {
	inner       *privnode.Admitter
	loseProfile bool

	mu       sync.Mutex
	batches  []model.Batch
	calls    int
	lost     bool
	original model.Receipt
}

func (a *rlAdmitter) Admit(ctx context.Context, g policy.SourceGrant, b model.Batch) (model.Receipt, error) {
	a.mu.Lock()
	a.calls++
	a.batches = append(a.batches, b)
	a.mu.Unlock()
	r, e := a.inner.Admit(ctx, g, b)
	if e != nil {
		return r, e
	}
	if a.loseProfile && !a.lost {
		for _, row := range b.Records {
			if row.Kind == model.Profile {
				a.mu.Lock()
				a.lost, a.original = true, r
				a.mu.Unlock()
				return model.Receipt{}, errors.New("fixture_lost_durable_response")
			}
		}
	}
	return r, nil
}
func (a *rlAdmitter) admitCalls() int { a.mu.Lock(); defer a.mu.Unlock(); return a.calls }

type rlRig struct {
	t        *testing.T
	ctx      context.Context
	n        *privnode.Node
	admit    *rlAdmitter
	exporter *nativeperf.Exporter
	token    string
	start    model.UnixNano
	end      model.UnixNano
	input    nativeperf.ProfileChunk
	root     model.ID
}

func rlCapabilities() nativeperf.Capabilities {
	return nativeperf.Capabilities{CPU: nativeperf.Supported, OffCPU: nativeperf.Denied, RunqueueSplit: nativeperf.Denied, Permissions: nativeperf.Permissions{CPUEventOpen: nativeperf.Supported, SchedulerEventOpen: nativeperf.Denied}, FrameCoverage: nativeperf.Coverage{Reasons: []nativeperf.Reason{nativeperf.ReasonUnmeasured}}, ThreadCoverage: nativeperf.Coverage{Reasons: []nativeperf.Reason{nativeperf.ReasonUnmeasured}}}
}

func rlSlot(t *testing.T, n *privnode.Node, row model.Record) uint16 {
	t.Helper()
	slot, e := model.OwnerSlot(n.Org, n.Project, n.Source, n.Producer, row)
	if e != nil {
		t.Fatal(e)
	}
	return slot
}

// rlCapabilitySlot is the owner slot every capability and loss record of the
// node's producer shares.
func rlCapabilitySlot(t *testing.T, n *privnode.Node) (capSlot, lossSlot uint16) {
	t.Helper()
	capSlot = rlSlot(t, n, model.Record{Kind: model.CapabilityKind, Payload: model.Payload{Capability: &model.Capability{}}})
	lossSlot = rlSlot(t, n, model.Record{Kind: model.Loss, Payload: model.Payload{Loss: &model.LossReport{}}})
	return
}

// rlRoot draws profile roots until pick accepts the owner slot of the profile
// record (a profile's slot is its root's).
func rlRoot(t *testing.T, n *privnode.Node, pick func(slot uint16) bool) model.ID {
	t.Helper()
	for range 8192 {
		root := model.NewID()
		if pick(rlSlot(t, n, model.Record{Kind: model.Profile, Payload: model.Payload{Profile: &model.ProfileChunk{Profile: root}}})) {
			return root
		}
	}
	t.Fatal("no profile root with the wanted owner slot")
	return model.ID{}
}

func rlInput(root model.ID, count int) (nativeperf.ProfileChunk, model.UnixNano, model.UnixNano) {
	now := model.UnixNano(time.Now().UnixNano())
	d := nativeperf.ClockDomain{HostID: "host", BootID: "boot"}
	k := nativeperf.TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 7, TID: 8, ProcessStart: 1, Generation: 1}
	events := make([]nativeperf.SanitizedEvent, 0, count)
	for i := range count {
		events = append(events, nativeperf.SanitizedEvent{Kind: nativeperf.EventCPU, Domain: d, Task: k, Sequence: model.Uint64(i + 1), Time: model.MonoNano(10 * (i + 1)), CPUEvent: &nativeperf.CPUSample{IP: 4096, Callchain: []nativeperf.CallchainEntry{{IP: 4096}}, Method: nativeperf.MethodSoftwareCPUClock, Unit: nativeperf.UnitCPUClockNanoseconds, RequestedHz: 99, Period: 901}})
	}
	return nativeperf.ProfileChunk{ProfileID: root, PolicyRevision: 1, Domain: d, Events: events}, now, now + 100
}

// newRlRig starts a real node and an exporter whose profile root has the owner
// slot pick accepts. Nothing is sent yet.
func newRlRig(t *testing.T, loseProfile bool, count int, pick func(profile, capability, loss uint16) bool) *rlRig {
	t.Helper()
	ctx := context.Background()
	n, e := privnode.Start(ctx, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(n.Close)
	token, e := n.IssueReaderToken(ctx)
	if e != nil {
		t.Fatal(e)
	}
	capSlot, lossSlot := rlCapabilitySlot(t, n)
	root := rlRoot(t, n, func(slot uint16) bool { return pick(slot, capSlot, lossSlot) })
	input, start, end := rlInput(root, count)
	limits := nativeperf.ProfileLimits{Profile: root, Process: model.NewID(), Capability: model.NewID(), Domain: input.Domain, PolicyRevision: 1, Sequence: 1, Start: start, End: end, Clock: model.TraceClock{Wall: start, Domain: model.ClockDomain{Host: model.ID{4}, Boot: model.ID{5}, Runtime: model.ID{6}}}, MaxBytes: 8 << 20, MaxSamples: 8192, MaxIntervals: 8192, MaxFrames: 4096, MaxStacks: 4096}
	admit := &rlAdmitter{inner: &privnode.Admitter{N: n}, loseProfile: loseProfile}
	exporter, e := nativeperf.NewExporter(admit, privnode.Lookup{N: n}, nativeperf.ExportConfig{Project: n.Project, Source: n.Source, Producer: n.Producer, Resource: n.Resource, Limits: limits, Capabilities: rlCapabilities()}, rlLease{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { exporter.Close() })
	return &rlRig{t: t, ctx: ctx, n: n, admit: admit, exporter: exporter, token: token.Token, start: start, end: end, input: input, root: root}
}

func (r *rlRig) grant() policy.SourceGrant {
	r.t.Helper()
	g, e := r.n.Grant(r.ctx)
	if e != nil {
		r.t.Fatal(e)
	}
	return g
}

func (r *rlRig) reservations() int {
	r.t.Helper()
	count := 0
	if e := r.n.App.Control.View(r.ctx, func(st model.ControlState) error { count = len(st.Reservations); return nil }); e != nil {
		r.t.Fatal(e)
	}
	return count
}

func (r *rlRig) viewBody(max uint32, cursor string) map[string]any {
	body := map[string]any{"org": r.n.Org.String(), "project": r.n.Project.String(), "profile": r.root.String(), "window": map[string]any{"start": strconv.FormatInt(int64(r.start), 10), "end": strconv.FormatInt(int64(r.end+1), 10)}}
	if max != 0 {
		body["max_samples"] = max
	}
	if cursor != "" {
		body["cursor"] = cursor
	}
	return body
}

// view reads through the canonical HTTP route over the node's TLS listener.
func (r *rlRig) view(max uint32, cursor string) (int, httpapi.ProfileResponse, []byte) {
	r.t.Helper()
	status, raw, e := r.n.ProfileView(r.ctx, r.token, r.viewBody(max, cursor))
	if e != nil {
		r.t.Fatal(e)
	}
	var out httpapi.ProfileResponse
	if status == http.StatusOK {
		if e = json.Unmarshal(raw, &out); e != nil {
			r.t.Fatalf("profile view is not a ProfileResponse: %v", e)
		}
	}
	return status, out, raw
}

func rlFaultCode(t *testing.T, raw []byte) model.Code {
	t.Helper()
	var f model.Fault
	if json.Unmarshal(raw, &f) != nil {
		t.Fatalf("response is not a fault: %s", raw)
	}
	return f.Code
}

func rlCanonicalEqual(t *testing.T, a, b model.Receipt) bool {
	t.Helper()
	a.Historical, b.Historical = false, false
	x, e := model.CanonicalJSON(a)
	if e != nil {
		t.Fatal(e)
	}
	y, e := model.CanonicalJSON(b)
	if e != nil {
		t.Fatal(e)
	}
	return bytes.Equal(x, y)
}

// C03 / 04.07 C8: the exporter partitions by canonical owner slot, and a batch
// that mixes slots posted to the real route is refused whole (422) with nothing
// stored: no reservation, no receipt, no readable profile. The same records
// partitioned by slot are admitted, so the refusal is the mixing and nothing else.
func TestProfileMixedSlotBatchIsRefusedWhole(t *testing.T) {
	r := newRlRig(t, false, 3, func(profile, capability, loss uint16) bool { return profile != capability && profile != loss })
	// The exporter's own output: send once and keep what it froze.
	receipt, e := r.exporter.Send(r.ctx, r.grant(), r.input)
	if e != nil {
		t.Fatalf("real export through the real route: %v", e)
	}
	if !r.exporter.Stats().Admitted || receipt.Historical {
		t.Fatal("the exporter did not report the capture admitted over the real route")
	}
	var profileRecord, capabilityRecord model.Record
	slots := map[uint16]bool{}
	for _, b := range r.admit.batches {
		slots[b.RouteSlot] = true
		for _, row := range b.Records {
			if got := rlSlot(t, r.n, row); got != b.RouteSlot {
				t.Fatalf("the exporter froze a batch for slot %d holding a %s record owned by slot %d", b.RouteSlot, row.Kind, got)
			}
			switch row.Kind {
			case model.Profile:
				profileRecord = row
			case model.CapabilityKind:
				capabilityRecord = row
			}
		}
	}
	if len(slots) < 2 || profileRecord.Payload.Profile == nil || capabilityRecord.Payload.Capability == nil {
		t.Fatalf("the exporter did not partition profile and capability records into distinct slot batches: %d slots", len(slots))
	}

	// A second profile (new root, owner slot different from the capability slot)
	// whose records are posted as ONE mixed batch.
	capSlot, lossSlot := rlCapabilitySlot(t, r.n)
	root2 := rlRoot(t, r.n, func(slot uint16) bool { return slot != capSlot && slot != lossSlot })
	chunk := *profileRecord.Payload.Profile
	chunk.Profile = root2
	mixedProfile := model.Record{ID: model.NewID(), Kind: model.Profile, ObservedAt: profileRecord.ObservedAt, Resource: profileRecord.Resource, Payload: model.Payload{Profile: &chunk}}
	mixedCapability := capabilityRecord
	mixedCapability.ID = model.NewID()
	profileSlot := rlSlot(t, r.n, mixedProfile)
	if profileSlot == rlSlot(t, r.n, mixedCapability) {
		t.Fatal("setup: the records already share a slot")
	}
	mixed := model.Batch{Version: 1, Project: r.n.Project, Source: r.n.Source, Producer: r.n.Producer, ID: model.NewID(), PolicyRevision: 1, RouteSlot: profileSlot, Records: []model.Record{mixedProfile, mixedCapability}}
	wire, e := json.Marshal(mixed)
	if e != nil {
		t.Fatal(e)
	}
	before := r.reservations()
	status, body, e := r.n.PostBatch(r.ctx, nil, wire)
	if e != nil {
		t.Fatal(e)
	}
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("a mixed-slot batch answered %d, want 422: %s", status, body)
	}
	if code := rlFaultCode(t, body); code != model.Invalid {
		t.Fatalf("the 422 carries code %q, want %q", code, model.Invalid)
	}
	if after := r.reservations(); after != before {
		t.Fatalf("a refused mixed batch left a reservation: %d -> %d", before, after)
	}
	hash := model.HashCanonical(wire)
	_, e = privnode.Lookup{N: r.n}.LookupReceipt(r.ctx, model.ReceiptRequest{Source: r.n.Source, Producer: r.n.Producer, RouteSlot: mixed.RouteSlot, BatchID: mixed.ID, OriginalHash: hash})
	var fault *model.Fault
	if !errors.As(e, &fault) || fault.Code != model.NotFound {
		t.Fatalf("a refused mixed batch has a receipt: %v", e)
	}
	// Nothing was stored for the mixed profile's root: not even its capability
	// companion made it into any readable view of the new root.
	probe := &rlRig{t: t, ctx: r.ctx, n: r.n, token: r.token, start: r.start, end: r.end, root: root2}
	if status, _, raw := probe.view(0, ""); status != http.StatusNotFound || rlFaultCode(t, raw) != model.NotFound {
		t.Fatalf("the refused mixed batch's profile is readable: %d %s", status, raw)
	}
	// Control: the very same records split by slot are admitted (200 each).
	for _, split := range []model.Batch{
		{Version: 1, Project: mixed.Project, Source: mixed.Source, Producer: mixed.Producer, ID: model.NewID(), PolicyRevision: 1, RouteSlot: profileSlot, Records: []model.Record{mixedProfile}},
		{Version: 1, Project: mixed.Project, Source: mixed.Source, Producer: mixed.Producer, ID: model.NewID(), PolicyRevision: 1, RouteSlot: rlSlot(t, r.n, mixedCapability), Records: []model.Record{mixedCapability}},
	} {
		raw, e := json.Marshal(split)
		if e != nil {
			t.Fatal(e)
		}
		if status, body, e = r.n.PostBatch(r.ctx, nil, raw); e != nil || status != http.StatusOK {
			t.Fatalf("the slot-partitioned records were refused: %d %v %s", status, e, body)
		}
	}
	if status, view, raw := probe.view(0, ""); status != http.StatusOK || view.View == nil || len(view.View.Samples) == 0 {
		t.Fatalf("the partitioned profile is not readable: %d %s", status, raw)
	}
}

// 04.07 C10 + C14: the product's real profile deletion (an entity deletion of the
// profile root by an organization admin) hides the profile at once (the fence)
// and erases it, while the historical receipt of the earlier, committed profile
// batch stays byte-identical, the exporter's retry returns it without any new
// admission, and a direct re-post of the committed batch resurrects nothing.
func TestProfileDeletionKeepsHistoricalReceiptAndResurrectsNothing(t *testing.T) {
	r := newRlRig(t, true, 3, func(profile, capability, loss uint16) bool { return profile >= capability && profile >= loss })
	if _, e := r.exporter.Send(r.ctx, r.grant(), r.input); e == nil || !r.admit.lost || r.exporter.Stats().Admitted {
		t.Fatalf("the lost durable response was ACKed: %v", e)
	}
	original := r.admit.original
	if status, view, raw := r.view(0, ""); status != http.StatusOK || view.View == nil || len(view.View.Samples) != 3 {
		t.Fatalf("the committed profile is not readable before deletion: %d %s", status, raw)
	}
	generation, e := r.n.App.Retention.DeleteGeneration(r.ctx, r.n.Org, []model.ID{r.n.Project})
	if e != nil {
		t.Fatal(e)
	}
	admin, e := r.n.AdminScope(r.ctx)
	if e != nil {
		t.Fatal(e)
	}
	var revision model.Revision
	if e = r.n.App.Control.View(r.ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); e != nil {
		t.Fatal(e)
	}
	begun, e := r.n.App.Retention.Delete(r.ctx, admin, retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: revision, Mode: model.DeleteEntity, OrgID: r.n.Org, ProjectIDs: []model.ID{r.n.Project}, Signals: []model.Kind{model.Profile}, EntityIDs: []model.ID{r.root}, Reason: "native export deletion fixture"})
	if e != nil {
		t.Fatalf("the product's deletion operation refused the profile: %v", e)
	}
	// Fence (C14): the deletion has begun and the erasure has not run, yet the
	// profile is already unreadable through the canonical route.
	if begun.Phase != model.DeletePhaseFencing {
		t.Fatalf("deletion phase %q, want %q before the worker ran", begun.Phase, model.DeletePhaseFencing)
	}
	if status, _, raw := r.view(0, ""); status != http.StatusNotFound || rlFaultCode(t, raw) != model.NotFound {
		t.Fatalf("the fenced profile is still readable: %d %s", status, raw)
	}
	if g, e := r.n.App.Retention.DeleteGeneration(r.ctx, r.n.Org, []model.ID{r.n.Project}); e != nil || g <= generation {
		t.Fatalf("the deletion did not advance the generation fence: %d -> %d %v", generation, g, e)
	}
	var done retention.DeleteReceipt
	for range 16 {
		if e = r.n.App.Retention.RunOnce(r.ctx); e != nil {
			t.Fatal(e)
		}
		if done, e = r.n.App.Retention.PollDelete(r.ctx, admin, begun.OperationID); e != nil {
			t.Fatal(e)
		}
		if done.Phase == model.DeletePhaseComplete && done.Physical == retention.PhysicalDone {
			break
		}
	}
	if done.Phase != model.DeletePhaseComplete || done.Physical != retention.PhysicalDone {
		t.Fatalf("the deletion did not complete: %+v", done)
	}
	if status, _, raw := r.view(0, ""); status != http.StatusNotFound || rlFaultCode(t, raw) != model.NotFound {
		t.Fatalf("the deleted profile is readable through the canonical route: %d %s", status, raw)
	}
	scope, e := r.n.ReaderScope(r.ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.n.App.NewNativeProfiles().Read(r.ctx, scope, r.root, profiles.Window{Start: r.start, End: r.end + 1, MaxSamples: 64}); e == nil {
		t.Fatal("the deleted profile is readable through the C05 reader")
	} else if f := new(model.Fault); !errors.As(e, &f) || f.Code != model.NotFound {
		t.Fatalf("the deleted profile read answered %v, want not_found", e)
	}

	// The historical receipt is unchanged, over the real receipt route and
	// through the exporter's retry, and neither admits anything.
	reservations, calls := r.reservations(), r.admit.admitCalls()
	q := r.exporter.LastReceiptRequest()
	if q.BatchID == (model.ID{}) {
		t.Fatal("the exporter froze no profile batch identity")
	}
	routed, e := privnode.Lookup{N: r.n}.LookupReceipt(r.ctx, q)
	if e != nil || !routed.Historical || !rlCanonicalEqual(t, routed, original) {
		t.Fatalf("the receipt route lost or changed the historical receipt after deletion: %v", e)
	}
	retried, e := r.exporter.Send(r.ctx, r.grant(), r.input)
	if e != nil || !retried.Historical || !rlCanonicalEqual(t, retried, original) {
		t.Fatalf("the exporter's retry after deletion did not return the original receipt: %v", e)
	}
	if r.reservations() != reservations || r.admit.admitCalls() != calls {
		t.Fatal("recovering the historical receipt after deletion admitted something")
	}

	// Nothing is resurrected: re-posting the committed batch bytes through the
	// real route neither brings the profile back nor reserves anything.
	var committed model.Batch
	for _, b := range r.admit.batches {
		for _, row := range b.Records {
			if row.Kind == model.Profile {
				committed = b
			}
		}
	}
	wire, e := json.Marshal(committed)
	if e != nil {
		t.Fatal(e)
	}
	status, body, e := r.n.PostBatch(r.ctx, nil, wire)
	if e != nil {
		t.Fatal(e)
	}
	if status == http.StatusOK {
		var again model.Receipt
		if e = model.StrictJSON(body, &again); e != nil || !rlCanonicalEqual(t, again, original) {
			t.Fatalf("re-posting the deleted profile batch answered 200 with a different receipt: %s", body)
		}
	}
	if r.reservations() != reservations {
		t.Fatalf("re-posting the deleted profile batch reserved quota again (status %d)", status)
	}
	if status, _, raw := r.view(0, ""); status != http.StatusNotFound || rlFaultCode(t, raw) != model.NotFound {
		t.Fatalf("re-posting the deleted profile batch resurrected it: %d %s", status, raw)
	}
	t.Logf("re-post of the deleted committed profile batch answered %d", status)
}

// 04.07 C17: the native export is read back through the canonical HTTP profile
// route over TLS whose certificate the client verifies (a client with the
// system roots refuses the node), with the native period, unit and capability
// evidence intact.
func TestProfileViewHTTPReadsTheNativeExportOverVerifiedTLS(t *testing.T) {
	r := newRlRig(t, false, 3, func(profile, capability, loss uint16) bool { return true })
	if _, e := r.exporter.Send(r.ctx, r.grant(), r.input); e != nil {
		t.Fatal(e)
	}
	status, view, raw := r.view(0, "")
	if status != http.StatusOK || view.View == nil || view.State != httpapi.StateIncomplete && view.State != httpapi.StateReady {
		t.Fatalf("canonical profile read: %d %s", status, raw)
	}
	v := view.View
	if len(v.Samples) != 3 || v.Units != "samples" || len(v.Capabilities) != 3 {
		t.Fatalf("the read lost samples/units/capabilities: %d %q %d", len(v.Samples), v.Units, len(v.Capabilities))
	}
	for _, s := range v.Samples {
		if s.Native == nil || s.Native.Period != 901 || s.Native.RequestedHz != 99 || s.Native.Unit != string(nativeperf.UnitCPUClockNanoseconds) || s.Count != 1 {
			t.Fatalf("native period/rate/unit lost over HTTP: %+v", s)
		}
	}
	// The HTTP read equals the in-process C05 read of the same window.
	scope, e := r.n.ReaderScope(r.ctx)
	if e != nil {
		t.Fatal(e)
	}
	direct, e := r.n.App.NewNativeProfiles().Read(r.ctx, scope, r.root, profiles.Window{Start: r.start, End: r.end + 1, MaxSamples: httpapi.DefaultProfileSamples})
	if e != nil || len(direct.Samples) != len(v.Samples) || direct.Units != v.Units {
		t.Fatalf("the HTTP view differs from the C05 read: %v", e)
	}
	// Verified TLS: a client that trusts only the system roots must refuse this node.
	system := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	request, e := http.NewRequestWithContext(r.ctx, http.MethodPost, r.n.Server.URL+"/api/v1/profiles/view", bytes.NewReader([]byte("{}")))
	if e != nil {
		t.Fatal(e)
	}
	if resp, e := system.Do(request); e == nil {
		resp.Body.Close()
		t.Fatal("a client without the node's CA reached the profile route: the TLS is not verified")
	}
}

// 04.07 C18: reader-grant revocation between two pages of the canonical HTTP
// read blocks the continuation, and a read after the revocation never returns
// profile data.
func TestProfileViewHTTPRevokedReaderGetsNoNextPage(t *testing.T) {
	r := newRlRig(t, false, 3, func(profile, capability, loss uint16) bool { return true })
	if _, e := r.exporter.Send(r.ctx, r.grant(), r.input); e != nil {
		t.Fatal(e)
	}
	status, first, raw := r.view(1, "")
	if status != http.StatusOK || first.View == nil || len(first.View.Samples) != 1 || first.View.NextCursor == "" {
		t.Fatalf("the first page: %d %s", status, raw)
	}
	if e := r.n.RevokeReaderGrant(r.ctx); e != nil {
		t.Fatal(e)
	}
	status, _, raw = r.view(1, first.View.NextCursor)
	if status == http.StatusOK {
		t.Fatalf("a revoked reader received the next page: %s", raw)
	}
	if status != http.StatusForbidden && status != http.StatusNotFound {
		t.Fatalf("a revoked reader's continuation answered %d: %s", status, raw)
	}
	if bytes.Contains(raw, []byte(`"samples"`)) {
		t.Fatalf("the refusal carries profile data: %s", raw)
	}
	// Any administrative change stales an outstanding cursor, so a refused continuation alone does
	// not prove the grant is gone: a fresh first page for the same token must be denied as well.
	status, _, raw = r.view(1, "")
	if status == http.StatusOK || bytes.Contains(raw, []byte(`"samples"`)) {
		t.Fatalf("a revoked reader read a fresh first page: %d %s", status, raw)
	}
}
