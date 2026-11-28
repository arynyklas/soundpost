// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
//go:build linux

package appcore_test

import (
	"context"
	"debug/elf"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/artifacts"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// 04.06-C14 / 04.07-C19 / 04.08-C15: native frames are named only through an approved GNU-build-ID -> C07 artifact
// association, through the artifact service's authorized, fenced, retention-checked read, on a REAL application
// (appcore.Open: real storage, control and auth) with a REAL ELF object built by the host C compiler (full DWARF, so a
// source path exists in the object that must never reach the profile).

const nativeSymbolSource = `
int soundpost_hot_loop(int n) { int s = 0; for (int i = 0; i < n; i++) s += i * 3; return s; }
int soundpost_other(int n) { return soundpost_hot_loop(n) + 1; }
`

type nativeObject struct {
	bytes   []byte
	buildID string
	dir     string
	// ipOffset is a file offset inside soundpost_hot_loop.
	ipOffset uint64
}

func buildNativeObject(t *testing.T, tag string) nativeObject {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no C compiler on this host")
	}
	dir := filepath.Join(t.TempDir(), "PRIVATE_CANARY_BUILD_DIR_"+tag)
	if err = os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	src, out := filepath.Join(dir, "secret_module_"+tag+".c"), filepath.Join(dir, "libnative_"+tag+".so")
	if err = os.WriteFile(src, []byte(nativeSymbolSource+"int soundpost_tag_"+tag+"(void) { return 1; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if o, e := exec.Command(cc, "-g", "-O0", "-shared", "-fPIC", "-Wl,--build-id=sha1", "-o", out, src).CombinedOutput(); e != nil {
		t.Fatalf("cc: %v\n%s", e, o)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	buildID, err := nativeperf.VerifyDebugELF(raw)
	if err != nil {
		t.Fatalf("the compiled object is not a valid native debug object: %v", err)
	}
	f, err := elf.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	syms, err := f.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range syms {
		if s.Name != "soundpost_hot_loop" {
			continue
		}
		for _, p := range f.Progs {
			if p.Type == elf.PT_LOAD && s.Value >= p.Vaddr && s.Value < p.Vaddr+p.Filesz {
				return nativeObject{bytes: raw, buildID: buildID, dir: dir, ipOffset: s.Value - p.Vaddr + p.Off + 4}
			}
		}
	}
	t.Fatal("soundpost_hot_loop is not in a loaded segment")
	return nativeObject{}
}

type workingLease uint64

func (w workingLease) Bytes() uint64 { return uint64(w) }
func (workingLease) Close() error    { return nil }

// assembleLeaf assembles a one-sample profile of a process that mapped obj's file from offset 0 and sampled inside
// soundpost_hot_loop, under binding, and returns the leaf frame of the sample plus the marshalled chunk.
func assembleLeaf(t *testing.T, obj nativeObject, mappedBuildID string, binding *nativeperf.SymbolBinding) (model.ProfileFrame, string, error) {
	t.Helper()
	d := nativeperf.ClockDomain{HostID: "host", BootID: "boot"}
	process := nativeperf.ProcessKey{BootID: "boot", PIDNamespace: 1, TGID: 7, ProcessStart: 1, Generation: 1}
	task := nativeperf.TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 7, TID: 8, ProcessStart: 1, Generation: 1}
	const base = 0x7f0000000000
	size := (uint64(len(obj.bytes)) + 4095) &^ 4095
	ip := base + obj.ipOffset
	events := []nativeperf.SanitizedEvent{
		{Kind: nativeperf.EventMapping, Time: 110, Sequence: 1, Domain: d, Mapping: &nativeperf.MappingUpdate{Process: process, Start: base, End: model.Uint64(base + size), FileOffset: 0, BuildID: mappedBuildID, Snapshot: true, Since: 100}},
		{Kind: nativeperf.EventMapping, Time: 110, Sequence: 2, Domain: d, Mapping: &nativeperf.MappingUpdate{Process: process, Snapshot: true, Confirm: true, Since: 100}},
		{Kind: nativeperf.EventCPU, Time: 200, Sequence: 3, Domain: d, Task: task, CPUEvent: &nativeperf.CPUSample{IP: model.Uint64(ip), Callchain: []nativeperf.CallchainEntry{{IP: model.Uint64(ip)}}, Method: nativeperf.MethodSoftwareCPUClock, Unit: nativeperf.UnitCPUClockNanoseconds, RequestedHz: 99, Period: 10_000_000, Truncated: nativeperf.ReasonTruncated}},
		{Kind: nativeperf.EventMapping, Time: 900, Sequence: 4, Domain: d, Mapping: &nativeperf.MappingUpdate{Process: process, Snapshot: true, Confirm: true, Since: 300}},
	}
	limits := nativeperf.ProfileLimits{Profile: model.ID{1}, Process: model.ID{2}, Capability: model.ID{3}, Domain: d, PolicyRevision: 1, Sequence: 1, Start: 1, End: 1000, Clock: model.TraceClock{Wall: 1, Domain: model.ClockDomain{Host: model.ID{4}, Boot: model.ID{5}, Runtime: model.ID{6}}}, MaxBytes: 8 << 20, MaxSamples: 1024, MaxIntervals: 1024, MaxFrames: 4096, MaxStacks: 4096, Symbols: binding}
	caps := nativeperf.Capabilities{CPU: nativeperf.Supported, OffCPU: nativeperf.Denied, RunqueueSplit: nativeperf.Denied, Permissions: nativeperf.Permissions{CPUEventOpen: nativeperf.Supported, SchedulerEventOpen: nativeperf.Denied}, FrameCoverage: nativeperf.Coverage{Reasons: []nativeperf.Reason{nativeperf.ReasonUnmeasured}}, ThreadCoverage: nativeperf.Coverage{Reasons: []nativeperf.Reason{nativeperf.ReasonUnmeasured}}}
	chunk, err := nativeperf.AssembleProfile(context.Background(), events, nil, caps, limits)
	if err != nil {
		return model.ProfileFrame{}, "", err
	}
	if len(chunk.Samples) != 1 {
		t.Fatalf("assembled %d samples, want 1", len(chunk.Samples))
	}
	raw, _ := json.Marshal(chunk)
	return chunk.Frames[chunk.Stacks[chunk.Samples[0].Stack].Frames[0]], string(raw), nil
}

// nativeStored is a registered native debug object: its C07 identity and the manifest the store holds for it.
type nativeStored struct {
	ID       model.ID
	Manifest artifacts.Manifest
}

func (r *wlRig) registerNative(t *testing.T, obj nativeObject, retain time.Duration) nativeStored {
	t.Helper()
	a, err := r.app.PutNativeDebugArtifact(r.ctx, r.scope(auth.ArtifactWrite), r.project, r.source, r.build, obj.bytes, model.UnixNano(time.Now().Add(retain).UnixNano()))
	if err != nil {
		t.Fatalf("PutNativeDebugArtifact: %v", err)
	}
	if a.BuildID != obj.buildID {
		t.Fatalf("registered under build %s, the object carries %s", a.BuildID, obj.buildID)
	}
	held, err := r.app.Artifacts.Lookup(r.ctx, r.scope(auth.ArtifactRead), a.ArtifactID)
	if err != nil {
		t.Fatalf("Lookup of the registered artifact: %v", err)
	}
	return nativeStored{ID: a.ArtifactID, Manifest: held.Manifest}
}

func (r *wlRig) binding(assoc map[string]model.ID, scope auth.Scope, project model.ID) *nativeperf.SymbolBinding {
	return r.app.NewNativeSymbolBinding(scope, project, assoc, workingLease(nativeperf.DefaultSymbolArtifactBytes+1))
}

func requirePrivate(t *testing.T, raw string, obj nativeObject) {
	t.Helper()
	for _, canary := range []string{"PRIVATE_CANARY", "secret_module", obj.dir, "/tmp/", "139637976727552"} {
		if strings.Contains(raw, canary) {
			t.Fatalf("%q reached the assembled profile: %.300s", canary, raw)
		}
	}
}

func TestNativeSymbolicationNamesFramesOnlyThroughTheApprovedArtifactAssociation(t *testing.T) {
	r := newWLRig(t)
	obj := buildNativeObject(t, "a")
	stored := r.registerNative(t, obj, time.Hour)
	m := stored.Manifest
	if m.DebugID != obj.buildID || m.Path != artifacts.NativeDebugPath(obj.buildID) || !artifacts.IsNativeDebug(m) {
		t.Fatalf("the stored manifest is not the object's own native identity: %+v", m)
	}

	// the approved association: the kernel-reported build ID of the mapped code -> the registered artifact
	frame, raw, err := assembleLeaf(t, obj, obj.buildID, r.binding(map[string]model.ID{obj.buildID: stored.ID}, r.scope(auth.ArtifactRead), r.project))
	if err != nil {
		t.Fatal(err)
	}
	if frame.Function != "soundpost_hot_loop" || frame.Reason != "" {
		t.Fatalf("the frame was not named by the approved artifact: %+v", frame)
	}
	requirePrivate(t, raw, obj)

	// no association for the build: identity only, never a guess
	frame, raw, err = assembleLeaf(t, obj, obj.buildID, r.binding(nil, r.scope(auth.ArtifactRead), r.project))
	if err != nil || frame.Function != "" || frame.Reason != string(nativeperf.FrameArtifactUnavailable) {
		t.Fatalf("an unassociated build was named or mislabelled: %+v %v", frame, err)
	}
	requirePrivate(t, raw, obj)

	// an association to an artifact that does not exist
	frame, _, err = assembleLeaf(t, obj, obj.buildID, r.binding(map[string]model.ID{obj.buildID: model.NewID()}, r.scope(auth.ArtifactRead), r.project))
	if err != nil || frame.Function != "" || frame.Reason != string(nativeperf.FrameArtifactUnavailable) {
		t.Fatalf("a missing artifact named a frame: %+v %v", frame, err)
	}

	// the kernel reports another build ID than the one the association is registered for
	other := buildNativeObject(t, "b")
	frame, _, err = assembleLeaf(t, other, other.buildID, r.binding(map[string]model.ID{other.buildID: stored.ID}, r.scope(auth.ArtifactRead), r.project))
	if err != nil || frame.Function != "" || frame.Reason != string(nativeperf.FrameArtifactUnavailable) {
		t.Fatalf("an artifact registered for build %s named a frame of build %s: %+v %v", obj.buildID, other.buildID, frame, err)
	}

	// an artifact that is not a native debug object (a source map of the same project) is never read as one
	sourceMap := r.upload("0123456789abcdef0123456789abcdef", false, time.Hour)
	frame, _, err = assembleLeaf(t, obj, obj.buildID, r.binding(map[string]model.ID{obj.buildID: sourceMap.ID}, r.scope(auth.ArtifactRead), r.project))
	if err != nil || frame.Function != "" || frame.Reason != string(nativeperf.FrameArtifactUnavailable) {
		t.Fatalf("a source-map artifact named a native frame: %+v %v", frame, err)
	}
}

func TestNativeSymbolicationRefusesAScopeThatCannotReadArtifacts(t *testing.T) {
	r := newWLRig(t)
	obj := buildNativeObject(t, "a")
	stored := r.registerNative(t, obj, time.Hour)
	assoc := map[string]model.ID{obj.buildID: stored.ID}
	// a write scope is not an artifacts.read scope: the binding is refused before any read
	if _, _, err := assembleLeaf(t, obj, obj.buildID, r.binding(assoc, r.scope(auth.ArtifactWrite), r.project)); err == nil {
		t.Fatal("a binding over an artifacts.write scope was accepted")
	}
	// a scope of another project cannot be bound to this project
	if _, _, err := assembleLeaf(t, obj, obj.buildID, r.binding(assoc, r.scope(auth.ArtifactRead), model.NewID())); err == nil {
		t.Fatal("a binding of a project the scope does not cover was accepted")
	}
	// the resolver itself refuses a reference outside the scope: no bytes
	resolver := nativeperf.ArtifactResolver(appcore.NativeDebugResolver{Store: r.app.Artifacts})
	for name, ref := range map[string]nativeperf.ArtifactReference{
		"write scope":     {Scope: r.scope(auth.ArtifactWrite), ProjectID: r.project, BuildID: obj.buildID, ArtifactID: stored.ID},
		"foreign project": {Scope: r.scope(auth.ArtifactRead), ProjectID: model.NewID(), BuildID: obj.buildID, ArtifactID: stored.ID},
		"zero artifact":   {Scope: r.scope(auth.ArtifactRead), ProjectID: r.project, BuildID: obj.buildID},
	} {
		if rc, err := resolver.ScopedRead(r.ctx, ref); err == nil {
			rc.Close()
			t.Errorf("%s: the resolver returned bytes", name)
		}
	}
	// and a reference that matches everything reads the object back byte for byte
	rc, err := resolver.ScopedRead(r.ctx, nativeperf.ArtifactReference{Scope: r.scope(auth.ArtifactRead), ProjectID: r.project, BuildID: obj.buildID, ArtifactID: stored.ID})
	if err != nil {
		t.Fatalf("the approved reference was refused: %v", err)
	}
	defer rc.Close()
	buf := make([]byte, len(obj.bytes)+1)
	n, _ := io.ReadFull(rc, buf)
	if n != len(obj.bytes) || string(buf[:n]) != string(obj.bytes) {
		t.Fatalf("the artifact read back %d bytes, want the %d of the object", n, len(obj.bytes))
	}
}

func TestNativeDebugRegistrationAcceptsOnlyAnELFOfTheBuildItNames(t *testing.T) {
	r := newWLRig(t)
	obj := buildNativeObject(t, "a")
	retain := model.UnixNano(time.Now().Add(time.Hour).UnixNano())
	if _, err := r.app.PutNativeDebugArtifact(r.ctx, r.scope(auth.ArtifactWrite), r.project, r.source, r.build, []byte("not an ELF object"), retain); err == nil {
		t.Fatal("garbage was registered as a native debug object")
	}
	if _, err := r.app.PutNativeDebugArtifact(r.ctx, r.scope(auth.ArtifactRead), r.project, r.source, r.build, obj.bytes, retain); err == nil {
		t.Fatal("a read scope registered a native debug object")
	}
	if _, err := r.app.PutNativeDebugArtifact(r.ctx, r.scope(auth.ArtifactWrite), r.project, r.source, r.build, obj.bytes, model.UnixNano(time.Now().Add(-time.Minute).UnixNano())); err == nil {
		t.Fatal("an already expired registration was accepted")
	}
	if _, err := r.app.PutNativeDebugArtifact(r.ctx, r.scope(auth.ArtifactWrite), r.project, r.source, model.NewID(), obj.bytes, retain); err == nil {
		t.Fatal("a build the source does not own was accepted")
	}
	// the stored identity is the one read out of the bytes, not a caller parameter: a manifest naming another build is refused
	m := artifacts.Manifest{Version: 1, Org: r.scope(auth.ArtifactWrite).OrgID(), Project: r.project, Source: r.source, Build: r.build, DebugID: strings.Repeat("ab", 20), GeneratedSHA256: model.HashCanonical(obj.bytes), MapSHA256: model.HashCanonical(obj.bytes), Path: artifacts.NativeDebugPath(strings.Repeat("ab", 20)), Size: model.Uint64(len(obj.bytes)), RetainUntil: retain}
	if _, err := r.app.Artifacts.PutNativeDebug(r.ctx, r.scope(auth.ArtifactWrite), m, strings.NewReader(string(obj.bytes)), nativeperf.VerifyDebugELF); err == nil {
		t.Fatal("an object was stored under a build ID it does not carry")
	}
}

// Retention is re-checked on every read: symbols stop naming frames when the registration expires, and the profile
// still assembles (identity only).
func TestNativeSymbolicationStopsAtTheRetentionOfTheArtifact(t *testing.T) {
	r := newWLRig(t)
	obj := buildNativeObject(t, "a")
	deadline := time.Now().Add(wlBase)
	stored := r.registerNative(t, obj, wlBase)
	binding := func() *nativeperf.SymbolBinding {
		return r.binding(map[string]model.ID{obj.buildID: stored.ID}, r.scope(auth.ArtifactRead), r.project)
	}
	frame, _, err := assembleLeaf(t, obj, obj.buildID, binding())
	wlWindow(t, "the symbolication before the retention deadline", deadline)
	if err != nil || frame.Function != "soundpost_hot_loop" {
		t.Fatalf("before the deadline: %+v %v", frame, err)
	}
	wlSleepUntil(deadline)
	if err = r.runOnce(); err != nil {
		t.Fatal(err)
	}
	frame, _, err = assembleLeaf(t, obj, obj.buildID, binding())
	if err != nil || frame.Function != "" || frame.Reason != string(nativeperf.FrameArtifactUnavailable) {
		t.Fatalf("after the deadline the expired artifact still named a frame: %+v %v", frame, err)
	}
}
