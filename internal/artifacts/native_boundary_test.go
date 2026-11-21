// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/artifacts"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// Boundary pins for the native debug object path of the artifact service (l4w33 mutation battery B): which manifest is a
// native one, which writer may store one, in which order the checks run, and that every failure of a step stops the
// upload there. The service is built over recording doubles of the byte store, the metadata store and the scope
// authorizer, while the scope, its source policy and its project are the real ones of the artifact fixture.

type nativeBlobs struct {
	written [][]byte
	err     error
}

func (b *nativeBlobs) WriteBlob(_ context.Context, _ auth.Scope, m model.BlobManifest, r io.Reader) (model.BlobReceipt, error) {
	raw, _ := io.ReadAll(r)
	b.written = append(b.written, raw)
	return model.BlobReceipt{Manifest: m}, b.err
}
func (*nativeBlobs) VerifyBlob(context.Context, model.BlobReceipt) error { return nil }
func (*nativeBlobs) ReadBlobFragment(context.Context, auth.Scope, model.BlobReceipt, uint32) ([]byte, error) {
	return nil, nil
}

type nativeMetadata struct {
	reserved   []model.BlobManifest
	published  []artifacts.Artifact
	reserveErr error
}

func (m *nativeMetadata) ReserveArtifact(_ context.Context, _ auth.Scope, b model.BlobManifest) (model.ArtifactQuotaReservation, error) {
	m.reserved = append(m.reserved, b)
	return model.ArtifactQuotaReservation{Manifest: b}, m.reserveErr
}
func (m *nativeMetadata) PublishArtifact(_ context.Context, _ auth.Scope, a artifacts.Artifact) (artifacts.Artifact, error) {
	m.published = append(m.published, a)
	return a, nil
}
func (*nativeMetadata) LookupArtifact(context.Context, auth.Scope, model.ID) (artifacts.Artifact, error) {
	return artifacts.Artifact{}, nil
}

type nativeAuthorizer struct{ err error }

func (a nativeAuthorizer) Revalidate(context.Context, auth.Scope) error { return a.err }

type nativeRig struct {
	f        *artifactFixture
	svc      *artifacts.Service
	blobs    *nativeBlobs
	meta     *nativeMetadata
	verified int
}

func newNativeRig(t *testing.T, authorizer nativeAuthorizer) *nativeRig {
	t.Helper()
	r := &nativeRig{f: newArtifactFixture(t), blobs: &nativeBlobs{}, meta: &nativeMetadata{}}
	var err error
	if r.svc, err = artifacts.New(r.blobs, r.meta, authorizer); err != nil {
		t.Fatal(err)
	}
	return r
}

const nativeBuildID = "abcdef0123456789abcdef0123456789abcdef01"

// verifier accepts any object as the build ID it is given and counts its calls.
func (r *nativeRig) verifier(buildID string) artifacts.NativeDebugVerifier {
	return func([]byte) (string, error) { r.verified++; return buildID, nil }
}

func (r *nativeRig) manifest(raw []byte) artifacts.Manifest {
	sum := model.Hash(sha256.Sum256(raw))
	return artifacts.Manifest{Version: 1, Org: r.f.org, Project: r.f.project, Source: r.f.source, Build: r.f.build, DebugID: nativeBuildID, GeneratedSHA256: sum, MapSHA256: sum, Path: artifacts.NativeDebugPath(nativeBuildID), Size: model.Uint64(len(raw)), RetainUntil: model.UnixNano(time.Now().Add(time.Hour).UnixNano())}
}

func (r *nativeRig) put(t *testing.T, scope auth.Scope, m artifacts.Manifest, body io.Reader, verify artifacts.NativeDebugVerifier) (artifacts.Artifact, error) {
	t.Helper()
	return r.svc.PutNativeDebug(context.Background(), scope, m, body, verify)
}

func faultCode(err error) model.Code {
	var fault *model.Fault
	if errors.As(err, &fault) {
		return fault.Code
	}
	return ""
}

// touched fails the test (through its flag) if the body is read.
type touchedReader struct{ read *bool }

func (r touchedReader) Read([]byte) (int, error) { *r.read = true; return 0, io.EOF }

var nativeObject = bytes.Repeat([]byte("native debug object "), 20)

// The reserved path of a native debug object is the fixed prefix and the build ID, spelled out: it is what separates a
// native object from a source map in the store.
func TestNativeDebugPathIsTheReservedPrefixAndTheBuildID(t *testing.T) {
	if artifacts.NativeDebugPathPrefix != "native-elf/" {
		t.Fatalf("the reserved prefix is %q", artifacts.NativeDebugPathPrefix)
	}
	if got := artifacts.NativeDebugPath("abcd"); got != "native-elf/abcd" {
		t.Fatalf("the path of build abcd is %q", got)
	}
}

// A manifest is a native one only when every rule holds: a GNU build ID as debug ID, the reserved path of exactly that
// ID, no source content, and one hash for both.
func TestIsNativeDebugNeedsEveryRuleOfTheNativeIdentity(t *testing.T) {
	r := newNativeRig(t, nativeAuthorizer{})
	good := r.manifest(nativeObject)
	if !artifacts.IsNativeDebug(good) {
		t.Fatal("the genuine native manifest is not one")
	}
	// withID changes the debug ID and keeps the reserved path of exactly that ID, so that only the shape of the ID is wrong
	withID := func(id string) func(*artifacts.Manifest) {
		return func(m *artifacts.Manifest) { m.DebugID, m.Path = id, artifacts.NativeDebugPath(id) }
	}
	for name, edit := range map[string]func(*artifacts.Manifest){
		"a debug ID that is not hex":           withID("zz"),
		"a debug ID in upper case":             withID("ABCDEF"),
		"a debug ID of odd length":             withID("abc"),
		"a debug ID of one byte less than two": withID("a"),
		"no debug ID":                          withID(""),
		"the path of another build":            func(m *artifacts.Manifest) { m.Path = artifacts.NativeDebugPath("abcd") },
		"a source map path":                    func(m *artifacts.Manifest) { m.Path = "dist/app.js.map" },
		"source content":                       func(m *artifacts.Manifest) { m.SourceContent = true },
		"two different hashes":                 func(m *artifacts.Manifest) { m.GeneratedSHA256 = model.HashCanonical([]byte("other")) },
	} {
		m := good
		edit(&m)
		if artifacts.IsNativeDebug(m) {
			t.Errorf("%s: still a native debug manifest", name)
		}
	}
	// the longest and the shortest build IDs the format allows
	for _, id := range []string{"ab", string(bytes.Repeat([]byte("cd"), 64))} {
		m := good
		m.DebugID, m.Path = id, artifacts.NativeDebugPath(id)
		if !artifacts.IsNativeDebug(m) {
			t.Errorf("a build ID of %d characters is refused", len(id))
		}
	}
	m := good
	m.DebugID = string(bytes.Repeat([]byte("cd"), 65))
	m.Path = artifacts.NativeDebugPath(m.DebugID)
	if artifacts.IsNativeDebug(m) {
		t.Error("a build ID of 130 characters is accepted")
	}
}

// ValidateNativeDebugManifest is the common manifest rules and then the native ones: it refuses a manifest the common
// rules refuse, refuses a common-valid manifest that is not native, and accepts only one that is both.
func TestValidateNativeDebugManifestAddsTheNativeRulesToTheCommonOnes(t *testing.T) {
	r := newNativeRig(t, nativeAuthorizer{})
	good := r.manifest(nativeObject)
	if err := artifacts.ValidateNativeDebugManifest(good); err != nil {
		t.Fatalf("the genuine manifest: %v", err)
	}
	commonInvalid := good
	commonInvalid.Version = 2
	if err := artifacts.ValidateNativeDebugManifest(commonInvalid); faultCode(err) != model.Invalid {
		t.Errorf("a manifest the common rules refuse: %v, want Invalid", err)
	}
	notNative := good
	notNative.Path = "dist/app.js.map"
	if err := artifacts.ValidateManifest(notNative); err != nil {
		t.Fatalf("the fixture manifest of a source map is not valid in general: %v", err)
	}
	if err := artifacts.ValidateNativeDebugManifest(notNative); faultCode(err) != model.Invalid {
		t.Errorf("a valid manifest that is not native: %v, want Invalid", err)
	}
}

// The scope is checked first and for three things on their own: the organization of the manifest, the project of the
// manifest and the artifacts.write permission. A refusal is NotFound, reads no byte of the body and runs no verifier, and
// it comes before any judgement of the manifest itself: a caller who is not a writer of that organization and project is
// told NotFound whatever the manifest says (the later checks of the policy would also answer NotFound for a valid
// manifest, so only an invalid one shows that the scope was looked at first).
func TestPutNativeDebugRefusesAScopeThatIsNotAWriterOfThatOrganizationAndProject(t *testing.T) {
	r := newNativeRig(t, nativeAuthorizer{})
	write := r.f.scope(t, auth.ArtifactWrite)
	good := r.manifest(nativeObject)
	invalid := good
	invalid.Path = "dist/app.js.map"
	for name, tc := range map[string]struct {
		scope auth.Scope
		edit  func(*artifacts.Manifest)
	}{
		"another organization":   {write, func(m *artifacts.Manifest) { m.Org = model.NewID() }},
		"another project":        {write, func(m *artifacts.Manifest) { m.Project = model.NewID() }},
		"a reader, not a writer": {r.f.scope(t, auth.ArtifactRead), func(*artifacts.Manifest) {}},
	} {
		for kind, base := range map[string]artifacts.Manifest{"a valid manifest": good, "a manifest that is not a native one": invalid} {
			m := base
			tc.edit(&m)
			bodyRead := false
			before := r.verified
			_, err := r.put(t, tc.scope, m, touchedReader{&bodyRead}, r.verifier(nativeBuildID))
			if faultCode(err) != model.NotFound {
				t.Errorf("%s, %s: %v, want NotFound", name, kind, err)
			}
			if bodyRead || r.verified != before || len(r.meta.reserved) != 0 || len(r.blobs.written) != 0 {
				t.Errorf("%s, %s: the upload went on past the scope check (body read %v, verifier calls %d)", name, kind, bodyRead, r.verified-before)
			}
		}
	}
}

// A scope the authorizer no longer vouches for stores nothing and the authorizer's own error is the answer.
func TestPutNativeDebugAnswersTheErrorOfAScopeThatIsNoLongerValid(t *testing.T) {
	gone := model.Fail(model.Stale)
	r := newNativeRig(t, nativeAuthorizer{gone})
	bodyRead := false
	_, err := r.put(t, r.f.scope(t, auth.ArtifactWrite), r.manifest(nativeObject), touchedReader{&bodyRead}, r.verifier(nativeBuildID))
	if !errors.Is(err, gone) && faultCode(err) != model.Stale {
		t.Fatalf("a revoked scope: %v, want the authorizer's Stale", err)
	}
	if bodyRead || len(r.blobs.written) != 0 {
		t.Fatal("a revoked scope reached the body")
	}
}

// What the declared manifest says is checked before the body is touched: the native rules, a verifier and a body, and a
// retention that has not elapsed.
func TestPutNativeDebugRefusesAnIncompleteRequestBeforeTheBody(t *testing.T) {
	r := newNativeRig(t, nativeAuthorizer{})
	write := r.f.scope(t, auth.ArtifactWrite)
	good := r.manifest(nativeObject)
	body := func() io.Reader { return bytes.NewReader(nativeObject) }
	notNative := good
	notNative.Path = "dist/app.js.map"
	elapsed := good
	elapsed.RetainUntil = model.UnixNano(time.Now().Add(-time.Minute).UnixNano())
	for name, call := range map[string]func() error{
		"a manifest that is not a native one": func() error { _, e := r.put(t, write, notNative, body(), r.verifier(nativeBuildID)); return e },
		"no body":                             func() error { _, e := r.put(t, write, good, nil, r.verifier(nativeBuildID)); return e },
		"no verifier":                         func() error { _, e := r.put(t, write, good, body(), nil); return e },
		"retention that has elapsed":          func() error { _, e := r.put(t, write, elapsed, body(), r.verifier(nativeBuildID)); return e },
	} {
		if err := call(); faultCode(err) != model.Invalid {
			t.Errorf("%s: %v, want Invalid", name, err)
		}
	}
	if r.verified != 0 || len(r.meta.reserved) != 0 || len(r.blobs.written) != 0 {
		t.Fatalf("an incomplete request went on (verifier calls %d)", r.verified)
	}
}

// The source policy's byte ceiling is exact: an object of exactly MaxBytes is stored, one byte more is TooLarge before
// any byte of the body is read.
func TestPutNativeDebugByteCeilingIsExactAndCheckedBeforeTheBody(t *testing.T) {
	r := newNativeRig(t, nativeAuthorizer{})
	ceiling := func(n int) {
		t.Helper()
		if err := r.f.app.Control.Update(context.Background(), func(st *model.ControlState) error {
			s := st.Sources[r.f.source.String()]
			s.Policy.MaxBytes = model.Uint64(n)
			st.Sources[r.f.source.String()] = s
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	ceiling(len(nativeObject))
	if _, err := r.put(t, r.f.scope(t, auth.ArtifactWrite), r.manifest(nativeObject), bytes.NewReader(nativeObject), r.verifier(nativeBuildID)); err != nil {
		t.Fatalf("an object of exactly the ceiling: %v", err)
	}
	ceiling(len(nativeObject) - 1)
	bodyRead := false
	_, err := r.put(t, r.f.scope(t, auth.ArtifactWrite), r.manifest(nativeObject), touchedReader{&bodyRead}, r.verifier(nativeBuildID))
	if faultCode(err) != model.TooLarge || bodyRead {
		t.Fatalf("an object one byte over the ceiling: %v (body read %v), want TooLarge before the body", err, bodyRead)
	}
}

// A native object is public bytes: it is checked against the source policy as one, so a writer who is not a named
// reader of the source's private content can store it.
func TestPutNativeDebugNeedsNoNamedReaderOfPrivateSources(t *testing.T) {
	r := newNativeRig(t, nativeAuthorizer{})
	if err := r.f.app.Control.Update(context.Background(), func(st *model.ControlState) error {
		o := st.Orgs[r.f.org.String()]
		cfg, err := json.Marshal(auth.SourcePolicyConfig{ProjectID: r.f.project, Enabled: true})
		if err != nil {
			return err
		}
		o.Settings["source_policy:"+r.f.source.String()] = cfg
		st.Orgs[r.f.org.String()] = o
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.put(t, r.f.scope(t, auth.ArtifactWrite), r.manifest(nativeObject), bytes.NewReader(nativeObject), r.verifier(nativeBuildID)); err != nil {
		t.Fatalf("a writer who is no named reader of the private sources: %v", err)
	}
}

// The in-flight upload budget admits an object at four times its size; a budget that cannot hold that refuses it with the
// retryable quota fault and reads no byte of the body.
func TestPutNativeDebugIsRefusedByTheUploadBudgetBeforeTheBody(t *testing.T) {
	r := newNativeRig(t, nativeAuthorizer{})
	need := uint64(len(nativeObject)) * 4
	r.svc.LimitUploads(need-1, need-1)
	bodyRead := false
	_, err := r.put(t, r.f.scope(t, auth.ArtifactWrite), r.manifest(nativeObject), touchedReader{&bodyRead}, r.verifier(nativeBuildID))
	if faultCode(err) != model.Quota || bodyRead {
		t.Fatalf("a budget one byte short: %v (body read %v), want Quota", err, bodyRead)
	}
	r.svc.LimitUploads(need, need)
	if _, err = r.put(t, r.f.scope(t, auth.ArtifactWrite), r.manifest(nativeObject), bytes.NewReader(nativeObject), r.verifier(nativeBuildID)); err != nil {
		t.Fatalf("a budget of exactly four times the object: %v", err)
	}
}

// The admission an upload took is given back when the upload ends, whatever the end: with room for exactly one object at
// a time, a refused upload and a stored one in any order leave room for the next.
func TestPutNativeDebugGivesBackItsUploadAdmissionWhateverTheEnd(t *testing.T) {
	r := newNativeRig(t, nativeAuthorizer{})
	need := uint64(len(nativeObject)) * 4
	r.svc.LimitUploads(need, need)
	write := func() auth.Scope { return r.f.scope(t, auth.ArtifactWrite) }
	good := r.manifest(nativeObject)
	different := append([]byte(nil), nativeObject...)
	different[0] ^= 1
	steps := []struct {
		name string
		body []byte
		want model.Code
	}{
		{"a stored object", nativeObject, ""},
		{"a stored object after it", nativeObject, ""},
		{"an object of other bytes", different, model.Invalid},
		{"a stored object after a refused one", nativeObject, ""},
	}
	for _, step := range steps {
		_, err := r.put(t, write(), good, bytes.NewReader(step.body), r.verifier(nativeBuildID))
		if step.want == "" && err != nil || step.want != "" && faultCode(err) != step.want {
			t.Fatalf("%s: %v, want %q", step.name, err, step.want)
		}
	}
}

// The body is the declared object and nothing else: shorter or failing is Invalid, longer is TooLarge (never mistaken
// for a hash mismatch), different bytes are Invalid before the verifier ever sees them, and an object whose build ID is
// not the declared one is Invalid. None of them stores anything.
func TestPutNativeDebugAcceptsOnlyTheDeclaredObject(t *testing.T) {
	r := newNativeRig(t, nativeAuthorizer{})
	write := func() auth.Scope { return r.f.scope(t, auth.ArtifactWrite) }
	good := r.manifest(nativeObject)
	longer := append(append([]byte(nil), nativeObject...), 'x')
	different := append([]byte(nil), nativeObject...)
	different[0] ^= 1
	for name, tc := range map[string]struct {
		body   io.Reader
		verify artifacts.NativeDebugVerifier
		want   model.Code
		runs   int // verifier calls
	}{
		"a body that ends early":         {bytes.NewReader(nativeObject[:len(nativeObject)-1]), r.verifier(nativeBuildID), model.Invalid, 0},
		"a body that fails":              {io.MultiReader(bytes.NewReader(nativeObject[:10]), errReader{}), r.verifier(nativeBuildID), model.Invalid, 0},
		"a body one byte too long":       {bytes.NewReader(longer), r.verifier(nativeBuildID), model.TooLarge, 0},
		"other bytes of that size":       {bytes.NewReader(different), r.verifier(nativeBuildID), model.Invalid, 0},
		"another build ID inside":        {bytes.NewReader(nativeObject), r.verifier("abcd"), model.Invalid, 1},
		"an object the verifier refuses": {bytes.NewReader(nativeObject), func([]byte) (string, error) { return "", errors.New("not ELF") }, model.Invalid, 0},
	} {
		before := r.verified
		if _, err := r.put(t, write(), good, tc.body, tc.verify); faultCode(err) != tc.want {
			t.Errorf("%s: %v, want %s", name, err, tc.want)
		}
		if r.verified-before != tc.runs {
			t.Errorf("%s: the verifier ran %d times, want %d", name, r.verified-before, tc.runs)
		}
	}
	if len(r.meta.reserved) != 0 || len(r.blobs.written) != 0 || len(r.meta.published) != 0 {
		t.Fatalf("a refused object was stored: %d reservations, %d writes, %d publications", len(r.meta.reserved), len(r.blobs.written), len(r.meta.published))
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrClosedPipe }

// A failing reservation or byte write is the answer, and nothing is published after it. The stored bytes are the object
// and the reservation names its size and hash.
func TestPutNativeDebugPublishesOnlyAfterEveryStoreStepSucceeded(t *testing.T) {
	r := newNativeRig(t, nativeAuthorizer{})
	write := func() auth.Scope { return r.f.scope(t, auth.ArtifactWrite) }
	good := r.manifest(nativeObject)

	reserveErr := errors.New("quota exhausted")
	r.meta.reserveErr = reserveErr
	if _, err := r.put(t, write(), good, bytes.NewReader(nativeObject), r.verifier(nativeBuildID)); !errors.Is(err, reserveErr) {
		t.Fatalf("a failing reservation: %v, want its own error", err)
	}
	if len(r.blobs.written) != 0 || len(r.meta.published) != 0 {
		t.Fatalf("bytes written (%d) or published (%d) after a failed reservation", len(r.blobs.written), len(r.meta.published))
	}

	r.meta.reserveErr = nil
	writeErr := errors.New("disk full")
	r.blobs.err = writeErr
	if _, err := r.put(t, write(), good, bytes.NewReader(nativeObject), r.verifier(nativeBuildID)); !errors.Is(err, writeErr) {
		t.Fatalf("a failing byte write: %v, want its own error", err)
	}
	if len(r.meta.published) != 0 {
		t.Fatalf("%d publications after a failed byte write", len(r.meta.published))
	}

	r.blobs.err = nil
	r.meta.reserved, r.blobs.written = nil, nil
	stored, err := r.put(t, write(), good, bytes.NewReader(nativeObject), r.verifier(nativeBuildID))
	if err != nil || len(r.meta.published) != 1 || stored.ID == (model.ID{}) || stored.ID != r.meta.published[0].ID {
		t.Fatalf("a good object: %+v %v, %d publications", stored, err, len(r.meta.published))
	}
	if len(r.blobs.written) != 1 || !bytes.Equal(r.blobs.written[0], nativeObject) {
		t.Fatal("the stored bytes are not the object")
	}
	reserved := r.meta.reserved[len(r.meta.reserved)-1]
	if reserved.Hash != good.MapSHA256 || uint64(reserved.Size) != uint64(len(nativeObject)) || reserved.DebugID != nativeBuildID || reserved.Path != good.Path || reserved.Org != r.f.org || reserved.PrivateSources {
		t.Fatalf("the reservation: %+v", reserved)
	}
}
