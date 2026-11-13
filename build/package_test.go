// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const testCommit = "0123456789abcdef0123456789abcdef01234567"
const testVersion = "1.2.3"

// signFor and approveFor stand in for the owner: the build tool itself has no signing code.
func signFor(priv ed25519.PrivateKey, manifest []byte) []byte {
	pub := priv.Public().(ed25519.PublicKey)
	d := ManifestDigest(manifest)
	e := SignatureEnvelope{Schema: signatureSchema, Algorithm: "ed25519", KeyID: KeyID(pub), ManifestSHA256: d,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, signatureMessage("manifest", d)))}
	raw, _ := json.Marshal(e)
	return raw
}

func approveFor(priv ed25519.PrivateKey, manifest []byte, version, commit string) []byte {
	pub := priv.Public().(ed25519.PublicKey)
	a := ApprovalEnvelope{Schema: approvalSchema, Owner: "Test Owner", Decision: "approve", Version: version, Commit: commit,
		ManifestSHA256: ManifestDigest(manifest), KeyID: KeyID(pub)}
	a.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, signatureMessage("approval", approvalPayload(a))))
	raw, _ := json.Marshal(a)
	return raw
}

type fixture struct {
	t        *testing.T
	root     string
	art      string
	ledger   string
	evidence map[string]string
	priv     ed25519.PrivateKey
	pubPath  string
	handles  *HandleReport
}

type fakeChecker map[string]string

func (f fakeChecker) Check(_ context.Context, h Handle) (string, error) {
	if s, ok := f[h.Ecosystem+"/"+h.Name]; ok {
		return s, nil
	}
	return HandleUnclaimed, nil
}

// newFixture writes a tiny, fully consistent repository root and every gate input so a release
// passes; tests then break exactly one thing.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{t: t, root: root, evidence: map[string]string{}}
	w := func(rel, body string) { write(t, filepath.Join(root, filepath.FromSlash(rel)), body) }
	w("go.mod", "module example.com/soundpost\n\ngo 1.27.3\n\nrequire example.com/a v1.0.0\n")
	w("go.sum", "example.com/a v1.0.0 h1:aaa=\nexample.com/a v1.0.0/go.mod h1:bbb=\nexample.org/testonly v0.1.0 h1:ccc=\n")
	w("build/auth-control-dependencies.json", `{"direct":[{"module":"example.com/a","version":"v1.0.0","license":"MIT"}],"runtime_indirect":[]}`)
	w("third_party/auth-control-NOTICES.txt", "Notices\n\n===== example.com/a@v1.0.0 (MIT) =====\nMIT text\n")
	w("third_party/config-tooling-NOTICES.txt", "Config notices\n")
	w("third_party/vend/v1/provenance.json", `{"license":"BSD-3-Clause (data is public domain)","upstream_release":"v1"}`)
	w("third_party/vend/v1/LICENSE", "BSD text\n")
	w("third_party/format/go124/provenance.json", `{"license":"BSD-3-Clause"}`)
	w("third_party/format/go124/LICENSE", "Go license\n")
	w("build/toolchains.json", `{"go":{"version":"1.27.3","linux_amd64":{"url":"u","sha256":"`+strings.Repeat("a", 64)+`"}}}`)
	lock := "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies: {}\n"
	w("pnpm-lock.yaml", lock)
	sum := sha256.Sum256([]byte(lock))
	w("build/dependencies/node-licenses.json", `{"lock_sha256":"`+hex.EncodeToString(sum[:])+`","packages":[]}`)
	w("sdk/python/requirements-dev.lock", "# no pins\n")
	w("sdk/python/requirements-integrations.lock", "# no pins\n")
	w("sdk/python/pyproject.toml", "[project]\nname = \"soundpost-test\"\n")
	w("packages/core/package.json", `{"name":"@soundpost/core"}`)
	w("build/promised_surfaces.json", `{"schema":"`+surfacesSchema+`","surfaces":[{"id":"alpha","claim":"alpha works","source":"README","tasks":["01.01","01.02"]}]}`)
	w("docs/releases/checklist.md", "- [ ] `alpha` alpha works\n")
	inv, err := collectInventory(root)
	if err != nil {
		t.Fatal(err)
	}
	body, err := renderNotices(root, inv)
	if err != nil {
		t.Fatal(err)
	}
	w("THIRD_PARTY_NOTICES", string(body))

	f.ledger = filepath.Join(root, "ledger.json")
	f.setLedger("complete", "complete")
	for _, k := range EvidenceKinds {
		p := filepath.Join(root, "evidence-"+k+".json")
		f.writeEvidence(p, k, "passed")
		f.evidence[k] = p
	}
	f.art = filepath.Join(root, "dist")
	bin := "binary-bytes"
	write(t, filepath.Join(f.art, "linux-amd64", "soundpost"), bin)
	bsum := sha256.Sum256([]byte(bin))
	bhex := hex.EncodeToString(bsum[:])
	write(t, filepath.Join(f.art, "SHA256SUMS"), bhex+"  linux-amd64/soundpost\n")
	man, _ := json.Marshal(Manifest{Version: testVersion, Commit: testCommit, Reproducibility: Reproducibility{Checked: true, Equal: true},
		Binaries: []Binary{{Platform: "linux/amd64", Name: "soundpost", SHA256: bhex}}})
	write(t, filepath.Join(f.art, "release.json"), string(man))
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	f.priv = priv
	f.pubPath = filepath.Join(root, "release.pub")
	write(t, f.pubPath, base64.StdEncoding.EncodeToString(pub)+"\n")
	hs, err := DeriveHandles(root)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := RunHandleChecks(context.Background(), fakeChecker{}, hs)
	if err != nil {
		t.Fatal(err)
	}
	f.handles = &rep
	return f
}

func (f *fixture) setLedger(states ...string) {
	var tasks []ledgerTask
	for i, s := range states {
		tasks = append(tasks, ledgerTask{ID: fmt.Sprintf("01.0%d", i+1), Title: "task " + fmt.Sprint(i+1), State: s})
	}
	raw, _ := json.Marshal(tasks)
	write(f.t, f.ledger, string(raw))
}

func (f *fixture) writeEvidence(path, kind, status string) {
	raw, _ := json.Marshal(EvidenceReport{Schema: evidenceSchema, Kind: kind, Commit: testCommit, Expected: []string{"row-1"},
		Rows: []EvidenceRow{{ID: "row-1", Status: status}}})
	write(f.t, path, string(raw))
}

func (f *fixture) manifest() []byte {
	raw, err := os.ReadFile(filepath.Join(f.art, "release.json"))
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func (f *fixture) manifestString() string { return string(f.manifest()) }

func (f *fixture) signed() *fixture {
	p := filepath.Join(f.root, "release.sig")
	write(f.t, p, string(signFor(f.priv, f.manifest())))
	return f
}

func (f *fixture) approve(commit string) string {
	p := filepath.Join(f.root, "approval.json")
	write(f.t, p, string(approveFor(f.priv, f.manifest(), testVersion, commit)))
	return p
}

func (f *fixture) reports() Reports {
	r := Reports{Root: f.root, Version: testVersion, Created: "2026-11-10T00:00:00Z", LedgerPath: f.ledger, Evidence: f.evidence,
		ArtifactDir: f.art, PublicKeyPath: f.pubPath, Handles: f.handles}
	if _, err := os.Stat(filepath.Join(f.root, "release.sig")); err == nil {
		r.SignaturePath = filepath.Join(f.root, "release.sig")
	}
	return r
}

func blockedOnly(t *testing.T, err error, wantPrefixes ...string) *BlockedError {
	t.Helper()
	var be *BlockedError
	if !errors.As(err, &be) {
		t.Fatalf("want BlockedError, got %v", err)
	}
	for _, b := range be.Blocking {
		ok := false
		for _, p := range wantPrefixes {
			ok = ok || strings.HasPrefix(b, p)
		}
		if !ok {
			t.Fatalf("unexpected extra blocking item %q (wanted only %q...): %v", b, wantPrefixes, be.Blocking)
		}
	}
	if len(be.Blocking) == 0 {
		t.Fatal("empty blocking list")
	}
	return be
}

func TestReleasePassesOnlyWhenEverythingIsProvenAndApproved(t *testing.T) {
	f := newFixture(t).signed()
	r := f.reports()
	r.ApprovalPath = f.approve(testCommit)
	m, err := Release(context.Background(), testCommit, r)
	if err != nil || !m.Ready || len(m.Blocking) != 0 {
		t.Fatalf("fully proven fixture must pass: ready=%v err=%v blocking=%v", m.Ready, err, m.Blocking)
	}
	if m.CycloneDXSHA256 == "" || m.SPDXSHA256 == "" || m.ArtifactManifestSHA256 == "" {
		t.Fatalf("digests not recorded: %+v", m)
	}
}

func TestReleaseRefusesIncompleteCoverage(t *testing.T) {
	f := newFixture(t).signed()
	f.setLedger("complete", "partial")
	r := f.reports()
	r.ApprovalPath = f.approve(testCommit)
	m, err := Release(context.Background(), testCommit, r)
	if m.Ready {
		t.Fatal("an incomplete task must not produce a ready release even with approval")
	}
	be := blockedOnly(t, err, "plan_coverage: task 01.02 is partial", "promised_surfaces: surface alpha")
	_ = be
	// the surface delivered by 01.02 is also named
	found := false
	for _, b := range m.Blocking {
		found = found || strings.Contains(b, "01.02")
	}
	if !found {
		t.Fatal("blocking list does not name task 01.02")
	}
}

func TestReleaseRefusesIncompleteCoverageNamesEveryTaskAndHonorsExplicitAcceptance(t *testing.T) {
	f := newFixture(t).signed()
	f.setLedger("implemented_reviewed", "pending")
	r := f.reports()
	r.ApprovalPath = f.approve(testCommit)
	_, err := Release(context.Background(), testCommit, r)
	var be *BlockedError
	if !errors.As(err, &be) {
		t.Fatal(err)
	}
	joined := strings.Join(be.Blocking, "\n")
	for _, want := range []string{"task 01.01 is implemented_reviewed", "task 01.02 is pending"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in %v", want, be.Blocking)
		}
	}
	r.AcceptedTasks = map[string]bool{"01.01": true, "01.02": true}
	_, err = Release(context.Background(), testCommit, r)
	if !errors.As(err, &be) || !strings.Contains(strings.Join(be.Blocking, "\n"), "task 01.02 is pending") || strings.Contains(strings.Join(be.Blocking, "\n"), "task 01.01 is") {
		t.Fatalf("acceptance must cover implemented_* only, never pending: %v", be)
	}
}

func TestReleaseRequiresOwnerApproval(t *testing.T) {
	f := newFixture(t).signed()
	r := f.reports()
	m, err := Release(context.Background(), testCommit, r)
	if m.Ready {
		t.Fatal("no approval must not be ready")
	}
	blockedOnly(t, err, "owner_approval: missing")

	otherPub, otherPriv, _ := ed25519.GenerateKey(nil)
	_ = otherPub
	// each negative case on its own fixture so mutations of one do not leak
	for name, mk := range map[string]func(*fixture) string{
		"wrong commit": func(f *fixture) string { return f.approve("ffffffffffffffffffffffffffffffffffffffff") },
		"wrong key": func(f *fixture) string {
			p := filepath.Join(f.root, "approval-other.json")
			write(t, p, string(approveFor(otherPriv, f.manifest(), testVersion, testCommit)))
			return p
		},
		"manifest changed after approval": func(f *fixture) string {
			p := f.approve(testCommit)
			write(t, filepath.Join(f.art, "release.json"), f.manifestString()+" ")
			return p
		},
		"unsigned decision": func(f *fixture) string {
			p := filepath.Join(f.root, "approval-bad.json")
			a := ApprovalEnvelope{Schema: approvalSchema, Owner: "x", Decision: "approve", Version: testVersion, Commit: testCommit, ManifestSHA256: ManifestDigest(f.manifest()), KeyID: KeyID(f.priv.Public().(ed25519.PublicKey)), Signature: base64.StdEncoding.EncodeToString(make([]byte, 64))}
			raw, _ := json.Marshal(a)
			write(t, p, string(raw))
			return p
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t).signed()
			r := f.reports()
			r.ApprovalPath = mk(f)
			m, err := Release(context.Background(), testCommit, r)
			if m.Ready {
				t.Fatal("invalid approval must not be ready")
			}
			blockedOnly(t, err, "owner_approval: invalid", "signature: invalid")
		})
	}
	r.ApprovalPath = f.approve(testCommit)
	if m, err := Release(context.Background(), testCommit, r); err != nil || !m.Ready {
		t.Fatalf("valid approval: %v %v", err, m.Blocking)
	}
}

func TestSignatureNotSignedAndSignatureTamperBlock(t *testing.T) {
	f := newFixture(t)
	r := f.reports()
	r.ApprovalPath = f.approve(testCommit)
	m, err := Release(context.Background(), testCommit, r)
	blockedOnly(t, err, "signature: not_signed")
	if m.Ready {
		t.Fatal("unsigned release must not be ready")
	}
	f.signed()
	write(t, filepath.Join(f.art, "release.json"), string(f.manifest())+"\n")
	// artifact manifest changed after signing and approval
	r = f.reports()
	r.ApprovalPath = filepath.Join(f.root, "approval.json")
	if _, err = Release(context.Background(), testCommit, r); err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatal("tampered manifest must block")
	}
	m, _ = Release(context.Background(), testCommit, r)
	if !strings.Contains(strings.Join(m.Blocking, "\n"), "signature: invalid") {
		t.Fatalf("want signature invalid, got %v", m.Blocking)
	}
}

func TestSignatureVerifierRejectsTamperedManifest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte(`{"version":"1.2.3","binaries":[]}`)
	env := signFor(priv, manifest)
	if err := VerifySignature(manifest, env, pub); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	flipped := append([]byte{}, manifest...)
	flipped[3] ^= 1
	otherPub, otherPriv, _ := ed25519.GenerateKey(nil)
	replay := approveFor(priv, manifest, "1.2.3", testCommit)
	var e SignatureEnvelope
	_ = json.Unmarshal(env, &e)
	badSig := e
	badSig.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
	badSigRaw, _ := json.Marshal(badSig)
	redigest := e
	redigest.ManifestSHA256 = ManifestDigest(flipped) // digest edited to match a tampered manifest, signature untouched
	redigestRaw, _ := json.Marshal(redigest)
	badSchema := e
	badSchema.Schema = "soundpost-release-signature/2"
	badSchemaRaw, _ := json.Marshal(badSchema)
	for name, c := range map[string]struct {
		manifest, env []byte
		key           ed25519.PublicKey
	}{
		"tampered manifest":       {flipped, env, pub},
		"appended byte":           {append(append([]byte{}, manifest...), '\n'), env, pub},
		"signature zeroed":        {manifest, badSigRaw, pub},
		"digest rewritten":        {flipped, redigestRaw, pub},
		"signed by another key":   {manifest, signFor(otherPriv, manifest), pub},
		"verified with other key": {manifest, env, otherPub},
		"wrong schema":            {manifest, badSchemaRaw, pub},
		"approval replayed":       {manifest, replay, pub},
		"unknown field":           {manifest, []byte(strings.Replace(string(env), "{", `{"extra":1,`, 1)), pub},
		"empty envelope":          {manifest, nil, pub},
		"no public key":           {manifest, env, nil},
	} {
		if err := VerifySignature(c.manifest, c.env, c.key); err == nil {
			t.Errorf("%s: verifier accepted it", name)
		}
	}
}

func TestEvidenceReportsAreNamedAndNeverSelfAsserted(t *testing.T) {
	for _, tc := range []struct {
		name   string
		break_ func(f *fixture)
		want   string
	}{
		{"missing file", func(f *fixture) { os.Remove(f.evidence["privacy"]) }, "evidence_privacy: privacy evidence report missing"},
		{"no path", func(f *fixture) { delete(f.evidence, "browser") }, "evidence_browser: browser evidence report missing: no path"},
		{"skipped row", func(f *fixture) { f.writeEvidence(f.evidence["language"], "language", "skipped") }, "language row row-1 is skipped"},
		{"wrong commit", func(f *fixture) {
			raw, _ := json.Marshal(EvidenceReport{Schema: evidenceSchema, Kind: "runtime", Commit: "deadbeef", Expected: []string{"row-1"}, Rows: []EvidenceRow{{ID: "row-1", Status: "passed"}}})
			write(t, f.evidence["runtime"], string(raw))
		}, "runtime evidence is for commit"},
		{"expected row absent", func(f *fixture) {
			raw, _ := json.Marshal(EvidenceReport{Schema: evidenceSchema, Kind: "node_loss", Commit: testCommit, Expected: []string{"row-1", "row-2"}, Rows: []EvidenceRow{{ID: "row-1", Status: "passed"}}})
			write(t, f.evidence["node_loss"], string(raw))
		}, "node_loss expected row row-2 has no result"},
		{"no expected rows", func(f *fixture) {
			raw, _ := json.Marshal(EvidenceReport{Schema: evidenceSchema, Kind: "runtime", Commit: testCommit, Rows: []EvidenceRow{{ID: "row-1", Status: "passed"}}})
			write(t, f.evidence["runtime"], string(raw))
		}, "runtime evidence declares no expected rows"},
		{"kind mismatch", func(f *fixture) { f.writeEvidence(f.evidence["browser"], "privacy", "passed") }, "browser evidence report has schema"},
		{"self asserted pass field", func(f *fixture) {
			write(t, f.evidence["browser"], `{"schema":"`+evidenceSchema+`","kind":"browser","commit":"`+testCommit+`","passed":true,"expected_rows":["a"],"rows":[]}`)
		}, "browser evidence report malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t).signed()
			tc.break_(f)
			r := f.reports()
			r.ApprovalPath = f.approve(testCommit)
			m, err := Release(context.Background(), testCommit, r)
			if m.Ready || err == nil {
				t.Fatal("must block")
			}
			if !strings.Contains(strings.Join(m.Blocking, "\n"), tc.want) {
				t.Fatalf("want %q in %v", tc.want, m.Blocking)
			}
		})
	}
}

func TestChecksumsDetectTamperAndUncoveredFiles(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(f *fixture)
		want   string
	}{
		"binary changed": {func(f *fixture) { write(t, filepath.Join(f.art, "linux-amd64", "soundpost"), "evil") }, "does not match SHA256SUMS"},
		"binary removed": {func(f *fixture) { os.Remove(filepath.Join(f.art, "linux-amd64", "soundpost")) }, "listed artifact missing"},
		"extra artifact": {func(f *fixture) { write(t, filepath.Join(f.art, "linux-amd64", "extra"), "x") }, "artifact not covered by SHA256SUMS: linux-amd64/extra"},
		"sums escape":    {func(f *fixture) { write(t, filepath.Join(f.art, "SHA256SUMS"), strings.Repeat("a", 64)+"  ../x\n") }, "escapes the artifact directory"},
		"not reproducible": {func(f *fixture) {
			man, _ := json.Marshal(Manifest{Version: testVersion, Commit: testCommit, Binaries: []Binary{{Platform: "linux/amd64", Name: "soundpost", SHA256: "x"}}})
			write(t, filepath.Join(f.art, "release.json"), string(man))
		}, "reproducibility"},
		"other commit": {func(f *fixture) {
			man, _ := json.Marshal(Manifest{Version: testVersion, Commit: "abc", Reproducibility: Reproducibility{Checked: true, Equal: true}})
			write(t, filepath.Join(f.art, "release.json"), string(man))
		}, "release.json is for version"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			tc.mutate(f)
			m, err := Release(context.Background(), testCommit, f.reports())
			if err == nil || m.Ready {
				t.Fatal("must block")
			}
			if !strings.Contains(strings.Join(m.Blocking, "\n"), tc.want) {
				t.Fatalf("want %q in %v", tc.want, m.Blocking)
			}
		})
	}
}

func TestLicenseAllowList(t *testing.T) {
	for expr, want := range map[string]bool{
		"MIT": true, "Apache-2.0": true, "BSD-2-Clause": true, "BSD-3-Clause": true, "ISC": true, "0BSD": true,
		"BlueOak-1.0.0": true, "CC-BY-4.0": true, "Python-2.0": true, "Unlicense": true, "MIT-0": true,
		"MIT AND Apache-2.0": true, "GPL-3.0-only OR MIT": true,
		"AGPL-3.0-only": false, "GPL-2.0-only": false, "MIT AND GPL-3.0-only": false, "MIT AND NOASSERTION": false,
		"": false, NoAssertion: false, "LGPL-3.0": false, "SSPL-1.0": false, "(MIT)": false, "MIT WITH x": false,
	} {
		if got := licenseApproved(expr); got != want {
			t.Errorf("licenseApproved(%q) = %v, want %v", expr, got, want)
		}
	}
}

// TestApprovedSetIsExactlyTheDocumentedList pins the approved set to docs/releases/checklist.md.
func TestApprovedSetIsExactlyTheDocumentedList(t *testing.T) {
	want := []string{"0BSD", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "BlueOak-1.0.0", "CC-BY-4.0", "ISC", "LGPL-3.0-only", "MIT", "MIT-0", "MPL-2.0", "PSF-2.0", "Python-2.0", "Unlicense"}
	var got []string
	for id := range approvedLicenses {
		got = append(got, id)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("approved set = %v, want %v", got, want)
	}
	doc, err := os.ReadFile("../docs/releases/checklist.md")
	if err != nil {
		t.Fatal(err)
	}
	line := ""
	for _, l := range strings.Split(string(doc), "\n") {
		if strings.Contains(l, "`licenses`:") {
			line = l
		}
	}
	for _, id := range want {
		if !strings.Contains(line, id) {
			t.Errorf("checklist.md `licenses` line does not list %s", id)
		}
	}
}

func TestUnapprovedOrUnknownLicenseBlocksTheGate(t *testing.T) {
	f := newFixture(t)
	write(t, filepath.Join(f.root, "build/auth-control-dependencies.json"), `{"direct":[{"module":"example.com/a","version":"v1.0.0","license":"AGPL-3.0-only"}]}`)
	write(t, filepath.Join(f.root, "third_party/auth-control-NOTICES.txt"), "AGPL text, no header\n===== example.com/a@v1.0.0 (AGPL-3.0-only) =====\n")
	write(t, filepath.Join(f.root, "sdk/python/requirements-dev.lock"), "somepkg==1.0 \\\n    --hash=sha256:00\n")
	m, err := Release(context.Background(), testCommit, f.reports())
	if err == nil {
		t.Fatal("must block")
	}
	joined := strings.Join(m.Blocking, "\n")
	for _, want := range []string{"licenses: golang example.com/a@v1.0.0: license AGPL-3.0-only is not in the approved set", "licenses: pypi somepkg@1.0: license NOASSERTION"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %s", want, joined)
		}
	}
}

func TestPromisedSurfaceNotDeliveredBlocksAndChecklistMustListIt(t *testing.T) {
	f := newFixture(t)
	f.setLedger("complete", "blocked")
	m, _ := Release(context.Background(), testCommit, f.reports())
	if !strings.Contains(strings.Join(m.Blocking, "\n"), "promised_surfaces: surface alpha (alpha works) is not delivered: 01.02 (blocked)") {
		t.Fatalf("surface not named: %v", m.Blocking)
	}
	f = newFixture(t)
	write(t, filepath.Join(f.root, "docs/releases/checklist.md"), "- [ ] `other`\n")
	m, _ = Release(context.Background(), testCommit, f.reports())
	if !strings.Contains(strings.Join(m.Blocking, "\n"), "surface alpha is missing from the release checklist") {
		t.Fatalf("checklist drift not reported: %v", m.Blocking)
	}
	f = newFixture(t)
	write(t, filepath.Join(f.root, "build/promised_surfaces.json"), `{"schema":"`+surfacesSchema+`","surfaces":[{"id":"alpha","claim":"c","source":"s","tasks":["99.99"]}]}`)
	m, _ = Release(context.Background(), testCommit, f.reports())
	if !strings.Contains(strings.Join(m.Blocking, "\n"), "99.99 (not in ledger)") {
		t.Fatalf("unknown task id must block: %v", m.Blocking)
	}
}

func TestHandleCheckNotRunAndResultsBlock(t *testing.T) {
	f := newFixture(t).signed()
	r := f.reports()
	r.Handles = nil
	r.ApprovalPath = f.approve(testCommit)
	m, err := Release(context.Background(), testCommit, r)
	blockedOnly(t, err, "handle_check: not_run")
	if m.Ready {
		t.Fatal("not_run must block")
	}
	hs, _ := DeriveHandles(f.root)
	if len(hs) != 3 {
		t.Fatalf("handles %v", hs)
	}
	rep, err := RunHandleChecks(context.Background(), fakeChecker{"npm/@soundpost/core": HandleExists, "pypi/soundpost-test": HandleUnclaimed}, hs)
	if err != nil {
		t.Fatal(err)
	}
	r.Handles = &rep
	_, err = Release(context.Background(), testCommit, r)
	blockedOnly(t, err, "handle_check: npm @soundpost/core is exists")
	rep.Results = rep.Results[:1]
	r.Handles = &rep
	m, _ = Release(context.Background(), testCommit, r)
	if !strings.Contains(strings.Join(m.Blocking, "\n"), "was not checked") {
		t.Fatalf("an unchecked handle must block: %v", m.Blocking)
	}
	// a bare Go module path is never asked of the checker
	bare, _ := RunHandleChecks(context.Background(), fakeChecker{"go/soundpost": HandleUnclaimed}, []Handle{{"go", "soundpost"}, {"go", "example.com/soundpost"}})
	if bare.Results[0].Status != HandleInvalid || bare.Results[1].Status != HandleUnclaimed {
		t.Fatalf("%+v", bare.Results)
	}
}

func TestStaleDependencyInventoryIsReported(t *testing.T) {
	f := newFixture(t)
	lockPath := filepath.Join(f.root, "pnpm-lock.yaml")
	invPath := filepath.Join(f.root, "build/dependencies/node-licenses.json")
	// the lock moves on (a new package, a pinned one removed) while the inventory keeps its old pin
	write(t, invPath, strings.Replace(mustRead(t, invPath), `"packages":[]`, `"packages":[{"name":"gone","version":"1.0.0","license_declared":"MIT"}]`, 1))
	write(t, lockPath, "lockfileVersion: '9.0'\n\npackages:\n\n  '@scope/new@2.0.0':\n    resolution: {integrity: sha512-AAAA}\n\nsnapshots:\n\n  '@scope/new@2.0.0': {}\n")
	before := mustRead(t, invPath)
	inv, err := collectInventory(f.root)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Stale) != 1 || !strings.Contains(inv.Stale[0], "stale") || !strings.Contains(inv.Stale[0], "1 lock packages (of 1) are absent from the inventory, 1 inventory packages are no longer in the lock") {
		t.Fatalf("staleness not reported precisely: %v", inv.Stale)
	}
	var npm *Component
	for i := range inv.Components {
		if inv.Components[i].Name == "@scope/new" {
			npm = &inv.Components[i]
		}
	}
	if npm == nil || npm.License != "" || !strings.Contains(npm.LicenseReason, "does not cover the current pnpm-lock.yaml") || npm.PURL != "pkg:npm/%40scope/new@2.0.0" {
		t.Fatalf("package missing from the stale inventory must be NOASSERTION: %+v", npm)
	}
	m, err := Release(context.Background(), testCommit, f.reports())
	if err == nil || !strings.Contains(strings.Join(m.Blocking, "\n"), "dependency_inventory: build/dependencies/node-licenses.json is stale") {
		t.Fatalf("gate must report staleness: %v", m.Blocking)
	}
	if mustRead(t, invPath) != before {
		t.Fatal("the stale inventory was rewritten; staleness must be reported, never refreshed")
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestNoticesDriftAndMissingTextsBlock(t *testing.T) {
	f := newFixture(t)
	write(t, filepath.Join(f.root, "THIRD_PARTY_NOTICES"), "hand edited\n")
	m, _ := Release(context.Background(), testCommit, f.reports())
	if !strings.Contains(strings.Join(m.Blocking, "\n"), "notices: THIRD_PARTY_NOTICES differs from a fresh") {
		t.Fatalf("%v", m.Blocking)
	}
}

func TestCheckedInPromisedSurfacesAndNotices(t *testing.T) {
	raw, err := os.ReadFile("promised_surfaces.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema   string
		Surfaces []PromisedSurface
	}
	if err = json.Unmarshal(raw, &doc); err != nil || doc.Schema != surfacesSchema || len(doc.Surfaces) == 0 {
		t.Fatalf("promised_surfaces.json: %v", err)
	}
	checklist := deployFile(t, "docs/releases/checklist.md")
	seen := map[string]bool{}
	for _, s := range doc.Surfaces {
		if seen[s.ID] || len(s.Tasks) == 0 || s.Claim == "" {
			t.Errorf("surface %q duplicate or incomplete", s.ID)
		}
		seen[s.ID] = true
		if !strings.Contains(checklist, "`"+s.ID+"`") {
			t.Errorf("surface %s missing from docs/releases/checklist.md", s.ID)
		}
	}
	inv, err := collectInventory("..")
	if err != nil {
		t.Fatal(err)
	}
	want, err := renderNotices("..", inv)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.ReplaceAll(deployFile(t, "THIRD_PARTY_NOTICES"), "\r\n", "\n"); got != string(want) {
		t.Fatal("THIRD_PARTY_NOTICES is not a fresh `go run ./build notices` generation")
	}
}
