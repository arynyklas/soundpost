// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

type fixtureSource struct{ pkgs map[string]packageFiles }

func (f fixtureSource) NPM(_ context.Context, p lockPackage) (packageFiles, error) {
	return f.pkgs[p.name+"@"+p.version], nil
}
func (fixtureSource) PyPIMeta(context.Context, string, string) ([]byte, error) {
	return nil, nil
}
func (fixtureSource) Download(context.Context, string) ([]byte, error) { return nil, nil }

const fixtureLock = `lockfileVersion: '9.0'

packages:

  '@scope/plat-linux@1.0.0':
    resolution: {integrity: sha512-AAAA}
    cpu: [x64]
    os: [linux]

  mit-pkg@2.0.0:
    resolution: {integrity: sha512-AAAA}

  weird-pkg@3.0.0:
    resolution: {integrity: sha512-AAAA}

  scope@1.0.0:
    resolution: {integrity: sha512-AAAA}

snapshots:

  ignored@9.9.9: {}
`

func TestGenerateNodeInventoryFixture(t *testing.T) {
	src := fixtureSource{pkgs: map[string]packageFiles{
		"mit-pkg@2.0.0":           {Metadata: []byte(`{"license":"MIT"}`), Texts: map[string][]byte{"LICENSE": []byte("MIT text\r\n")}, Source: "fixture"},
		"weird-pkg@3.0.0":         {Metadata: []byte(`{"license":"SEE LICENSE IN FILE"}`), Texts: map[string][]byte{}, Source: "fixture"},
		"scope@1.0.0":             {Metadata: []byte(`{"license":"(MIT OR Apache-2.0)"}`), Texts: map[string][]byte{"LICENSE": []byte("scope text\n")}, Source: "fixture"},
		"@scope/plat-linux@1.0.0": {Metadata: []byte(`{"license":"(MIT OR Apache-2.0)"}`), Texts: map[string][]byte{}, Source: "fixture"},
	}}
	ov := inventoryOverrides{NPMTextParents: map[string]string{"@scope/plat-": "scope"}}
	inv, texts, err := GenerateNodeInventory(context.Background(), src, []byte(fixtureLock), ov)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Packages) != 4 {
		t.Fatalf("want exactly the 4 lock packages, got %d", len(inv.Packages))
	}
	by := map[string]nodeEntry{}
	for _, p := range inv.Packages {
		by[p.Name] = p
	}
	if p := by["mit-pkg"]; p.License != "MIT" || p.NoticeAudit != noticeAuditDone || string(texts[p.LicenseTextSHA256]) != "MIT text\n" {
		t.Fatalf("mit-pkg: %+v", p)
	}
	if p := by["weird-pkg"]; p.License != NoAssertion || p.LicenseReason == "" || p.NoticeAudit != noticeAuditPending {
		t.Fatalf("weird-pkg must be NOASSERTION with a reason and no text: %+v", p)
	}
	if p := by["scope"]; p.License != "MIT OR Apache-2.0" {
		t.Fatalf("scope: %+v", p)
	}
	plat := by["@scope/plat-linux"]
	if plat.LicenseTextSHA256 != by["scope"].LicenseTextSHA256 || plat.OS[0] != "linux" || plat.CPU[0] != "x64" {
		t.Fatalf("platform package: %+v", plat)
	}
	if plat.MetadataURL != "https://registry.npmjs.org/%40scope%2Fplat-linux/1.0.0" || plat.Tarball != "https://registry.npmjs.org/@scope/plat-linux/-/plat-linux-1.0.0.tgz" {
		t.Fatalf("urls: %s %s", plat.MetadataURL, plat.Tarball)
	}
}

func TestNpmDeclared(t *testing.T) {
	for in, want := range map[string]string{
		`{"license":"MIT"}`:                                   "MIT",
		`{"license":{"type":"ISC"}}`:                          "ISC",
		`{"licenses":[{"type":"MIT"},{"type":"Apache-2.0"}]}`: "MIT OR Apache-2.0",
		`{"license":"(BSD-2-Clause OR MIT)"}`:                 "BSD-2-Clause OR MIT",
		`{"license":"UNLICENSED"}`:                            "",
		`{"license":"Apache 2.0"}`:                            "",
		`{}`:                                                  "",
	} {
		got, reason := npmDeclared([]byte(in))
		if got != want || (got == "" && reason == "") {
			t.Errorf("%s: got %q (%s), want %q", in, got, reason, want)
		}
	}
}

func TestNpmTarballIntegrityAndFiles(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{"package/package.json": `{"license":"MIT"}`, "package/LICENSE": "text", "package/lib/LICENSE": "nested", "package/index.js": "x"} {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()
	sum := sha512.Sum512(buf.Bytes())
	integ := "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
	pf, err := npmTarballFiles(buf.Bytes(), integ)
	if err != nil || len(pf.Texts) != 1 || string(pf.Texts["LICENSE"]) != "text" {
		t.Fatalf("%v %+v", err, pf)
	}
	if _, err = npmTarballFiles(buf.Bytes(), "sha512-bad"); err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("integrity mismatch must fail, got %v", err)
	}
}

func TestParsePyPins(t *testing.T) {
	a := "Foo_Bar==1.0 \\\n    --hash=sha256:aa \\\n    --hash=sha256:bb\nbaz==2 \\\n    --hash=sha256:cc\n"
	b := "foo-bar==1.0 \\\n    --hash=sha256:dd\n"
	pins := parsePyPins(a, b)
	if len(pins) != 2 || pins[1].name != "foo-bar" || len(pins[1].hashes) != 3 {
		t.Fatalf("%+v", pins)
	}
}

const spdxFixtureText = "MIT License\n\nCopyright (c) <year> <copyright holders>\n\nPermission is hereby granted\n"

type spdxFixture struct{ fixtureSource }

func (spdxFixture) Download(context.Context, string) ([]byte, error) {
	return []byte(spdxFixtureText), nil
}

func TestSPDXCanonicalTextOnlyForAllowlistedPackages(t *testing.T) {
	lock := "packages:\n\n  listed@1.0.0:\n    resolution: {integrity: sha512-AAAA}\n\n  unlisted@1.0.0:\n    resolution: {integrity: sha512-AAAA}\n"
	src := spdxFixture{fixtureSource{pkgs: map[string]packageFiles{
		"listed@1.0.0":   {Metadata: []byte(`{"license":"MIT","author":"Jane Doe"}`), Source: "fixture"},
		"unlisted@1.0.0": {Metadata: []byte(`{"license":"MIT"}`), Source: "fixture"},
	}}}
	sum := sha256.Sum256([]byte(spdxFixtureText))
	good := spdxTextOverride{URL: "https://x/text/MIT.txt", SHA256: hex.EncodeToString(sum[:]), Reason: spdxReason}
	inv, texts, err := GenerateNodeInventory(context.Background(), src, []byte(lock), inventoryOverrides{NPMSPDXText: map[string]spdxTextOverride{"listed@1.0.0": good}})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]nodeEntry{}
	for _, p := range inv.Packages {
		by[p.Name] = p
	}
	if p := by["listed"]; p.NoticeAudit != noticeAuditDone || !strings.Contains(string(texts[p.LicenseTextSHA256]), "Copyright (c) Jane Doe\n") {
		t.Fatalf("listed: %+v", p)
	}
	if p := by["unlisted"]; p.LicenseTextSHA256 != "" || p.NoticeAudit != noticeAuditPending {
		t.Fatalf("unlisted package must not receive the SPDX text: %+v", p)
	}
	// No author: "the <name> authors".
	inv, texts, err = GenerateNodeInventory(context.Background(), src, []byte(lock), inventoryOverrides{NPMSPDXText: map[string]spdxTextOverride{"unlisted@1.0.0": good}})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range inv.Packages {
		if p.Name == "unlisted" && !strings.Contains(string(texts[p.LicenseTextSHA256]), "Copyright (c) the unlisted authors\n") {
			t.Fatalf("missing-author holder: %s", texts[p.LicenseTextSHA256])
		}
	}
	// Wrong reason and wrong hash are refused.
	for name, o := range map[string]spdxTextOverride{
		"reason": {URL: good.URL, SHA256: good.SHA256, Reason: "other"},
		"hash":   {URL: good.URL, SHA256: "00", Reason: spdxReason},
	} {
		if _, _, err := GenerateNodeInventory(context.Background(), src, []byte(lock), inventoryOverrides{NPMSPDXText: map[string]spdxTextOverride{"listed@1.0.0": o}}); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
}
