// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

// `go run ./build inventory --node|--python` regenerates the committed license inventories
// (build/dependencies/node-licenses.json, python-licenses.json) and the deduplicated license
// texts (build/dependencies/license-texts/<sha256>.txt) for exactly the current locks. This is
// the only code in the build that reads node_modules or the network; sbom/notices/gate stay
// pure functions of committed files. A license is only ever copied from the package's own
// metadata; anything else is NOASSERTION with the reason, never a guess.

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	nodeInventoryFile   = "node-licenses.json"
	pythonInventoryFile = "python-licenses.json"
	licenseTextsDir     = "license-texts"
	noticeAuditDone     = "license_text_collected"
	noticeAuditPending  = "no_license_text_in_package"
)

var pythonLockFiles = []string{"requirements-dev.lock", "requirements-integrations.lock"}

// packageFiles are the license-relevant files of one distributed package. Names are paths
// relative to the package root (npm) or archive-relative (PyPI); content is LF-normalized.
type packageFiles struct {
	Metadata []byte // npm: package.json; PyPI: unused
	Texts    map[string][]byte
	Source   string // where the files came from (for the committed record)
}

// artifactSource fetches package files. Tests substitute a fixture.
type artifactSource interface {
	NPM(ctx context.Context, p lockPackage) (packageFiles, error)
	PyPIMeta(ctx context.Context, name, version string) ([]byte, error)
	Download(ctx context.Context, url string) ([]byte, error)
}

var licenseFileName = regexp.MustCompile(`(?i)^(licen[sc]e|licen[sc]es|copying|copyright|notice|unlicense)([-_.].*)?$`)

func isLicenseFile(name string) bool { return licenseFileName.MatchString(name) }

func normText(b []byte) []byte {
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	s = strings.TrimRight(s, " \t\n")
	if s == "" {
		return nil
	}
	return []byte(s + "\n")
}

// combineTexts joins a package's license files into one text. A single file is stored as is
// so identical licenses deduplicate; several files are labelled with their paths.
func combineTexts(files map[string][]byte) []byte {
	var names []string
	for n, b := range files {
		if normText(b) != nil {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	switch len(names) {
	case 0:
		return nil
	case 1:
		return normText(files[names[0]])
	}
	var b bytes.Buffer
	for i, n := range names {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString("### " + n + "\n")
		b.Write(normText(files[n]))
	}
	return b.Bytes()
}

var spdxExpr = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+-]*( (AND|OR) [A-Za-z0-9][A-Za-z0-9.+-]*)*$`)

// cleanSPDX accepts a declared license only when it is already an SPDX-shaped expression
// (outer parentheses around a flat expression are dropped). Anything else returns "".
func cleanSPDX(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") && strings.Count(s, "(") == 1 {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	if strings.EqualFold(s, "UNLICENSED") || strings.EqualFold(s, "NONE") || !spdxExpr.MatchString(s) {
		return ""
	}
	return s
}

// npmDeclared derives the declared license from a package.json document.
func npmDeclared(pkgJSON []byte) (license, reason string) {
	var m struct {
		License  json.RawMessage `json:"license"`
		Licenses []struct {
			Type string `json:"type"`
		} `json:"licenses"`
	}
	if err := json.Unmarshal(pkgJSON, &m); err != nil {
		return "", "package.json unreadable: " + err.Error()
	}
	var raw string
	if len(m.License) > 0 {
		var s string
		var o struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(m.License, &s) == nil {
			raw = s
		} else if json.Unmarshal(m.License, &o) == nil {
			raw = o.Type
		}
	} else if len(m.Licenses) > 0 {
		var ts []string
		for _, l := range m.Licenses {
			ts = append(ts, strings.TrimSpace(l.Type))
		}
		raw = strings.Join(ts, " OR ")
	}
	if raw == "" {
		return "", "package.json declares no license"
	}
	if l := cleanSPDX(raw); l != "" {
		return l, ""
	}
	return "", fmt.Sprintf("package.json license %q is not an SPDX expression", raw)
}

// ---- npm ----

type nodeEntry struct {
	Name              string   `json:"name"`
	Version           string   `json:"version"`
	License           string   `json:"license_declared"`
	LicenseReason     string   `json:"license_reason,omitempty"`
	LicenseSource     string   `json:"license_source"`
	MetadataURL       string   `json:"metadata_url"`
	Tarball           string   `json:"tarball"`
	Integrity         string   `json:"integrity"`
	OS                []string `json:"os,omitempty"`
	CPU               []string `json:"cpu,omitempty"`
	LicenseTextSHA256 string   `json:"license_text_sha256,omitempty"`
	NoticeAudit       string   `json:"notice_audit"`
	author            string
}

type nodeInventory struct {
	Copyright  string      `json:"copyright"`
	License    string      `json:"license"`
	Scope      string      `json:"scope"`
	Lock       string      `json:"lock"`
	LockSHA256 string      `json:"lock_sha256"`
	Packages   []nodeEntry `json:"packages"`
}

func lockIntegrity(sha512hex string) string {
	b, _ := hex.DecodeString(sha512hex)
	return "sha512-" + base64.StdEncoding.EncodeToString(b)
}

func npmURLs(name, version string) (meta, tarball string) {
	esc := strings.NewReplacer("@", "%40", "/", "%2F").Replace(name)
	meta = "https://registry.npmjs.org/" + esc + "/" + version
	base := name[strings.LastIndex(name, "/")+1:]
	tarball = "https://registry.npmjs.org/" + name + "/-/" + base + "-" + version + ".tgz"
	return
}

func buildNodeEntry(ctx context.Context, src artifactSource, p lockPackage, texts map[string][]byte, mu *sync.Mutex) (nodeEntry, error) {
	meta, tarball := npmURLs(p.name, p.version)
	e := nodeEntry{Name: p.name, Version: p.version, MetadataURL: meta, Tarball: tarball, Integrity: lockIntegrity(p.sha512), OS: p.os, CPU: p.cpu, NoticeAudit: noticeAuditPending}
	files, err := src.NPM(ctx, p)
	if err != nil {
		return e, fmt.Errorf("%s@%s: %w", p.name, p.version, err)
	}
	e.LicenseSource = files.Source
	e.License, e.LicenseReason = npmDeclared(files.Metadata)
	e.author = npmAuthor(files.Metadata)
	if e.License == "" {
		e.License = NoAssertion
	}
	if text := combineTexts(files.Texts); text != nil {
		sum := sha256.Sum256(text)
		e.LicenseTextSHA256 = hex.EncodeToString(sum[:])
		e.NoticeAudit = noticeAuditDone
		mu.Lock()
		texts[e.LicenseTextSHA256] = text
		mu.Unlock()
	}
	return e, nil
}

const overridesFile = "license-overrides.json"

// inventoryOverrides is reviewed data, never derived from the network.
type inventoryOverrides struct {
	// NPMTextParents maps a package-name prefix to the parent project whose license text
	// (same version, same declared license) the sub-package reuses when it ships none.
	NPMTextParents map[string]string `json:"npm_text_parents"`
	// NPMTextSources records, per package that ships no license file, the upstream
	// repository file (fetched bytes pinned by sha256) whose Heading section is the MIT text.
	NPMTextSources map[string]textSource `json:"npm_text_sources"`
	// NPMSPDXText is the explicit allowlist (not a general fallback) of packages that use the
	// SPDX canonical text because neither package nor repository ships one.
	NPMSPDXText map[string]spdxTextOverride `json:"npm_spdx_text"`
	// PyPILicense assigns an SPDX license to a pin whose metadata only carries an ambiguous
	// classifier, with the reviewer's evidence. Applied only while the record is NOASSERTION.
	PyPILicense map[string]struct {
		License  string `json:"license"`
		Evidence string `json:"evidence"`
	} `json:"pypi_license"`
}

// GenerateNodeInventory builds the inventory for exactly the given lock text.
func GenerateNodeInventory(ctx context.Context, src artifactSource, lockRaw []byte, ov inventoryOverrides) (nodeInventory, map[string][]byte, error) {
	sum := sha256.Sum256(lockRaw)
	inv := nodeInventory{
		Copyright: "Copyright 2026 Aryn Yklas", License: "Apache-2.0",
		Scope: "Declared licenses and license texts of all current pnpm lock packages, including optional platforms; regenerate with `go run ./build inventory --node`",
		Lock:  "pnpm-lock.yaml", LockSHA256: hex.EncodeToString(sum[:]),
	}
	lock := parsePnpmLock(strings.ReplaceAll(string(lockRaw), "\r\n", "\n"))
	inv.Packages = make([]nodeEntry, len(lock))
	texts := map[string][]byte{}
	var mu sync.Mutex
	errs := make([]error, len(lock))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i := range lock {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			inv.Packages[i], errs[i] = buildNodeEntry(ctx, src, lock[i], texts, &mu)
		}(i)
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return inv, nil, err
	}
	// A platform sub-package that ships no license file reuses the text of its parent
	// project at the same version, only where license-overrides.json names the parent.
	byKey := map[string]nodeEntry{}
	for _, p := range inv.Packages {
		byKey[p.Name+"@"+p.Version] = p
	}
	for i := range inv.Packages {
		p := &inv.Packages[i]
		if p.LicenseTextSHA256 != "" {
			continue
		}
		for prefix, parent := range ov.NPMTextParents {
			if !strings.HasPrefix(p.Name, prefix) {
				continue
			}
			if par, ok := byKey[parent+"@"+p.Version]; ok && par.LicenseTextSHA256 != "" && par.License == p.License {
				p.LicenseTextSHA256, p.NoticeAudit = par.LicenseTextSHA256, noticeAuditDone
				p.LicenseSource += "; license text from parent package " + parent + "@" + p.Version
			}
		}
	}
	for i := range inv.Packages {
		p := &inv.Packages[i]
		s, ok := ov.NPMTextSources[p.Name+"@"+p.Version]
		if !ok || p.LicenseTextSHA256 != "" {
			continue
		}
		text, err := upstreamLicenseText(ctx, src, s, p.License)
		if err != nil {
			return inv, nil, fmt.Errorf("%s@%s: %w", p.Name, p.Version, err)
		}
		sum := sha256.Sum256(text)
		p.LicenseTextSHA256, p.NoticeAudit = hex.EncodeToString(sum[:]), noticeAuditDone
		p.LicenseSource += "; license text from upstream " + s.URL + " (" + s.Reason + ")"
		texts[p.LicenseTextSHA256] = text
	}
	for i := range inv.Packages {
		p := &inv.Packages[i]
		s, ok := ov.NPMSPDXText[p.Name+"@"+p.Version]
		if !ok || p.LicenseTextSHA256 != "" {
			continue
		}
		text, err := spdxCanonicalText(ctx, src, s, *p)
		if err != nil {
			return inv, nil, fmt.Errorf("%s@%s: %w", p.Name, p.Version, err)
		}
		sum := sha256.Sum256(text)
		p.LicenseTextSHA256, p.NoticeAudit = hex.EncodeToString(sum[:]), noticeAuditDone
		p.LicenseSource += "; license text: " + s.Reason + " (" + s.URL + ")"
		texts[p.LicenseTextSHA256] = text
	}
	return inv, texts, nil
}

type textSource struct {
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	Heading string `json:"heading"`
	Reason  string `json:"reason"`
}

const spdxReason = "spdx_canonical_text: upstream ships no license file"

// spdxTextOverride allowlists one package for the SPDX canonical text of its declared license.
type spdxTextOverride struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Reason string `json:"reason"`
}

// npmAuthor returns the package.json author name (string or {name}), or "".
func npmAuthor(pkgJSON []byte) string {
	var m struct {
		Author json.RawMessage `json:"author"`
	}
	if json.Unmarshal(pkgJSON, &m) != nil || len(m.Author) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(m.Author, &s) == nil {
		return strings.TrimSpace(s)
	}
	var o struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(m.Author, &o) == nil {
		return strings.TrimSpace(o.Name)
	}
	return ""
}

// spdxCanonicalText fetches the pinned SPDX license text for the package's declared
// identifier and fills the copyright line from the package author (or "the <name> authors").
// Only MIT is supported; the caller applies it solely to allowlisted packages.
func spdxCanonicalText(ctx context.Context, src artifactSource, s spdxTextOverride, p nodeEntry) ([]byte, error) {
	if s.Reason != spdxReason {
		return nil, fmt.Errorf("override reason must be %q", spdxReason)
	}
	if p.License != "MIT" || !strings.HasSuffix(s.URL, "/text/MIT.txt") {
		return nil, errors.New("SPDX canonical text is only supported for a declared MIT license with a MIT.txt source")
	}
	raw, err := src.Download(ctx, s.URL)
	if err != nil {
		return nil, err
	}
	if got := sha256.Sum256(raw); hex.EncodeToString(got[:]) != s.SHA256 {
		return nil, fmt.Errorf("%s sha256 %x differs from the recorded %s", s.URL, got, s.SHA256)
	}
	holder := p.author
	if holder == "" {
		holder = "the " + p.Name + " authors"
	}
	const tmpl = "Copyright (c) <year> <copyright holders>"
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if !strings.Contains(text, tmpl) {
		return nil, errors.New(s.URL + ": unexpected SPDX MIT template")
	}
	return normText([]byte(strings.Replace(text, tmpl, "Copyright (c) "+holder, 1))), nil
}

// upstreamLicenseText fetches the pinned upstream file, verifies its sha256 and returns the
// section under Heading (up to the next "## " heading). Only an MIT text for a package that
// declares MIT is accepted; anything else is an error, never a guess.
func upstreamLicenseText(ctx context.Context, src artifactSource, s textSource, declared string) ([]byte, error) {
	if declared != "MIT" {
		return nil, errors.New("upstream text source only supports packages declaring MIT")
	}
	raw, err := src.Download(ctx, s.URL)
	if err != nil {
		return nil, err
	}
	if got := sha256.Sum256(raw); hex.EncodeToString(got[:]) != s.SHA256 {
		return nil, fmt.Errorf("%s sha256 %x differs from the recorded %s", s.URL, got, s.SHA256)
	}
	var sect []string
	in := false
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if strings.EqualFold(strings.TrimSpace(line), s.Heading) {
			in = true
			continue
		}
		if in && strings.HasPrefix(line, "## ") {
			break
		}
		if in {
			sect = append(sect, line)
		}
	}
	text := normText([]byte(strings.Join(sect, "\n")))
	if text == nil || !bytes.Contains(text, []byte("Permission is hereby granted, free of charge")) || !bytes.Contains(text, []byte("THE SOFTWARE IS PROVIDED \"AS IS\"")) {
		return nil, errors.New(s.URL + ": section " + s.Heading + " is not the MIT license text")
	}
	return text, nil
}

// ---- PyPI ----

type pyEntry struct {
	Name              string `json:"name"`
	Version           string `json:"version"`
	License           string `json:"license_declared"`
	LicenseReason     string `json:"license_reason,omitempty"`
	LicenseSource     string `json:"license_source"`
	MetadataURL       string `json:"metadata_url"`
	Artifact          string `json:"artifact,omitempty"`
	ArtifactSHA256    string `json:"artifact_sha256,omitempty"`
	LicenseTextSHA256 string `json:"license_text_sha256,omitempty"`
	NoticeAudit       string `json:"notice_audit"`
}

type pyInventory struct {
	Copyright string            `json:"copyright"`
	License   string            `json:"license"`
	Scope     string            `json:"scope"`
	Locks     map[string]string `json:"locks_sha256"`
	Packages  []pyEntry         `json:"packages"`
}

type pyPinned struct {
	name, version string
	hashes        map[string]bool
}

func pyNormName(s string) string {
	return strings.ToLower(strings.NewReplacer("_", "-", ".", "-").Replace(s))
}

// parsePyPins reads name==version pins and their --hash=sha256 values from uv lock texts.
func parsePyPins(texts ...string) []pyPinned {
	idx := map[string]*pyPinned{}
	var order []string
	for _, text := range texts {
		var cur *pyPinned
		for _, line := range strings.Split(text, "\n") {
			if m := pyPin.FindStringSubmatch(line); m != nil {
				k := pyNormName(m[1]) + "@" + m[2]
				if idx[k] == nil {
					idx[k] = &pyPinned{name: pyNormName(m[1]), version: m[2], hashes: map[string]bool{}}
					order = append(order, k)
				}
				cur = idx[k]
				continue
			}
			if cur != nil {
				if i := strings.Index(line, "--hash=sha256:"); i >= 0 {
					cur.hashes[strings.TrimRight(strings.TrimSpace(line[i+len("--hash=sha256:"):]), " \\")] = true
				}
			}
		}
	}
	sort.Strings(order)
	out := make([]pyPinned, len(order))
	for i, k := range order {
		out[i] = *idx[k]
	}
	return out
}

// pypiClassifier maps the unambiguous OSI license classifiers; BSD License, GNU and
// "Other/Proprietary" classifiers carry no specific license and are not mapped.
var pypiClassifier = map[string]string{
	"License :: OSI Approved :: MIT License":                        "MIT",
	"License :: OSI Approved :: Apache Software License":            "Apache-2.0",
	"License :: OSI Approved :: ISC License (ISCL)":                 "ISC",
	"License :: OSI Approved :: Python Software Foundation License": "Python-2.0",
	"License :: OSI Approved :: MIT No Attribution License (MIT-0)": "MIT-0",
	"License :: OSI Approved :: BSD-2-Clause":                       "BSD-2-Clause",
}

type pypiDoc struct {
	Info struct {
		License           string   `json:"license"`
		LicenseExpression string   `json:"license_expression"`
		Classifiers       []string `json:"classifiers"`
	} `json:"info"`
	URLs []struct {
		Filename    string            `json:"filename"`
		URL         string            `json:"url"`
		PackageType string            `json:"packagetype"`
		Digests     map[string]string `json:"digests"`
	} `json:"urls"`
}

func pypiDeclared(d pypiDoc) (license, source, reason string) {
	if l := cleanSPDX(d.Info.LicenseExpression); l != "" {
		return l, "PyPI JSON info.license_expression", ""
	}
	if l := cleanSPDX(d.Info.License); l != "" && len(d.Info.License) < 40 {
		return l, "PyPI JSON info.license", ""
	}
	var found []string
	for _, c := range d.Info.Classifiers {
		if l, ok := pypiClassifier[c]; ok {
			found = append(found, l)
		}
	}
	if len(found) == 1 {
		return found[0], "PyPI JSON info.classifiers (" + d.Info.Classifiers[0] + "...)", ""
	}
	return "", "PyPI JSON", "PyPI metadata carries no SPDX license expression (info.license_expression empty; info.license is free text or empty; classifiers ambiguous)"
}

// pickArtifact prefers a pure-Python wheel, then an sdist, then any wheel, restricted to
// files whose sha256 appears in the lock (so the evidence is the pinned artifact).
func pickArtifact(d pypiDoc, hashes map[string]bool) (name, url, sha string) {
	rank := func(fn, pt string) int {
		switch {
		case pt == "bdist_wheel" && strings.HasSuffix(fn, "-none-any.whl"):
			return 0
		case pt == "sdist":
			return 1
		case pt == "bdist_wheel":
			return 2
		}
		return 9
	}
	best := 9
	for _, u := range d.URLs {
		if !hashes[u.Digests["sha256"]] {
			continue
		}
		if r := rank(u.Filename, u.PackageType); r < best || (r == best && u.Filename < name) {
			best, name, url, sha = r, u.Filename, u.URL, u.Digests["sha256"]
		}
	}
	return
}

// archiveLicenseFiles extracts license-like files from a wheel (zip) or sdist (tar.gz).
func archiveLicenseFiles(filename string, data []byte) (map[string][]byte, error) {
	out := map[string][]byte{}
	switch {
	case strings.HasSuffix(filename, ".whl"), strings.HasSuffix(filename, ".zip"):
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			if f.FileInfo().IsDir() || !wheelLicensePath(f.Name) {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			b, err := io.ReadAll(io.LimitReader(rc, 4<<20))
			rc.Close()
			if err != nil {
				return nil, err
			}
			out[f.Name] = b
		}
	case strings.HasSuffix(filename, ".tar.gz"):
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		tr := tar.NewReader(gz)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			if h.Typeflag != tar.TypeReg {
				continue
			}
			parts := strings.Split(h.Name, "/")
			// <top>/LICENSE or <top>/licenses|LICENSES/<file>
			ok := (len(parts) == 2 && isLicenseFile(parts[1])) ||
				(len(parts) == 3 && strings.EqualFold(parts[1], "licenses") && isLicenseFile(parts[2]))
			if !ok {
				continue
			}
			b, err := io.ReadAll(io.LimitReader(tr, 4<<20))
			if err != nil {
				return nil, err
			}
			out[strings.Join(parts[1:], "/")] = b
		}
	default:
		return nil, errors.New("unsupported artifact " + filename)
	}
	return out, nil
}

func wheelLicensePath(name string) bool {
	parts := strings.Split(name, "/")
	if len(parts) < 2 || !strings.HasSuffix(parts[0], ".dist-info") {
		return false
	}
	rest := parts[1:]
	if (rest[0] == "licenses" || rest[0] == "license_files") && len(rest) > 1 {
		return isLicenseFile(rest[len(rest)-1])
	}
	return len(rest) == 1 && isLicenseFile(rest[0])
}

func buildPyEntry(ctx context.Context, src artifactSource, p pyPinned, texts map[string][]byte, mu *sync.Mutex) (pyEntry, error) {
	e := pyEntry{Name: p.name, Version: p.version, MetadataURL: "https://pypi.org/pypi/" + p.name + "/" + p.version + "/json", NoticeAudit: noticeAuditPending}
	raw, err := src.PyPIMeta(ctx, p.name, p.version)
	if err != nil {
		return e, fmt.Errorf("%s==%s: %w", p.name, p.version, err)
	}
	var d pypiDoc
	if err = json.Unmarshal(raw, &d); err != nil {
		return e, fmt.Errorf("%s==%s: %w", p.name, p.version, err)
	}
	var reason string
	e.License, e.LicenseSource, reason = pypiDeclared(d)
	e.LicenseReason = reason
	if e.License == "" {
		e.License = NoAssertion
	}
	fn, u, sha := pickArtifact(d, p.hashes)
	if fn == "" {
		return e, fmt.Errorf("%s==%s: no PyPI artifact matches a hash in the lock", p.name, p.version)
	}
	e.Artifact, e.ArtifactSHA256 = fn, sha
	data, err := src.Download(ctx, u)
	if err != nil {
		return e, fmt.Errorf("%s==%s: %w", p.name, p.version, err)
	}
	if got := sha256.Sum256(data); hex.EncodeToString(got[:]) != sha {
		return e, fmt.Errorf("%s==%s: %s sha256 mismatch", p.name, p.version, fn)
	}
	files, err := archiveLicenseFiles(fn, data)
	if err != nil {
		return e, fmt.Errorf("%s==%s: %w", p.name, p.version, err)
	}
	if text := combineTexts(files); text != nil {
		s := sha256.Sum256(text)
		e.LicenseTextSHA256 = hex.EncodeToString(s[:])
		e.NoticeAudit = noticeAuditDone
		mu.Lock()
		texts[e.LicenseTextSHA256] = text
		mu.Unlock()
	}
	return e, nil
}

// GeneratePythonInventory builds the inventory for the given lock texts (name -> content).
func GeneratePythonInventory(ctx context.Context, src artifactSource, locks map[string][]byte, ov inventoryOverrides) (pyInventory, map[string][]byte, error) {
	inv := pyInventory{
		Copyright: "Copyright 2026 Aryn Yklas", License: "Apache-2.0",
		Scope: "Declared licenses and license texts of the pinned packages in sdk/python/requirements-*.lock; regenerate with `go run ./build inventory --python`",
		Locks: map[string]string{},
	}
	var texts []string
	for _, n := range pythonLockFiles {
		raw, ok := locks[n]
		if !ok {
			return inv, nil, errors.New("missing Python lock " + n)
		}
		s := sha256.Sum256(raw)
		inv.Locks[n] = hex.EncodeToString(s[:])
		texts = append(texts, strings.ReplaceAll(string(raw), "\r\n", "\n"))
	}
	pins := parsePyPins(texts...)
	inv.Packages = make([]pyEntry, len(pins))
	lt := map[string][]byte{}
	var mu sync.Mutex
	errs := make([]error, len(pins))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i := range pins {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			inv.Packages[i], errs[i] = buildPyEntry(ctx, src, pins[i], lt, &mu)
		}(i)
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return inv, nil, err
	}
	for i := range inv.Packages {
		p := &inv.Packages[i]
		if o, ok := ov.PyPILicense[p.Name+"@"+p.Version]; ok && p.License == NoAssertion {
			p.License, p.LicenseReason, p.LicenseSource = o.License, "", "reviewed override license-overrides.json: "+o.Evidence
		}
	}
	return inv, lt, nil
}

// ---- real source ----

type netSource struct {
	root   string
	client *http.Client
}

func (s netSource) Download(ctx context.Context, u string) ([]byte, error) {
	var last error
	for try := range 4 {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		resp, err := s.client.Do(req)
		if err == nil {
			b, rerr := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
			resp.Body.Close()
			if rerr == nil && resp.StatusCode == 200 {
				return b, nil
			}
			if rerr != nil {
				err = rerr
			} else {
				err = fmt.Errorf("GET %s: %s", u, resp.Status)
			}
		}
		last = err
		time.Sleep(time.Duration(try+1) * 2 * time.Second)
	}
	return nil, last
}

func (s netSource) PyPIMeta(ctx context.Context, name, version string) ([]byte, error) {
	return s.Download(ctx, "https://pypi.org/pypi/"+name+"/"+version+"/json")
}

// localNPM reads the package from the pnpm virtual store when it is installed.
func (s netSource) localNPM(p lockPackage) (packageFiles, bool) {
	store := filepath.Join(s.root, "node_modules", ".pnpm")
	dirName := strings.ReplaceAll(p.name, "/", "+") + "@" + p.version
	cands := []string{filepath.Join(store, dirName)}
	if m, _ := filepath.Glob(filepath.Join(store, dirName+"_*")); m != nil {
		cands = append(cands, m...)
	}
	for _, c := range cands {
		dir := filepath.Join(c, "node_modules", filepath.FromSlash(p.name))
		meta, err := os.ReadFile(filepath.Join(dir, "package.json"))
		if err != nil {
			continue
		}
		var v struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(meta, &v) != nil || v.Version != p.version {
			continue
		}
		pf := packageFiles{Metadata: meta, Texts: map[string][]byte{}, Source: "node_modules/.pnpm package.json at exact version"}
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			if !e.IsDir() && isLicenseFile(e.Name()) {
				if b, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil {
					pf.Texts[e.Name()] = b
				}
			}
		}
		return pf, true
	}
	return packageFiles{}, false
}

func (s netSource) NPM(ctx context.Context, p lockPackage) (packageFiles, error) {
	if pf, ok := s.localNPM(p); ok {
		return pf, nil
	}
	_, tarball := npmURLs(p.name, p.version)
	data, err := s.Download(ctx, tarball)
	if err != nil {
		return packageFiles{}, err
	}
	return npmTarballFiles(data, lockIntegrity(p.sha512))
}

// npmTarballFiles verifies the sha512 integrity and returns package.json plus the root
// license files of an npm tarball.
func npmTarballFiles(data []byte, integrity string) (packageFiles, error) {
	sum := sha512.Sum512(data)
	if got := "sha512-" + base64.StdEncoding.EncodeToString(sum[:]); got != integrity {
		return packageFiles{}, fmt.Errorf("tarball integrity mismatch: got %s want %s", got, integrity)
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return packageFiles{}, err
	}
	pf := packageFiles{Texts: map[string][]byte{}, Source: "registry tarball package.json (integrity verified against pnpm-lock.yaml)"}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return pf, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		parts := strings.SplitN(path.Clean(h.Name), "/", 2)
		if len(parts) != 2 || strings.Contains(parts[1], "/") {
			continue
		}
		switch {
		case parts[1] == "package.json":
			if pf.Metadata, err = io.ReadAll(io.LimitReader(tr, 4<<20)); err != nil {
				return pf, err
			}
		case isLicenseFile(parts[1]):
			b, err := io.ReadAll(io.LimitReader(tr, 4<<20))
			if err != nil {
				return pf, err
			}
			pf.Texts[parts[1]] = b
		}
	}
	if pf.Metadata == nil {
		return pf, errors.New("tarball has no package.json")
	}
	return pf, nil
}

// writeLicenseTexts replaces the committed text store with exactly the given texts.
func writeLicenseTexts(dir string, texts map[string][]byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for h, b := range texts {
		if err := os.WriteFile(filepath.Join(dir, h+".txt"), b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func runInventory(args []string, out io.Writer) error {
	f := flag.NewFlagSet("inventory", flag.ContinueOnError)
	root := f.String("root", ".", "repository root")
	node := f.Bool("node", false, "regenerate build/dependencies/node-licenses.json")
	python := f.Bool("python", false, "regenerate build/dependencies/python-licenses.json")
	if err := f.Parse(args); err != nil {
		return err
	}
	if !*node && !*python {
		return errors.New("inventory needs --node and/or --python")
	}
	absRoot, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	depDir := filepath.Join(absRoot, "build", "dependencies")
	src := netSource{root: absRoot, client: &http.Client{Timeout: 120 * time.Second}}
	ctx := context.Background()
	var ov inventoryOverrides
	if raw, rerr := os.ReadFile(filepath.Join(depDir, overridesFile)); rerr == nil {
		if err := json.Unmarshal(raw, &ov); err != nil {
			return fmt.Errorf("%s: %w", overridesFile, err)
		}
	}
	allTexts := map[string][]byte{}
	if *node {
		lock, err := os.ReadFile(filepath.Join(absRoot, "pnpm-lock.yaml"))
		if err != nil {
			return err
		}
		inv, texts, err := GenerateNodeInventory(ctx, src, lock, ov)
		if err != nil {
			return err
		}
		raw, err := marshalStable(inv)
		if err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(depDir, nodeInventoryFile), raw, 0o644); err != nil {
			return err
		}
		for h, t := range texts {
			allTexts[h] = t
		}
		fmt.Fprintf(out, "node: %d packages, %d distinct license texts\n", len(inv.Packages), len(texts))
	}
	if *python {
		locks := map[string][]byte{}
		for _, n := range pythonLockFiles {
			b, err := os.ReadFile(filepath.Join(absRoot, "sdk", "python", n))
			if err != nil {
				return err
			}
			locks[n] = b
		}
		inv, texts, err := GeneratePythonInventory(ctx, src, locks, ov)
		if err != nil {
			return err
		}
		raw, err := marshalStable(inv)
		if err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(depDir, pythonInventoryFile), raw, 0o644); err != nil {
			return err
		}
		for h, t := range texts {
			allTexts[h] = t
		}
		fmt.Fprintf(out, "python: %d packages, %d distinct license texts\n", len(inv.Packages), len(texts))
	}
	return writeLicenseTexts(filepath.Join(depDir, licenseTextsDir), allTexts)
}
