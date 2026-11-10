// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

// Dependency inventory, SBOM (CycloneDX 1.5 and SPDX 2.3 JSON) and THIRD_PARTY_NOTICES, all
// generated from tracked repository files only: go.mod, go.sum, pnpm-lock.yaml, the Python
// locks, third_party/* provenance and the committed license inventories. Nothing here reads
// the network, the module cache or node_modules, so the output is a pure function of the tree
// and of the explicit created timestamp. A license is only ever copied from a committed record;
// without one the component carries NOASSERTION plus the reason.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// NoAssertion is the SPDX value for "no committed license record".
const NoAssertion = "NOASSERTION"

// Scope values follow CycloneDX: required ships in the first-party distribution, optional is a
// development/test lock input, excluded is in go.sum only (not required by go.mod).
const (
	ScopeRequired = "required"
	ScopeOptional = "optional"
	ScopeExcluded = "excluded"
)

// Component is one dependency with the license evidence it carries.
type Component struct {
	Ecosystem     string `json:"ecosystem"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	PURL          string `json:"purl"`
	License       string `json:"license,omitempty"`
	LicenseReason string `json:"license_reason,omitempty"`
	LicenseSource string `json:"license_source,omitempty"`
	Scope         string `json:"scope"`
	SHA512        string `json:"sha512,omitempty"`
	NoticeText    bool   `json:"notice_text_carried"`
}

// Inventory is the collected dependency set plus every finding that makes it untrustworthy.
type Inventory struct {
	Components []Component
	// Stale lists committed inventories that no longer match the tree they claim to describe.
	// They are reported and never refreshed.
	Stale []string
}

func readLF(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(string(raw), "\r\n", "\n"), nil
}

// normLicense rewrites the lower-case " and "/" or " joiners some notices use into SPDX form.
func normLicense(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, " and ", " AND ")
	s = strings.ReplaceAll(s, " or ", " OR ")
	return s
}

// approvedLicenses is the repository's approved set (SPDX identifiers).
var approvedLicenses = map[string]bool{
	"MIT": true, "Apache-2.0": true, "BSD-2-Clause": true, "BSD-3-Clause": true, "ISC": true,
	"0BSD": true, "BlueOak-1.0.0": true, "CC-BY-4.0": true, "Python-2.0": true, "Unlicense": true, "MIT-0": true,
}

// licenseApproved evaluates a flat SPDX expression: OR needs one approved alternative, AND
// needs every term approved. Parentheses, WITH and unknown identifiers are not approved.
func licenseApproved(expr string) bool {
	if expr == "" || expr == NoAssertion {
		return false
	}
	for _, alt := range strings.Split(expr, " OR ") {
		all := true
		for _, id := range strings.Split(alt, " AND ") {
			if !approvedLicenses[strings.TrimSpace(id)] {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

type licenseRecord struct {
	license string
	source  string
	text    bool
	clash   string
}

var noticeHeader = regexp.MustCompile(`(?m)^===== (\S+)@(\S+) \((.+)\) =====$`)

// goLicenseRecords reads the committed Go license evidence keyed "module@version".
func goLicenseRecords(root string) (map[string]licenseRecord, error) {
	recs := map[string]licenseRecord{}
	add := func(key, license, source string, text bool) {
		license = normLicense(license)
		if old, ok := recs[key]; ok {
			if old.license != license {
				old.clash = fmt.Sprintf("%s says %q but %s says %q", old.source, old.license, source, license)
			}
			old.text = old.text || text
			recs[key] = old
			return
		}
		recs[key] = licenseRecord{license: license, source: source, text: text}
	}
	raw, err := os.ReadFile(filepath.Join(root, "build", "auth-control-dependencies.json"))
	if err != nil {
		return nil, err
	}
	var ac struct {
		Direct          []struct{ Module, Version, License string } `json:"direct"`
		RuntimeIndirect []struct{ Module, Version, License string } `json:"runtime_indirect"`
	}
	if err = json.Unmarshal(raw, &ac); err != nil {
		return nil, fmt.Errorf("build/auth-control-dependencies.json: %w", err)
	}
	for _, d := range append(ac.Direct, ac.RuntimeIndirect...) {
		if d.License != "" {
			add(d.Module+"@"+d.Version, d.License, "build/auth-control-dependencies.json", false)
		}
	}
	for _, rel := range []string{"third_party/auth-control-NOTICES.txt", "third_party/config-tooling-NOTICES.txt"} {
		text, err := readLF(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return nil, err
		}
		for _, m := range noticeHeader.FindAllStringSubmatch(text, -1) {
			add(m[1]+"@"+m[2], m[3], rel, true)
		}
	}
	return recs, nil
}

func parseGoMod(text string) map[string]string {
	mods := map[string]string{}
	block := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(strings.SplitN(line, "//", 2)[0]), ","))
		switch {
		case line == "":
		case line == ")":
			block = ""
		case strings.HasSuffix(line, "("):
			block = strings.TrimSpace(strings.TrimSuffix(line, "("))
		case block == "require":
			if f := strings.Fields(line); len(f) == 2 {
				mods[f[0]] = f[1]
			}
		case block == "" && strings.HasPrefix(line, "require "):
			if f := strings.Fields(line); len(f) == 3 {
				mods[f[1]] = f[2]
			}
		}
	}
	return mods
}

func parseGoSum(text string) map[string]bool {
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		if f := strings.Fields(line); len(f) == 3 {
			seen[f[0]+"@"+strings.TrimSuffix(f[1], "/go.mod")] = true
		}
	}
	return seen
}

func collectGo(root string) ([]Component, error) {
	modText, err := readLF(filepath.Join(root, "go.mod"))
	if err != nil {
		return nil, err
	}
	sumText, err := readLF(filepath.Join(root, "go.sum"))
	if err != nil {
		return nil, err
	}
	recs, err := goLicenseRecords(root)
	if err != nil {
		return nil, err
	}
	required := parseGoMod(modText)
	keys := parseGoSum(sumText)
	for m, v := range required {
		keys[m+"@"+v] = true
	}
	var out []Component
	for key := range keys {
		at := strings.LastIndex(key, "@")
		name, version := key[:at], key[at+1:]
		c := Component{Ecosystem: "golang", Name: name, Version: version, PURL: "pkg:golang/" + name + "@" + version, Scope: ScopeExcluded}
		if required[name] == version {
			c.Scope = ScopeRequired
		}
		switch rec, ok := recs[key]; {
		case ok && rec.clash != "":
			c.LicenseReason = "committed records disagree: " + rec.clash
		case ok:
			c.License, c.LicenseSource, c.NoticeText = rec.license, rec.source, rec.text
		default:
			c.LicenseReason = "no committed license record for " + key + " (build/auth-control-dependencies.json, third_party/*-NOTICES.txt)"
		}
		out = append(out, c)
	}
	return out, nil
}

var pnpmKey = regexp.MustCompile(`^  '?([^\s']+)'?:$`)
var pnpmIntegrity = regexp.MustCompile(`integrity: (sha512-[A-Za-z0-9+/=]+)`)

type lockPackage struct{ name, version, sha512 string }

// parsePnpmLock reads the lock's `packages:` section (resolved packages only).
func parsePnpmLock(text string) []lockPackage {
	var out []lockPackage
	in := false
	cur := -1
	for _, line := range strings.Split(text, "\n") {
		if line != "" && line[0] != ' ' {
			in = line == "packages:"
			cur = -1
			continue
		}
		if !in {
			continue
		}
		if m := pnpmKey.FindStringSubmatch(line); m != nil {
			at := strings.LastIndex(m[1], "@")
			if at <= 0 {
				cur = -1
				continue
			}
			out = append(out, lockPackage{name: m[1][:at], version: m[1][at+1:]})
			cur = len(out) - 1
			continue
		}
		if cur >= 0 {
			if m := pnpmIntegrity.FindStringSubmatch(line); m != nil {
				if b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(m[1], "sha512-")); err == nil {
					out[cur].sha512 = hex.EncodeToString(b)
				}
			}
		}
	}
	return out
}

func npmPURL(name, version string) string {
	return "pkg:npm/" + strings.Replace(name, "@", "%40", 1) + "@" + version
}

func collectNode(root string) ([]Component, []string, error) {
	lockRaw, err := os.ReadFile(filepath.Join(root, "pnpm-lock.yaml"))
	if err != nil {
		return nil, nil, err
	}
	invRaw, err := os.ReadFile(filepath.Join(root, "build", "dependencies", "node-licenses.json"))
	if err != nil {
		return nil, nil, err
	}
	var inv struct {
		LockSHA256 string `json:"lock_sha256"`
		Packages   []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			License string `json:"license_declared"`
		} `json:"packages"`
	}
	if err = json.Unmarshal(invRaw, &inv); err != nil {
		return nil, nil, fmt.Errorf("build/dependencies/node-licenses.json: %w", err)
	}
	lock := parsePnpmLock(strings.ReplaceAll(string(lockRaw), "\r\n", "\n"))
	have := map[string]string{}
	for _, p := range inv.Packages {
		have[p.Name+"@"+p.Version] = normLicense(p.License)
	}
	var stale []string
	sum := sha256.Sum256(lockRaw)
	if got := hex.EncodeToString(sum[:]); got != inv.LockSHA256 {
		missing, extra := 0, 0
		inLock := map[string]bool{}
		for _, p := range lock {
			inLock[p.name+"@"+p.version] = true
			if _, ok := have[p.name+"@"+p.version]; !ok {
				missing++
			}
		}
		for k := range have {
			if !inLock[k] {
				extra++
			}
		}
		stale = append(stale, fmt.Sprintf("build/dependencies/node-licenses.json is stale: pins pnpm-lock.yaml sha256 %s, current lock is %s; %d lock packages (of %d) are absent from the inventory, %d inventory packages are no longer in the lock", inv.LockSHA256, got, missing, len(lock), extra))
	}
	var out []Component
	for _, p := range lock {
		c := Component{Ecosystem: "npm", Name: p.name, Version: p.version, PURL: npmPURL(p.name, p.version), Scope: ScopeOptional, SHA512: p.sha512}
		if l, ok := have[p.name+"@"+p.version]; ok && l != "" {
			c.License, c.LicenseSource = l, "build/dependencies/node-licenses.json"
		} else {
			c.LicenseReason = "not in build/dependencies/node-licenses.json (inventory does not cover the current pnpm-lock.yaml)"
		}
		out = append(out, c)
	}
	return out, stale, nil
}

var pyPin = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\;]+)`)

func collectPython(root string) ([]Component, error) {
	seen := map[string]bool{}
	var out []Component
	for _, rel := range []string{"sdk/python/requirements-dev.lock", "sdk/python/requirements-integrations.lock"} {
		text, err := readLF(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(text, "\n") {
			m := pyPin.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			name := strings.ToLower(strings.NewReplacer("_", "-", ".", "-").Replace(m[1]))
			if seen[name+"@"+m[2]] {
				continue
			}
			seen[name+"@"+m[2]] = true
			out = append(out, Component{Ecosystem: "pypi", Name: name, Version: m[2], PURL: "pkg:pypi/" + name + "@" + m[2], Scope: ScopeOptional,
				LicenseReason: "no committed Python license inventory covers " + rel + " pins"})
		}
	}
	return out, nil
}

// spdxLead returns the leading SPDX-looking token of a provenance license field. The
// parenthetical remainder (for example "IANA data is public domain") stays in LicenseSource.
func spdxLead(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " ("); i >= 0 {
		s = s[:i]
	}
	return s
}

func collectVendored(root string) ([]Component, error) {
	tp := filepath.Join(root, "third_party")
	entries, err := os.ReadDir(tp)
	if err != nil {
		return nil, err
	}
	var out []Component
	add := func(rel, version, license, source string) {
		name := "third_party/" + rel
		c := Component{Ecosystem: "generic", Name: name, Version: version, PURL: "pkg:generic/" + strings.ReplaceAll(name, "/", "-") + "@" + version, Scope: ScopeRequired, LicenseSource: source}
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(name), "LICENSE")); err == nil {
			c.NoticeText = true
		}
		if lead := spdxLead(license); lead != "" {
			c.License = lead
		} else {
			c.LicenseReason = "no license field in " + source
		}
		out = append(out, c)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(tp, e.Name())
		if raw, err := os.ReadFile(filepath.Join(dir, "sources.json")); err == nil {
			var s struct {
				License string `json:"license"`
			}
			if err = json.Unmarshal(raw, &s); err != nil {
				return nil, fmt.Errorf("third_party/%s/sources.json: %w", e.Name(), err)
			}
			subs, _ := os.ReadDir(dir)
			for _, sub := range subs {
				if sub.IsDir() {
					add(e.Name()+"/"+sub.Name(), sub.Name(), s.License, "third_party/"+e.Name()+"/sources.json license field: "+s.License)
				}
			}
			continue
		}
		subs, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		for _, sub := range subs {
			if !sub.IsDir() {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, sub.Name(), "provenance.json"))
			if err != nil {
				continue
			}
			var p struct {
				License string `json:"license"`
				Release string `json:"upstream_release"`
			}
			if err = json.Unmarshal(raw, &p); err != nil {
				return nil, fmt.Errorf("third_party/%s/%s/provenance.json: %w", e.Name(), sub.Name(), err)
			}
			v := sub.Name()
			if p.Release != "" {
				v = p.Release
			}
			add(e.Name()+"/"+sub.Name(), v, p.License, "third_party/"+e.Name()+"/"+sub.Name()+"/provenance.json license field: "+p.License)
		}
	}
	return out, nil
}

// collectInventory gathers every dependency class the distribution or its build touches.
func collectInventory(root string) (Inventory, error) {
	var inv Inventory
	goc, err := collectGo(root)
	if err != nil {
		return inv, err
	}
	node, stale, err := collectNode(root)
	if err != nil {
		return inv, err
	}
	py, err := collectPython(root)
	if err != nil {
		return inv, err
	}
	vend, err := collectVendored(root)
	if err != nil {
		return inv, err
	}
	// The static binaries embed the Go runtime and standard library. Its license text is
	// committed as the Go distribution license in third_party/format/go124.
	pin, err := loadPins(root)
	if err != nil {
		return inv, err
	}
	stdlib := Component{Ecosystem: "golang", Name: "go-standard-library", Version: pin.Go.Version, PURL: "pkg:generic/go-standard-library@" + pin.Go.Version, Scope: ScopeRequired}
	if raw, err := os.ReadFile(filepath.Join(root, "third_party", "format", "go124", "provenance.json")); err == nil {
		var p struct {
			License string `json:"license"`
		}
		if json.Unmarshal(raw, &p) == nil && spdxLead(p.License) != "" {
			stdlib.License, stdlib.LicenseSource, stdlib.NoticeText = spdxLead(p.License), "third_party/format/go124/provenance.json (Go distribution license; Go version pinned by build/toolchains.json)", true
		}
	}
	if stdlib.License == "" {
		stdlib.LicenseReason = "third_party/format/go124/provenance.json has no license field for the Go distribution"
	}
	inv.Components = append(append(append(append(goc, node...), py...), vend...), stdlib)
	inv.Stale = stale
	sort.Slice(inv.Components, func(i, j int) bool { return inv.Components[i].PURL < inv.Components[j].PURL })
	for i := 1; i < len(inv.Components); i++ {
		if inv.Components[i].PURL == inv.Components[i-1].PURL {
			return inv, errors.New("duplicate component " + inv.Components[i].PURL)
		}
	}
	return inv, nil
}

// ---- CycloneDX 1.5 ----

type cdxLicense struct {
	License    *cdxID `json:"license,omitempty"`
	Expression string `json:"expression,omitempty"`
}
type cdxID struct {
	ID string `json:"id"`
}
type cdxProp struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}
type cdxComp struct {
	Type       string       `json:"type"`
	BOMRef     string       `json:"bom-ref"`
	Name       string       `json:"name"`
	Version    string       `json:"version"`
	Scope      string       `json:"scope,omitempty"`
	PURL       string       `json:"purl"`
	Hashes     []cdxHash    `json:"hashes,omitempty"`
	Licenses   []cdxLicense `json:"licenses,omitempty"`
	Properties []cdxProp    `json:"properties,omitempty"`
}
type cdxDoc struct {
	BOMFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	Version     int    `json:"version"`
	Metadata    struct {
		Timestamp string  `json:"timestamp,omitempty"`
		Component cdxComp `json:"component"`
	} `json:"metadata"`
	Components []cdxComp `json:"components"`
}

func isExpression(l string) bool { return strings.Contains(l, " AND ") || strings.Contains(l, " OR ") }

// GenerateCycloneDX renders the inventory as CycloneDX 1.5 JSON. created may be empty.
func GenerateCycloneDX(inv Inventory, version, created string) ([]byte, error) {
	var d cdxDoc
	d.BOMFormat, d.SpecVersion, d.Version, d.Metadata.Timestamp = "CycloneDX", "1.5", 1, created
	d.Metadata.Component = cdxComp{Type: "application", BOMRef: "pkg:generic/soundpost@" + version, Name: "soundpost", Version: version, PURL: "pkg:generic/soundpost@" + version,
		Licenses: []cdxLicense{{License: &cdxID{ID: "Apache-2.0"}}}}
	d.Components = []cdxComp{}
	for _, c := range inv.Components {
		cc := cdxComp{Type: "library", BOMRef: c.PURL, Name: c.Name, Version: c.Version, Scope: c.Scope, PURL: c.PURL}
		if c.SHA512 != "" {
			cc.Hashes = []cdxHash{{Alg: "SHA-512", Content: c.SHA512}}
		}
		switch {
		case c.License == "":
			cc.Properties = append(cc.Properties, cdxProp{"soundpost:license", NoAssertion + ": " + c.LicenseReason})
		case isExpression(c.License):
			cc.Licenses = []cdxLicense{{Expression: c.License}}
		default:
			cc.Licenses = []cdxLicense{{License: &cdxID{ID: c.License}}}
		}
		if c.LicenseSource != "" {
			cc.Properties = append(cc.Properties, cdxProp{"soundpost:license-source", c.LicenseSource})
		}
		cc.Properties = append(cc.Properties, cdxProp{"soundpost:notice-text-carried", fmt.Sprint(c.NoticeText)})
		d.Components = append(d.Components, cc)
	}
	return marshalStable(d)
}

// ---- SPDX 2.3 ----

type spdxRef struct {
	Category string `json:"referenceCategory"`
	Type     string `json:"referenceType"`
	Locator  string `json:"referenceLocator"`
}
type spdxSum struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"checksumValue"`
}
type spdxPkg struct {
	Name             string    `json:"name"`
	SPDXID           string    `json:"SPDXID"`
	Version          string    `json:"versionInfo"`
	Download         string    `json:"downloadLocation"`
	FilesAnalyzed    bool      `json:"filesAnalyzed"`
	Concluded        string    `json:"licenseConcluded"`
	Declared         string    `json:"licenseDeclared"`
	Copyright        string    `json:"copyrightText"`
	Comment          string    `json:"comment,omitempty"`
	Checksums        []spdxSum `json:"checksums,omitempty"`
	ExternalRefs     []spdxRef `json:"externalRefs,omitempty"`
	PrimaryPurpose   string    `json:"primaryPackagePurpose,omitempty"`
	LicenseComments  string    `json:"licenseComments,omitempty"`
	AttributionTexts []string  `json:"attributionTexts,omitempty"`
}
type spdxRel struct {
	Element string `json:"spdxElementId"`
	Type    string `json:"relationshipType"`
	Related string `json:"relatedSpdxElement"`
}
type spdxDoc struct {
	Version   string `json:"spdxVersion"`
	DataLic   string `json:"dataLicense"`
	ID        string `json:"SPDXID"`
	Name      string `json:"name"`
	Namespace string `json:"documentNamespace"`
	Creation  struct {
		Created  string   `json:"created"`
		Creators []string `json:"creators"`
	} `json:"creationInfo"`
	DocDescribes  []string  `json:"documentDescribes"`
	Packages      []spdxPkg `json:"packages"`
	Relationships []spdxRel `json:"relationships"`
}

// GenerateSPDX renders the inventory as SPDX 2.3 JSON. SPDX requires a creation time, so
// created must be supplied; it is never read from the clock.
func GenerateSPDX(inv Inventory, version, created string) ([]byte, error) {
	if created == "" {
		return nil, errors.New("SPDX creationInfo.created is required: pass an explicit timestamp input")
	}
	var d spdxDoc
	d.Version, d.DataLic, d.ID, d.Name = "SPDX-2.3", "CC0-1.0", "SPDXRef-DOCUMENT", "soundpost-"+version
	d.Creation.Created, d.Creation.Creators = created, []string{"Tool: soundpost-build-sbom"}
	root := spdxPkg{Name: "soundpost", SPDXID: "SPDXRef-Package-soundpost", Version: version, Download: NoAssertion, Concluded: "Apache-2.0", Declared: "Apache-2.0",
		Copyright: "Copyright 2026 Aryn Yklas", PrimaryPurpose: "APPLICATION"}
	d.Packages = []spdxPkg{root}
	d.DocDescribes = []string{root.SPDXID}
	d.Relationships = []spdxRel{{"SPDXRef-DOCUMENT", "DESCRIBES", root.SPDXID}}
	digest := sha256.New()
	for i, c := range inv.Components {
		fmt.Fprintf(digest, "%s\t%s\n", c.PURL, c.License)
		p := spdxPkg{Name: c.Name, SPDXID: fmt.Sprintf("SPDXRef-Package-%04d", i), Version: c.Version, Download: NoAssertion, Copyright: NoAssertion,
			ExternalRefs: []spdxRef{{"PACKAGE-MANAGER", "purl", c.PURL}}, Comment: "scope: " + c.Scope}
		if c.License == "" {
			p.Concluded, p.Declared, p.LicenseComments = NoAssertion, NoAssertion, c.LicenseReason
		} else {
			p.Concluded, p.Declared = c.License, c.License
			p.LicenseComments = "from " + c.LicenseSource
		}
		if c.SHA512 != "" {
			p.Checksums = []spdxSum{{"SHA512", c.SHA512}}
		}
		d.Packages = append(d.Packages, p)
		rel := "DEPENDS_ON"
		if c.Scope != ScopeRequired {
			rel = "DEV_DEPENDENCY_OF"
			d.Relationships = append(d.Relationships, spdxRel{p.SPDXID, rel, root.SPDXID})
			continue
		}
		d.Relationships = append(d.Relationships, spdxRel{root.SPDXID, rel, p.SPDXID})
	}
	d.Namespace = "https://spdx.invalid/soundpost/" + version + "/" + hex.EncodeToString(digest.Sum(nil))
	return marshalStable(d)
}

func marshalStable(v any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// ---- THIRD_PARTY_NOTICES ----

func renderNotices(root string, inv Inventory) ([]byte, error) {
	var b strings.Builder
	b.WriteString("Soundpost third-party notices\nCopyright 2026 Aryn Yklas\nFirst-party code: Apache-2.0 (see LICENSE and NOTICE)\n\n")
	b.WriteString("Generated by `go run ./build notices` from go.mod, go.sum, pnpm-lock.yaml, sdk/python/requirements-*.lock,\n")
	b.WriteString("third_party/* and the committed license inventories. Do not edit by hand; `go run ./build notices --check` and the\n")
	b.WriteString("release gate fail when this file differs from a fresh generation.\n\n")
	b.WriteString("A component whose license reads NOASSERTION has no committed license record; no license is assumed for it.\n")
	b.WriteString("\"text\" says whether the full license/notice text is carried in this file or in third_party/. npm and Python\n")
	b.WriteString("dependencies are development/test lock inputs and are NOT bundled in the Go release archives; their license texts\n")
	b.WriteString("have not been collected (distribution gate pending).\n")
	for _, eco := range []struct{ id, title string }{{"golang", "Go modules and runtime"}, {"generic", "Vendored data and primitives (third_party)"}, {"npm", "npm packages (pnpm-lock.yaml)"}, {"pypi", "Python packages (sdk/python/requirements-*.lock)"}} {
		fmt.Fprintf(&b, "\n== %s ==\n", eco.title)
		for _, c := range inv.Components {
			if c.Ecosystem != eco.id {
				continue
			}
			lic := c.License
			if lic == "" {
				lic = NoAssertion
			}
			text := "no"
			if c.NoticeText {
				text = "yes"
			}
			fmt.Fprintf(&b, "%s %s | license %s | scope %s | text %s\n", c.Name, c.Version, lic, c.Scope, text)
		}
	}
	b.WriteString("\n== License and notice texts ==\n")
	var files []string
	err := filepath.WalkDir(filepath.Join(root, "third_party"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		n := d.Name()
		if n == "LICENSE" || n == "NOTICE" || n == "NOTICE.txt" || strings.HasPrefix(n, "UPSTREAM-NOTICE-") || strings.HasSuffix(n, "-NOTICES.txt") {
			rel, _ := filepath.Rel(root, p)
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	byBody := map[string][]string{}
	var order []string
	for _, rel := range files {
		body, err := readLF(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return nil, err
		}
		body = strings.TrimRight(body, "\n") + "\n"
		if _, ok := byBody[body]; !ok {
			order = append(order, body)
		}
		byBody[body] = append(byBody[body], rel)
	}
	for _, body := range order {
		b.WriteString("\n----- " + strings.Join(byBody[body], ", ") + " -----\n" + body)
	}
	return []byte(b.String()), nil
}
