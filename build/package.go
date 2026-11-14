// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

// The whole-product release gate (plan 07 task 8). Release refuses to report a release as
// ready unless every check passes: complete plan-index coverage, promised surfaces delivered,
// language/runtime/privacy/node-loss/browser evidence, a current dependency inventory, only
// approved licenses, current notices, SBOM generation, verified checksums, a verified
// signature, a public-handle check result and an explicit owner approval. It never publishes,
// signs or contacts a network service; the one real network client (NetHandleChecker) is only
// used by the separate `handles` subcommand.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/releaseevidence"
)

// Check names, stable for scripts.
const (
	checkCoverage   = "plan_coverage"
	checkSurfaces   = "promised_surfaces"
	checkInventory  = "dependency_inventory"
	checkLicenses   = "licenses"
	checkNotices    = "notices"
	checkSBOM       = "sbom"
	checkChecksums  = "checksums"
	checkSignature  = "signature"
	checkHandles    = "handle_check"
	checkApproval   = "owner_approval"
	evidenceSchema  = releaseevidence.Schema
	handleSchema    = "soundpost-handle-check/1"
	surfacesSchema  = "soundpost-promised-surfaces/1"
	gateSchema      = "soundpost-release-gate/1"
	ledgerCompleted = "complete"
)

// EvidenceKinds are the five reports the gate consumes. Producers: language = the 07.05 query
// campaign, runtime = 07.06 qualification, privacy = 07.06 privacy canaries, node_loss = 07.07
// drills, browser = 05/09 real-browser acceptance. Each must be written in the envelope of
// internal/releaseevidence, which the exporters of the producers share with this gate.
var EvidenceKinds = releaseevidence.Kinds

// EvidenceReport is the narrow interface the gate reads. The gate recomputes the verdict from
// Rows and Expected and ignores any producer-side summary, so a report cannot assert its own pass.
type EvidenceReport = releaseevidence.Report

// EvidenceRow is one measured row. Status "passed" is the only passing value; "skipped",
// "not_run", "unqualified" and "failed" all block.
type EvidenceRow = releaseevidence.Row

// Reports is everything the gate is given; every path is an explicit input.
type Reports struct {
	Root             string
	Version          string
	Created          string            // explicit timestamp for the SBOM; never read from the clock
	LedgerPath       string            // copy of the plan ledger (tasks.json)
	AcceptedTasks    map[string]bool   // task ids whose implemented_* state the owner accepts
	Evidence         map[string]string // kind -> report path
	ArtifactDir      string            // output directory of `go run ./build release`
	PublicKeyPath    string            // base64 Ed25519 public key
	SignaturePath    string            // detached signature envelope (optional)
	ApprovalPath     string            // owner approval envelope (optional)
	Handles          *HandleReport     // result of RunHandleChecks (nil = not run)
	SurfacesPath     string            // default build/promised_surfaces.json
	ChecklistPath    string            // default docs/releases/checklist.md
	NoticesPath      string            // default THIRD_PARTY_NOTICES
	ArtifactManifest string            // default <ArtifactDir>/release.json
}

// Check is one gate result.
type Check struct {
	Name     string   `json:"name"`
	Status   string   `json:"status"` // pass | blocked
	Detail   string   `json:"detail,omitempty"`
	Blocking []string `json:"blocking,omitempty"`
	// Items is the unabridged blocking list when Blocking is summarized.
	Items []string `json:"items,omitempty"`
}

// ReleaseManifest is the gate verdict. Ready is true only when every check passes.
type ReleaseManifest struct {
	Schema                 string   `json:"schema"`
	Version                string   `json:"version"`
	Commit                 string   `json:"commit"`
	Ready                  bool     `json:"ready"`
	Checks                 []Check  `json:"checks"`
	Blocking               []string `json:"blocking"`
	ArtifactManifestSHA256 string   `json:"artifact_manifest_sha256,omitempty"`
	CycloneDXSHA256        string   `json:"sbom_cyclonedx_sha256,omitempty"`
	SPDXSHA256             string   `json:"sbom_spdx_sha256,omitempty"`
	Components             int      `json:"sbom_components"`
}

// BlockedError is returned with the manifest when the gate does not pass.
type BlockedError struct{ Blocking []string }

func (e *BlockedError) Error() string {
	return fmt.Sprintf("release gate blocked by %d item(s)", len(e.Blocking))
}

type ledgerTask struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	State string `json:"state"`
}

func readLedger(path string) ([]ledgerTask, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t []ledgerTask
	if err = json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("ledger %s: %w", path, err)
	}
	if len(t) == 0 {
		return nil, errors.New("ledger has no tasks")
	}
	return t, nil
}

func taskSatisfied(t ledgerTask, accepted map[string]bool) bool {
	return t.State == ledgerCompleted || ((t.State == "implemented_reviewed" || t.State == "implemented_verified") && accepted[t.ID])
}

func checkCoverageOf(r Reports) Check {
	c := Check{Name: checkCoverage}
	tasks, err := readLedger(r.LedgerPath)
	if err != nil {
		c.Blocking = []string{"ledger unreadable: " + err.Error()}
		return c
	}
	known := map[string]bool{}
	for _, t := range tasks {
		known[t.ID] = true
		if !taskSatisfied(t, r.AcceptedTasks) {
			c.Blocking = append(c.Blocking, fmt.Sprintf("task %s is %s: %s", t.ID, t.State, t.Title))
		}
	}
	for id := range r.AcceptedTasks {
		if !known[id] {
			c.Blocking = append(c.Blocking, "accepted task "+id+" is not in the ledger")
		}
	}
	sort.Strings(c.Blocking)
	c.Detail = fmt.Sprintf("%d tasks, %d blocking", len(tasks), len(c.Blocking))
	return c
}

// PromisedSurface is one claim the product makes, with the tasks that deliver it.
type PromisedSurface struct {
	ID     string   `json:"id"`
	Claim  string   `json:"claim"`
	Source string   `json:"source"`
	Tasks  []string `json:"tasks"`
}

func checkSurfacesOf(r Reports) Check {
	c := Check{Name: checkSurfaces}
	raw, err := os.ReadFile(r.SurfacesPath)
	if err != nil {
		c.Blocking = []string{"promised-surface list unreadable: " + err.Error()}
		return c
	}
	var doc struct {
		Schema   string            `json:"schema"`
		Surfaces []PromisedSurface `json:"surfaces"`
	}
	if err = json.Unmarshal(raw, &doc); err != nil || doc.Schema != surfacesSchema || len(doc.Surfaces) == 0 {
		c.Blocking = []string{fmt.Sprintf("promised-surface list %s is not a non-empty %s document (%v)", r.SurfacesPath, surfacesSchema, err)}
		return c
	}
	tasks, err := readLedger(r.LedgerPath)
	if err != nil {
		c.Blocking = []string{"ledger unreadable: " + err.Error()}
		return c
	}
	byID := map[string]ledgerTask{}
	for _, t := range tasks {
		byID[t.ID] = t
	}
	checklist, err := readLF(r.ChecklistPath)
	if err != nil {
		c.Blocking = append(c.Blocking, "checklist unreadable: "+err.Error())
	}
	for _, s := range doc.Surfaces {
		if len(s.Tasks) == 0 {
			c.Blocking = append(c.Blocking, fmt.Sprintf("surface %s names no delivering task", s.ID))
		}
		if err == nil && !strings.Contains(checklist, "`"+s.ID+"`") {
			c.Blocking = append(c.Blocking, fmt.Sprintf("surface %s is missing from the release checklist", s.ID))
		}
		var open []string
		for _, id := range s.Tasks {
			t, ok := byID[id]
			if !ok {
				open = append(open, id+" (not in ledger)")
			} else if !taskSatisfied(t, r.AcceptedTasks) {
				open = append(open, id+" ("+t.State+")")
			}
		}
		if len(open) > 0 {
			c.Blocking = append(c.Blocking, fmt.Sprintf("surface %s (%s) is not delivered: %s", s.ID, s.Claim, strings.Join(open, ", ")))
		}
	}
	c.Detail = fmt.Sprintf("%d surfaces", len(doc.Surfaces))
	return c
}

func checkEvidenceOf(kind string, r Reports, commit string) Check {
	c := Check{Name: "evidence_" + kind}
	path := r.Evidence[kind]
	if path == "" {
		c.Blocking = []string{kind + " evidence report missing: no path supplied"}
		return c
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		c.Blocking = []string{kind + " evidence report missing: " + err.Error()}
		return c
	}
	var e EvidenceReport
	if err = decodeStrict(raw, &e); err != nil {
		c.Blocking = []string{kind + " evidence report malformed: " + err.Error()}
		return c
	}
	if e.Schema != evidenceSchema || e.Kind != kind {
		c.Blocking = []string{fmt.Sprintf("%s evidence report has schema %q kind %q, want %q %q", kind, e.Schema, e.Kind, evidenceSchema, kind)}
		return c
	}
	if e.Commit != commit {
		c.Blocking = append(c.Blocking, fmt.Sprintf("%s evidence is for commit %q, not %q", kind, e.Commit, commit))
	}
	if len(e.Expected) == 0 {
		c.Blocking = append(c.Blocking, kind+" evidence declares no expected rows")
	}
	status := map[string]string{}
	for _, row := range e.Rows {
		if _, dup := status[row.ID]; dup {
			c.Blocking = append(c.Blocking, fmt.Sprintf("%s evidence has duplicate row %s", kind, row.ID))
		}
		status[row.ID] = row.Status
		if row.Status != "passed" {
			c.Blocking = append(c.Blocking, fmt.Sprintf("%s row %s is %s %s", kind, row.ID, row.Status, row.Detail))
		}
	}
	for _, id := range e.Expected {
		if _, ok := status[id]; !ok {
			c.Blocking = append(c.Blocking, fmt.Sprintf("%s expected row %s has no result", kind, id))
		}
	}
	c.Detail = fmt.Sprintf("%d rows, %d expected", len(e.Rows), len(e.Expected))
	return c
}

func summarize(prefix string, items []string, limit int) []string {
	if len(items) <= limit {
		return items
	}
	return append(append([]string{}, items[:limit]...), fmt.Sprintf("%s ... and %d more (full list: gate --json, check items)", prefix, len(items)-limit))
}

// checkSupplyChain covers inventory staleness, licenses, notices and SBOM generation.
func checkSupplyChain(r Reports, m *ReleaseManifest) []Check {
	inv, err := collectInventory(r.Root)
	if err != nil {
		var out []Check
		for _, n := range []string{checkInventory, checkLicenses, checkNotices, checkSBOM} {
			out = append(out, Check{Name: n, Blocking: []string{"dependency inventory unreadable: " + err.Error()}})
		}
		return out
	}
	stale := Check{Name: checkInventory, Blocking: inv.Stale, Detail: fmt.Sprintf("%d components", len(inv.Components))}

	lic := Check{Name: checkLicenses}
	byEco := map[string][]string{}
	for _, c := range inv.Components {
		if c.Scope == ScopeExcluded || licenseApproved(c.License) {
			continue
		}
		why := "license " + c.License + " is not in the approved set"
		if c.License == "" {
			why = "license NOASSERTION: " + c.LicenseReason
		}
		byEco[c.Ecosystem] = append(byEco[c.Ecosystem], fmt.Sprintf("%s@%s: %s", c.Name, c.Version, why))
	}
	var ecos []string
	for e := range byEco {
		ecos = append(ecos, e)
	}
	sort.Strings(ecos)
	for _, e := range ecos {
		all := prefixAll(e+" ", byEco[e])
		lic.Items = append(lic.Items, all...)
		lic.Blocking = append(lic.Blocking, summarize(e, all, 5)...)
	}
	lic.Detail = "scope required+optional components must carry an approved SPDX license"

	notices := Check{Name: checkNotices}
	want, err := renderNotices(r.Root, inv)
	have, herr := os.ReadFile(r.NoticesPath)
	switch {
	case err != nil:
		notices.Blocking = append(notices.Blocking, "notices generation failed: "+err.Error())
	case herr != nil:
		notices.Blocking = append(notices.Blocking, "THIRD_PARTY_NOTICES missing: "+herr.Error())
	case strings.ReplaceAll(string(have), "\r\n", "\n") != string(want):
		notices.Blocking = append(notices.Blocking, "THIRD_PARTY_NOTICES differs from a fresh `go run ./build notices` generation")
	}
	noText := map[string]int{}
	for _, c := range inv.Components {
		if c.Scope != ScopeExcluded && !c.NoticeText {
			noText[c.Ecosystem]++
		}
	}
	for _, e := range []string{"golang", "generic", "npm", "pypi"} {
		if noText[e] > 0 {
			notices.Blocking = append(notices.Blocking, fmt.Sprintf("%s: %d component(s) carry no license/notice text in the repository", e, noText[e]))
		}
	}

	sb := Check{Name: checkSBOM}
	cdx, err1 := GenerateCycloneDX(inv, r.Version, r.Created)
	spdx, err2 := GenerateSPDX(inv, r.Version, r.Created)
	if err1 != nil || err2 != nil {
		sb.Blocking = append(sb.Blocking, fmt.Sprintf("SBOM generation failed: cyclonedx=%v spdx=%v", err1, err2))
	} else {
		m.CycloneDXSHA256, m.SPDXSHA256, m.Components = ManifestDigest(cdx), ManifestDigest(spdx), len(inv.Components)
		sb.Detail = fmt.Sprintf("%d components; cyclonedx sha256 %s; spdx sha256 %s", len(inv.Components), m.CycloneDXSHA256, m.SPDXSHA256)
	}
	return []Check{stale, lic, notices, sb}
}

func prefixAll(p string, items []string) []string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = p + s
	}
	return out
}

// checkArtifacts verifies SHA256SUMS against the files and release.json against the sums.
func checkArtifacts(r Reports, commit string, m *ReleaseManifest) Check {
	c := Check{Name: checkChecksums}
	dir := r.ArtifactDir
	if dir == "" {
		c.Blocking = []string{"no artifact directory supplied"}
		return c
	}
	sumsRaw, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		c.Blocking = []string{"SHA256SUMS missing: " + err.Error()}
		return c
	}
	listed := map[string]string{}
	for _, line := range strings.Split(strings.ReplaceAll(string(sumsRaw), "\r\n", "\n"), "\n") {
		if line == "" {
			continue
		}
		f := strings.SplitN(line, "  ", 2)
		if len(f) != 2 || len(f[0]) != 64 {
			c.Blocking = append(c.Blocking, "malformed SHA256SUMS line: "+line)
			continue
		}
		rel := filepath.ToSlash(filepath.Clean(f[1]))
		if filepath.IsAbs(rel) || strings.HasPrefix(rel, "../") || rel == ".." {
			c.Blocking = append(c.Blocking, "SHA256SUMS entry escapes the artifact directory: "+f[1])
			continue
		}
		listed[rel] = f[0]
	}
	if len(listed) == 0 {
		c.Blocking = append(c.Blocking, "SHA256SUMS lists no artifact")
	}
	for rel, want := range listed {
		got, err := sha256File(filepath.Join(dir, filepath.FromSlash(rel)))
		switch {
		case err != nil:
			c.Blocking = append(c.Blocking, "listed artifact missing: "+rel)
		case got != want:
			c.Blocking = append(c.Blocking, fmt.Sprintf("artifact %s sha256 %s does not match SHA256SUMS %s", rel, got, want))
		}
	}
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if _, ok := listed[rel]; !ok && rel != "SHA256SUMS" && rel != "release.json" {
			c.Blocking = append(c.Blocking, "artifact not covered by SHA256SUMS: "+rel)
		}
		return nil
	})
	manPath := r.ArtifactManifest
	if manPath == "" {
		manPath = filepath.Join(dir, "release.json")
	}
	raw, err := os.ReadFile(manPath)
	if err != nil {
		c.Blocking = append(c.Blocking, "release.json missing: "+err.Error())
		sort.Strings(c.Blocking)
		return c
	}
	m.ArtifactManifestSHA256 = ManifestDigest(raw)
	var man Manifest
	if err = json.Unmarshal(raw, &man); err != nil {
		c.Blocking = append(c.Blocking, "release.json malformed: "+err.Error())
		return c
	}
	if man.Commit != commit || man.Version != r.Version {
		c.Blocking = append(c.Blocking, fmt.Sprintf("release.json is for version %q commit %q, not %q %q", man.Version, man.Commit, r.Version, commit))
	}
	if !man.Reproducibility.Checked || !man.Reproducibility.Equal {
		c.Blocking = append(c.Blocking, "release.json does not record an equal reproducibility check")
	}
	if len(man.Binaries) == 0 {
		c.Blocking = append(c.Blocking, "release.json lists no binaries")
	}
	for _, b := range man.Binaries {
		rel := strings.ReplaceAll(b.Platform, "/", "-") + "/" + b.Name
		if listed[rel] != b.SHA256 {
			c.Blocking = append(c.Blocking, fmt.Sprintf("release.json binary %s sha256 %s is not what SHA256SUMS lists (%q)", rel, b.SHA256, listed[rel]))
		}
	}
	sort.Strings(c.Blocking)
	c.Detail = fmt.Sprintf("%d artifacts; release.json sha256 %s", len(listed), m.ArtifactManifestSHA256)
	return c
}

func loadPublicKey(path string) (ed25519.PublicKey, error) {
	if path == "" {
		return nil, errors.New("no public key supplied")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(string(raw))
}

func checkSignatureOf(r Reports, m *ReleaseManifest) Check {
	c := Check{Name: checkSignature}
	if r.SignaturePath == "" {
		c.Detail = "not_signed"
		c.Blocking = []string{"not_signed (no detached signature supplied; signing is an owner action)"}
		return c
	}
	pub, err := loadPublicKey(r.PublicKeyPath)
	if err != nil {
		c.Blocking = []string{"cannot verify: " + err.Error()}
		return c
	}
	env, err := os.ReadFile(r.SignaturePath)
	if err != nil {
		c.Blocking = []string{"" + err.Error()}
		return c
	}
	man, err := os.ReadFile(manifestPath(r))
	if err != nil {
		c.Blocking = []string{"release.json unreadable: " + err.Error()}
		return c
	}
	if err = VerifySignature(man, env, pub); err != nil {
		c.Blocking = []string{"invalid: " + err.Error()}
		return c
	}
	c.Detail = "verified"
	return c
}

func manifestPath(r Reports) string {
	if r.ArtifactManifest != "" {
		return r.ArtifactManifest
	}
	return filepath.Join(r.ArtifactDir, "release.json")
}

func checkApprovalOf(r Reports, commit string) Check {
	c := Check{Name: checkApproval}
	if r.ApprovalPath == "" {
		c.Detail = "missing"
		c.Blocking = []string{"missing (no explicit owner approval input; nothing may be published without it)"}
		return c
	}
	pub, err := loadPublicKey(r.PublicKeyPath)
	if err != nil {
		c.Blocking = []string{"cannot verify: " + err.Error()}
		return c
	}
	env, err := os.ReadFile(r.ApprovalPath)
	if err != nil {
		c.Blocking = []string{"" + err.Error()}
		return c
	}
	man, err := os.ReadFile(manifestPath(r))
	if err != nil {
		c.Blocking = []string{"release.json unreadable: " + err.Error()}
		return c
	}
	if err = VerifyApproval(man, env, pub, r.Version, commit); err != nil {
		c.Blocking = []string{"invalid: " + err.Error()}
		return c
	}
	c.Detail = "approved"
	return c
}

func checkHandlesOf(r Reports) Check {
	c := Check{Name: checkHandles}
	if r.Handles == nil {
		c.Detail = "not_run"
		c.Blocking = []string{"not_run (public package handles are checked before publishing; no checker result supplied)"}
		return c
	}
	handles, err := DeriveHandles(r.Root)
	if err != nil {
		c.Blocking = []string{"cannot derive handles: " + err.Error()}
		return c
	}
	owned, err := loadOwnedHandles(r.Root)
	if err != nil {
		c.Blocking = []string{"cannot read owned handles: " + err.Error()}
		return c
	}
	got := map[Handle]string{}
	if r.Handles.Schema != handleSchema {
		c.Blocking = append(c.Blocking, fmt.Sprintf("result schema %q, want %q", r.Handles.Schema, handleSchema))
	}
	for _, res := range r.Handles.Results {
		got[res.Handle] = res.Status
	}
	for _, h := range handles {
		switch st, ok := got[h]; {
		case !ok:
			c.Blocking = append(c.Blocking, fmt.Sprintf("%s %s was not checked", h.Ecosystem, h.Name))
		case st == HandleExists && owned[h]:
			// Already published by this project (recorded in build/owned-handles.json): existing is the expected state.
		case st != HandleUnclaimed:
			c.Blocking = append(c.Blocking, fmt.Sprintf("%s %s is %s", h.Ecosystem, h.Name, st))
		}
	}
	return c
}

// ownedHandlesFile records handles this project has already claimed, each with the evidence of ownership. A
// handle listed here may exist in its registry; any other existing handle still blocks (someone else's name).
const ownedHandlesFile = "build/owned-handles.json"

type ownedHandle struct {
	Handle
	Evidence string `json:"evidence"`
}

func loadOwnedHandles(root string) (map[Handle]bool, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ownedHandlesFile)))
	if errors.Is(err, os.ErrNotExist) {
		return map[Handle]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	var doc struct {
		Owned []ownedHandle `json:"owned"`
	}
	if err = decodeStrict(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", ownedHandlesFile, err)
	}
	out := map[Handle]bool{}
	for _, o := range doc.Owned {
		if o.Ecosystem == "" || o.Name == "" || o.Evidence == "" {
			return nil, fmt.Errorf("%s: every entry needs ecosystem, name and evidence", ownedHandlesFile)
		}
		out[o.Handle] = true
	}
	return out, nil
}

// Release runs every gate check. The returned manifest is always populated; the error is a
// *BlockedError naming every blocking item unless the release is fully approved and ready.
func Release(ctx context.Context, commit string, r Reports) (ReleaseManifest, error) {
	m := ReleaseManifest{Schema: gateSchema, Version: r.Version, Commit: commit, Blocking: []string{}}
	if err := ctx.Err(); err != nil {
		return m, err
	}
	if r.Root == "" || r.Version == "" || commit == "" {
		return m, errors.New("Reports.Root, Reports.Version and the commit are required")
	}
	if r.SurfacesPath == "" {
		r.SurfacesPath = filepath.Join(r.Root, "build", "promised_surfaces.json")
	}
	if r.ChecklistPath == "" {
		r.ChecklistPath = filepath.Join(r.Root, "docs", "releases", "checklist.md")
	}
	if r.NoticesPath == "" {
		r.NoticesPath = filepath.Join(r.Root, "THIRD_PARTY_NOTICES")
	}
	m.Checks = append(m.Checks, checkCoverageOf(r), checkSurfacesOf(r))
	for _, k := range EvidenceKinds {
		m.Checks = append(m.Checks, checkEvidenceOf(k, r, commit))
	}
	m.Checks = append(m.Checks, checkSupplyChain(r, &m)...)
	m.Checks = append(m.Checks, checkArtifacts(r, commit, &m), checkSignatureOf(r, &m), checkHandlesOf(r), checkApprovalOf(r, commit))
	for i := range m.Checks {
		c := &m.Checks[i]
		if len(c.Blocking) == 0 {
			c.Status = "pass"
			continue
		}
		c.Status = "blocked"
		for _, b := range c.Blocking {
			m.Blocking = append(m.Blocking, c.Name+": "+b)
		}
	}
	if err := ctx.Err(); err != nil {
		return m, err
	}
	if len(m.Blocking) > 0 {
		return m, &BlockedError{Blocking: m.Blocking}
	}
	m.Ready = true
	return m, nil
}

// ---- public handles ----

// Handle is a public package name the release would claim.
type Handle struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// Handle statuses.
const (
	HandleUnclaimed = "unclaimed"
	HandleExists    = "exists"
	HandleInvalid   = "invalid"
)

// HandleResult is one checked handle.
type HandleResult struct {
	Handle
	Status string `json:"status"`
}

// HandleReport is the recorded outcome of a handle check run.
type HandleReport struct {
	Schema  string         `json:"schema"`
	Results []HandleResult `json:"results"`
}

// HandleChecker reports whether a public handle is unclaimed. The real implementation makes
// network calls; tests inject a fake.
type HandleChecker interface {
	Check(ctx context.Context, h Handle) (string, error)
}

// DeriveHandles lists the npm, PyPI and Go module handles of this tree.
func DeriveHandles(root string) ([]Handle, error) {
	var out []Handle
	pkgs, err := filepath.Glob(filepath.Join(root, "packages", "*", "package.json"))
	if err != nil {
		return nil, err
	}
	web, _ := filepath.Glob(filepath.Join(root, "web", "package.json"))
	for _, p := range append(pkgs, web...) {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var pj struct {
			Name string `json:"name"`
		}
		if err = json.Unmarshal(raw, &pj); err != nil || pj.Name == "" {
			return nil, fmt.Errorf("%s has no package name: %v", p, err)
		}
		out = append(out, Handle{"npm", pj.Name})
	}
	toml, err := readLF(filepath.Join(root, "sdk", "python", "pyproject.toml"))
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(toml, "\n") {
		if strings.HasPrefix(line, "name = ") {
			out = append(out, Handle{"pypi", strings.Trim(strings.TrimPrefix(line, "name = "), "\" ")})
			break
		}
	}
	mod, err := readLF(filepath.Join(root, "go.mod"))
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(mod, "\n") {
		if strings.HasPrefix(line, "module ") {
			out = append(out, Handle{"go", strings.TrimSpace(strings.TrimPrefix(line, "module "))})
			break
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Ecosystem+"/"+out[i].Name < out[j].Ecosystem+"/"+out[j].Name
	})
	return out, nil
}

// RunHandleChecks checks every handle. A Go module path without a dotted host element cannot
// be fetched from any module proxy, so it is invalid without asking the checker.
func RunHandleChecks(ctx context.Context, checker HandleChecker, handles []Handle) (HandleReport, error) {
	rep := HandleReport{Schema: handleSchema}
	for _, h := range handles {
		st := HandleInvalid
		if h.Ecosystem != "go" || strings.Contains(strings.SplitN(h.Name, "/", 2)[0], ".") {
			var err error
			if st, err = checker.Check(ctx, h); err != nil {
				return rep, fmt.Errorf("%s %s: %w", h.Ecosystem, h.Name, err)
			}
		}
		rep.Results = append(rep.Results, HandleResult{h, st})
	}
	return rep, nil
}

// NetHandleChecker queries the public registries. It performs network requests and is only
// reachable through the `handles` subcommand; the gate and the tests never run it.
type NetHandleChecker struct{ Client *http.Client }

func (n NetHandleChecker) Check(ctx context.Context, h Handle) (string, error) {
	var target string
	switch h.Ecosystem {
	case "npm":
		target = "https://registry.npmjs.org/" + strings.Replace(url.PathEscape(h.Name), "%40", "@", 1)
	case "pypi":
		target = "https://pypi.org/pypi/" + url.PathEscape(h.Name) + "/json"
	case "go":
		segs := strings.Split(strings.ToLower(h.Name), "/")
		for i, s := range segs {
			segs[i] = url.PathEscape(s)
		}
		target = "https://proxy.golang.org/" + strings.Join(segs, "/") + "/@v/list"
	default:
		return "", fmt.Errorf("unknown ecosystem %q", h.Ecosystem)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	client := n.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return HandleUnclaimed, nil
	case resp.StatusCode == http.StatusOK:
		return HandleExists, nil
	}
	return "", fmt.Errorf("registry answered %d", resp.StatusCode)
}

// ---- CLI ----

type kvFlag map[string]string

func (k kvFlag) String() string { return fmt.Sprint(map[string]string(k)) }
func (k kvFlag) Set(s string) error {
	i := strings.Index(s, "=")
	if i <= 0 {
		return errors.New("want kind=path")
	}
	k[s[:i]] = s[i+1:]
	return nil
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(s string) error { *l = append(*l, s); return nil }

// runPackage serves the sbom, notices, gate, verify-signature and handles subcommands.
func runPackage(cmd string, args []string, out io.Writer) error {
	f := flag.NewFlagSet(cmd, flag.ContinueOnError)
	root := f.String("root", ".", "repository root")
	version := f.String("version", "", "release version")
	created := f.String("created", "", "explicit RFC 3339 timestamp for the SBOM")
	outDir := f.String("out", "", "output directory (sbom) or file (handles, gate)")
	check := f.Bool("check", false, "notices: fail when THIRD_PARTY_NOTICES is not a fresh generation")
	commit := f.String("commit", "", "gate: source commit")
	ledger := f.String("ledger", "", "gate: copy of the plan ledger tasks.json")
	artifacts := f.String("artifacts", "", "gate: output directory of `build release`")
	pubkey := f.String("public-key", "", "base64 Ed25519 public key file")
	sig := f.String("signature", "", "detached signature envelope")
	approval := f.String("approval", "", "gate: owner approval envelope")
	handles := f.String("handle-report", "", "gate: handle check result JSON")
	manifest := f.String("manifest", "", "verify-signature: release.json")
	asJSON := f.Bool("json", false, "gate: print the full manifest as JSON")
	evidence, accepted := kvFlag{}, listFlag{}
	f.Var(evidence, "evidence", "gate: kind=path (repeat for language, runtime, privacy, node_loss, browser)")
	f.Var(&accepted, "accept-task", "gate: accept this implemented_* task id (repeatable)")
	if err := f.Parse(args); err != nil {
		return err
	}
	absRoot, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	switch cmd {
	case "sbom":
		if *version == "" || *created == "" || *outDir == "" {
			return errors.New("sbom needs --version, --created and --out")
		}
		inv, err := collectInventory(absRoot)
		if err != nil {
			return err
		}
		cdx, err := GenerateCycloneDX(inv, *version, *created)
		if err != nil {
			return err
		}
		spdx, err := GenerateSPDX(inv, *version, *created)
		if err != nil {
			return err
		}
		if err = os.MkdirAll(*outDir, 0o755); err != nil {
			return err
		}
		for name, body := range map[string][]byte{"soundpost.cdx.json": cdx, "soundpost.spdx.json": spdx} {
			if err = os.WriteFile(filepath.Join(*outDir, name), body, 0o644); err != nil {
				return err
			}
			fmt.Fprintf(out, "%s  %s\n", ManifestDigest(body), name)
		}
		for _, s := range inv.Stale {
			fmt.Fprintln(out, "STALE:", s)
		}
		return nil
	case "notices":
		inv, err := collectInventory(absRoot)
		if err != nil {
			return err
		}
		body, err := renderNotices(absRoot, inv)
		if err != nil {
			return err
		}
		path := filepath.Join(absRoot, "THIRD_PARTY_NOTICES")
		if *check {
			have, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.ReplaceAll(string(have), "\r\n", "\n") != string(body) {
				return errors.New("THIRD_PARTY_NOTICES differs from a fresh generation")
			}
			return nil
		}
		return os.WriteFile(path, body, 0o644)
	case "verify-signature":
		pub, err := loadPublicKey(*pubkey)
		if err != nil {
			return err
		}
		man, err := os.ReadFile(*manifest)
		if err != nil {
			return err
		}
		env, err := os.ReadFile(*sig)
		if err != nil {
			return err
		}
		if err = VerifySignature(man, env, pub); err != nil {
			return err
		}
		fmt.Fprintln(out, "signature verified for manifest sha256", ManifestDigest(man))
		return nil
	case "handles":
		hs, err := DeriveHandles(absRoot)
		if err != nil {
			return err
		}
		rep, err := RunHandleChecks(context.Background(), NetHandleChecker{}, hs)
		if err != nil {
			return err
		}
		raw, err := marshalStable(rep)
		if err != nil {
			return err
		}
		if *outDir != "" {
			return os.WriteFile(*outDir, raw, 0o644)
		}
		_, err = out.Write(raw)
		return err
	}
	// gate
	r := Reports{Root: absRoot, Version: *version, Created: *created, LedgerPath: *ledger, Evidence: evidence,
		ArtifactDir: *artifacts, PublicKeyPath: *pubkey, SignaturePath: *sig, ApprovalPath: *approval, AcceptedTasks: map[string]bool{}}
	for _, id := range accepted {
		r.AcceptedTasks[id] = true
	}
	if *handles != "" {
		raw, err := os.ReadFile(*handles)
		if err != nil {
			return err
		}
		var hr HandleReport
		if err = decodeStrict(raw, &hr); err != nil {
			return fmt.Errorf("handle report: %w", err)
		}
		r.Handles = &hr
	}
	m, gateErr := Release(context.Background(), *commit, r)
	if *asJSON {
		raw, err := marshalStable(m)
		if err != nil {
			return err
		}
		out.Write(raw)
	} else {
		for _, b := range m.Blocking {
			fmt.Fprintln(out, "BLOCKING", b)
		}
		fmt.Fprintf(out, "release gate: ready=%v blocking=%d\n", m.Ready, len(m.Blocking))
	}
	return gateErr
}
