// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type ReadOnlyTargets struct{ Targets []Target }
type Target struct {
	ID, Repository, ExpectedRef, EvidenceURL string
	SecretReferences                         []string
}
type TargetScope struct {
	ID, Repository, EvidenceURL string
	Collectors                  []string
}
type Authorization struct {
	GrantID, Authority    string
	ReadOnly              bool
	NotBefore, ExpiresAt  time.Time
	MaxEvidenceAgeSeconds int64
	Scopes                []TargetScope
}
type SourceEvidence struct {
	Version  string
	Coverage []string
	Ordering string
}
type RuntimeEvidence struct{ Name, Version string }
type BuildEvidence struct{ Release, Ref string }
type ProtocolEvidence struct{ Name, Version string }
type PolicyEvidence struct{ Registration, Template string }
type OwnerEvidence struct{ Owner, Mode string }
type RetentionEvidence struct {
	Until           time.Time
	ExportReference string
	LegacyReadOnly  bool
}
type RollbackEvidence struct{ Owner, ProcedureReference string }
type DeadmanEvidence struct{ Owner, FailureDomain, ProductFailureDomain, ProofReference string }
type LiveEvidence struct {
	ObservedAt        time.Time
	ReportedAt        time.Time // Producer clock sampled while preparing this response.
	CurrentRef        string
	Source            SourceEvidence
	Runtime           RuntimeEvidence
	Build             BuildEvidence
	Protocol          ProtocolEvidence
	Policy            PolicyEvidence
	NotificationOwner OwnerEvidence
	Retention         RetentionEvidence
	Rollback          RollbackEvidence
	Deadman           DeadmanEvidence
}
type CollectedTarget struct {
	ID, Repository, ExpectedRef, ObservedRef, EvidenceURL string
	Evidence                                              LiveEvidence
	SecretReferences, Discrepancies                       []string
	CollectorStartedAt, CollectorReceivedAt               time.Time
	ProducerClockDeltaNano                                int64 // Receipt minus producer ReportedAt; includes transport latency.
	CurrentEvidenceComplete                               bool
}
type PrivateIntake struct {
	CollectedAt           time.Time
	GrantID               string
	MaxEvidenceAgeSeconds int64
	Targets               []CollectedTarget
}

func nonempty(values ...string) bool {
	for _, v := range values {
		if strings.TrimSpace(v) == "" {
			return false
		}
	}
	return true
}
func canonical(path string) (string, error) {
	p, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(p)
}
func samePath(a, b string) bool {
	if os.PathSeparator == '\\' {
		return strings.EqualFold(a, b)
	}
	return a == b
}
func validateEvidence(e LiveEvidence, now time.Time, age int64) error {
	if age <= 0 || age > 86400 || e.ObservedAt.IsZero() || e.ObservedAt.After(now) || now.Sub(e.ObservedAt) > time.Duration(age)*time.Second {
		return errors.New("missing or stale observation")
	}
	if !nonempty(e.CurrentRef, e.Source.Version, e.Source.Ordering, e.Runtime.Name, e.Runtime.Version, e.Build.Release, e.Build.Ref, e.Protocol.Name, e.Protocol.Version, e.Policy.Registration, e.Policy.Template, e.NotificationOwner.Owner, e.NotificationOwner.Mode, e.Retention.ExportReference, e.Rollback.Owner, e.Rollback.ProcedureReference, e.Deadman.Owner, e.Deadman.FailureDomain, e.Deadman.ProductFailureDomain, e.Deadman.ProofReference) || len(e.Source.Coverage) == 0 {
		return errors.New("incomplete current evidence")
	}
	for _, v := range e.Source.Coverage {
		if !nonempty(v) {
			return errors.New("incomplete coverage")
		}
	}
	if !e.Retention.LegacyReadOnly || !e.Retention.Until.After(now) || e.Deadman.FailureDomain == e.Deadman.ProductFailureDomain {
		return errors.New("missing retention or independent deadman evidence")
	}
	return nil
}
func decodeStrict(r io.Reader, v any) error {
	d := json.NewDecoder(io.LimitReader(r, 1048577))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("trailing or oversized JSON")
	}
	return nil
}
func CollectIntake(ctx context.Context, targets ReadOnlyTargets, grant Authorization) (PrivateIntake, error) {
	now := time.Now().UTC()
	fail := func() (PrivateIntake, error) {
		return PrivateIntake{}, errors.New("authorization or target validation failed")
	}
	if !grant.ReadOnly || !nonempty(grant.GrantID, grant.Authority) || grant.NotBefore.IsZero() || now.Before(grant.NotBefore) || !now.Before(grant.ExpiresAt) || grant.MaxEvidenceAgeSeconds <= 0 || grant.MaxEvidenceAgeSeconds > 86400 || len(targets.Targets) == 0 {
		return fail()
	}
	type approved struct {
		target     Target
		repository string
	}
	items := []approved{}
	seen := map[string]bool{}
	for _, t := range targets.Targets {
		if !nonempty(t.ID, t.Repository, t.ExpectedRef, t.EvidenceURL) || seen[t.ID] {
			return fail()
		}
		seen[t.ID] = true
		repo, err := canonical(t.Repository)
		if err != nil {
			return fail()
		}
		u, err := url.Parse(t.EvidenceURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fail()
		}
		for _, ref := range t.SecretReferences {
			if !strings.HasPrefix(ref, "external:") || len(ref) <= 9 {
				return fail()
			}
		}
		matches := 0
		for _, s := range grant.Scopes {
			if s.ID != t.ID {
				continue
			}
			sr, err := canonical(s.Repository)
			if err != nil || !samePath(sr, repo) || s.EvidenceURL != t.EvidenceURL {
				return fail()
			}
			collectors := map[string]bool{}
			for _, c := range s.Collectors {
				if c != "git-current-ref" && c != "http-live-evidence" {
					return fail()
				}
				collectors[c] = true
			}
			if !collectors["git-current-ref"] || !collectors["http-live-evidence"] {
				return fail()
			}
			matches++
		}
		if matches != 1 {
			return fail()
		}
		items = append(items, approved{t, repo})
	}
	result := PrivateIntake{CollectedAt: now, GrantID: grant.GrantID, MaxEvidenceAgeSeconds: grant.MaxEvidenceAgeSeconds}
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect forbidden") }, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	defer client.CloseIdleConnections()
	for _, item := range items {
		started := time.Now().UTC()
		if !time.Now().Before(grant.ExpiresAt) {
			return fail()
		}
		cmd := exec.CommandContext(ctx, "git", "--no-optional-locks", "-C", item.repository, "rev-parse", "--verify", "HEAD")
		cmd.Env = []string{}
		for _, kv := range os.Environ() {
			if !strings.HasPrefix(strings.ToUpper(kv), "GIT_") {
				cmd.Env = append(cmd.Env, kv)
			}
		}
		b, err := cmd.Output()
		if err != nil {
			return PrivateIntake{}, errors.New("current ref collector failed")
		}
		ref := strings.TrimSpace(string(b))
		if len(ref) != 40 && len(ref) != 64 {
			return PrivateIntake{}, errors.New("invalid current ref")
		}
		if _, err := hex.DecodeString(ref); err != nil {
			return PrivateIntake{}, errors.New("invalid current ref")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, item.target.EvidenceURL, nil)
		if err != nil {
			return fail()
		}
		resp, err := client.Do(req)
		if err != nil {
			return PrivateIntake{}, errors.New("live evidence collector failed")
		}
		var evidence LiveEvidence
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return PrivateIntake{}, errors.New("live evidence status failed")
		}
		err = decodeStrict(resp.Body, &evidence)
		resp.Body.Close()
		if err != nil {
			return PrivateIntake{}, errors.New("invalid live evidence")
		}
		received := time.Now().UTC()
		entry := CollectedTarget{ID: item.target.ID, Repository: item.repository, ExpectedRef: item.target.ExpectedRef, ObservedRef: ref, EvidenceURL: item.target.EvidenceURL, Evidence: evidence, SecretReferences: item.target.SecretReferences, CollectorStartedAt: started, CollectorReceivedAt: received, ProducerClockDeltaNano: received.Sub(evidence.ReportedAt).Nanoseconds()}
		if err = validateObservation(entry, received, grant.MaxEvidenceAgeSeconds); err != nil {
			entry.Discrepancies = append(entry.Discrepancies, "producer-clock-or-freshness-incomplete")
			result.Targets = append(result.Targets, entry)
			return result, err
		}
		entry.CurrentEvidenceComplete = true
		if ref != entry.ExpectedRef {
			entry.Discrepancies = append(entry.Discrepancies, "checkout-ref-differs-from-expected")
		}
		if ref != evidence.CurrentRef {
			entry.Discrepancies = append(entry.Discrepancies, "live-ref-differs-from-checkout")
		}
		if evidence.Build.Ref != evidence.CurrentRef {
			entry.Discrepancies = append(entry.Discrepancies, "build-ref-differs-from-live")
		}
		result.Targets = append(result.Targets, entry)
	}
	if !time.Now().Before(grant.ExpiresAt) {
		return fail()
	}
	return result, nil
}

// Clock claims remain unattested. Bound both collector age and producer-reported age;
// never translate a future producer claim into apparently current evidence.
func validateObservation(t CollectedTarget, now time.Time, age int64) error {
	e := t.Evidence
	if t.CollectorStartedAt.IsZero() || t.CollectorReceivedAt.Before(t.CollectorStartedAt) || t.CollectorReceivedAt.After(now) || now.Sub(t.CollectorStartedAt) > time.Duration(age)*time.Second || e.ReportedAt.IsZero() || e.ObservedAt.After(e.ReportedAt) {
		return errors.New("incomplete collector observation window")
	}
	delta := t.CollectorReceivedAt.Sub(e.ReportedAt)
	if t.ProducerClockDeltaNano != delta.Nanoseconds() || e.ReportedAt.After(t.CollectorReceivedAt) || delta > 5*time.Second || e.ReportedAt.Sub(e.ObservedAt) > time.Duration(age)*time.Second {
		return errors.New("producer clock or freshness discrepancy")
	}
	return validateEvidence(e, now, age)
}
