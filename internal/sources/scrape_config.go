// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"sort"
	"time"

	"soundpost/internal/adapters/queryinput"
	"soundpost/internal/model"
)

// Scrape configuration failure reasons. They are static codes that serve may
// print: never a path, a URL, an alias or a secret.
const (
	ScrapeConfigUnreadable   = "config_unreadable"
	ScrapeConfigNotPrivate   = "config_not_private"
	ScrapeConfigInvalid      = "config_invalid"
	ScrapeConfigTargetFailed = "config_target_invalid"
	ScrapeConfigTLSRoots     = "config_tls_roots_invalid"
)

// ScrapeConfigError is the only error loading a scrape configuration returns.
type ScrapeConfigError struct{ Reason string }

func (e *ScrapeConfigError) Error() string { return "sources: scrape configuration: " + e.Reason }

func scrapeConfigFail(reason string) error { return &ScrapeConfigError{Reason: reason} }

const (
	scrapeConfigMaxBytes  = 1 << 20
	scrapeConfigMaxTarget = 256
	scrapeRootsMaxBytes   = 1 << 20
)

// ScrapeConfig is the closed JSON document behind `--scrape-config`. Unknown
// fields are refused at every level.
type ScrapeConfig struct {
	Version int                  `json:"version"`
	Targets []ScrapeConfigTarget `json:"targets"`
}

// ScrapeConfigTarget is one operator-approved target and the source it admits as.
type ScrapeConfigTarget struct {
	Alias    string               `json:"alias"`
	URL      string               `json:"url"`
	Interval scrapeConfigDuration `json:"interval"`
	Timeout  scrapeConfigDuration `json:"timeout"`
	MaxBytes int64                `json:"max_bytes"`
	TLS      ScrapeConfigTLS      `json:"tls"`
	Egress   ScrapeConfigEgress   `json:"egress"`
	// Auth is "", "bearer" or "basic"; Secret is the reference of the target's
	// own credential in the secrets directory (never the credential itself).
	Auth    string              `json:"auth"`
	Secret  string              `json:"secret"`
	Profile ScrapeConfigProfile `json:"profile"`
	Stale   ScrapeConfigStale   `json:"stale"`
	Source  ScrapeConfigSource  `json:"source"`
}

// ScrapeConfigTLS pins the trust roots of an https target.
type ScrapeConfigTLS struct {
	RootsFile  string `json:"roots_file"`
	ServerName string `json:"server_name"`
}

// ScrapeConfigEgress lifts the default block of exact private prefixes.
type ScrapeConfigEgress struct {
	AllowPrefixes []string `json:"allow_prefixes"`
}

// ScrapeConfigStale is the stale marker policy.
type ScrapeConfigStale struct {
	OnDisappear bool `json:"on_disappear"`
	OnFailure   bool `json:"on_failure"`
}

// ScrapeConfigProfile selects the closed normalization vocabulary of the
// decoder; an empty field takes the default named in docs/collection.
type ScrapeConfigProfile struct {
	Names       string `json:"names"`
	OutOfOrder  string `json:"out_of_order"`
	Histograms  string `json:"histograms"`
	Exemplars   string `json:"exemplars"`
	Help        string `json:"help"`
	DefaultUnit string `json:"default_unit"`
}

// ScrapeConfigSource names the installation source the target admits as. The
// target never carries an identity of its own: it uses a source credential the
// operator provisioned, stored under CredentialSecret in the secrets directory.
type ScrapeConfigSource struct {
	Project          string               `json:"project"`
	Source           string               `json:"source"`
	Producer         string               `json:"producer"`
	PolicyRevision   uint64               `json:"policy_revision"`
	CredentialSecret string               `json:"credential_secret"`
	Resource         ScrapeConfigResource `json:"resource"`
}

// ScrapeConfigResource is the resource identity every sample is attributed to.
type ScrapeConfigResource struct {
	Service     string            `json:"service"`
	Environment string            `json:"environment"`
	Build       string            `json:"build"`
	Instance    string            `json:"instance"`
	Labels      map[string]string `json:"labels"`
}

type scrapeConfigDuration time.Duration

func (d *scrapeConfigDuration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = scrapeConfigDuration(v)
	return nil
}

// ScrapeTargetSpec is a validated target together with the secret reference of
// the source credential its grant is resolved from.
type ScrapeTargetSpec struct {
	Target ScrapeTarget
	// Source is the project/source/policy revision the grant must cover.
	Project          model.ID
	Source           model.ID
	PolicyRevision   model.Revision
	CredentialSecret SecretRef
}

// LoadScrapeConfig reads and decodes the private configuration file. The file
// selects which hosts the node dials and which source credentials it uses, so
// it must be a regular file no other principal can write (the same rule as
// --symbolicate-config); unknown fields and trailing data are refused.
func LoadScrapeConfig(name string) (ScrapeConfig, error) {
	info, err := os.Stat(name)
	if err != nil || !info.Mode().IsRegular() {
		return ScrapeConfig{}, scrapeConfigFail(ScrapeConfigUnreadable)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		return ScrapeConfig{}, scrapeConfigFail(ScrapeConfigNotPrivate)
	}
	if info.Size() > scrapeConfigMaxBytes {
		return ScrapeConfig{}, scrapeConfigFail(ScrapeConfigInvalid)
	}
	raw, err := os.ReadFile(name)
	if err != nil {
		return ScrapeConfig{}, scrapeConfigFail(ScrapeConfigUnreadable)
	}
	return ParseScrapeConfig(raw)
}

// ParseScrapeConfig is the strict decoder of LoadScrapeConfig.
func ParseScrapeConfig(raw []byte) (ScrapeConfig, error) {
	var c ScrapeConfig
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&c) != nil {
		return ScrapeConfig{}, scrapeConfigFail(ScrapeConfigInvalid)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ScrapeConfig{}, scrapeConfigFail(ScrapeConfigInvalid)
	}
	if c.Version != 1 || len(c.Targets) == 0 || len(c.Targets) > scrapeConfigMaxTarget {
		return ScrapeConfig{}, scrapeConfigFail(ScrapeConfigInvalid)
	}
	return c, nil
}

// Specs validates every target (through ScrapeTarget's own validation) and
// binds each to the secret reader. A configuration with one bad target is
// refused as a whole: a node never starts with a silently dropped target.
func (c ScrapeConfig) Specs(secrets SecretReader) ([]ScrapeTargetSpec, error) {
	seen := map[string]bool{}
	out := make([]ScrapeTargetSpec, 0, len(c.Targets))
	for _, t := range c.Targets {
		spec, err := t.spec(secrets)
		if err != nil {
			return nil, err
		}
		if seen[spec.Target.Alias] {
			return nil, scrapeConfigFail(ScrapeConfigTargetFailed)
		}
		seen[spec.Target.Alias] = true
		out = append(out, spec)
	}
	return out, nil
}

func scrapeConfigID(s string) (model.ID, bool) {
	id, err := model.ParseID(s)
	return id, err == nil && id != (model.ID{})
}

func (t ScrapeConfigTarget) spec(secrets SecretReader) (ScrapeTargetSpec, error) {
	bad := scrapeConfigFail(ScrapeConfigTargetFailed)
	target := ScrapeTarget{
		Alias: t.Alias, URL: t.URL,
		Interval: time.Duration(t.Interval), Timeout: time.Duration(t.Timeout), MaxBytes: t.MaxBytes,
		Auth:   ScrapeAuth(t.Auth),
		Secret: SecretRef(t.Secret),
		Stale:  StalePolicy{OnDisappear: t.Stale.OnDisappear, OnFailure: t.Stale.OnFailure},
	}
	if target.Auth != ScrapeAuthNone {
		target.Secrets = secrets
		if !ValidSecretRef(target.Secret) {
			return ScrapeTargetSpec{}, bad
		}
	}
	if u, err := url.Parse(t.URL); err != nil || ((t.TLS.RootsFile != "" || t.TLS.ServerName != "") && u.Scheme != "https") {
		return ScrapeTargetSpec{}, bad
	}
	for _, p := range t.Egress.AllowPrefixes {
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			return ScrapeTargetSpec{}, bad
		}
		target.Egress.AllowPrefixes = append(target.Egress.AllowPrefixes, prefix)
	}
	target.TLS.ServerName = t.TLS.ServerName
	if t.TLS.RootsFile != "" {
		raw, err := readScrapeRoots(t.TLS.RootsFile)
		if err != nil {
			return ScrapeTargetSpec{}, scrapeConfigFail(ScrapeConfigTLSRoots)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return ScrapeTargetSpec{}, scrapeConfigFail(ScrapeConfigTLSRoots)
		}
		target.TLS.RootCAs = pool
	}

	s := t.Source
	project, ok1 := scrapeConfigID(s.Project)
	source, ok2 := scrapeConfigID(s.Source)
	producer, ok3 := scrapeConfigID(s.Producer)
	service, ok4 := scrapeConfigID(s.Resource.Service)
	environment, ok5 := scrapeConfigID(s.Resource.Environment)
	build, ok6 := scrapeConfigID(s.Resource.Build)
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6) || s.PolicyRevision == 0 || s.Resource.Instance == "" || !ValidSecretRef(SecretRef(s.CredentialSecret)) {
		return ScrapeTargetSpec{}, bad
	}
	labels := make(model.Labels, 0, len(s.Resource.Labels))
	for k, v := range s.Resource.Labels {
		labels = append(labels, model.Label{Name: k, Value: v})
	}
	sort.Slice(labels, func(i, j int) bool { return labels[i].Name < labels[j].Name })

	profile := queryinput.InputProfile{
		Project: project, Source: source, Producer: producer, PolicyRevision: model.Revision(s.PolicyRevision),
		Resource: model.Resource{Service: service, Environment: environment, Build: build, Instance: s.Resource.Instance, Labels: labels},
		Limits:   queryinput.DefaultLimits(), DefaultUnit: t.Profile.DefaultUnit,
	}
	var okNames, okOrder, okHist, okEx, okHelp bool
	if profile.Names, okNames = pick(t.Profile.Names, queryinput.NamesStrict, queryinput.NamesStrict, queryinput.NamesUTF8); !okNames {
		return ScrapeTargetSpec{}, bad
	}
	if profile.OutOfOrder, okOrder = pick(t.Profile.OutOfOrder, queryinput.OutOfOrderSort, queryinput.OutOfOrderSort, queryinput.OutOfOrderReject); !okOrder {
		return ScrapeTargetSpec{}, bad
	}
	if profile.Histograms, okHist = pick(t.Profile.Histograms, queryinput.HistogramsPreserve, queryinput.HistogramsPreserve, queryinput.HistogramsReject); !okHist {
		return ScrapeTargetSpec{}, bad
	}
	if profile.Exemplars, okEx = pick(t.Profile.Exemplars, queryinput.ExemplarsReject, queryinput.ExemplarsReject, queryinput.ExemplarsTraceLink); !okEx {
		return ScrapeTargetSpec{}, bad
	}
	if profile.Help, okHelp = pick(t.Profile.Help, queryinput.HelpReject, queryinput.HelpReject, queryinput.HelpDiscard); !okHelp {
		return ScrapeTargetSpec{}, bad
	}
	target.Profile = profile
	if _, err := target.validate(); err != nil {
		return ScrapeTargetSpec{}, bad
	}
	return ScrapeTargetSpec{Target: target, Project: project, Source: source, PolicyRevision: profile.PolicyRevision, CredentialSecret: SecretRef(s.CredentialSecret)}, nil
}

// pick maps a configured word to one of the closed vocabulary values.
func pick[T ~string](got string, def T, allowed ...T) (T, bool) {
	if got == "" {
		return def, true
	}
	for _, a := range allowed {
		if string(a) == got {
			return a, true
		}
	}
	return def, false
}

func readScrapeRoots(name string) ([]byte, error) {
	info, err := os.Stat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > scrapeRootsMaxBytes {
		return nil, errors.New("sources: scrape tls roots")
	}
	return os.ReadFile(name)
}
