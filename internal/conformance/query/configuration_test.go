// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const configurationCasesPath = "cases/release-configuration.json"

type recordedConfiguration struct {
	Oracles      map[string]OracleIdentity `json:"oracles"`
	Observations []struct {
		Profile   string                   `json:"profile"`
		Case      string                   `json:"case"`
		Scenario  string                   `json:"scenario"`
		InputHash string                   `json:"input_sha256"`
		Reference ConfigurationObservation `json:"reference"`
	} `json:"observations"`
}

func configurationInputDigest(profile string, s ConfigurationScenario) string {
	sum := sha256.Sum256([]byte(profile + "\x00" + strings.Join(s.Features, ",") + "\x00" + s.Config))
	return hex.EncodeToString(sum[:])
}

func loadConfigurationCorpus(t testing.TB) ([]ConfigurationCase, recordedConfiguration) {
	t.Helper()
	cases, err := readConfigurationCases(loadRealLock(t), []string{queryRoot(configurationCasesPath)})
	if err != nil {
		t.Fatal(err)
	}
	var rec recordedConfiguration
	raw, err := os.ReadFile(filepath.Join("testdata", "native-configuration-observations.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	return cases, rec
}

// replayConfiguration compares the owned resolver with the recorded reference
// observation of every scenario of the named obligation whose authored
// acceptance is accepted, and with the authored expectation. It returns how many
// scenarios it covered per profile so a vacuous replay fails.
func replayConfiguration(t *testing.T, obligation string, accepted bool) {
	t.Helper()
	cases, rec := loadConfigurationCorpus(t)
	recorded := map[string]ConfigurationObservation{}
	for _, o := range rec.Observations {
		recorded[o.Profile+"\x00"+o.Case+"\x00"+o.Scenario] = o.Reference
	}
	covered := map[string]int{}
	for _, c := range cases {
		if !strings.HasSuffix(c.Obligation, "/configuration/"+obligation) {
			continue
		}
		for _, p := range c.Profiles {
			for _, s := range c.Scenarios {
				if s.Accepted != accepted {
					continue
				}
				reference, ok := recorded[p+"\x00"+c.ID+"\x00"+s.Name]
				if !ok {
					t.Errorf("%s/%s/%s: no recorded reference observation", p, c.ID, s.Name)
					continue
				}
				for _, problem := range compareConfiguration(s, reference, observeOwnedConfiguration(p, s)) {
					t.Errorf("%s/%s/%s: %s", p, c.ID, s.Name, problem)
				}
				covered[p]++
			}
		}
	}
	if covered["promql-prometheus-3.1.0"] < 10 || covered["promql-prometheus-3.13.5"] < 10 {
		t.Fatalf("a vacuous configuration replay: %v scenarios covered for %s accepted=%t", covered, obligation, accepted)
	}
}

// The protocol list must be nonempty, known, duplicate-free ignoring case, and
// inherits from the global list or from the release's defaults; native histogram
// and start-timestamp features move the default preference.
func TestReleaseConfigurationProtocolsResolution(t *testing.T) {
	replayConfiguration(t, "protocols", true)
}

func TestReleaseConfigurationProtocolsRefusesWhatThePinnedReleaseRefuses(t *testing.T) {
	replayConfiguration(t, "protocols", false)
}

// Interval, timeout and acquisition-limit inheritance, honor_* defaults and
// duration/size grammar, including the cases where a zero means inherit.
func TestReleaseConfigurationScrapeInheritanceResolution(t *testing.T) {
	replayConfiguration(t, "scrape-inheritance", true)
}

func TestReleaseConfigurationScrapeInheritanceRefusesWhatThePinnedReleaseRefuses(t *testing.T) {
	replayConfiguration(t, "scrape-inheritance", false)
}

// A recording is evidence only for the exact input it was observed on, from the
// oracle the lock names; every authored scenario has exactly one.
func TestReleaseConfigurationRecordedObservationsAreBoundToTheirInputs(t *testing.T) {
	cases, rec := loadConfigurationCorpus(t)
	lock := loadRealLock(t)
	for _, p := range lock.Profiles {
		if p.ConfigurationOracle == nil {
			continue
		}
		id, ok := rec.Oracles[p.ID]
		if !ok || id.Revision != p.Commit || id.ImageSHA256 != strings.TrimPrefix(p.ConfigurationOracle.ImageID, "sha256:") || id.ConfigurationSHA256 != p.ConfigurationOracle.ConfigurationFileSHA256 {
			t.Errorf("%s: the recording does not come from the locked configuration oracle: %+v", p.ID, id)
		}
	}
	seen := map[string]bool{}
	byKey := map[string]string{}
	for _, o := range rec.Observations {
		key := o.Profile + "\x00" + o.Case + "\x00" + o.Scenario
		if seen[key] {
			t.Errorf("duplicate recording %s", key)
		}
		seen[key] = true
		byKey[key] = o.InputHash
	}
	total := 0
	for _, c := range cases {
		for _, p := range c.Profiles {
			for _, s := range c.Scenarios {
				total++
				if got := byKey[p+"\x00"+c.ID+"\x00"+s.Name]; got != configurationInputDigest(p, s) {
					t.Errorf("%s/%s/%s: recording is missing or was observed on a different input", p, c.ID, s.Name)
				}
			}
		}
	}
	if total != len(rec.Observations) || total < 150 {
		t.Fatalf("recorded %d observations for %d authored scenarios", len(rec.Observations), total)
	}
}

// Reference texts are classified, never compared as prose, and an unknown text
// is an error rather than a family.
func TestClassifyReferenceConfigurationError(t *testing.T) {
	for text, want := range map[string]string{
		`parsing YAML file /fixture/x.yml: global scrape timeout greater than scrape interval`:                                                                 "timeout_exceeds_interval@global",
		`parsing YAML file /fixture/x.yml: scrape timeout greater than scrape interval for scrape config with job name "a"`:                                    "timeout_exceeds_interval@job:a",
		`parsing YAML file /fixture/x.yml: scrape_protocols cannot be empty for global config`:                                                                 "protocols_empty@global",
		`parsing YAML file /fixture/x.yml: scrape_protocols cannot be empty for scrape config with job name "b"`:                                               "protocols_empty@job:b",
		`parsing YAML file /fixture/x.yml: duplicated protocol in scrape_protocols, got [PrometheusProto prometheusproto] for scrape config with job name "a"`: "protocols_duplicate@job:a",
		`parsing YAML file /fixture/x.yml: scrape_protocols: unknown scrape protocol Foo, supported: [OpenMetricsText0.0.1] for global config`:                 "protocols_unknown@global",
		`parsing YAML file /fixture/x.yml: invalid fallback_scrape_protocol for scrape config with job name "a": unknown scrape protocol Nope, supported: [X]`: "fallback_protocol_unknown@job:a",
		`parsing YAML file /fixture/x.yml: not a valid duration string: "abc"`:                                                                                 "invalid_duration@document",
		`parsing YAML file /fixture/x.yml: unknown unit "." in duration "1.5s"`:                                                                                "invalid_duration@document",
		`parsing YAML file /fixture/x.yml: units: unknown unit  in 1000`:                                                                                       "invalid_size@document",
		"parsing YAML file /fixture/x.yml: yaml: unmarshal errors:\n  line 3: cannot unmarshal !!int `-1` into uint":                                           "invalid_value@document",
		"parsing YAML file /fixture/x.yml: yaml: unmarshal errors:\n  line 2: field scrape_native_histograms not found in type config.plain":                   "unknown_field@document",
		`parsing YAML file /fixture/x.yml: unrecognized ValidationScheme: "nope"`:                                                                              "validation_scheme_unknown@document",
		`parsing YAML file /fixture/x.yml: utf8 metric names requested but validation scheme is not set to UTF8`:                                               "escaping_requires_utf8@scrape",
		`parsing YAML file /fixture/x.yml: unknown global name escaping method specified, must be one of 'a', got "nope"`:                                      "escaping_scheme_unknown@global",
	} {
		got, err := classifyReferenceConfigurationError(text)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", text, got, err, want)
		}
	}
	for _, text := range []string{"opening storage failed: no space", "parsing YAML file /f.yml: something new", "yaml: unmarshal errors:\n  line 1: mystery"} {
		if got, err := classifyReferenceConfigurationError(text); err == nil {
			t.Errorf("unknown reference text %q classified as %q", text, got)
		}
	}
}

// The lock must name a variant that is the evaluation oracle plus one file, and
// every file the lock hashes must be the file the build and the harness use.
func TestConfigurationOracleLockIsVerifiable(t *testing.T) {
	lock := loadRealLock(t)
	found := 0
	for _, p := range lock.Profiles {
		if !strings.HasPrefix(p.ID, "promql-") {
			if p.ConfigurationOracle != nil {
				t.Errorf("%s: only the Prometheus profiles have a configuration oracle", p.ID)
			}
			continue
		}
		found++
		if _, err := verifyConfigurationOracle(queryRoot(), p); err != nil {
			t.Errorf("%v", err)
		}
		bad := p
		co := *p.ConfigurationOracle
		bad.ConfigurationOracle = &co
		co.BaseImageID = "sha256:" + strings.Repeat("0", 64)
		if _, err := verifyConfigurationOracle(queryRoot(), bad); err == nil {
			t.Errorf("%s: a variant built from some other image was accepted", p.ID)
		}
		co = *p.ConfigurationOracle
		co.ImageID = co.BaseImageID
		if _, err := verifyConfigurationOracle(queryRoot(), bad); err == nil {
			t.Errorf("%s: the evaluation oracle itself was accepted as its variant", p.ID)
		}
		co = *p.ConfigurationOracle
		co.ObserverScriptSHA256 = strings.Repeat("0", 64)
		if _, err := verifyConfigurationOracle(queryRoot(), bad); err == nil {
			t.Errorf("%s: a changed observation script was accepted", p.ID)
		}
		co = *p.ConfigurationOracle
		co.DockerfileSHA256 = strings.Repeat("0", 64)
		if _, err := verifyConfigurationOracle(queryRoot(), bad); err == nil {
			t.Errorf("%s: a changed Dockerfile was accepted", p.ID)
		}
	}
	if found != 2 {
		t.Fatalf("expected both Prometheus profiles, found %d", found)
	}
}

func TestConfigurationDockerfileMayOnlyAddTheConfigurationFile(t *testing.T) {
	co := &ConfigurationOracle{ConfigurationFile: "oracles/x-configuration.yaml", InstalledAt: "/etc/prometheus/soundpost-configuration-phase.yaml"}
	base := "sha256:" + strings.Repeat("a", 64)
	good := "# c\nFROM local-image@" + base + "\nCOPY --chmod=0444 x-configuration.yaml /etc/prometheus/soundpost-configuration-phase.yaml\n"
	if err := checkConfigurationDockerfile(good, base, co); err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{
		"extra RUN":         good + "RUN echo changed\n",
		"entrypoint change": good + "ENTRYPOINT [\"/bin/sh\"]\n",
		"other base":        strings.Replace(good, base, "sha256:"+strings.Repeat("b", 64), 1),
		"tag not digest":    strings.Replace(good, "@"+base, ":latest", 1),
		"other target":      strings.Replace(good, "/soundpost-configuration-phase.yaml", "/prometheus", 1),
		"no copy":           "FROM local-image@" + base + "\n",
	} {
		if err := checkConfigurationDockerfile(text, base, co); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A configuration-phase observation is identified by the locked variant, any
// other row by the locked evaluation oracle; neither may stand in for the other.
func TestOracleIdentityFollowsThePhaseOfTheRow(t *testing.T) {
	var p SourceProfile
	for _, c := range loadRealLock(t).Profiles {
		if c.ID == "promql-prometheus-3.13.5" {
			p = c
		}
	}
	co := p.ConfigurationOracle
	version := "3.13.5"
	variant := &OracleIdentity{Profile: p.ID, Revision: p.Commit, Version: version, ImageSHA256: strings.TrimPrefix(co.ImageID, "sha256:"), ConfigurationSHA256: co.ConfigurationFileSHA256}
	base := &OracleIdentity{Profile: p.ID, Revision: p.Commit, Version: version, ImageSHA256: p.Artifact.SHA256, ConfigurationSHA256: p.Artifact.ConfigurationSHA256}
	for _, tc := range []struct {
		name string
		typ  string
		id   *OracleIdentity
		want bool
	}{
		{"variant on a configuration row", ConfigurationPhaseType, variant, true},
		{"evaluation oracle on a configuration row", ConfigurationPhaseType, base, false},
		{"variant on an evaluation row", "promql:evaluation", variant, false},
		{"evaluation oracle on an evaluation row", "promql:evaluation", base, true},
	} {
		if got := oracleIdentityOK(p, SemanticResult{Kind: "phase-case", Type: tc.typ, Oracle: tc.id}); got != tc.want {
			t.Errorf("%s: got %t, want %t", tc.name, got, tc.want)
		}
	}
	noVariant := p
	noVariant.ConfigurationOracle = nil
	if oracleIdentityOK(noVariant, SemanticResult{Kind: "phase-case", Type: ConfigurationPhaseType, Oracle: variant}) {
		t.Error("a configuration row was accepted without a locked variant")
	}
}

// The runner trusts a run only if every scenario produced either an effective
// configuration or a logged error, and the script reached its end.
func TestParseConfigurationObservationsNeverReportsAnEmptySuccess(t *testing.T) {
	fixtures := []observerFixture{{Name: "s1"}}
	head := "@@control-sha256 abc\n@@version v\n@@revision r\n"
	control := "@@begin control\n@@ready\n@@status\n{\"status\":\"success\"}\n@@end control\n"
	ready := "@@begin s1\n@@ready\n@@status\n{\"status\":\"success\"}\n@@end s1\n"
	refused := "@@begin s1\n@@exited\n{\"level\":\"ERROR\",\"err\":\"boom\"}\n@@end s1\n"
	got, err := parseConfigurationObservations(head+control+ready+"@@done\n", fixtures)
	if err != nil || !got.Scenarios["s1"].Ready || got.Scenarios["s1"].Status == "" {
		t.Fatalf("ready scenario: %+v, %v", got.Scenarios["s1"], err)
	}
	if got, err = parseConfigurationObservations(head+control+refused+"@@done\n", fixtures); err != nil || got.Scenarios["s1"].Err != "boom" {
		t.Fatalf("refused scenario: %+v, %v", got.Scenarios["s1"], err)
	}
	for name, text := range map[string]string{
		"no done marker":        head + control + ready,
		"missing scenario":      head + control + "@@done\n",
		"missing control":       head + ready + "@@done\n",
		"ready without status":  head + control + "@@begin s1\n@@ready\n@@end s1\n@@done\n",
		"neither ready nor err": head + control + "@@begin s1\n@@exited\n@@end s1\n@@done\n",
		"scenario seen twice":   head + control + ready + ready + "@@done\n",
	} {
		if _, err := parseConfigurationObservations(text, fixtures); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The release manifest runs the configuration file through the phase and yields
// one row per ledger case of both profiles.
func TestReleaseManifestCarriesTheConfigurationRows(t *testing.T) {
	m, err := LoadReleaseCaseManifest(queryRoot("release-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	listed := false
	for _, f := range m.Files {
		listed = listed || (f.Path == configurationCasesPath && f.Language == "promql" && f.Phase == "configuration")
	}
	if !listed {
		t.Fatal("release-cases.json does not run the configuration case file")
	}
	rows, err := ReleaseCasesFromManifest(loadRealLock(t), queryRoot(), ReleaseCaseManifest{Schema: m.Schema, Files: []ReleasePhaseFile{{Path: configurationCasesPath, Language: "promql", Phase: "configuration"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 12 {
		t.Fatalf("expected the 12 ledger case rows (2 profiles x 2 obligations x 3 roles), got %d", len(rows))
	}
	for _, r := range rows {
		if r.Expected.Type != ConfigurationPhaseType || !strings.HasPrefix(r.ID, r.Profile+"/configuration/") {
			t.Errorf("unexpected row %s/%s type %s", r.Profile, r.ID, r.Expected.Type)
		}
	}
}
