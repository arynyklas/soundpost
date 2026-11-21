// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ConfigurationOracle is the lock record of the configuration-phase variant of
// one pinned Prometheus oracle image (decision D29): the digest-pinned image the
// evaluation oracle already uses, plus exactly one added file. The harness runs
// the upstream binary of that image through an entrypoint override and a fixed
// observation script; the variant adds no code.
type ConfigurationOracle struct {
	Image                   string `json:"image"`
	ImageID                 string `json:"image_id"`
	BaseImageID             string `json:"base_image_id"`
	Architecture            string `json:"architecture"`
	BaseLayers              int    `json:"base_layers"`
	AddedLayerDiffID        string `json:"added_layer_diff_id"`
	Dockerfile              string `json:"dockerfile"`
	DockerfileSHA256        string `json:"dockerfile_sha256"`
	ConfigurationFile       string `json:"configuration_file"`
	ConfigurationFileSHA256 string `json:"configuration_file_sha256"`
	InstalledAt             string `json:"installed_at"`
	ObserverScript          string `json:"observer_script"`
	ObserverScriptSHA256    string `json:"observer_script_sha256"`

	// ContentIdentity is the proof an image rebuilt from the pinned inputs must pass when the daemon lacks ImageID.
	ContentIdentity *ContentIdentity `json:"content_identity,omitempty"`
}

//go:embed configuration_observe.sh
var configurationObserveScript []byte

// ConfigurationPhaseType is the Type of a configuration-phase release row.
const ConfigurationPhaseType = "promql:configuration"

func sha256Bytes(b []byte) string { return sha256Hex(string(b)) }

// verifyConfigurationOracle checks the lock record against the files it names
// and against the evaluation oracle it was built from.
func verifyConfigurationOracle(queryDir string, p SourceProfile) (*ConfigurationOracle, error) {
	co := p.ConfigurationOracle
	if co == nil || p.Artifact == nil {
		return nil, fmt.Errorf("%s: no configuration-phase oracle in the source lock", p.ID)
	}
	if !strings.HasPrefix(co.ImageID, "sha256:") || !hex64.MatchString(strings.TrimPrefix(co.ImageID, "sha256:")) || co.Architecture != "linux/amd64" {
		return nil, fmt.Errorf("%s: configuration oracle image id must be a sha256 image digest for linux/amd64", p.ID)
	}
	if co.BaseImageID != p.Artifact.Path || co.ImageID == co.BaseImageID {
		return nil, fmt.Errorf("%s: configuration oracle must be a distinct image built from the locked evaluation oracle %s", p.ID, p.Artifact.Path)
	}
	for _, f := range []struct{ path, want, what string }{
		{co.Dockerfile, co.DockerfileSHA256, "Dockerfile"},
		{co.ConfigurationFile, co.ConfigurationFileSHA256, "configuration file"},
	} {
		raw, err := os.ReadFile(filepath.Join(queryDir, filepath.FromSlash(f.path)))
		if err != nil {
			return nil, err
		}
		if sha256Bytes(raw) != f.want {
			return nil, fmt.Errorf("%s: configuration oracle %s %s changed; rebuild and relock", p.ID, f.what, f.path)
		}
		if f.what == "Dockerfile" {
			if err = checkConfigurationDockerfile(string(raw), p.Artifact.Path, co); err != nil {
				return nil, fmt.Errorf("%s: %w", p.ID, err)
			}
		}
	}
	if sha256Bytes(configurationObserveScript) != co.ObserverScriptSHA256 {
		return nil, fmt.Errorf("%s: observation script changed; relock the configuration oracle", p.ID)
	}
	return co, nil
}

// checkConfigurationDockerfile enforces "FROM the locked digest, add only a
// configuration file": exactly one FROM naming the base image id and exactly one
// COPY, nothing else.
func checkConfigurationDockerfile(text, baseID string, co *ConfigurationOracle) error {
	var instructions []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		instructions = append(instructions, line)
	}
	if len(instructions) != 2 || !strings.HasPrefix(instructions[0], "FROM ") || !strings.HasSuffix(instructions[0], "@"+baseID) {
		return fmt.Errorf("Dockerfile must be FROM <image>@%s followed by one COPY", baseID)
	}
	if !strings.HasPrefix(instructions[1], "COPY ") || !strings.HasSuffix(instructions[1], " "+co.InstalledAt) || !strings.Contains(instructions[1], filepath.Base(co.ConfigurationFile)) {
		return fmt.Errorf("Dockerfile must add only %s at %s", co.ConfigurationFile, co.InstalledAt)
	}
	return nil
}

type observedScenario struct {
	Ready  bool
	Status string
	Err    string
}

type configurationObservations struct {
	ControlSHA256 string
	Version       string
	Revision      string
	Scenarios     map[string]observedScenario
}

type observerFixture struct {
	Name     string
	Features []string
	Config   string
}

// runConfigurationObserver starts the variant image with the observation script
// as its entrypoint and parses what the script printed.
func runConfigurationObserver(ctx context.Context, runtime, imageID string, fixtures []observerFixture) (configurationObservations, error) {
	var out configurationObservations
	if !filepath.IsAbs(runtime) {
		return out, fmt.Errorf("absolute OCI runtime path required")
	}
	dir, err := os.MkdirTemp("", "soundpost-query-configuration-")
	if err != nil {
		return out, err
	}
	defer os.RemoveAll(dir)
	if err = os.Chmod(dir, 0755); err != nil {
		return out, err
	}
	var index strings.Builder
	write := func(name string, data []byte) error { return os.WriteFile(filepath.Join(dir, name), data, 0444) }
	if err = write("observe.sh", configurationObserveScript); err != nil {
		return out, err
	}
	for _, f := range fixtures {
		for _, feature := range f.Features {
			if !configurationFeature.MatchString(feature) {
				return out, fmt.Errorf("invalid feature %q", feature)
			}
		}
		flags := ""
		if len(f.Features) > 0 {
			flags = "--enable-feature=" + strings.Join(f.Features, ",")
		}
		if err = write(f.Name+".yml", []byte(f.Config)); err != nil {
			return out, err
		}
		if err = write(f.Name+".flags", []byte(flags+"\n")); err != nil {
			return out, err
		}
		index.WriteString(f.Name + "\n")
	}
	if err = write("index", []byte(index.String())); err != nil {
		return out, err
	}
	cidfile := filepath.Join(dir, "container-id")
	args := []string{"run", "--rm", "--cidfile=" + cidfile, "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=128", "--memory=512m", "--cpus=1", "--user=65534:65534", "--tmpfs=/tmp:rw,noexec,nosuid,size=268435456", "--mount=type=bind,src=" + dir + ",dst=/fixture,readonly", "--entrypoint=/bin/sh", imageID, "/fixture/observe.sh"}
	cmd := exec.CommandContext(ctx, runtime, args...)
	cmd.Env = []string{}
	defer func() {
		id, e := os.ReadFile(cidfile)
		if e != nil {
			return
		}
		value := strings.TrimSpace(string(id))
		if len(value) != 64 {
			return
		}
		if _, e = hex.DecodeString(value); e != nil {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cleanup := exec.CommandContext(cleanupCtx, runtime, "rm", "--force", value)
		cleanup.Env = []string{}
		_ = cleanup.Run()
	}()
	var stdout, stderr boundedBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err = cmd.Run(); err != nil {
		return out, fmt.Errorf("configuration oracle failed: %w; diagnostic: %s", err, stderr.data)
	}
	return parseConfigurationObservations(string(stdout.data), fixtures)
}

func parseConfigurationObservations(text string, fixtures []observerFixture) (configurationObservations, error) {
	out := configurationObservations{Scenarios: map[string]observedScenario{}}
	var current string
	var section string
	done := false
	for _, line := range strings.Split(text, "\n") {
		switch {
		case strings.HasPrefix(line, "@@control-sha256 "):
			out.ControlSHA256 = strings.TrimSpace(strings.TrimPrefix(line, "@@control-sha256 "))
		case strings.HasPrefix(line, "@@version "):
			out.Version = strings.TrimPrefix(line, "@@version ")
		case strings.HasPrefix(line, "@@revision "):
			out.Revision = strings.TrimSpace(strings.TrimPrefix(line, "@@revision "))
		case strings.HasPrefix(line, "@@begin "):
			current, section = strings.TrimPrefix(line, "@@begin "), ""
			if _, dup := out.Scenarios[current]; dup {
				return out, fmt.Errorf("configuration oracle observed %s twice", current)
			}
			out.Scenarios[current] = observedScenario{}
		case line == "@@ready":
			s := out.Scenarios[current]
			s.Ready = true
			out.Scenarios[current] = s
		case line == "@@status":
			section = "status"
		case line == "@@exited":
			section = "exited"
		case strings.HasPrefix(line, "@@end "):
			current, section = "", ""
		case line == "@@done":
			done = true
		case section == "status" && line != "":
			s := out.Scenarios[current]
			s.Status += line
			out.Scenarios[current] = s
		case section == "exited" && line != "":
			var entry struct {
				Level string `json:"level"`
				Err   string `json:"err"`
			}
			if json.Unmarshal([]byte(line), &entry) == nil && entry.Err != "" {
				s := out.Scenarios[current]
				if s.Err == "" {
					s.Err = entry.Err
				}
				out.Scenarios[current] = s
			}
		}
	}
	if !done {
		return out, fmt.Errorf("configuration oracle did not finish its observation run")
	}
	need := append([]string{"control"}, nil...)
	for _, f := range fixtures {
		need = append(need, f.Name)
	}
	for _, name := range need {
		s, ok := out.Scenarios[name]
		if !ok {
			return out, fmt.Errorf("configuration oracle did not observe %s", name)
		}
		if s.Ready && s.Status == "" {
			return out, fmt.Errorf("configuration oracle %s: ready without an effective configuration", name)
		}
		if !s.Ready && s.Err == "" {
			return out, fmt.Errorf("configuration oracle %s: neither ready nor a logged configuration error", name)
		}
	}
	return out, nil
}

var promVersionLine = regexp.MustCompile(`^prometheus, version (\S+) \(branch: \S+, revision: ([0-9a-f]{40})\)`)

// ConfigurationScenarioComparison is one scenario of a row.
type ConfigurationScenarioComparison struct {
	Name       string                   `json:"name"`
	Reference  ConfigurationObservation `json:"reference"`
	Owned      ConfigurationObservation `json:"owned"`
	Mismatches []string                 `json:"mismatches"`
}

// ConfigurationCaseComparison is one (profile, case) row.
type ConfigurationCaseComparison struct {
	ID         string                            `json:"id"`
	Profile    string                            `json:"profile"`
	Oracle     *OracleIdentity                   `json:"oracle"`
	Scenarios  []ConfigurationScenarioComparison `json:"scenarios"`
	Mismatches []string                          `json:"mismatches"`
}

// ConfigurationPhaseReport is the result of RunConfigurationPhase.
type ConfigurationPhaseReport struct {
	Phase         string                        `json:"phase"`
	Cases         []ConfigurationCaseComparison `json:"cases"`
	Compared      int                           `json:"compared"`
	Scenarios     int                           `json:"scenarios"`
	Failed        int                           `json:"failed"`
	Qualification string                        `json:"qualification"`
}

// the control file's rule-text expectations: values the added configuration file
// fixes for both pins.
var configurationControlExpect = map[string]string{
	"global.scrape_interval": "30s", "global.scrape_timeout": "5s", "global.evaluation_interval": "45s",
	"job:control.scrape_interval": "30s", "job:control.scrape_timeout": "5s", "jobs": "control",
}

// RunConfigurationPhase executes every row of the locked case files once against
// the configuration-phase oracle variant and the owned resolver. Inventory and
// content locks precede any container, and no unobserved scenario is skipped.
func RunConfigurationPhase(ctx context.Context, lock SourceLock, casesPaths []string, runtime string) (ConfigurationPhaseReport, error) {
	report := ConfigurationPhaseReport{Phase: "configuration", Qualification: "Observes the configuration/protocols and configuration/scrape-inheritance obligations of both pinned Prometheus profiles by running the unmodified upstream binary of each pinned image in its configuration-phase variant (decision D29). It qualifies the authored scenarios only."}
	if err := ValidateSourceLock(lock); err != nil {
		return report, err
	}
	if _, err := Inventory(ctx, lock); err != nil {
		return report, err
	}
	cases, err := readConfigurationCases(lock, casesPaths)
	if err != nil {
		return report, err
	}
	queryDir := filepath.Dir(lock.LedgerPath)
	byProfile := map[string][]ConfigurationCase{}
	for _, c := range cases {
		for _, p := range c.Profiles {
			byProfile[p] = append(byProfile[p], c)
		}
	}
	if len(byProfile) != 2 {
		return report, fmt.Errorf("configuration comparison requires applicable cases for both exact PromQL profiles")
	}
	for _, source := range lock.Profiles {
		rows := byProfile[source.ID]
		if len(rows) == 0 {
			continue
		}
		co, err := verifyConfigurationOracle(queryDir, source)
		if err != nil {
			return report, err
		}
		control, err := os.ReadFile(filepath.Join(queryDir, filepath.FromSlash(co.ConfigurationFile)))
		if err != nil {
			return report, err
		}
		fixtures := []observerFixture{}
		scenarioName := func(i, j int) string { return fmt.Sprintf("s%03d-%03d", i, j) }
		for i, c := range rows {
			for j, s := range c.Scenarios {
				fixtures = append(fixtures, observerFixture{Name: scenarioName(i, j), Features: s.Features, Config: s.Config})
			}
		}
		runCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		image, rebuilt, e := resolveOracleImage(runCtx, runtime, co.ImageID, co.Image, co.ContentIdentity)
		if e != nil {
			cancel()
			return report, e
		}
		observed, e := runConfigurationObserver(runCtx, runtime, image, fixtures)
		cancel()
		if e != nil {
			return report, e
		}
		m := promVersionLine.FindStringSubmatch(observed.Version)
		if m == nil || m[1] != strings.TrimPrefix(source.ID, "promql-prometheus-") || m[2] != source.Commit || observed.Revision != source.Commit {
			return report, fmt.Errorf("%s: the observed binary %q is not the pinned release", source.ID, observed.Version)
		}
		if observed.ControlSHA256 != co.ConfigurationFileSHA256 {
			return report, fmt.Errorf("%s: the image carries a different configuration file than the lock", source.ID)
		}
		identity := &OracleIdentity{Profile: source.ID, Revision: m[2], Version: m[1], ImageSHA256: strings.TrimPrefix(co.ImageID, "sha256:"), ConfigurationSHA256: co.ConfigurationFileSHA256}
		if rebuilt {
			identity.ResolvedImageID, identity.IdentityBasis = image, IdentityBasisContent
		}
		project := func(name string) (ConfigurationObservation, error) {
			o := observed.Scenarios[name]
			if o.Ready {
				return projectReferenceConfiguration(source.ID, o.Status)
			}
			reason, e := classifyReferenceConfigurationError(o.Err)
			return ConfigurationObservation{Reason: reason}, e
		}
		// The control row: the observer must see the added file's own rule-text values.
		ctl := ConfigurationScenario{Name: "control", Config: string(control), Accepted: true, Expect: configurationControlExpect}
		ref, e := project("control")
		if e != nil {
			return report, fmt.Errorf("%s control: %w", source.ID, e)
		}
		if problems := compareConfiguration(ctl, ref, observeOwnedConfiguration(source.ID, ctl)); len(problems) > 0 {
			return report, fmt.Errorf("%s: the configuration oracle failed its control observation: %s", source.ID, strings.Join(problems, "; "))
		}
		for i, c := range rows {
			cmp := ConfigurationCaseComparison{ID: c.ID, Profile: source.ID, Oracle: identity}
			for j, s := range c.Scenarios {
				name := scenarioName(i, j)
				ref, e := project(name)
				if e != nil {
					return report, fmt.Errorf("%s/%s/%s: %w", source.ID, c.ID, s.Name, e)
				}
				sc := ConfigurationScenarioComparison{Name: s.Name, Reference: ref, Owned: observeOwnedConfiguration(source.ID, s)}
				sc.Mismatches = compareConfiguration(s, sc.Reference, sc.Owned)
				report.Scenarios++
				for _, p := range sc.Mismatches {
					cmp.Mismatches = append(cmp.Mismatches, s.Name+": "+p)
				}
				cmp.Scenarios = append(cmp.Scenarios, sc)
			}
			report.Compared++
			if len(cmp.Mismatches) > 0 {
				report.Failed++
			}
			report.Cases = append(report.Cases, cmp)
		}
	}
	expected := 0
	for _, rows := range byProfile {
		expected += len(rows)
	}
	if report.Compared == 0 || report.Compared != expected {
		return report, fmt.Errorf("unobserved applicable configuration cases")
	}
	if report.Failed > 0 {
		return report, fmt.Errorf("%d of %d configuration comparisons failed", report.Failed, report.Compared)
	}
	return report, nil
}
