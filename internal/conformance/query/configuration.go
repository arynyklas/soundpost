// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/arynyklas/soundpost/internal/sources"
)

// The configuration phase (decision D29). Rows carry a Prometheus configuration
// document and the process features the reference is started with. The reference
// side is the unmodified upstream /bin/prometheus of the pinned image, observed
// black-box in the configuration-phase oracle variant: it either loads the
// document (and then serves its effective configuration on
// /api/v1/status/config) or exits with the error it logged. The owned side is
// sources.ResolvePrometheusScrapeConfig. Both are projected into the same flat
// observation and compared exactly; an authored row also fixes the acceptance,
// the refusal family and any listed effective values, so agreement between the
// two sides alone never certifies a row.

// ConfigurationScenario is one authored configuration and its expectation.
type ConfigurationScenario struct {
	Name     string   `json:"name"`
	Features []string `json:"features,omitempty"`
	Config   string   `json:"config"`
	// Accepted is the authored acceptance; Reason is the authored refusal
	// family and scope ("<family>@<scope>") of a refused configuration.
	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason,omitempty"`
	// Expect lists effective values the rule text fixes, by observation key.
	// Keys naming a duration take Go duration syntax ("30s").
	Expect map[string]string `json:"expect,omitempty"`
}

// ConfigurationCase is one ledger case row: every scenario must agree.
type ConfigurationCase struct {
	ID         string                  `json:"id"`
	Profiles   []string                `json:"profiles"`
	Obligation string                  `json:"obligation"`
	Scenarios  []ConfigurationScenario `json:"scenarios"`
}

// ConfigurationObservation is the comparable outcome of loading one document.
// Values are keyed "global.<key>" and "job:<name>.<key>"; "jobs" lists the job
// names in order. Durations are nanoseconds, byte sizes bytes, lists comma
// joined and an unset list "<unset>".
type ConfigurationObservation struct {
	Accepted bool              `json:"accepted"`
	Reason   string            `json:"reason,omitempty"`
	Values   map[string]string `json:"values,omitempty"`
}

var (
	configurationName    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	configurationFeature = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	configurationProfile = map[string]sources.PrometheusConfigProfile{
		"promql-prometheus-3.1.0":  sources.PrometheusConfig310,
		"promql-prometheus-3.13.5": sources.PrometheusConfig3135,
	}
)

func validateConfigurationCase(c ConfigurationCase) error {
	if c.ID == "" || c.Obligation == "" || len(c.Profiles) == 0 || len(c.Scenarios) == 0 {
		return fmt.Errorf("configuration case %q is incomplete", c.ID)
	}
	for _, p := range c.Profiles {
		if _, ok := configurationProfile[p]; !ok {
			return fmt.Errorf("configuration case %s: unsupported profile %s", c.ID, p)
		}
	}
	seen := map[string]bool{}
	for _, s := range c.Scenarios {
		if !configurationName.MatchString(s.Name) || seen[s.Name] {
			return fmt.Errorf("configuration case %s: scenario name %q is invalid or duplicated", c.ID, s.Name)
		}
		seen[s.Name] = true
		for _, f := range s.Features {
			if !configurationFeature.MatchString(f) {
				return fmt.Errorf("configuration case %s/%s: invalid feature %q", c.ID, s.Name, f)
			}
		}
		if s.Accepted == (s.Reason != "") {
			return fmt.Errorf("configuration case %s/%s: a refused scenario names its reason family, an accepted one names none", c.ID, s.Name)
		}
		if !s.Accepted && len(s.Expect) > 0 {
			return fmt.Errorf("configuration case %s/%s: a refused scenario has no effective values", c.ID, s.Name)
		}
		if len(s.Config) > 64<<10 {
			return fmt.Errorf("configuration case %s/%s: document exceeds 64 KiB", c.ID, s.Name)
		}
	}
	return nil
}

func readConfigurationCases(lock SourceLock, paths []string) ([]ConfigurationCase, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("configuration case files required")
	}
	var out []ConfigurationCase
	files := map[string]bool{}
	ids := map[string]bool{}
	for _, path := range paths {
		key := "cases/" + filepath.Base(path)
		if path == "" || files[key] {
			return nil, fmt.Errorf("empty or duplicate configuration case file %q", path)
		}
		files[key] = true
		var raw json.RawMessage
		if err := ReadLockedJSON(lock, key, path, &raw); err != nil {
			return nil, err
		}
		var suite struct {
			Copyright string              `json:"copyright"`
			License   string              `json:"license"`
			Schema    string              `json:"schema"`
			Phase     string              `json:"phase"`
			Cases     []ConfigurationCase `json:"cases"`
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&suite); err != nil {
			return nil, err
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			return nil, fmt.Errorf("trailing configuration fixture JSON")
		}
		if suite.Phase != "configuration" || suite.Schema != "soundpost-authored-prometheus-configuration-cases-v1" || len(suite.Cases) == 0 {
			return nil, fmt.Errorf("nonempty configuration phase suite required: %s", path)
		}
		for _, c := range suite.Cases {
			if err := validateConfigurationCase(c); err != nil {
				return nil, err
			}
			if ids[c.ID] {
				return nil, fmt.Errorf("duplicate configuration case %s", c.ID)
			}
			ids[c.ID] = true
			out = append(out, c)
		}
	}
	return out, nil
}

// ----- owned side ------------------------------------------------------------

func configurationFlatten(profile sources.PrometheusConfigProfile, res sources.PrometheusScrapeResolution) map[string]string {
	v := map[string]string{}
	set := func(k string, x any) { v[k] = fmt.Sprint(x) }
	limits := func(prefix string, l sources.PrometheusLimits) {
		set(prefix+".body_size_limit", l.BodySizeBytes)
		set(prefix+".sample_limit", l.Sample)
		set(prefix+".target_limit", l.Target)
		set(prefix+".label_limit", l.Label)
		set(prefix+".label_name_length_limit", l.LabelNameLength)
		set(prefix+".label_value_length_limit", l.LabelValueLength)
		set(prefix+".keep_dropped_targets", l.KeepDroppedTargets)
	}
	list := func(p []string) string {
		if p == nil {
			return "<unset>"
		}
		return strings.Join(p, ",")
	}
	g := res.Global
	set("global.scrape_interval", int64(g.ScrapeInterval))
	set("global.scrape_timeout", int64(g.ScrapeTimeout))
	set("global.evaluation_interval", int64(g.EvaluationInterval))
	v["global.scrape_protocols"] = list(g.ScrapeProtocols)
	limits("global", g.Limits)
	if profile == sources.PrometheusConfig3135 {
		set("global.scrape_native_histograms", g.ScrapeNativeHistograms)
		set("global.metric_name_validation_scheme", g.MetricNameValidation)
	}
	names := make([]string, 0, len(res.Jobs))
	for _, j := range res.Jobs {
		names = append(names, j.Name)
		p := "job:" + j.Name
		set(p+".scrape_interval", int64(j.ScrapeInterval))
		set(p+".scrape_timeout", int64(j.ScrapeTimeout))
		v[p+".scrape_protocols"] = list(j.ScrapeProtocols)
		fallback := j.FallbackProtocol
		if fallback == "" {
			fallback = "<unset>"
		}
		v[p+".fallback_scrape_protocol"] = fallback
		set(p+".honor_labels", j.HonorLabels)
		set(p+".honor_timestamps", j.HonorTimestamps)
		set(p+".track_timestamps_staleness", j.TrackTimestampsStaleness)
		limits(p, j.Limits)
		if profile == sources.PrometheusConfig3135 {
			set(p+".scrape_native_histograms", j.ScrapeNativeHistograms)
			set(p+".metric_name_validation_scheme", j.MetricNameValidation)
			set(p+".metric_name_escaping_scheme", j.MetricNameEscaping)
		}
	}
	v["jobs"] = strings.Join(names, ",")
	return v
}

func observeOwnedConfiguration(profileID string, s ConfigurationScenario) ConfigurationObservation {
	profile := configurationProfile[profileID]
	res, err := sources.ResolvePrometheusScrapeConfig(profile, s.Features, []byte(s.Config))
	if err != nil {
		var ce *sources.PrometheusConfigError
		if asConfigError(err, &ce) {
			return ConfigurationObservation{Reason: ce.Family + "@" + ce.Scope}
		}
		return ConfigurationObservation{Reason: "owned_error:" + err.Error()}
	}
	return ConfigurationObservation{Accepted: true, Values: configurationFlatten(profile, res)}
}

func asConfigError(err error, target **sources.PrometheusConfigError) bool {
	ce, ok := err.(*sources.PrometheusConfigError)
	if ok {
		*target = ce
	}
	return ok
}

// ----- reference side ----------------------------------------------------------

type promStatusLimits struct {
	BodySizeLimit         string `yaml:"body_size_limit"`
	SampleLimit           uint64 `yaml:"sample_limit"`
	TargetLimit           uint64 `yaml:"target_limit"`
	LabelLimit            uint64 `yaml:"label_limit"`
	LabelNameLengthLimit  uint64 `yaml:"label_name_length_limit"`
	LabelValueLengthLimit uint64 `yaml:"label_value_length_limit"`
	KeepDroppedTargets    uint64 `yaml:"keep_dropped_targets"`
}

type promStatusConfig struct {
	Global struct {
		ScrapeInterval             string   `yaml:"scrape_interval"`
		ScrapeTimeout              string   `yaml:"scrape_timeout"`
		EvaluationInterval         string   `yaml:"evaluation_interval"`
		ScrapeProtocols            []string `yaml:"scrape_protocols"`
		ScrapeNativeHistograms     bool     `yaml:"scrape_native_histograms"`
		MetricNameValidationScheme string   `yaml:"metric_name_validation_scheme"`
		promStatusLimits           `yaml:",inline"`
	} `yaml:"global"`
	ScrapeConfigs []struct {
		JobName                    string   `yaml:"job_name"`
		HonorLabels                bool     `yaml:"honor_labels"`
		HonorTimestamps            bool     `yaml:"honor_timestamps"`
		TrackTimestampsStaleness   bool     `yaml:"track_timestamps_staleness"`
		ScrapeInterval             string   `yaml:"scrape_interval"`
		ScrapeTimeout              string   `yaml:"scrape_timeout"`
		ScrapeProtocols            []string `yaml:"scrape_protocols"`
		FallbackScrapeProtocol     string   `yaml:"fallback_scrape_protocol"`
		ScrapeNativeHistograms     bool     `yaml:"scrape_native_histograms"`
		MetricNameValidationScheme string   `yaml:"metric_name_validation_scheme"`
		MetricNameEscapingScheme   string   `yaml:"metric_name_escaping_scheme"`
		promStatusLimits           `yaml:",inline"`
	} `yaml:"scrape_configs"`
}

var (
	promDurationPart = regexp.MustCompile(`(\d+)(ms|y|w|d|h|m|s)`)
	promBytesPart    = regexp.MustCompile(`(\d+)(EiB|PiB|TiB|GiB|MiB|KiB|B)`)
)

// referenceDuration parses a duration as the reference prints it. It is a
// separate implementation from the owned parser on purpose.
func referenceDuration(text string) (time.Duration, error) {
	if text == "" || text == "0s" || text == "0" {
		return 0, nil
	}
	unit := map[string]time.Duration{"y": 365 * 24 * time.Hour, "w": 7 * 24 * time.Hour, "d": 24 * time.Hour, "h": time.Hour, "m": time.Minute, "s": time.Second, "ms": time.Millisecond}
	var total time.Duration
	consumed := 0
	for _, m := range promDurationPart.FindAllStringSubmatchIndex(text, -1) {
		if m[0] != consumed {
			return 0, fmt.Errorf("unparsable reference duration %q", text)
		}
		n, err := strconv.ParseInt(text[m[2]:m[3]], 10, 64)
		if err != nil {
			return 0, err
		}
		total += time.Duration(n) * unit[text[m[4]:m[5]]]
		consumed = m[1]
	}
	if consumed != len(text) {
		return 0, fmt.Errorf("unparsable reference duration %q", text)
	}
	return total, nil
}

func referenceBytes(text string) (int64, error) {
	if text == "" {
		return 0, nil
	}
	unit := map[string]int64{"EiB": 1 << 60, "PiB": 1 << 50, "TiB": 1 << 40, "GiB": 1 << 30, "MiB": 1 << 20, "KiB": 1 << 10, "B": 1}
	var total int64
	consumed := 0
	for _, m := range promBytesPart.FindAllStringSubmatchIndex(text, -1) {
		if m[0] != consumed {
			return 0, fmt.Errorf("unparsable reference size %q", text)
		}
		n, err := strconv.ParseInt(text[m[2]:m[3]], 10, 64)
		if err != nil {
			return 0, err
		}
		total += n * unit[text[m[4]:m[5]]]
		consumed = m[1]
	}
	if consumed != len(text) {
		return 0, fmt.Errorf("unparsable reference size %q", text)
	}
	return total, nil
}

// projectReferenceConfiguration turns the reference's served effective
// configuration into the comparable observation.
func projectReferenceConfiguration(profileID, statusJSON string) (ConfigurationObservation, error) {
	var status struct {
		Status string `json:"status"`
		Data   struct {
			YAML string `json:"yaml"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(statusJSON), &status); err != nil || status.Status != "success" || status.Data.YAML == "" {
		return ConfigurationObservation{}, fmt.Errorf("reference served no effective configuration")
	}
	var cfg promStatusConfig
	if err := yaml.Unmarshal([]byte(status.Data.YAML), &cfg); err != nil {
		return ConfigurationObservation{}, fmt.Errorf("reference effective configuration: %w", err)
	}
	profile := configurationProfile[profileID]
	dur := func(text string) (time.Duration, error) { return referenceDuration(text) }
	var res sources.PrometheusScrapeResolution
	var err error
	g := &res.Global
	if g.ScrapeInterval, err = dur(cfg.Global.ScrapeInterval); err != nil {
		return ConfigurationObservation{}, err
	}
	if g.ScrapeTimeout, err = dur(cfg.Global.ScrapeTimeout); err != nil {
		return ConfigurationObservation{}, err
	}
	if g.EvaluationInterval, err = dur(cfg.Global.EvaluationInterval); err != nil {
		return ConfigurationObservation{}, err
	}
	g.ScrapeProtocols = cfg.Global.ScrapeProtocols
	g.ScrapeNativeHistograms = cfg.Global.ScrapeNativeHistograms
	g.MetricNameValidation = cfg.Global.MetricNameValidationScheme
	if g.Limits, err = referenceLimits(cfg.Global.promStatusLimits); err != nil {
		return ConfigurationObservation{}, err
	}
	for _, s := range cfg.ScrapeConfigs {
		j := sources.PrometheusScrapeJob{Name: s.JobName, ScrapeProtocols: s.ScrapeProtocols, FallbackProtocol: s.FallbackScrapeProtocol,
			HonorLabels: s.HonorLabels, HonorTimestamps: s.HonorTimestamps, TrackTimestampsStaleness: s.TrackTimestampsStaleness,
			ScrapeNativeHistograms: s.ScrapeNativeHistograms, MetricNameValidation: s.MetricNameValidationScheme, MetricNameEscaping: s.MetricNameEscapingScheme}
		if j.ScrapeInterval, err = dur(s.ScrapeInterval); err != nil {
			return ConfigurationObservation{}, err
		}
		if j.ScrapeTimeout, err = dur(s.ScrapeTimeout); err != nil {
			return ConfigurationObservation{}, err
		}
		if j.Limits, err = referenceLimits(s.promStatusLimits); err != nil {
			return ConfigurationObservation{}, err
		}
		res.Jobs = append(res.Jobs, j)
	}
	return ConfigurationObservation{Accepted: true, Values: configurationFlatten(profile, res)}, nil
}

func referenceLimits(l promStatusLimits) (sources.PrometheusLimits, error) {
	body, err := referenceBytes(l.BodySizeLimit)
	return sources.PrometheusLimits{BodySizeBytes: body, Sample: l.SampleLimit, Target: l.TargetLimit, Label: l.LabelLimit,
		LabelNameLength: l.LabelNameLengthLimit, LabelValueLength: l.LabelValueLengthLimit, KeepDroppedTargets: l.KeepDroppedTargets}, err
}

var (
	referenceErrorPrefix = regexp.MustCompile(`^parsing YAML file \S+: `)
	referenceJobScope    = regexp.MustCompile(`for scrape config with job name "([^"]*)"`)
)

// classifyReferenceConfigurationError maps the error the reference logged when
// it refused a configuration to a refusal family and scope. Text that matches no
// known family is an error: it is never compared as an opaque string.
func classifyReferenceConfigurationError(text string) (string, error) {
	msg := referenceErrorPrefix.ReplaceAllString(strings.TrimSpace(text), "")
	scope := "global"
	if m := referenceJobScope.FindStringSubmatch(msg); m != nil {
		scope = "job:" + m[1]
	}
	family := ""
	switch {
	case strings.HasPrefix(msg, "global scrape timeout greater than scrape interval"):
		family = sources.PromConfigTimeoutExceedsInterval
	case strings.HasPrefix(msg, "scrape timeout greater than scrape interval for scrape config"):
		family = sources.PromConfigTimeoutExceedsInterval
	case strings.HasPrefix(msg, "scrape_protocols cannot be empty"):
		family = sources.PromConfigProtocolsEmpty
	case strings.HasPrefix(msg, "duplicated protocol in scrape_protocols"):
		family = sources.PromConfigProtocolsDuplicate
	case strings.HasPrefix(msg, "scrape_protocols: unknown scrape protocol"):
		family = sources.PromConfigProtocolsUnknown
	case strings.HasPrefix(msg, "invalid fallback_scrape_protocol"):
		family = sources.PromConfigFallbackUnknown
	case strings.HasPrefix(msg, "not a valid duration string") || strings.HasPrefix(msg, "unknown unit") && strings.Contains(msg, "in duration"):
		family, scope = sources.PromConfigInvalidDuration, "document"
	case strings.HasPrefix(msg, "units: "):
		family, scope = sources.PromConfigInvalidSize, "document"
	case strings.HasPrefix(msg, "yaml: unmarshal errors:"):
		family, scope = sources.PromConfigInvalidValue, "document"
		first := ""
		for _, line := range strings.Split(msg, "\n")[1:] {
			if first = strings.TrimSpace(line); first != "" {
				break
			}
		}
		if strings.Contains(first, "not found in type") {
			family = sources.PromConfigUnknownField
		} else if !strings.Contains(first, "cannot unmarshal") && !strings.Contains(first, "already set") {
			return "", fmt.Errorf("unclassified reference YAML error %q", first)
		}
	case strings.HasPrefix(msg, "unrecognized ValidationScheme"):
		family, scope = sources.PromConfigValidationUnknown, "document"
	case strings.HasPrefix(msg, "unknown scrape config name escaping method"):
		family, scope = sources.PromConfigEscapingUnknown, "scrape"
	case strings.HasPrefix(msg, "unknown global name escaping method"):
		family = sources.PromConfigEscapingUnknown
	case strings.HasPrefix(msg, "utf8 metric names requested but validation scheme is not set to UTF8"):
		family, scope = sources.PromConfigEscapingNeedsUTF8, "scrape"
	default:
		return "", fmt.Errorf("unclassified reference configuration error %q", msg)
	}
	if strings.HasPrefix(msg, "unknown global name escaping method") {
		scope = "global"
	}
	return family + "@" + scope, nil
}

// ----- comparison ---------------------------------------------------------------

func configurationExpectValue(key, want string) (string, error) {
	if strings.HasSuffix(key, "scrape_interval") || strings.HasSuffix(key, "scrape_timeout") || strings.HasSuffix(key, "evaluation_interval") {
		d, err := time.ParseDuration(want)
		if err != nil {
			return "", fmt.Errorf("expectation %s=%q: %w", key, want, err)
		}
		return strconv.FormatInt(int64(d), 10), nil
	}
	return want, nil
}

// compareConfiguration returns every disagreement of one scenario: the authored
// expectation against each side, and the two sides against each other.
func compareConfiguration(s ConfigurationScenario, reference, owned ConfigurationObservation) []string {
	var out []string
	check := func(side string, o ConfigurationObservation) {
		if o.Accepted != s.Accepted {
			out = append(out, fmt.Sprintf("%s accepted=%t, authored %t (reason %q)", side, o.Accepted, s.Accepted, o.Reason))
			return
		}
		if !o.Accepted {
			if o.Reason != s.Reason {
				out = append(out, fmt.Sprintf("%s refusal %q, authored %q", side, o.Reason, s.Reason))
			}
			return
		}
		keys := make([]string, 0, len(s.Expect))
		for k := range s.Expect {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			want, err := configurationExpectValue(k, s.Expect[k])
			if err != nil {
				out = append(out, err.Error())
				continue
			}
			if got, ok := o.Values[k]; !ok || got != want {
				out = append(out, fmt.Sprintf("%s %s=%q, authored %q", side, k, got, want))
			}
		}
	}
	check("reference", reference)
	check("owned", owned)
	if reference.Accepted != owned.Accepted || reference.Reason != owned.Reason {
		out = append(out, fmt.Sprintf("reference accepted=%t reason=%q, owned accepted=%t reason=%q", reference.Accepted, reference.Reason, owned.Accepted, owned.Reason))
		return out
	}
	keys := map[string]bool{}
	for k := range reference.Values {
		keys[k] = true
	}
	for k := range owned.Values {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, k := range sorted {
		r, rok := reference.Values[k]
		o, ook := owned.Values[k]
		if rok != ook || r != o {
			out = append(out, fmt.Sprintf("%s: reference %q, owned %q", k, r, o))
		}
	}
	return out
}
