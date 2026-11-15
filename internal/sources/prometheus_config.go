// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Prometheus scrape-configuration semantics (conformance ledger
// configuration/protocols and configuration/scrape-inheritance of both pinned
// Prometheus profiles). ResolvePrometheusScrapeConfig answers, for one profile and
// one set of enabled process features, exactly the questions the pinned release
// answers when it loads a configuration file: is it accepted, and what are the
// effective global values and the effective values of every scrape job after
// global inheritance. It is a pure function over the document; it opens no file,
// dials nothing and is not wired into `soundpost serve` (the served scrape
// configuration remains the closed JSON document of ScrapeConfig).
//
// Scope, by design: the keys named in PrometheusScrapeJob and
// PrometheusGlobalSettings are modelled; every other key of the document
// (service discovery, relabelling, TLS, ...) is neither interpreted nor
// rejected. The text forms of the numeric keys are the ones the conformance
// campaign authors (decimal unsigned integers, one-unit or compound byte sizes
// with the unit set B/KB/KiB/.../EiB, Prometheus duration strings). Corner
// spellings the pinned release happens to accept beyond them (fractional or
// wrapped integer limits, YAML 1.1 booleans, negative byte sizes, fractional
// byte sizes) are not modelled.

// PrometheusConfigProfile names one pinned Prometheus release.
type PrometheusConfigProfile string

const (
	PrometheusConfig310  PrometheusConfigProfile = "promql-prometheus-3.1.0"
	PrometheusConfig3135 PrometheusConfigProfile = "promql-prometheus-3.13.5"
)

// Reason families of a refused configuration. A refusal carries a family and a
// scope: "document", "global", "job:<name>", or "scrape" for the two name
// escaping refusals (the reference names no job in them).
const (
	PromConfigTimeoutExceedsInterval = "timeout_exceeds_interval"
	PromConfigProtocolsEmpty         = "protocols_empty"
	PromConfigProtocolsDuplicate     = "protocols_duplicate"
	PromConfigProtocolsUnknown       = "protocols_unknown"
	PromConfigFallbackUnknown        = "fallback_protocol_unknown"
	PromConfigInvalidDuration        = "invalid_duration"
	PromConfigInvalidSize            = "invalid_size"
	PromConfigInvalidValue           = "invalid_value"
	PromConfigUnknownField           = "unknown_field"
	PromConfigValidationUnknown      = "validation_scheme_unknown"
	PromConfigEscapingUnknown        = "escaping_scheme_unknown"
	PromConfigEscapingNeedsUTF8      = "escaping_requires_utf8"
)

// PrometheusConfigError is the only error ResolvePrometheusScrapeConfig returns.
type PrometheusConfigError struct{ Family, Scope string }

func (e *PrometheusConfigError) Error() string {
	return "sources: prometheus configuration: " + e.Family + " (" + e.Scope + ")"
}

func promFail(family, scope string) error {
	return &PrometheusConfigError{Family: family, Scope: scope}
}

// PrometheusGlobalSettings are the effective global values.
type PrometheusGlobalSettings struct {
	ScrapeInterval, ScrapeTimeout, EvaluationInterval time.Duration
	// ScrapeProtocols is nil when the release leaves the global list unset
	// (3.13.5 without a protocol-default feature and without an explicit list).
	ScrapeProtocols []string
	Limits          PrometheusLimits
	// 3.13.5 only.
	ScrapeNativeHistograms bool
	MetricNameValidation   string
	MetricNameEscaping     string
}

// PrometheusLimits are the acquisition limits; zero means no cap.
type PrometheusLimits struct {
	BodySizeBytes                                                                int64
	Sample, Target, Label, LabelNameLength, LabelValueLength, KeepDroppedTargets uint64
}

// PrometheusScrapeJob is one scrape job after global inheritance.
type PrometheusScrapeJob struct {
	Name                                                   string
	ScrapeInterval, ScrapeTimeout                          time.Duration
	ScrapeProtocols                                        []string
	FallbackProtocol                                       string
	HonorLabels, HonorTimestamps, TrackTimestampsStaleness bool
	Limits                                                 PrometheusLimits
	// 3.13.5 only.
	ScrapeNativeHistograms bool
	MetricNameValidation   string
	MetricNameEscaping     string
}

// PrometheusScrapeResolution is the loaded configuration.
type PrometheusScrapeResolution struct {
	Global PrometheusGlobalSettings
	Jobs   []PrometheusScrapeJob
}

var (
	promProtocolsDefault = []string{"OpenMetricsText1.0.0", "OpenMetricsText0.0.1", "PrometheusText1.0.0", "PrometheusText0.0.4"}
	promProtocolsProto   = []string{"PrometheusProto", "OpenMetricsText1.0.0", "OpenMetricsText0.0.1", "PrometheusText1.0.0", "PrometheusText0.0.4"}
	promProtocolsKnown   = map[string]bool{"PrometheusProto": true, "PrometheusText0.0.4": true, "PrometheusText1.0.0": true, "OpenMetricsText0.0.1": true, "OpenMetricsText1.0.0": true}
)

// protoFirstDefault reports whether an enabled process feature makes the
// release's default protocol list prefer PrometheusProto. In 3.1.0 the
// native-histograms and created-timestamp-zero-ingestion features do; in 3.13.5
// native-histograms is an accepted no-op and created-timestamp-zero-ingestion
// and st-storage do.
func protoFirstDefault(profile PrometheusConfigProfile, features []string) bool {
	for _, f := range features {
		switch profile {
		case PrometheusConfig310:
			if f == "native-histograms" || f == "created-timestamp-zero-ingestion" {
				return true
			}
		case PrometheusConfig3135:
			if f == "created-timestamp-zero-ingestion" || f == "st-storage" {
				return true
			}
		}
	}
	return false
}

// promDecode walks the document in order. Two failure channels mirror the
// pinned loader: an immediate failure (an unparsable duration or size, an
// unrecognised validation scheme, the global block's own validation) aborts the
// walk with its error and discards the type errors collected so far; type errors
// (wrong kind, negative unsigned value, unknown key) accumulate and the first
// one is reported after the walk.
type promDecode struct {
	profile  PrometheusConfigProfile
	typeErr  *PrometheusConfigError
	hasProto bool
}

func (d *promDecode) typeError(family string) {
	if d.typeErr == nil {
		d.typeErr = &PrometheusConfigError{Family: family, Scope: "document"}
	}
}

type promGlobalRaw struct {
	interval, timeout, evaluation time.Duration
	protocols                     []string
	protocolsSet                  bool // a non-null list was given (possibly empty)
	limits                        PrometheusLimits
	native                        *bool
	validation, escaping          string
}

type promJobRaw struct {
	name                 string
	interval, timeout    time.Duration
	protocols            []string
	protocolsSet         bool
	fallback             string
	honorLabels          bool
	honorTimestamps      bool
	trackStaleness       bool
	limits               PrometheusLimits
	native               *bool
	validation, escaping string
}

func promNode(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

func promIsNull(n *yaml.Node) bool {
	return n == nil || (n.Kind == yaml.ScalarNode && n.Tag == "!!null")
}

func (d *promDecode) scalarString(n *yaml.Node) (string, bool) {
	if n.Kind != yaml.ScalarNode {
		d.typeError(PromConfigInvalidValue)
		return "", false
	}
	return n.Value, true
}

func (d *promDecode) duration(n *yaml.Node) (time.Duration, error) {
	n = promNode(n)
	if promIsNull(n) {
		return 0, nil
	}
	if n.Kind != yaml.ScalarNode {
		d.typeError(PromConfigInvalidValue)
		return 0, nil
	}
	v, ok := parsePromDuration(n.Value)
	if !ok {
		return 0, promFail(PromConfigInvalidDuration, "document")
	}
	return v, nil
}

func (d *promDecode) uint(n *yaml.Node) uint64 {
	n = promNode(n)
	if promIsNull(n) {
		return 0
	}
	if n.Kind != yaml.ScalarNode || n.Tag != "!!int" {
		d.typeError(PromConfigInvalidValue)
		return 0
	}
	v, err := strconv.ParseUint(n.Value, 10, 64)
	if err != nil {
		d.typeError(PromConfigInvalidValue)
		return 0
	}
	return v
}

func (d *promDecode) boolean(n *yaml.Node, def bool) bool {
	n = promNode(n)
	if promIsNull(n) {
		return false
	}
	if n.Kind != yaml.ScalarNode || n.Tag != "!!bool" || (n.Value != "true" && n.Value != "false") {
		d.typeError(PromConfigInvalidValue)
		return def
	}
	return n.Value == "true"
}

func (d *promDecode) boolPtr(n *yaml.Node) *bool {
	n = promNode(n)
	if promIsNull(n) {
		return nil
	}
	v := d.boolean(n, false)
	return &v
}

func (d *promDecode) size(n *yaml.Node) (int64, error) {
	n = promNode(n)
	if promIsNull(n) {
		return 0, nil
	}
	if n.Kind != yaml.ScalarNode {
		d.typeError(PromConfigInvalidValue)
		return 0, nil
	}
	v, ok := parsePromBytes(n.Value)
	if !ok {
		return 0, promFail(PromConfigInvalidSize, "document")
	}
	return v, nil
}

func (d *promDecode) text(n *yaml.Node) string {
	n = promNode(n)
	if promIsNull(n) {
		return ""
	}
	s, _ := d.scalarString(n)
	return s
}

// protocols returns the list and whether the key held a list at all; a null
// value leaves the key unset.
func (d *promDecode) protocols(n *yaml.Node) ([]string, bool) {
	n = promNode(n)
	if promIsNull(n) {
		return nil, false
	}
	if n.Kind != yaml.SequenceNode {
		d.typeError(PromConfigInvalidValue)
		return nil, false
	}
	out := make([]string, 0, len(n.Content))
	for _, item := range n.Content {
		item = promNode(item)
		if item.Kind != yaml.ScalarNode {
			d.typeError(PromConfigInvalidValue)
			continue
		}
		out = append(out, item.Value)
	}
	return out, true
}

// limit decodes the keys shared by the global block and a job; it reports
// whether it consumed the key.
func (d *promDecode) limit(key string, v *yaml.Node, l *PrometheusLimits) (bool, error) {
	switch key {
	case "body_size_limit":
		n, err := d.size(v)
		l.BodySizeBytes = n
		return true, err
	case "sample_limit":
		l.Sample = d.uint(v)
	case "target_limit":
		l.Target = d.uint(v)
	case "label_limit":
		l.Label = d.uint(v)
	case "label_name_length_limit":
		l.LabelNameLength = d.uint(v)
	case "label_value_length_limit":
		l.LabelValueLength = d.uint(v)
	case "keep_dropped_targets":
		l.KeepDroppedTargets = d.uint(v)
	default:
		return false, nil
	}
	return true, nil
}

func (d *promDecode) known3135Only(key string) bool {
	if d.profile == PrometheusConfig3135 {
		return false
	}
	switch key {
	case "scrape_native_histograms", "metric_name_escaping_scheme", "extra_scrape_metrics":
		return true
	}
	return false
}

func (d *promDecode) validationScheme(n *yaml.Node) (string, error) {
	s := d.text(n)
	switch s {
	case "", "utf8", "legacy":
		return s, nil
	}
	return "", promFail(PromConfigValidationUnknown, "document")
}

func (d *promDecode) global(n *yaml.Node) (promGlobalRaw, error) {
	var g promGlobalRaw
	n = promNode(n)
	if promIsNull(n) {
		return g, nil
	}
	if n.Kind != yaml.MappingNode {
		d.typeError(PromConfigInvalidValue)
		return g, nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, v := n.Content[i].Value, n.Content[i+1]
		var err error
		switch key {
		case "scrape_interval":
			g.interval, err = d.duration(v)
		case "scrape_timeout":
			g.timeout, err = d.duration(v)
		case "evaluation_interval":
			g.evaluation, err = d.duration(v)
		case "scrape_protocols":
			g.protocols, g.protocolsSet = d.protocols(v)
		case "scrape_native_histograms":
			if d.known3135Only(key) {
				d.typeError(PromConfigUnknownField)
			} else {
				g.native = d.boolPtr(v)
			}
		case "metric_name_validation_scheme":
			if d.profile == PrometheusConfig3135 {
				g.validation, err = d.validationScheme(v)
			}
		case "metric_name_escaping_scheme":
			if d.known3135Only(key) {
				d.typeError(PromConfigUnknownField)
			} else {
				g.escaping = d.text(v)
			}
		default:
			if d.known3135Only(key) {
				d.typeError(PromConfigUnknownField)
				break
			}
			if key == "honor_labels" || key == "honor_timestamps" || key == "track_timestamps_staleness" || key == "job_name" || key == "fallback_scrape_protocol" {
				d.typeError(PromConfigUnknownField)
				break
			}
			_, err = d.limit(key, v, &g.limits)
		}
		if err != nil {
			return g, err
		}
	}
	return g, nil
}

func (d *promDecode) job(n *yaml.Node) (promJobRaw, error) {
	j := promJobRaw{honorTimestamps: true}
	n = promNode(n)
	if promIsNull(n) {
		return j, nil
	}
	if n.Kind != yaml.MappingNode {
		d.typeError(PromConfigInvalidValue)
		return j, nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, v := n.Content[i].Value, n.Content[i+1]
		var err error
		switch key {
		case "job_name":
			j.name = d.text(v)
		case "scrape_interval":
			j.interval, err = d.duration(v)
		case "scrape_timeout":
			j.timeout, err = d.duration(v)
		case "scrape_protocols":
			j.protocols, j.protocolsSet = d.protocols(v)
		case "fallback_scrape_protocol":
			j.fallback = d.text(v)
		case "honor_labels":
			j.honorLabels = d.boolean(v, false)
		case "honor_timestamps":
			j.honorTimestamps = d.boolean(v, true)
		case "track_timestamps_staleness":
			j.trackStaleness = d.boolean(v, false)
		case "scrape_native_histograms":
			if d.known3135Only(key) {
				d.typeError(PromConfigUnknownField)
			} else {
				j.native = d.boolPtr(v)
			}
		case "metric_name_validation_scheme":
			if d.profile == PrometheusConfig3135 {
				j.validation, err = d.validationScheme(v)
			}
		case "metric_name_escaping_scheme":
			if d.known3135Only(key) {
				d.typeError(PromConfigUnknownField)
			} else {
				j.escaping = d.text(v)
			}
		default:
			if d.known3135Only(key) {
				d.typeError(PromConfigUnknownField)
				break
			}
			_, err = d.limit(key, v, &j.limits)
		}
		if err != nil {
			return j, err
		}
	}
	return j, nil
}

// ResolvePrometheusScrapeConfig loads raw (a Prometheus configuration document)
// under profile with the given enabled process features (the names given to
// --enable-feature) and returns the effective values, or a *PrometheusConfigError.
func ResolvePrometheusScrapeConfig(profile PrometheusConfigProfile, features []string, raw []byte) (PrometheusScrapeResolution, error) {
	var res PrometheusScrapeResolution
	if profile != PrometheusConfig310 && profile != PrometheusConfig3135 {
		return res, errors.New("sources: unknown prometheus configuration profile")
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return res, promFail(PromConfigInvalidValue, "document")
	}
	d := &promDecode{profile: profile}
	var globalRaw promGlobalRaw
	var jobs []promJobRaw
	globalValid := true
	root := &doc
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}
	root = promNode(root)
	if root.Kind != 0 && !promIsNull(root) {
		if root.Kind != yaml.MappingNode {
			d.typeError(PromConfigInvalidValue)
		} else {
			for i := 0; i+1 < len(root.Content); i += 2 {
				key, v := root.Content[i].Value, root.Content[i+1]
				switch key {
				case "global":
					before := d.typeErr
					g, err := d.global(v)
					if err != nil {
						return res, err
					}
					globalRaw = g
					globalValid = d.typeErr == before
					if globalValid {
						// The global block validates itself while it decodes: a failure
						// there is immediate, like an unparsable duration.
						if err = d.validateGlobal(&globalRaw, features); err != nil {
							return res, err
						}
					}
				case "scrape_configs":
					v = promNode(v)
					if promIsNull(v) {
						break
					}
					if v.Kind != yaml.SequenceNode {
						d.typeError(PromConfigInvalidValue)
						break
					}
					for _, item := range v.Content {
						j, err := d.job(item)
						if err != nil {
							return res, err
						}
						jobs = append(jobs, j)
					}
				}
			}
		}
	}
	if d.typeErr != nil {
		return res, d.typeErr
	}
	if root.Kind == 0 || promIsNull(root) || !globalSeen(root) {
		// An absent or empty global block is the release default.
		if err := d.validateGlobal(&globalRaw, features); err != nil {
			return res, err
		}
	}
	res.Global = d.globalSettings(globalRaw, features)
	for _, j := range jobs {
		job, err := d.resolveJob(j, res.Global, features)
		if err != nil {
			return res, err
		}
		res.Jobs = append(res.Jobs, job)
	}
	return res, nil
}

func globalSeen(root *yaml.Node) bool {
	if root.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "global" {
			return true
		}
	}
	return false
}

// validateGlobal applies the block's own rules to raw in place.
func (d *promDecode) validateGlobal(g *promGlobalRaw, features []string) error {
	if g.interval == 0 {
		g.interval = time.Minute
	}
	if g.timeout > g.interval {
		return promFail(PromConfigTimeoutExceedsInterval, "global")
	}
	if g.timeout == 0 {
		g.timeout = min(10*time.Second, g.interval)
	}
	if g.evaluation == 0 {
		g.evaluation = time.Minute
	}
	switch d.profile {
	case PrometheusConfig310:
		if !g.protocolsSet {
			g.protocols = defaultGlobalProtocols(d.profile, features)
		}
		if err := validatePromProtocols(g.protocols, "global"); err != nil {
			return err
		}
	case PrometheusConfig3135:
		if !g.protocolsSet && protoFirstDefault(d.profile, features) {
			g.protocols = append([]string(nil), promProtocolsProto...)
			g.protocolsSet = true
		}
		if g.protocolsSet {
			if err := validatePromProtocols(g.protocols, "global"); err != nil {
				return err
			}
		}
	}
	return nil
}

func defaultGlobalProtocols(profile PrometheusConfigProfile, features []string) []string {
	if protoFirstDefault(profile, features) {
		return append([]string(nil), promProtocolsProto...)
	}
	return append([]string(nil), promProtocolsDefault...)
}

func (d *promDecode) globalSettings(g promGlobalRaw, features []string) PrometheusGlobalSettings {
	out := PrometheusGlobalSettings{ScrapeInterval: g.interval, ScrapeTimeout: g.timeout, EvaluationInterval: g.evaluation, Limits: g.limits}
	switch d.profile {
	case PrometheusConfig310:
		out.ScrapeProtocols = g.protocols
		if !g.protocolsSet && out.ScrapeProtocols == nil {
			out.ScrapeProtocols = defaultGlobalProtocols(d.profile, features)
		}
	case PrometheusConfig3135:
		if g.protocolsSet {
			out.ScrapeProtocols = g.protocols
		}
		out.ScrapeNativeHistograms = g.native != nil && *g.native
		out.MetricNameValidation = g.validation
		out.MetricNameEscaping = g.escaping
		if out.MetricNameValidation == "" {
			out.MetricNameValidation = "utf8"
		}
	}
	return out
}

func validatePromProtocols(list []string, scope string) error {
	if len(list) == 0 {
		return promFail(PromConfigProtocolsEmpty, scope)
	}
	seen := map[string]bool{}
	for _, p := range list {
		folded := strings.ToLower(p)
		if seen[folded] {
			return promFail(PromConfigProtocolsDuplicate, scope)
		}
		if !promProtocolsKnown[p] {
			return promFail(PromConfigProtocolsUnknown, scope)
		}
		seen[folded] = true
	}
	return nil
}

func inheritLimit(local, global uint64) uint64 {
	if local == 0 {
		return global
	}
	return local
}

func (d *promDecode) resolveJob(j promJobRaw, g PrometheusGlobalSettings, features []string) (PrometheusScrapeJob, error) {
	scope := "job:" + j.name
	out := PrometheusScrapeJob{Name: j.name, HonorLabels: j.honorLabels, HonorTimestamps: j.honorTimestamps, TrackTimestampsStaleness: j.trackStaleness, FallbackProtocol: j.fallback}
	out.ScrapeInterval = j.interval
	if out.ScrapeInterval == 0 {
		out.ScrapeInterval = g.ScrapeInterval
	}
	if j.timeout > out.ScrapeInterval {
		return out, promFail(PromConfigTimeoutExceedsInterval, scope)
	}
	out.ScrapeTimeout = j.timeout
	if out.ScrapeTimeout == 0 {
		out.ScrapeTimeout = min(g.ScrapeTimeout, out.ScrapeInterval)
	}
	out.Limits = j.limits
	if out.Limits.BodySizeBytes == 0 {
		out.Limits.BodySizeBytes = g.Limits.BodySizeBytes
	}
	out.Limits.Sample = inheritLimit(j.limits.Sample, g.Limits.Sample)
	out.Limits.Target = inheritLimit(j.limits.Target, g.Limits.Target)
	out.Limits.Label = inheritLimit(j.limits.Label, g.Limits.Label)
	out.Limits.LabelNameLength = inheritLimit(j.limits.LabelNameLength, g.Limits.LabelNameLength)
	out.Limits.LabelValueLength = inheritLimit(j.limits.LabelValueLength, g.Limits.LabelValueLength)
	out.Limits.KeepDroppedTargets = inheritLimit(j.limits.KeepDroppedTargets, g.Limits.KeepDroppedTargets)
	switch d.profile {
	case PrometheusConfig310:
		out.ScrapeProtocols = j.protocols
		if !j.protocolsSet {
			out.ScrapeProtocols = g.ScrapeProtocols
		}
	case PrometheusConfig3135:
		out.ScrapeNativeHistograms = g.ScrapeNativeHistograms
		if j.native != nil {
			out.ScrapeNativeHistograms = *j.native
		}
		switch {
		case j.protocolsSet:
			out.ScrapeProtocols = j.protocols
		case g.ScrapeProtocols != nil:
			out.ScrapeProtocols = g.ScrapeProtocols
		case out.ScrapeNativeHistograms:
			out.ScrapeProtocols = append([]string(nil), promProtocolsProto...)
		default:
			out.ScrapeProtocols = append([]string(nil), promProtocolsDefault...)
		}
	}
	if err := validatePromProtocols(out.ScrapeProtocols, scope); err != nil {
		return out, err
	}
	if out.FallbackProtocol != "" && !promProtocolsKnown[out.FallbackProtocol] {
		return out, promFail(PromConfigFallbackUnknown, scope)
	}
	if d.profile == PrometheusConfig3135 {
		return d.resolveNames3135(j, g, out)
	}
	return out, nil
}

// resolveNames3135 applies the 3.13.5 name validation and escaping defaults:
// escaping follows the validation scheme (UTF-8 allows UTF-8 names, legacy
// escapes with underscores), a job that sets only a legacy validation scheme
// does not inherit a global UTF-8 escaping, and UTF-8 escaping requires UTF-8
// validation.
func (d *promDecode) resolveNames3135(j promJobRaw, g PrometheusGlobalSettings, out PrometheusScrapeJob) (PrometheusScrapeJob, error) {
	localUnset := j.validation == ""
	out.MetricNameValidation = j.validation
	if localUnset {
		out.MetricNameValidation = g.MetricNameValidation
	}
	globalEscaping := g.MetricNameEscaping
	switch globalEscaping {
	case "":
		if g.MetricNameValidation == "legacy" {
			globalEscaping = "underscores"
		} else {
			globalEscaping = "allow-utf-8"
		}
	case "allow-utf-8", "underscores", "dots", "values":
	default:
		return out, promFail(PromConfigEscapingUnknown, "global")
	}
	out.MetricNameEscaping = j.escaping
	if out.MetricNameEscaping == "" {
		switch {
		case localUnset:
			out.MetricNameEscaping = globalEscaping
		case out.MetricNameValidation == "legacy":
			out.MetricNameEscaping = "underscores"
		default:
			out.MetricNameEscaping = "allow-utf-8"
		}
	}
	switch out.MetricNameEscaping {
	case "allow-utf-8":
		if out.MetricNameValidation != "utf8" {
			return out, promFail(PromConfigEscapingNeedsUTF8, "scrape")
		}
	case "underscores", "dots", "values":
	default:
		return out, promFail(PromConfigEscapingUnknown, "scrape")
	}
	return out, nil
}

// parsePromDuration parses a Prometheus duration: "0" or a sequence of
// <digits><unit> in the strictly descending unit order y, w, d, h, m, s, ms.
func parsePromDuration(s string) (time.Duration, bool) {
	if s == "0" {
		return 0, true
	}
	if s == "" {
		return 0, false
	}
	units := []struct {
		suffix string
		d      time.Duration
	}{{"y", 365 * 24 * time.Hour}, {"w", 7 * 24 * time.Hour}, {"d", 24 * time.Hour}, {"h", time.Hour}, {"m", time.Minute}, {"s", time.Second}, {"ms", time.Millisecond}}
	var total time.Duration
	rest := s
	next := 0
	for rest != "" {
		i := 0
		for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
			i++
		}
		if i == 0 {
			return 0, false
		}
		n, err := strconv.ParseInt(rest[:i], 10, 64)
		if err != nil {
			return 0, false
		}
		rest = rest[i:]
		matched := -1
		for u := next; u < len(units); u++ {
			if strings.HasPrefix(rest, units[u].suffix) && !(units[u].suffix == "m" && strings.HasPrefix(rest, "ms")) {
				matched = u
				break
			}
		}
		if matched < 0 {
			return 0, false
		}
		rest = rest[len(units[matched].suffix):]
		next = matched + 1
		if n > int64((1<<63-1)/int64(units[matched].d)) {
			return 0, false
		}
		total += time.Duration(n) * units[matched].d
		if total < 0 {
			return 0, false
		}
	}
	return total, true
}

var promByteUnits = []struct {
	suffix string
	mult   int64
}{{"EiB", 1 << 60}, {"PiB", 1 << 50}, {"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10},
	{"EB", 1 << 60}, {"PB", 1 << 50}, {"TB", 1 << 40}, {"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10}, {"B", 1}}

// parsePromBytes parses one or more <digits><unit> segments (units are binary:
// KB and KiB both mean 1024 bytes).
func parsePromBytes(s string) (int64, bool) {
	if s == "0" {
		return 0, true
	}
	if s == "" {
		return 0, false
	}
	var total int64
	rest := s
	for rest != "" {
		i := 0
		for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
			i++
		}
		if i == 0 {
			return 0, false
		}
		n, err := strconv.ParseInt(rest[:i], 10, 64)
		if err != nil {
			return 0, false
		}
		rest = rest[i:]
		var mult int64
		for _, u := range promByteUnits {
			if strings.HasPrefix(rest, u.suffix) {
				mult = u.mult
				rest = rest[len(u.suffix):]
				break
			}
		}
		if mult == 0 || n > (1<<63-1)/mult || total > (1<<63-1)-n*mult {
			return 0, false
		}
		total += n * mult
	}
	return total, true
}
