// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"encoding/json"
	"math"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

func oneOf(v string, allowed ...string) bool {
	for _, x := range allowed {
		if v == x {
			return true
		}
	}
	return false
}
func safeCode(s string, n int) bool {
	if s == "" || len(s) > n {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_.:/<>-+ $", c)) {
			return false
		}
	}
	return true
}
func safePath(s string) bool {
	return s != "" && len(s) <= 512 && !strings.Contains(s, "\\") && !strings.Contains(s, ":") && !strings.HasPrefix(s, "/") && path.Clean(s) == s && s != ".." && !strings.HasPrefix(s, "../") && !strings.ContainsAny(s, "?#\x00")
}
func ValidateSourcePolicy(p SourcePolicy) error {
	if p.Revision == 0 || !oneOf(p.Class, "structured", "restricted_raw") || len(p.Kinds) == 0 || p.MaxBytes == 0 || p.MaxSeries == 0 {
		return Fail(Invalid)
	}
	if p.Class == "restricted_raw" && (p.RawOwner == nil || p.RawRationale == "" || len(p.RawRationale) > 512 || p.Expires == 0 || p.RawMaxBytes == 0 || p.RawMaxBytes > 65536) {
		return Fail(Invalid)
	}
	if p.Class == "structured" && (p.RawOwner != nil || p.RawRationale != "" || p.RawMaxBytes != 0) {
		return Fail(Invalid)
	}
	seen := map[Kind]bool{}
	for _, k := range p.Kinds {
		if !k.Valid() || seen[k] || p.RetentionDays[k] == 0 || p.RetentionDays[k] > 3650 {
			return Fail(Invalid)
		}
		if p.Class == "restricted_raw" && (p.RetentionDays[k] > 7 || !oneOf(string(k), string(Log), string(CapabilityKind), string(Loss))) {
			return Fail(Invalid)
		}
		seen[k] = true
	}
	ids := map[string]bool{}
	placeholders := regexp.MustCompile(`\{([^{}]+)\}`)
	for _, t := range p.Templates {
		key := t.ID + ":" + strconvRevision(t.Revision)
		if !safeCode(t.ID, 128) || t.Revision == 0 || ids[key] || len(t.Line) > 4096 || !oneOf(t.Severity, "trace", "debug", "info", "warn", "error", "fatal") {
			return Fail(Invalid)
		}
		ids[key] = true
		fields := map[string]bool{}
		for _, f := range t.Fields {
			raw := p.Class == "restricted_raw" && f.Sensitivity == "restricted_raw"
			if !safeCode(f.Name, 64) || fields[f.Name] || !oneOf(f.Type, "string", "int64", "bool", "null") || f.MaxBytes == 0 || f.MaxBytes > 4096 || (!raw && f.Sensitivity != "metadata") || !raw && len(f.Values) == 0 || len(f.Values) > 256 {
				return Fail(Invalid)
			}
			if raw && (f.Type != "string" || f.MaxBytes > p.RawMaxBytes) {
				return Fail(Invalid)
			}
			fields[f.Name] = true
			for _, v := range f.Values {
				if !validField(v, f) {
					return Fail(Invalid)
				}
			}
		}
		for _, m := range placeholders.FindAllStringSubmatch(t.Line, -1) {
			if !fields[m[1]] {
				return Fail(Invalid)
			}
		}
		if strings.ContainsAny(placeholders.ReplaceAllString(t.Line, ""), "{}") {
			return Fail(Invalid)
		}
	}
	if e := p.Resources.Validate(); e != nil {
		return e
	}
	for name, values := range p.Labels {
		if name == "" || !utf8.ValidString(name) || len(values) == 0 {
			return Fail(Invalid)
		}
		for _, value := range values {
			if !utf8.ValidString(value) {
				return Fail(Invalid)
			}
		}
	}
	for _, codes := range [][]string{p.Operations, p.Dependencies, p.Codes} {
		for _, code := range codes {
			if !safeCode(code, 256) {
				return Fail(Invalid)
			}
		}
	}
	return nil
}
func strconvRevision(r Revision) string { b, _ := json.Marshal(r); return string(b) }
func validField(v Scalar, f TemplateField) bool {
	b, _ := v.MarshalJSON()
	if f.Type == "string" {
		var text string
		return len(b) > 0 && b[0] == '"' && json.Unmarshal(b, &text) == nil && utf8.ValidString(text) && len(text) <= int(f.MaxBytes)
	}
	if len(b) > int(f.MaxBytes) {
		return false
	}
	switch f.Type {
	case "bool":
		return string(b) == "true" || string(b) == "false"
	case "null":
		return string(b) == "null"
	case "int64":
		return len(b) > 0 && (b[0] == '-' || b[0] >= '0' && b[0] <= '9')
	}
	return false
}
func allowedLabels(l Labels, p SourcePolicy) error {
	if l.Validate() != nil {
		return Fail(Invalid)
	}
	for _, v := range l {
		if !utf8.ValidString(v.Name) || !utf8.ValidString(v.Value) || !oneOf(v.Value, p.Labels[v.Name]...) {
			return Fail(Invalid)
		}
	}
	return nil
}
func framesValid(frames []Frame) bool {
	if len(frames) > 128 {
		return false
	}
	for _, f := range frames {
		if !safeCode(f.Module, 256) || !safeCode(f.Function, 256) || !safePath(f.Artifact) || f.Line == 0 {
			return false
		}
	}
	return true
}
func framesEqual(a, b []Frame) bool {
	if len(a) != len(b) {
		return false
	}
	for i, f := range a {
		other := b[i]
		if f.Module != other.Module || f.Function != other.Function || f.Artifact != other.Artifact || f.Line != other.Line || f.InApp != other.InApp || f.Async != other.Async {
			return false
		}
		if (f.Column == nil) != (other.Column == nil) || f.Column != nil && *f.Column != *other.Column {
			return false
		}
	}
	return true
}
func ValidateRecord(r *Record, p SourcePolicy) error {
	if r.ID == (ID{}) || !r.Kind.Valid() {
		return Fail(Invalid)
	}
	if _, e := r.Payload.Value(r.Kind); e != nil {
		return e
	}
	allowed := false
	for _, k := range p.Kinds {
		if r.Kind == k {
			allowed = true
		}
	}
	if !allowed {
		return Fail(Forbidden)
	}
	if !p.Resources.Allows(r.Resource) {
		return Fail(Invalid)
	}
	if e := allowedLabels(r.Resource.Labels, p); e != nil {
		return e
	}
	switch r.Kind {
	case Metric:
		m := r.Payload.Metric
		if m.Name == "" || len(m.Name) > 1024 || strings.ContainsAny(m.Name, "\x00\r\n") || allowedLabels(m.Labels, p) != nil || !safeCode(m.Unit, 64) || !oneOf(m.Type, "counter", "gauge", "histogram", "unknown") {
			return Fail(Invalid)
		}
		switch m.SampleKind {
		case "float", "stale":
			if m.Value == nil || m.Histogram != nil {
				return Fail(Invalid)
			}
			stale := uint64(*m.Value) == 0x7ff0000000000002
			if (m.SampleKind == "stale") != stale {
				return Fail(Invalid)
			}
		case "integer_histogram", "float_histogram":
			if m.Value != nil || m.Histogram == nil || m.Histogram.Validate() != nil || m.SampleKind == "integer_histogram" && m.Histogram.Integer == nil || m.SampleKind == "float_histogram" && m.Histogram.Float == nil {
				return Fail(Invalid)
			}
		default:
			return Fail(Invalid)
		}
	case Log:
		l := r.Payload.Log
		var template *LogTemplate
		for i := range p.Templates {
			if p.Templates[i].ID == l.TemplateID && p.Templates[i].Revision == l.TemplateRevision {
				template = &p.Templates[i]
			}
		}
		if template == nil {
			return Fail(Invalid)
		}
		fields, metadata := map[string]Scalar{}, map[string]Scalar{}
		line := template.Line
		for _, f := range template.Fields {
			v, ok := l.Fields[f.Name]
			if !ok || !validField(v, f) {
				return Fail(Invalid)
			}
			found := p.Class == "restricted_raw" && f.Sensitivity == "restricted_raw" && len(f.Values) == 0
			for _, a := range f.Values {
				if a.raw == v.raw {
					found = true
				}
			}
			if !found {
				return Fail(Invalid)
			}
			fields[f.Name] = v
			if v, ok := l.Metadata[f.Name]; ok {
				found := false
				for _, a := range f.Values {
					if a.raw == v.raw {
						found = true
					}
				}
				if !found {
					return Fail(Invalid)
				}
				metadata[f.Name] = v
			}
		}
		line = renderTemplate(line, fields)
		if p.Class == "restricted_raw" && len(line) > int(p.RawMaxBytes) {
			return Fail(TooLarge)
		}
		l.Fields = fields
		l.Line = line
		l.Severity = template.Severity
		l.SourceClass = p.Class
		l.Metadata = metadata
		if allowedLabels(l.StreamLabels, p) != nil {
			return Fail(Invalid)
		}
	case SpanKind:
		s := r.Payload.Span
		if s.Trace == (ID{}) || s.ID == (SpanID{}) || !oneOf(s.Kind, "internal", "server", "client", "producer", "consumer") || !oneOf(s.Operation, p.Operations...) || s.Dependency != "" && !oneOf(s.Dependency, p.Dependencies...) || !oneOf(s.Status, "ok", "error", "cancelled", "incomplete") || !oneOf(s.SampleDecision, "keep", "drop") || len(s.Links) > 128 {
			return Fail(Invalid)
		}
		prob := math.Float64frombits(uint64(s.SampleProbability))
		if math.IsNaN(prob) || prob < 0 || prob > 1 {
			return Fail(Invalid)
		}
		if s.Start.Domain.Host == (ID{}) || s.Start.Domain.Boot == (ID{}) || s.Start.Domain.Runtime == (ID{}) {
			return Fail(Invalid)
		}
		if s.End == nil {
			if s.Status != "incomplete" && s.Status != "cancelled" {
				return Fail(Invalid)
			}
		} else if s.End.Domain != s.Start.Domain || s.End.Mono < s.Start.Mono {
			return Fail(Invalid)
		}
	case ErrorKind:
		e := r.Payload.Error
		if e.Occurrence == (ID{}) || !safeCode(e.Class, 256) || e.Build != r.Resource.Build || !oneOf(e.Mechanism, "manual", "uncaught_exception", "unhandled_rejection", "thread_exception", "asyncio_exception") || !framesValid(e.Frames) || e.Code != nil && !oneOf(*e.Code, p.Codes...) {
			return Fail(Invalid)
		}
		if e.Template != nil {
			found := false
			for _, t := range p.Templates {
				if t.ID == *e.Template {
					found = true
				}
			}
			if !found {
				return Fail(Invalid)
			}
		}
		if e.Graph != nil {
			g := e.Graph
			if len(g.Nodes) == 0 || len(g.Nodes) > 16 || len(g.Edges) > 272 || len(g.Reasons) > 16 {
				return Fail(Invalid)
			}
			if g.Nodes[0].Class != e.Class || !framesEqual(g.Nodes[0].Frames, e.Frames) {
				return Fail(Invalid)
			}
			count := 0
			for i, n := range g.Nodes {
				if n.ID != uint32(i) || !safeCode(n.Class, 256) || !framesValid(n.Frames) {
					return Fail(Invalid)
				}
				count += len(n.Frames)
			}
			if count > 128 {
				return Fail(Invalid)
			}
			for _, edge := range g.Edges {
				if edge.From >= uint32(len(g.Nodes)) || edge.To >= uint32(len(g.Nodes)) || !oneOf(edge.Kind, "cause", "context", "group") {
					return Fail(Invalid)
				}
				if edge.Kind == "group" {
					if edge.Ordinal == nil || *edge.Ordinal >= 16 {
						return Fail(Invalid)
					}
				} else if edge.Ordinal != nil {
					return Fail(Invalid)
				}
			}
			for _, reason := range g.Reasons {
				if !oneOf(reason, "cycle", "node_limit", "frame_limit", "group_limit", "unknown_throw", "project_root_unconfigured", "frame_not_project_safe", "foreign_or_custom_error_class", "safe_original_stack_unavailable", "native_brand_unavailable", "cause_accessor", "group_accessor", "safe_group_boundary_unavailable", "unsafe_group_container") {
					return Fail(Invalid)
				}
			}
		}
	case JobAttempt:
		j := r.Payload.Job
		if j.Job == (ID{}) || j.Run == (ID{}) || j.Attempt == (ID{}) || j.Epoch == (ID{}) || !safeCode(j.Schedule, 256) || j.Ordinal == 0 || !oneOf(j.State, "started", "succeeded", "failed", "cancelled") || j.State == "started" && j.Terminal != nil || j.State != "started" && (j.Terminal == nil || *j.Terminal < j.Observed) {
			return Fail(Invalid)
		}
	case Replay:
		c := r.Payload.Replay
		if !p.Replay || c.Replay == (ID{}) || c.Session == (ID{}) || !safeCode(c.Recorder, 128) || c.PolicyRevision != p.Revision || len(c.Nodes) > 4096 || len(c.Events) > 4096 {
			return Fail(Invalid)
		}
		for _, n := range c.Nodes {
			if !oneOf(n.Tag, "div", "span", "p", "button", "input", "section", "canvas", "masked") || n.Text != "[masked]" && n.Text != "" || n.Class != "" && n.Class != "masked" {
				return Fail(Invalid)
			}
		}
		for _, e := range c.Events {
			if !oneOf(e.Kind, "pointer", "scroll", "resize", "mutation", "checkpoint", "gap") {
				return Fail(Invalid)
			}
		}
	case Profile:
		c := r.Payload.Profile
		if c.Profile == (ID{}) || c.Process == (ID{}) || c.Capability == (ID{}) || c.End < c.Start || !oneOf(c.Method, "runtime_cpu", "native_cpu", "native_offcpu") || !oneOf(c.Units, "samples", "nanoseconds") || len(c.Frames) > 4096 || len(c.Stacks) > 4096 || len(c.Samples) > 8192 || len(c.Intervals) > 8192 {
			return Fail(Invalid)
		}
		for _, f := range c.Frames {
			if !safeCode(f.Module, 256) || f.Function != "" && !safeCode(f.Function, 256) || f.Artifact != "" && !safePath(f.Artifact) || f.Reason != "" && !oneOf(f.Reason, "unresolved", "not_captured", "unsupported", "missing_artifact") {
				return Fail(Invalid)
			}
		}
		for _, s := range c.Stacks {
			if len(s.Frames) > 128 {
				return Fail(Invalid)
			}
			for _, f := range s.Frames {
				if int(f) >= len(c.Frames) {
					return Fail(Invalid)
				}
			}
		}
		for _, s := range c.Samples {
			if int(s.Stack) >= len(c.Stacks) || s.Count == 0 {
				return Fail(Invalid)
			}
		}
		for _, i := range c.Intervals {
			if i.End < i.Start || int(i.Stack) >= len(c.Stacks) || !oneOf(i.Kind, "blocked", "runnable", "unknown_offcpu") {
				return Fail(Invalid)
			}
		}
	case CapabilityKind:
		c := r.Payload.Capability
		if !safeCode(c.Runtime, 128) || !safeCode(c.Version, 128) || !safeCode(c.Build, 256) || !safeCode(c.OS, 64) || !safeCode(c.Arch, 64) || !c.Signal.Valid() || !safeCode(c.Method, 128) || !oneOf(c.Status, "supported", "denied", "unsupported", "error") || !safeCode(c.Reason, 128) || c.Expires <= r.ObservedAt {
			return Fail(Invalid)
		}
		for _, v := range []string{c.Coverage.Frames, c.Coverage.Threads, c.Coverage.Workers, c.Coverage.Tasks} {
			if !oneOf(v, "complete", "partial", "none", "unknown") {
				return Fail(Invalid)
			}
		}
	case Loss:
		l := r.Payload.Loss
		if l.Source == (ID{}) || l.Producer == (ID{}) || l.Epoch == (ID{}) || l.End < l.Start || !l.Signal.Valid() || !oneOf(l.Reason, "queue_full", "expired", "policy", "unsupported", "ring_overflow", "reorder_gap", "transport", "shutdown", "truncated") {
			return Fail(Invalid)
		}
	case Condition:
		c := r.Payload.Condition
		if c.Condition == (ID{}) || c.Epoch == (ID{}) || !oneOf(c.Status, "firing", "recovered", "unknown") || !oneOf(c.Severity, "info", "warning", "error", "critical") || allowedLabels(c.Labels, p) != nil || len(c.Links) > 64 {
			return Fail(Invalid)
		}
	}
	return nil
}
func renderTemplate(line string, fields map[string]Scalar) string {
	var out strings.Builder
	out.Grow(len(line))
	for {
		open := strings.IndexByte(line, '{')
		if open < 0 {
			out.WriteString(line)
			return out.String()
		}
		close := strings.IndexByte(line[open+1:], '}')
		if close < 0 {
			return ""
		}
		close += open + 1
		out.WriteString(line[:open])
		out.WriteString(fields[line[open+1:close]].Text())
		line = line[close+1:]
	}
}
