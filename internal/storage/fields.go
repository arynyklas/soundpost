// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"encoding/hex"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/model"
	"strconv"
)

func nativeIDField(p Page, i int, name string) (model.ID, bool) {
	v := p.Values[i]
	switch name {
	case "id":
		return p.IDs[i], true
	case "source_id":
		return p.Sources[i], true
	case "service_id":
		return p.Resources[i].Service, true
	case "environment_id":
		return p.Resources[i].Environment, true
	case "build_id":
		return p.Resources[i].Build, true
	case "trace_id":
		if v.Span != nil {
			return v.Span.Trace, true
		}
		if v.Log != nil && v.Log.Trace != nil {
			return *v.Log.Trace, true
		}
		if v.Error != nil && v.Error.Trace != nil {
			return *v.Error.Trace, true
		}
	case "occurrence_id":
		if v.Error != nil {
			return v.Error.Occurrence, true
		}
	case "job_id":
		if v.Job != nil {
			return v.Job.Job, true
		}
		if v.Span != nil && v.Span.Job != nil {
			return *v.Span.Job, true
		}
	case "run_id":
		if v.Job != nil {
			return v.Job.Run, true
		}
		if v.Log != nil && v.Log.Run != nil {
			return *v.Log.Run, true
		}
		if v.Error != nil && v.Error.Run != nil {
			return *v.Error.Run, true
		}
	case "attempt_id":
		if v.Job != nil {
			return v.Job.Attempt, true
		}
	case "replay_id":
		if v.Replay != nil {
			return v.Replay.Replay, true
		}
		if v.Error != nil && v.Error.Replay != nil {
			return *v.Error.Replay, true
		}
		if v.Span != nil && v.Span.Replay != nil {
			return *v.Span.Replay, true
		}
	case "session_id":
		if v.Replay != nil {
			return v.Replay.Session, true
		}
	case "profile_id":
		if v.Profile != nil {
			return v.Profile.Profile, true
		}
		if v.Error != nil && v.Error.Profile != nil {
			return *v.Error.Profile, true
		}
		if v.Span != nil && v.Span.Profile != nil {
			return *v.Span.Profile, true
		}
	case "process_id":
		if v.Profile != nil {
			return v.Profile.Process, true
		}
	case "capability_id":
		if v.Profile != nil {
			return v.Profile.Capability, true
		}
	case "condition_id":
		if v.Condition != nil {
			return v.Condition.Condition, true
		}
	case "producer_id":
		if v.Loss != nil {
			return v.Loss.Producer, true
		}
	case "epoch_id":
		if v.Job != nil {
			return v.Job.Epoch, true
		}
		if v.Loss != nil {
			return v.Loss.Epoch, true
		}
		if v.Condition != nil {
			return v.Condition.Epoch, true
		}
	case "release_id":
		if v.Error != nil && v.Error.Release != nil {
			return *v.Error.Release, true
		}
	}
	return model.ID{}, false
}
func isIDField(name string) bool {
	switch name {
	case "id", "source_id", "service_id", "environment_id", "build_id", "trace_id", "occurrence_id", "job_id", "run_id", "attempt_id", "replay_id", "session_id", "profile_id", "process_id", "capability_id", "condition_id", "producer_id", "epoch_id", "release_id":
		return true
	}
	return false
}
func nativeSpanField(p Page, i int) (model.SpanID, bool) {
	v := p.Values[i]
	if v.Span != nil {
		return v.Span.ID, true
	}
	if v.Log != nil && v.Log.Span != nil {
		return *v.Log.Span, true
	}
	if v.Error != nil && v.Error.Span != nil {
		return *v.Error.Span, true
	}
	return model.SpanID{}, false
}
func parseSpanLiteral(text string) (model.SpanID, bool) {
	var out model.SpanID
	b, err := hex.DecodeString(text)
	if err != nil || len(b) != 8 || hex.EncodeToString(b) != text {
		return out, false
	}
	copy(out[:], b)
	return out, out != (model.SpanID{})
}
func spanText(id model.SpanID) string { return hex.EncodeToString(id[:]) }
func nativeValueField(p Page, i int, name string) (Literal, bool) {
	return nativePayloadValue(&p.Values[i], p.Loss[i], name)
}
func nativePayloadValue(v *model.Payload, loss uint64, name string) (Literal, bool) {
	text := func(s string) (Literal, bool) { return Literal{Kind: LiteralString, String: s}, true }
	count := func(n model.Uint64) (Literal, bool) { return Literal{Kind: LiteralUnsigned, Unsigned: uint64(n)}, true }
	boolean := func(b bool) (Literal, bool) { return Literal{Kind: LiteralBoolean, Boolean: b}, true }
	bits := func(b model.FloatBits) (Literal, bool) { return Literal{Kind: LiteralFloatBits, Bits: b}, true }
	switch name {
	case "name":
		if v.Metric != nil {
			return text(v.Metric.Name)
		}
	case "line":
		if v.Log != nil {
			return text(v.Log.Line)
		}
	case "template_id":
		if v.Log != nil {
			return text(v.Log.TemplateID)
		}
	case "unit":
		if v.Metric != nil {
			return text(v.Metric.Unit)
		}
	case "type":
		if v.Metric != nil {
			return text(v.Metric.Type)
		}
	case "sample_kind":
		if v.Metric != nil {
			return text(v.Metric.SampleKind)
		}
	case "float_bits":
		if v.Metric != nil && v.Metric.Value != nil {
			return bits(*v.Metric.Value)
		}
	case "histogram_count":
		if v.Metric != nil && v.Metric.Histogram != nil && v.Metric.Histogram.Integer != nil {
			return count(v.Metric.Histogram.Integer.Count)
		}
	case "histogram_count_bits":
		if v.Metric != nil && v.Metric.Histogram != nil && v.Metric.Histogram.Float != nil {
			return bits(v.Metric.Histogram.Float.Count)
		}
	case "exception_class":
		if v.Error != nil {
			return text(v.Error.Class)
		}
	case "mechanism":
		if v.Error != nil {
			return text(v.Error.Mechanism)
		}
	case "handled":
		if v.Error != nil {
			return boolean(v.Error.Handled)
		}
	case "fatal":
		if v.Error != nil {
			return boolean(v.Error.Fatal)
		}
	case "operation":
		if v.Span != nil {
			return text(v.Span.Operation)
		}
	case "dependency_alias":
		if v.Span != nil {
			return text(v.Span.Dependency)
		}
	case "state":
		if v.Job != nil {
			return text(v.Job.State)
		}
	case "status":
		if v.Span != nil {
			return text(v.Span.Status)
		}
		if v.Capability != nil {
			return text(v.Capability.Status)
		}
		if v.Condition != nil {
			return text(v.Condition.Status)
		}
	case "severity":
		if v.Log != nil {
			return text(v.Log.Severity)
		}
		if v.Condition != nil {
			return text(v.Condition.Severity)
		}
	case "ordinal":
		if v.Job != nil {
			return count(v.Job.Ordinal)
		}
	case "sequence":
		if v.Job != nil {
			return count(v.Job.Sequence)
		}
		if v.Replay != nil {
			return count(v.Replay.Sequence)
		}
		if v.Condition != nil {
			return count(v.Condition.Sequence)
		}
	case "checkpoint_sequence":
		if v.Replay != nil {
			return count(v.Replay.CheckpointSequence)
		}
	case "gap":
		if v.Replay != nil {
			return boolean(v.Replay.Gap)
		}
	case "truncated":
		if v.Profile != nil {
			return boolean(v.Profile.Truncated)
		}
	case "method":
		if v.Profile != nil {
			return text(v.Profile.Method)
		}
		if v.Capability != nil {
			return text(v.Capability.Method)
		}
	case "units":
		if v.Profile != nil {
			return text(v.Profile.Units)
		}
	case "runtime":
		if v.Capability != nil {
			return text(v.Capability.Runtime)
		}
	case "runtime_version":
		if v.Capability != nil {
			return text(v.Capability.Version)
		}
	case "reason":
		if v.Capability != nil {
			return text(v.Capability.Reason)
		}
		if v.Loss != nil {
			return text(v.Loss.Reason)
		}
	case "signal":
		if v.Capability != nil {
			return text(string(v.Capability.Signal))
		}
		if v.Loss != nil {
			return text(string(v.Loss.Signal))
		}
	case "count":
		if v.Loss != nil {
			return count(v.Loss.Count)
		}
	case "queue_bytes":
		if v.Loss != nil {
			return count(v.Loss.QueueBytes)
		}
	case "queue_records":
		if v.Loss != nil {
			return count(v.Loss.QueueRecords)
		}
	case "loss":
		return count(model.Uint64(loss))
	}
	return Literal{}, false
}
func equalLiteral(a, b Literal) bool {
	if a.Kind == LiteralInteger && b.Kind == LiteralUnsigned {
		return a.Integer >= 0 && uint64(a.Integer) == b.Unsigned
	}
	if b.Kind == LiteralInteger && a.Kind == LiteralUnsigned {
		return b.Integer >= 0 && a.Unsigned == uint64(b.Integer)
	}
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case LiteralString:
		return a.String == b.String
	case LiteralInteger:
		return a.Integer == b.Integer
	case LiteralUnsigned:
		return a.Unsigned == b.Unsigned
	case LiteralFloatBits:
		return a.Bits == b.Bits
	case LiteralBoolean:
		return a.Boolean == b.Boolean
	case LiteralNull:
		return true
	}
	return false
}
func scalarLiteral(s model.Scalar) Literal {
	raw, _ := s.MarshalJSON()
	if len(raw) == 0 {
		return Literal{Kind: LiteralNull}
	}
	if raw[0] == '"' {
		var value string
		_ = json.Unmarshal(raw, &value)
		return Literal{Kind: LiteralString, String: value}
	}
	switch string(raw) {
	case "null":
		return Literal{Kind: LiteralNull}
	case "true":
		return Literal{Kind: LiteralBoolean, Boolean: true}
	case "false":
		return Literal{Kind: LiteralBoolean}
	default:
		value, _ := strconv.ParseInt(string(raw), 10, 64)
		return Literal{Kind: LiteralInteger, Integer: value}
	}
}
