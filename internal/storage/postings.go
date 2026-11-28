// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"github.com/arynyklas/soundpost/internal/model"
	"strconv"
)

// Closed native scalar fields are indexed with their exact type, never float64.
var nativePostingFields = map[model.Kind][]string{
	model.Metric:         {"unit", "type", "sample_kind", "float_bits", "histogram_count", "histogram_count_bits"},
	model.Log:            {"loss"},
	model.SpanKind:       {"operation", "dependency_alias", "status"},
	model.ErrorKind:      {"exception_class", "mechanism", "handled", "fatal"},
	model.JobAttempt:     {"state", "ordinal", "sequence"},
	model.Replay:         {"sequence", "checkpoint_sequence", "gap", "loss"},
	model.Profile:        {"method", "units", "truncated", "loss"},
	model.CapabilityKind: {"runtime", "runtime_version", "method", "status", "reason", "signal"},
	model.Loss:           {"count", "reason", "queue_bytes", "queue_records", "loss", "signal"},
	model.Condition:      {"sequence", "status"},
}

func literalKey(v Literal) string {
	switch v.Kind {
	case LiteralString:
		return "s:" + v.String
	case LiteralInteger:
		if v.Integer < 0 {
			return "i:" + strconv.FormatInt(v.Integer, 10)
		}
		return "u:" + strconv.FormatInt(v.Integer, 10)
	case LiteralUnsigned:
		return "u:" + strconv.FormatUint(v.Unsigned, 10)
	case LiteralFloatBits:
		return "f:" + strconv.FormatUint(uint64(v.Bits), 16)
	case LiteralBoolean:
		return "b:" + strconv.FormatBool(v.Boolean)
	case LiteralNull:
		return "n:"
	}
	return ""
}
func nativePosting(kind model.Kind, name string) bool {
	for _, field := range nativePostingFields[kind] {
		if field == name {
			return true
		}
	}
	return false
}
func logScalarPosting(name string) bool {
	return !isIDField(name) && name != "span_id" && name != "line" && name != "severity" && name != "template_id" && name != "loss"
}
func payloadLoss(v *model.Payload) uint64 {
	if v.Loss != nil {
		return uint64(v.Loss.Count)
	}
	if v.Replay != nil {
		return uint64(v.Replay.Loss)
	}
	if v.Profile != nil {
		return uint64(v.Profile.Loss)
	}
	return 0
}
func typedRecordTerms(r model.Record, terms []string) []string {
	for _, name := range nativePostingFields[r.Kind] {
		if value, ok := nativePayloadValue(&r.Payload, payloadLoss(&r.Payload), name); ok {
			terms = append(terms, "typed:"+name+"="+literalKey(value))
		}
	}
	if r.Payload.Log != nil {
		for name, value := range r.Payload.Log.Fields {
			if logScalarPosting(name) {
				terms = append(terms, "field:"+name+"="+literalKey(scalarLiteral(value)))
			}
		}
		for name, value := range r.Payload.Log.Metadata {
			if logScalarPosting(name) {
				terms = append(terms, "field:"+name+"="+literalKey(scalarLiteral(value)))
			}
		}
		for _, token := range lineTokens(r.Payload.Log.Line) {
			terms = append(terms, "token:"+token)
		}
	}
	return terms
}

// Tokens are a bounded candidate index, not LogQL parsing or a language-level
// containment operator. Exact line equality still compares immutable full bytes.
func lineTokens(line string) []string {
	tokens := make([]string, 0, 8)
	seen := map[string]bool{}
	for at := 0; at < len(line) && len(tokens) < 64; {
		for at < len(line) && !tokenByte(line[at]) {
			at++
		}
		start := at
		for at < len(line) && tokenByte(line[at]) {
			at++
		}
		if at == start {
			continue
		}
		end := at
		if end-start > 64 {
			end = start + 64
		}
		token := line[start:end]
		if !seen[token] {
			seen[token] = true
			tokens = append(tokens, token)
		}
	}
	return tokens
}
func tokenByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}
