// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package queryinput

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sort"
	"strconv"

	"github.com/arynyklas/soundpost/internal/ingest"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/policy"
)

const fmtConditions = "condition_webhook"

// ConditionsSchemaVersion is the only version of the closed condition webhook.
const ConditionsSchemaVersion = 1

// maxConditionName bounds a source's own condition and epoch names.
const maxConditionName = 128

// conditionsWire is the closed, versioned body of the condition webhook. It
// carries C04 condition events and nothing else: no free text, no annotations,
// no URLs, no arbitrary source payload. Unknown fields and duplicate keys are
// rejected, so a sender cannot smuggle content through the translator.
//
//	{"version":1,"events":[{
//	  "condition":"checkout-latency",      the source's own condition name
//	  "epoch":"2026-11-15.1",              the source's producer epoch
//	  "sequence":"42",                     optional; decimal string >= 1
//	  "event_time_ns":"1700000000000000000",
//	  "status":"firing|recovered|unknown",
//	  "severity":"info|warning|error|critical",
//	  "labels":{"job":"api"},              approved labels only (source policy)
//	  "links":["<32-hex id>"]}]}           optional C04 link IDs
//
// Condition and epoch identities inside Soundpost are derived from the names and
// are bound to the authenticated project and source, so the same name from two
// sources or projects never collides.
type conditionsWire struct {
	Version int                  `json:"version"`
	Events  []conditionEventWire `json:"events"`
}

type conditionEventWire struct {
	Condition string            `json:"condition"`
	Epoch     string            `json:"epoch"`
	Sequence  *string           `json:"sequence"`
	EventNS   string            `json:"event_time_ns"`
	Status    string            `json:"status"`
	Severity  string            `json:"severity"`
	Labels    map[string]string `json:"labels"`
	Links     []string          `json:"links"`
}

// DecodeConditions translates a closed condition webhook body into condition
// admission batches: one canonical-owner slot and a stable identity per batch,
// derived from the body, so a retried request yields the same batches.
func DecodeConditions(ctx context.Context, grant policy.SourceGrant, input io.Reader, cfg InputProfile) ([]ingest.Batch, error) {
	const format = fmtConditions
	if err := cfg.validate(format); err != nil {
		return nil, err
	}
	cfg, err := bind(format, grant, cfg)
	if err != nil {
		return nil, err
	}
	if err := ctxErr(format, ctx); err != nil {
		return nil, err
	}
	body, err := readBounded(format, input, cfg.Limits.MaxCompressedBytes)
	if err != nil {
		return nil, err
	}
	bad := func(detail string) error { return fail(format, ReasonMalformed, detail) }
	if model.ValidateJSON(body) != nil {
		return nil, bad("json")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var wire conditionsWire
	if err := dec.Decode(&wire); err != nil {
		return nil, bad("json_shape")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, bad("json_trailing")
	}
	if wire.Version != ConditionsSchemaVersion {
		return nil, fail(format, ReasonUnrepresentable, "schema_version")
	}
	if len(wire.Events) == 0 {
		return nil, bad("empty_request")
	}
	if len(wire.Events) > cfg.Limits.MaxSamples {
		return nil, fail(format, ReasonLimit, "events")
	}
	a := &assembler{format: format, cfg: cfg, request: requestDigest(format, cfg, body)}
	for i := range wire.Events {
		if i&255 == 0 {
			if err := ctxErr(format, ctx); err != nil {
				return nil, err
			}
		}
		rec, err := conditionRecord(format, cfg, a.request[:], i, wire.Events[i], &a.report)
		if err != nil {
			return nil, err
		}
		a.add(rec)
	}
	return a.finish(ctx)
}

func safeConditionName(s string) bool {
	if s == "" || len(s) > maxConditionName {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == ':' || c == '-') {
			return false
		}
	}
	return true
}

// canonicalDecimal parses a canonical (no sign, no leading zero) decimal string.
func canonicalDecimal(s string) (uint64, bool) {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || strconv.FormatUint(v, 10) != s {
		return 0, false
	}
	return v, true
}

func conditionRecord(format string, cfg InputProfile, request []byte, ordinal int, w conditionEventWire, rep *NormalizationReport) (model.Record, error) {
	bad := func(detail string) (model.Record, error) {
		return model.Record{}, fail(format, ReasonMalformed, detail)
	}
	if !safeConditionName(w.Condition) {
		return bad("condition")
	}
	if !safeConditionName(w.Epoch) {
		return bad("epoch")
	}
	var seq uint64
	if w.Sequence != nil {
		v, ok := canonicalDecimal(*w.Sequence)
		if !ok || v == 0 {
			return bad("sequence")
		}
		seq = v
	}
	ns, ok := canonicalDecimal(w.EventNS)
	if !ok || ns > uint64(1<<63-1) {
		return bad("event_time_ns")
	}
	at := model.UnixNano(ns)
	if !inBounds(cfg, at) {
		return model.Record{}, fail(format, ReasonTimestampRange, "event_time_ns")
	}
	switch w.Status {
	case "firing", "recovered", "unknown":
	default:
		return bad("status")
	}
	switch w.Severity {
	case "info", "warning", "error", "critical":
	default:
		return bad("severity")
	}
	labels := make(model.Labels, 0, len(w.Labels))
	for k, v := range w.Labels {
		labels = append(labels, model.Label{Name: k, Value: v})
	}
	sort.Slice(labels, func(i, j int) bool { return labels[i].Name < labels[j].Name })
	labels, err := cleanLabels(format, labels, cfg, rep)
	if err != nil {
		return model.Record{}, err
	}
	if len(w.Links) > 64 {
		return model.Record{}, fail(format, ReasonLimit, "links")
	}
	links := make([]model.ID, 0, len(w.Links))
	seenLink := map[model.ID]bool{}
	for _, l := range w.Links {
		id, err := model.ParseID(l)
		if err != nil || seenLink[id] {
			return bad("link")
		}
		seenLink[id] = true
		links = append(links, id)
	}
	condition := deriveID("condition", cfg.Project[:], cfg.Source[:], []byte(w.Condition))
	epoch := deriveID("condition-epoch", cfg.Project[:], cfg.Source[:], []byte(w.Epoch))
	var id model.ID
	if seq > 0 {
		id = deriveID("condition-record", condition[:], epoch[:], u64bytes(seq))
	} else {
		id = deriveID("condition-record", request, u64bytes(uint64(ordinal)))
	}
	return model.Record{
		ID: id, Kind: model.Condition, ObservedAt: at, Resource: cfg.Resource,
		Payload: model.Payload{Condition: &model.ConditionEvent{
			Condition: condition, Epoch: epoch, Sequence: model.Uint64(seq), At: at,
			Status: w.Status, Severity: w.Severity, Labels: labels, Links: links,
		}},
	}, nil
}
