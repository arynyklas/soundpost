// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package queryinput_test

// Cross-check of the Loki push decoder against bytes produced by the unmodified upstream
// promtail client of the pinned Loki (02.08#12; capture program and provenance in
// conformance/query/fixtures/adapters/real/PROVENANCE.json "loki_push"). The expectation is
// loki-push-sent.json: the entries fed to that client, never anything the decoder produced.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	. "github.com/arynyklas/soundpost/internal/adapters/queryinput"
	"github.com/arynyklas/soundpost/internal/adapters/queryinput/corpus"
)

func TestRealPromtailPushBodiesDecodeToTheEntriesTheClientSent(t *testing.T) {
	var sent []struct {
		Labels   map[string]string `json:"labels"`
		TimeNS   int64             `json:"timestamp_ns"`
		Line     string            `json:"line"`
		Metadata map[string]string `json:"structured_metadata"`
	}
	if err := json.Unmarshal(realFile(t, "loki-push-sent.json"), &sent); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 8 {
		t.Fatalf("sent manifest lists %d entries", len(sent))
	}
	var headers map[string]string
	e := newRealEnv(t)
	cfg := e.cfg
	cfg.Loki.Encoding = EncodingProtobufSnappy
	// The registered template of the harness declares only `tenant`: a real request carrying other
	// structured metadata keys is refused, never stored with the keys dropped.
	if _, err := DecodeLokiPush(t.Context(), e.g, bytes.NewReader(realFile(t, "loki-push-002.bin")), cfg); err == nil {
		t.Fatal("structured metadata keys outside the template were accepted")
	} else if reason, _ := detailOf(err); reason != ReasonUnrepresentable {
		t.Fatalf("undeclared structured metadata keys: %v", err)
	}
	cfg.Loki.MetadataFields = append(append([]string(nil), cfg.Loki.MetadataFields...), "trace_id", "level")
	var projected []string
	for _, path := range realFiles(t, "loki-push-0*.bin") {
		if err := json.Unmarshal(realFile(t, strings.TrimSuffix(path[strings.LastIndex(path, "/")+1:], ".bin")+".headers.json"), &headers); err != nil {
			t.Fatal(err)
		}
		if headers["Content-Type"] != "application/x-protobuf" || headers["path"] != "/loki/api/v1/push" {
			t.Fatalf("%s: unexpected client headers %v", path, headers)
		}
		batches, err := DecodeLokiPush(t.Context(), e.g, bytes.NewReader(realFile(t, path[strings.LastIndex(path, "/")+1:])), cfg)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, record := range corpus.ProjectRecords(batches) {
			raw, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			projected = append(projected, string(raw))
		}
	}
	if len(projected) != len(sent) {
		t.Fatalf("decoded %d records from the captured requests, the client sent %d entries", len(projected), len(sent))
	}
	for _, s := range sent {
		line, _ := json.Marshal(s.Line)
		found := false
		for _, p := range projected {
			if strings.Contains(p, string(line)) {
				found = true
				if !strings.Contains(p, strconv.FormatInt(s.TimeNS, 10)) {
					t.Errorf("entry %q: timestamp %d not preserved in %s", s.Line[:min(len(s.Line), 20)], s.TimeNS, p[:min(len(p), 300)])
				}
				for k, v := range s.Labels {
					if !strings.Contains(p, fmt.Sprintf("%q", k)) || !strings.Contains(p, fmt.Sprintf("%q", v)) {
						t.Errorf("entry %q: stream label %s=%s missing in %s", s.Line[:min(len(s.Line), 20)], k, v, p[:min(len(p), 300)])
					}
				}
				for k, v := range s.Metadata {
					if !strings.Contains(p, v) {
						t.Errorf("entry %q: structured metadata %s=%s missing", s.Line[:min(len(s.Line), 20)], k, v)
					}
				}
			}
		}
		if !found {
			t.Errorf("entry %q was not decoded", s.Line[:min(len(s.Line), 20)])
		}
	}
}
