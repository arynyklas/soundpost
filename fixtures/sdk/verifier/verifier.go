// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package verifier is the independent record verifier of decision D8 for the SDK critical-path fixtures
// (critical_path.py, gateway.ts, the Node/Bun/browser fixtures). It is a TEST FIXTURE, not a product route.
//
// The fixture POSTs {org_id, project_id, batch_ids, minimum_receipts, trace_ids, start_ns, end_ns} with an
// independent reader credential. The verifier never touches the SDK, the ingest path or private storage: it
// replays the caller's own bearer credential against the product's existing authenticated read route
// (POST /api/v1/exports: create, status, download) for the span, error, loss and job_attempt signals and returns what the
// product serves, as {partial, records:[{id,kind,payload}]}.
//
// Honest limit: no product read route exposes ingest batch ids or receipt cursors, so records are matched by the
// 128-bit record ids the fixture listed before sending (a record visible through the read route was durably
// admitted), not by batch id. The request's batch ids are echoed back as `unmatched_batch_ids` = all of them,
// `batch_matching` names the method, and the caller may not treat them as verified.
package verifier

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/fixtures/sdk/estate"
	"github.com/arynyklas/soundpost/internal/model"
)

// Record is one record as served by the product.
type Record struct {
	ID      string         `json:"id"`
	Kind    string         `json:"kind"`
	Payload map[string]any `json:"payload"`
}

// Serve starts the HTTPS verifier on a free loopback port and returns its URL and a stop function.
func Serve(est *estate.Estate) (string, func()) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	estate.Must(err, "verifier listen")
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { handle(est, w, r) })
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, TLSConfig: &tls.Config{Certificates: []tls.Certificate{est.TLSCertificate()}, MinVersion: tls.VersionTLS13}}
	go func() { _ = srv.ServeTLS(l, "", "") }()
	return "https://" + l.Addr().String() + "/", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}

func handle(est *estate.Estate, w http.ResponseWriter, r *http.Request) {
	reader := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if r.Method != http.MethodPost || reader == "" || reader == r.Header.Get("Authorization") {
		http.Error(w, "reader credential required", http.StatusUnauthorized)
		return
	}
	var body struct {
		Org      string   `json:"org_id"`
		Project  string   `json:"project_id"`
		Batches  []string `json:"batch_ids"`
		TraceIDs []string `json:"trace_ids"`
		Signals  []string `json:"signals"`
	}
	raw := new(bytes.Buffer)
	if _, err := raw.ReadFrom(http.MaxBytesReader(w, r.Body, 1<<20)); err != nil || json.Unmarshal(raw.Bytes(), &body) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	org, e1 := model.ParseID(body.Org)
	project, e2 := model.ParseID(body.Project)
	if e1 != nil || e2 != nil {
		http.Error(w, "bad identity", http.StatusBadRequest)
		return
	}
	// The export route allows only a few live exports per principal, so a caller names the signals it needs
	// (default: spans only); one verification call never needs more than three.
	signals := []model.Kind{model.SpanKind}
	if len(body.Signals) > 0 {
		signals = nil
		for _, s := range body.Signals {
			switch model.Kind(s) {
			case model.SpanKind, model.ErrorKind, model.Loss, model.JobAttempt:
				signals = append(signals, model.Kind(s))
			default:
				http.Error(w, "unsupported signal", http.StatusBadRequest)
				return
			}
		}
	}
	records, err := Fetch(est, reader, org, project, signals...)
	if err != nil {
		estate.Logf("verifier: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"partial": false, "records": records, "batch_matching": "record_id", "unmatched_batch_ids": body.Batches, "route": "/api/v1/exports"})
}

// Fetch reads every span, error and loss record of the project through the product's export route under the
// caller's own reader credential.
func Fetch(est *estate.Estate, reader string, org, project model.ID, signals ...model.Kind) ([]Record, error) {
	if len(signals) == 0 {
		signals = []model.Kind{model.SpanKind, model.ErrorKind, model.Loss}
	}
	now := time.Now()
	start, end := now.Add(-3*time.Hour).UnixNano(), now.Add(time.Hour).UnixNano()
	var records []Record
	for _, signal := range signals {
		rows, err := exportSignal(est, reader, org, project, signal, start, end)
		if err != nil {
			return nil, fmt.Errorf("export %s: %w", signal, err)
		}
		records = append(records, rows...)
	}
	return records, nil
}

func exportSignal(est *estate.Estate, reader string, org, project model.ID, signal model.Kind, start, end int64) ([]Record, error) {
	status, raw := est.Post("/api/v1/exports", map[string]any{"operation": "create", "org": org, "project": project, "signal": signal, "start_ns": fmt.Sprint(start), "end_ns": fmt.Sprint(end)}, reader)
	if status != http.StatusAccepted {
		return nil, fmt.Errorf("create status %d: %s", status, estate.Tail(string(raw)))
	}
	var grant struct {
		Operation struct {
			ID model.ID `json:"id"`
		} `json:"operation"`
		Ticket string `json:"ticket"`
	}
	if err := json.Unmarshal(raw, &grant); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		status, raw = est.Post("/api/v1/exports", map[string]any{"operation": "status", "org": org, "project": project, "id": grant.Operation.ID}, reader)
		if status != 200 {
			return nil, fmt.Errorf("status route %d: %s", status, estate.Tail(string(raw)))
		}
		var op struct {
			Phase      string `json:"phase"`
			SafeReason string `json:"safe_reason"`
		}
		if err := json.Unmarshal(raw, &op); err != nil {
			return nil, err
		}
		if op.Phase == "complete" {
			break
		}
		if op.Phase == "failed" || time.Now().After(deadline) {
			return nil, fmt.Errorf("export %s (%s)", op.Phase, op.SafeReason)
		}
		time.Sleep(200 * time.Millisecond)
	}
	status, raw = est.Post("/api/v1/exports", map[string]any{"operation": "download", "org": org, "project": project, "id": grant.Operation.ID, "ticket": grant.Ticket}, reader)
	if status != 200 {
		return nil, fmt.Errorf("download status %d", status)
	}
	var out []Record
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var row struct {
			ID      string         `json:"id"`
			Payload map[string]any `json:"payload"`
		}
		if err := json.Unmarshal(sc.Bytes(), &row); err != nil {
			return nil, err
		}
		// model.Payload serializes every member; exactly one is non-null.
		var inner map[string]any
		for _, member := range row.Payload {
			if m, ok := member.(map[string]any); ok {
				inner = m
			}
		}
		if inner == nil {
			return nil, fmt.Errorf("row %s has no payload member", row.ID)
		}
		out = append(out, Record{ID: row.ID, Kind: string(signal), Payload: inner})
	}
	return out, sc.Err()
}
