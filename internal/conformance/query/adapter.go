// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type adapterInput struct {
	Expression string `json:"expression"`
	TimeNS     string `json:"time_ns"`
	StartNS    string `json:"start_ns"`
	EndNS      string `json:"end_ns"`
	Logs       []struct {
		Timestamp string            `json:"timestamp_ns"`
		Line      string            `json:"line"`
		Labels    map[string]string `json:"labels"`
	} `json:"logs"`
	Phase           string           `json:"phase"`
	EnabledFeatures []string         `json:"enabled_features"`
	SyntaxCases     []SyntaxProbe    `json:"syntax_cases"`
	Evaluation      *evaluationInput `json:"evaluation,omitempty"`
	LogQL           *LogQLInput      `json:"logql,omitempty"`
}

// ServeAdapter runs only inside the disposable no-network OCI sandbox. Syntax
// and sanity use the real upstream HTTP process; evaluation invokes the separate
// native driver built inside the exact pinned module/compiler. No owned query
// evaluator or production fallback is used for reference observations.
func ServeAdapter(ctx context.Context, profileID string, input io.Reader, output io.Writer) error {
	commit, ok := exactPins[profileID]
	if !ok {
		return fmt.Errorf("unknown pinned profile")
	}
	var fixture adapterInput
	if e := json.NewDecoder(input).Decode(&fixture); e != nil {
		return e
	}
	if fixture.LogQL != nil {
		if profileID != logQLProfile {
			return fmt.Errorf("native LogQL payload requires exact Loki profile")
		}
		return ServeLogQLAdapter(ctx, profileID, fixture.LogQL, output)
	}
	if profileID == logQLProfile && fixture.Phase != "" {
		return fmt.Errorf("native LogQL phase requires typed input; no HTTP fallback")
	}
	if fixture.Phase == "evaluation" {
		return serveEvaluationAdapter(ctx, profileID, fixture.Evaluation, output)
	}
	loki := strings.HasPrefix(profileID, "logql-")
	binary := "/bin/prometheus"
	args := []string{"--config.file=/fixture/configuration", "--storage.tsdb.path=/tmp/data", "--web.listen-address=127.0.0.1:19090"}
	base := "http://127.0.0.1:19090"
	buildPath := "/api/v1/status/buildinfo"
	if loki {
		binary = "/usr/bin/loki"
		args = []string{"-config.file=/fixture/configuration"}
		base = "http://127.0.0.1:13100"
		buildPath = "/loki/api/v1/status/buildinfo"
	}
	if fixture.Phase != "" && fixture.Phase != "syntax" {
		return fmt.Errorf("unknown oracle phase")
	}
	if fixture.Phase == "syntax" {
		if loki {
			return fmt.Errorf("PromQL syntax adapter requires Prometheus")
		}
		for _, feature := range fixture.EnabledFeatures {
			switch feature {
			case "promql-experimental-functions", "promql-duration-expr", "promql-binop-fill-modifiers", "promql-extended-range-selectors", "promql-delayed-name-removal", "type-and-unit-labels", "use-start-timestamps":
			default:
				return fmt.Errorf("unregistered syntax feature %s", feature)
			}
		}
		if len(fixture.EnabledFeatures) > 0 {
			args = append(args, "--enable-feature="+strings.Join(fixture.EnabledFeatures, ","))
		}
	}
	process := exec.CommandContext(ctx, binary, args...)
	process.Stdout = os.Stderr
	process.Stderr = os.Stderr
	if e := process.Start(); e != nil {
		return e
	}
	defer func() { _ = process.Process.Kill(); _ = process.Wait() }()
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	request := func(method, path string, body []byte) ([]byte, error) {
		req, e := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(body))
		if e != nil {
			return nil, e
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, e := client.Do(req)
		if e != nil {
			return nil, e
		}
		defer resp.Body.Close()
		b, e := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		if e != nil {
			return nil, e
		}
		if resp.StatusCode/100 != 2 {
			return nil, fmt.Errorf("upstream HTTP %d: %s", resp.StatusCode, b)
		}
		return b, nil
	}
	deadline := time.Now().Add(20 * time.Second)
	var build []byte
	for {
		var e error
		build, e = request("GET", buildPath, nil)
		if e == nil {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("upstream startup: %w", e)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	var info struct {
		Data struct {
			Revision string `json:"revision"`
			Version  string `json:"version"`
		} `json:"data"`
		Revision string `json:"revision"`
		Version  string `json:"version"`
	}
	if e := json.Unmarshal(build, &info); e != nil {
		return e
	}
	revision, version := info.Revision, info.Version
	if revision == "" {
		revision = info.Data.Revision
		version = info.Data.Version
	}
	if len(revision) < 7 || !strings.HasPrefix(commit, revision) {
		return fmt.Errorf("upstream revision mismatch: %q expected %s", revision, commit)
	}
	expectedVersion := strings.TrimPrefix(strings.TrimPrefix(profileID, "promql-prometheus-"), "logql-loki-")
	if strings.TrimPrefix(version, "v") != expectedVersion {
		return fmt.Errorf("upstream version mismatch: %s", version)
	}
	readyPath := "/-/ready"
	if loki {
		readyPath = "/ready"
	}
	deadline = time.Now().Add(20 * time.Second)
	for {
		_, e := request("GET", readyPath, nil)
		if e == nil {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("upstream readiness: %w", e)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	if fixture.Phase == "syntax" {
		observations, e := observeSyntax(ctx, client, base, fixture.SyntaxCases)
		if e != nil {
			return e
		}
		return json.NewEncoder(output).Encode(SemanticResult{Kind: "syntax", Type: "syntax", Syntax: observations, Oracle: &OracleIdentity{Profile: profileID, Revision: revision, Version: version}})
	}
	params := url.Values{"query": {fixture.Expression}}
	path := "/api/v1/query"
	if loki {
		type stream struct {
			Stream map[string]string `json:"stream"`
			Values [][2]string       `json:"values"`
		}
		streams := []stream{}
		for _, line := range fixture.Logs {
			streams = append(streams, stream{line.Labels, [][2]string{{line.Timestamp, line.Line}}})
		}
		payload, _ := json.Marshal(struct {
			Streams []stream `json:"streams"`
		}{streams})
		if _, e := request("POST", "/loki/api/v1/push", payload); e != nil {
			return e
		}
		params.Set("start", fixture.StartNS)
		params.Set("end", fixture.EndNS)
		params.Set("direction", "forward")
		path = "/loki/api/v1/query_range"
	} else {
		ns, e := strconv.ParseInt(fixture.TimeNS, 10, 64)
		if e != nil {
			return e
		}
		params.Set("time", fmt.Sprintf("%d.%09d", ns/1000000000, ns%1000000000))
	}
	method := "POST"
	if loki {
		method = "GET"
	}
	body, e := request(method, path+"?"+params.Encode(), nil)
	if e != nil {
		return e
	}
	result, e := normalizeUpstream(body, loki)
	if e != nil {
		return e
	}
	result.Oracle = &OracleIdentity{Profile: profileID, Revision: revision, Version: version}
	return json.NewEncoder(output).Encode(result)
}
func normalizeUpstream(raw []byte, loki bool) (SemanticResult, error) {
	var envelope struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string          `json:"resultType"`
			Result     json.RawMessage `json:"result"`
		} `json:"data"`
		Warnings []string `json:"warnings"`
		Infos    []string `json:"infos"`
	}
	if e := json.Unmarshal(raw, &envelope); e != nil {
		return SemanticResult{}, e
	}
	if envelope.Status != "success" {
		return SemanticResult{}, fmt.Errorf("upstream query failed: %s", raw)
	}
	r := SemanticResult{Kind: envelope.Data.ResultType, Type: envelope.Data.ResultType}
	for _, w := range envelope.Warnings {
		r.Diagnostics = append(r.Diagnostics, Diagnostic{Code: "warning", Message: w})
	}
	for _, w := range envelope.Infos {
		r.Diagnostics = append(r.Diagnostics, Diagnostic{Code: "info", Message: w})
	}
	if !loki {
		if r.Kind != "scalar" {
			return r, fmt.Errorf("sanity adapter requires scalar observation")
		}
		var pair []json.RawMessage
		if e := json.Unmarshal(envelope.Data.Result, &pair); e != nil || len(pair) != 2 {
			return r, fmt.Errorf("invalid scalar observation")
		}
		var value string
		if e := json.Unmarshal(pair[1], &value); e != nil {
			return r, e
		}
		ns, e := NormalizeSeconds(json.Number(string(pair[0])))
		if e != nil {
			return r, e
		}
		bits, e := NormalizeFloat(value)
		if e != nil {
			return r, e
		}
		r.Values = []Value{{Timestamp: ns, Bits: bits}}
		return r, nil
	}
	if r.Kind != "streams" {
		return r, fmt.Errorf("sanity adapter requires log stream observation")
	}
	r.Type = "log"
	var streams []struct {
		Stream map[string]string `json:"stream"`
		Values [][2]string       `json:"values"`
	}
	if e := json.Unmarshal(envelope.Data.Result, &streams); e != nil {
		return r, e
	}
	for _, s := range streams {
		for _, v := range s.Values {
			if _, e := strconv.ParseInt(v[0], 10, 64); e != nil {
				return r, e
			}
			r.Values = append(r.Values, Value{Timestamp: v[0], Line: v[1], Labels: s.Stream})
		}
	}
	return r, nil
}
