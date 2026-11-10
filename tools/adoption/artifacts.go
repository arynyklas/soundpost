// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"soundpost/internal/httpapi"
	"soundpost/internal/sourcemap"
)

// This file is how the journey verifier acquires evidence: scoped, read-only
// product reads over the committed investigation routes, plus the local source
// map identity of a build supplied by the operator. It never reads telemetry
// from the application itself, never follows redirects and never copies a
// response body into an error: a failed read is one of three closed errors.

// The closed read failures. None carries response text.
var (
	journeyErrNotFound = errors.New("target not found in the authorized scope")
	journeyErrDenied   = errors.New("credential not accepted for this read")
	journeyErrFailed   = errors.New("product read failed")
)

const (
	journeyMaxResponseBytes = 16 << 20
	journeyMaxMapBytes      = 32 << 20
	journeyReadTimeout      = 30 * time.Second
)

// JourneyReader is the consumer-owned seam over the scoped product reads. The
// HTTP implementation below is the production one; tests substitute loopback
// fixtures or in-process engines behind the same interface.
type JourneyReader interface {
	Trace(ctx context.Context, body httpapi.TraceBody) (httpapi.TraceView, error)
	Frames(ctx context.Context, body httpapi.FramesBody) (httpapi.FramesView, error)
	Release(ctx context.Context, body httpapi.ReleaseBody) (httpapi.ReleaseView, error)
	Issue(ctx context.Context, body httpapi.IssueBody) (httpapi.IssueView, error)
	Job(ctx context.Context, body httpapi.JobViewBody) (httpapi.JobView, error)
	Replay(ctx context.Context, body httpapi.ReplayBody) ([]httpapi.ReplayLine, error)
	Profile(ctx context.Context, body httpapi.ProfileBody) (httpapi.ProfileResponse, error)
}

// journeyHTTPReader reads one Soundpost server with one bearer token.
type journeyHTTPReader struct {
	base   *url.URL
	bearer string
	client *http.Client
}

func journeyLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func journeyBearerValid(token string) bool {
	if token == "" || len(token) > 4096 {
		return false
	}
	for _, r := range token {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// journeyServerURL validates a server base URL: http(s), a host, no
// credentials, no query, no fragment and no path. The bearer is only ever sent
// to this origin, and only in clear text when the host is loopback.
func journeyServerURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("invalid server URL")
	}
	if u.Scheme == "http" && !journeyLoopbackHost(u.Hostname()) {
		return nil, errors.New("bearer is only sent over https, or http to a loopback host")
	}
	return u, nil
}

func newJourneyHTTPReader(serverURL, bearer string) (*journeyHTTPReader, error) {
	u, err := journeyServerURL(serverURL)
	if err != nil {
		return nil, err
	}
	if !journeyBearerValid(bearer) {
		return nil, errors.New("invalid bearer")
	}
	client := &http.Client{
		Timeout:       journeyReadTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
	}
	return &journeyHTTPReader{base: u, bearer: bearer, client: client}, nil
}

// post sends one JSON body and returns the bounded raw response. Only status
// classes are surfaced; the body of a failed response is discarded unread.
func (r *journeyHTTPReader) post(ctx context.Context, path string, body any) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, journeyErrFailed
	}
	target := *r.base
	target.Path = path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, journeyErrFailed
	}
	req.Header.Set("Authorization", "Bearer "+r.bearer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, journeyErrFailed
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, journeyErrNotFound
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, journeyErrDenied
	case resp.StatusCode != http.StatusOK:
		return nil, journeyErrFailed
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, journeyMaxResponseBytes+1))
	if err != nil || len(raw) > journeyMaxResponseBytes {
		return nil, journeyErrFailed
	}
	return raw, nil
}

func journeyPostJSON[T any](ctx context.Context, r *journeyHTTPReader, path string, body any) (T, error) {
	var out T
	raw, err := r.post(ctx, path, body)
	if err != nil {
		return out, err
	}
	if json.Unmarshal(raw, &out) != nil {
		return out, journeyErrFailed
	}
	return out, nil
}

func (r *journeyHTTPReader) Trace(ctx context.Context, body httpapi.TraceBody) (httpapi.TraceView, error) {
	return journeyPostJSON[httpapi.TraceView](ctx, r, "/api/v1/traces/view", body)
}
func (r *journeyHTTPReader) Frames(ctx context.Context, body httpapi.FramesBody) (httpapi.FramesView, error) {
	return journeyPostJSON[httpapi.FramesView](ctx, r, "/api/v1/evidence/frames", body)
}
func (r *journeyHTTPReader) Release(ctx context.Context, body httpapi.ReleaseBody) (httpapi.ReleaseView, error) {
	return journeyPostJSON[httpapi.ReleaseView](ctx, r, "/api/v1/evidence/release", body)
}
func (r *journeyHTTPReader) Issue(ctx context.Context, body httpapi.IssueBody) (httpapi.IssueView, error) {
	return journeyPostJSON[httpapi.IssueView](ctx, r, "/api/v1/evidence/issue", body)
}
func (r *journeyHTTPReader) Job(ctx context.Context, body httpapi.JobViewBody) (httpapi.JobView, error) {
	return journeyPostJSON[httpapi.JobView](ctx, r, "/api/v1/jobs/view", body)
}
func (r *journeyHTTPReader) Profile(ctx context.Context, body httpapi.ProfileBody) (httpapi.ProfileResponse, error) {
	return journeyPostJSON[httpapi.ProfileResponse](ctx, r, "/api/v1/profiles/view", body)
}

// Replay reads the NDJSON replay stream. A line that does not decode as a
// ReplayLine, or a stream larger than the response bound, is a failed read.
func (r *journeyHTTPReader) Replay(ctx context.Context, body httpapi.ReplayBody) ([]httpapi.ReplayLine, error) {
	raw, err := r.post(ctx, "/api/v1/replays/stream", body)
	if err != nil {
		return nil, err
	}
	var lines []httpapi.ReplayLine
	for _, part := range bytes.Split(raw, []byte{'\n'}) {
		if len(bytes.TrimSpace(part)) == 0 {
			continue
		}
		var line httpapi.ReplayLine
		if json.Unmarshal(part, &line) != nil {
			return nil, journeyErrFailed
		}
		lines = append(lines, line)
	}
	return lines, nil
}

// journeyMapIdentity is the exact identity of one operator-supplied build map:
// its SHA-256 and the decoded map, so an expected original position can be
// checked against the build rather than typed by hand.
type journeyMapIdentity struct {
	SHA256 string
	Map    *sourcemap.Map
}

func journeyDecodeMap(raw []byte) (journeyMapIdentity, error) {
	if len(raw) == 0 || len(raw) > journeyMaxMapBytes {
		return journeyMapIdentity{}, errors.New("map size out of bounds")
	}
	sum := sha256.Sum256(raw)
	m, err := sourcemap.Decode(bytes.NewReader(raw), sourcemap.Limits{})
	if err != nil {
		return journeyMapIdentity{}, errors.New("map does not decode")
	}
	return journeyMapIdentity{SHA256: hex.EncodeToString(sum[:]), Map: m}, nil
}
