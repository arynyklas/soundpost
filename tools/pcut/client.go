// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/health"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
	"github.com/arynyklas/soundpost/profiles"
)

// The metric every record of the power-cut drill carries. One record is one batch, one sample of one of the
// fixture's series (label w), and its float value is the per-series sequence number: an acknowledged record is
// read back as exactly (series, observed time, sequence number).
const (
	metricName     = "pcut_writes"
	seriesLabel    = "w"
	ownerPassword  = "pcut owner password 2026"
	readerPassword = "pcut reader password 2026"
	readerEmail    = "reader@pcut.invalid"
)

// Endpoint is one voter's public HTTPS listener.
type Endpoint struct {
	Name string `json:"name"`
	ID   uint64 `json:"id"`
	URL  string `json:"url"`
}

// Fixture is what bootstrap leaves for the generator, the prober and the verifier. It carries the source credential
// and the reader password of the throwaway installation: never copy it into an evidence directory.
type Fixture struct {
	Org            string     `json:"org"`
	Project        string     `json:"project"`
	Source         string     `json:"source"`
	Service        string     `json:"service"`
	Environment    string     `json:"environment"`
	Build          string     `json:"build"`
	Credential     string     `json:"credential"`
	ReaderEmail    string     `json:"reader_email"`
	ReaderPassword string     `json:"reader_password"`
	Series         []string   `json:"series"`
	CA             string     `json:"ca"` // PEM the clients trust for the voters' public listeners
	Endpoints      []Endpoint `json:"endpoints"`
}

func loadFixture(path string) (*Fixture, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var fx Fixture
	if err = json.Unmarshal(raw, &fx); err != nil {
		return nil, fmt.Errorf("fixture %s: %w", path, err)
	}
	if fx.Credential == "" || len(fx.Series) == 0 || len(fx.Endpoints) == 0 || fx.CA == "" {
		return nil, fmt.Errorf("fixture %s is incomplete", path)
	}
	return &fx, nil
}

// fixtureIDs are the fixture's identifiers parsed once.
type fixtureIDs struct {
	org, project, source, service, environment, build model.ID
}

func (f *Fixture) ids() (fixtureIDs, error) {
	var out fixtureIDs
	var err error
	for _, p := range []struct {
		dst *model.ID
		src string
	}{{&out.org, f.Org}, {&out.project, f.Project}, {&out.source, f.Source}, {&out.service, f.Service}, {&out.environment, f.Environment}, {&out.build, f.Build}} {
		if *p.dst, err = model.ParseID(p.src); err != nil {
			return out, err
		}
	}
	return out, nil
}

// site is an HTTPS client of one voter, pinned to a CA (or to a self-signed certificate).
type site struct {
	name   string
	base   string
	client *http.Client
}

func newSite(name, base, caPath string, withJar bool) (*site, error) {
	raw, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("no certificate in %s", caPath)
	}
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
		DialContext:         (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
		TLSHandshakeTimeout: 4 * time.Second,
		IdleConnTimeout:     20 * time.Second,
		MaxIdleConnsPerHost: 16,
	}
	c := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if withJar {
		c.Jar, _ = cookiejar.New(nil)
	}
	return &site{name: name, base: base, client: c}, nil
}

func (s *site) do(method, path string, body []byte, timeout time.Duration, csrf, bearer string) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		} else {
			req.Header.Set("Origin", s.base)
			req.Header.Set("X-CSRF-Token", csrf)
		}
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 512<<20))
	return resp.StatusCode, out, err
}

func (s *site) get(path string, timeout time.Duration) (int, []byte, error) {
	return s.do("GET", path, nil, timeout, "", "")
}

func (s *site) postJSON(path string, v any, timeout time.Duration, csrf, bearer string) (int, []byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return 0, nil, err
	}
	return s.do("POST", path, raw, timeout, csrf, bearer)
}

// readyz is one /readyz answer of a voter.
type readyz struct {
	Code    int
	Ready   bool
	Reason  string
	Role    string
	Leader  uint64
	Term    uint64
	Applied string // control applied cursor, group:index
	Err     string
}

var tokenRE = regexp.MustCompile(`^[a-z_]{1,48}$`)

func safeToken(s string) string {
	if tokenRE.MatchString(s) {
		return s
	}
	return "unknown"
}

func (s *site) readyz(timeout time.Duration) readyz {
	code, raw, err := s.get("/readyz", timeout)
	if err != nil {
		return readyz{Err: transportClass(err)}
	}
	r := readyz{Code: code}
	var st health.Readiness
	if json.Unmarshal(raw, &st) != nil {
		r.Err = "decode"
		return r
	}
	r.Ready, r.Reason, r.Role, r.Leader, r.Term = st.Ready, safeToken(string(st.Reason)), string(st.Role), st.Leader, st.Term
	if st.Ready {
		r.Reason = ""
	}
	if st.Applied != nil {
		r.Applied = st.Applied.Group.String() + ":" + strconv.FormatUint(uint64(st.Applied.Index), 10)
	}
	return r
}

// transportClass names the class of a transport error without printing the error text.
func transportClass(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	case errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	}
	text := err.Error()
	for _, k := range []struct{ needle, class string }{{"connection refused", "connection_refused"}, {"connection reset", "connection_reset"}, {"no route to host", "no_route"}, {"network is unreachable", "unreachable"}, {"certificate", "tls_certificate"}, {"tls:", "tls"}} {
		if bytes.Contains([]byte(text), []byte(k.needle)) {
			return k.class
		}
	}
	return "transport_error"
}

// ---- reader (login + PromQL) ----

var featureSetRE = regexp.MustCompile(`"feature_sets"\s*:\s*\[\s*\{\s*"id"\s*:\s*"([^"]+)"`)

const promProfile = "promql-prometheus-3.1.0"

var (
	featureOnce sync.Once
	featureID   string
	featureErr  error
)

func featureSet() (string, error) {
	featureOnce.Do(func() {
		files, err := profiles.Query()
		if err != nil {
			featureErr = err
			return
		}
		manifest, err := fs.ReadFile(files, promProfile+".json")
		if err != nil {
			featureErr = err
			return
		}
		m := featureSetRE.FindSubmatch(manifest)
		if m == nil {
			featureErr = errors.New("query profile manifest has no feature set")
			return
		}
		featureID = string(m[1])
	})
	return featureID, featureErr
}

// reader is the project reader's session on one voter.
type reader struct {
	s    *site
	fx   *Fixture
	mu   sync.Mutex
	csrf string
}

func newReader(s *site, fx *Fixture) *reader { return &reader{s: s, fx: fx} }

func (r *reader) login(timeout time.Duration) error {
	status, raw, err := r.s.postJSON("/api/v1/login", map[string]string{"Email": r.fx.ReaderEmail, "Password": r.fx.ReaderPassword, "Code": ""}, timeout, "", "")
	if err != nil {
		return fmt.Errorf("login: %s", transportClass(err))
	}
	if status != 200 {
		return fmt.Errorf("login: status %d", status)
	}
	var session auth.Session
	if err = json.Unmarshal(raw, &session); err != nil || session.CSRF == "" {
		return errors.New("login: undecodable session")
	}
	r.mu.Lock()
	r.csrf = session.CSRF
	r.mu.Unlock()
	return nil
}

// query runs one PromQL instant query as the project reader and returns the status and body exactly as answered.
func (r *reader) query(expression string, at time.Time, timeout time.Duration) (int, []byte, error) {
	feature, err := featureSet()
	if err != nil {
		return 0, nil, err
	}
	body := map[string]any{"org": r.fx.Org, "language": "promql", "profile": promProfile, "feature_set": feature, "expression": expression,
		"evaluation": map[string]any{"instant": true, "time": strconv.FormatInt(at.UnixNano(), 10), "start": "0", "end": "0", "step": "0"},
		"projects":   []string{r.fx.Project}, "budget": map[string]any{"timeout_ns": "0", "memory_bytes": "0", "max_returned": "0"}, "allow_partial": false}
	for attempt := 0; ; attempt++ {
		r.mu.Lock()
		csrf := r.csrf
		r.mu.Unlock()
		if csrf == "" {
			if err = r.login(timeout); err != nil {
				return 0, nil, err
			}
			r.mu.Lock()
			csrf = r.csrf
			r.mu.Unlock()
		}
		status, raw, err := r.s.postJSON("/api/v1/query", body, timeout, csrf, "")
		if err == nil && (status == 401 || status == 403) && attempt == 0 {
			r.mu.Lock()
			r.csrf = ""
			r.mu.Unlock()
			continue
		}
		return status, raw, err
	}
}

// completeValue decodes a query answer and returns the value only when it is a COMPLETE answer of one project.
func completeValue(status int, raw []byte) (*query.Value, error) {
	if status != 200 {
		var f struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(raw, &f)
		return nil, fmt.Errorf("status_%d_%s", status, safeToken(f.Code))
	}
	var result query.Result
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, errors.New("answer_is_not_a_query_result")
	}
	if len(result.Projects) != 1 {
		return nil, errors.New("answer_without_exactly_one_project")
	}
	p := result.Projects[0]
	switch {
	case p.Failure != nil:
		return nil, errors.New("answer_with_typed_failure")
	case p.Completeness != query.CompletenessComplete:
		return nil, errors.New("answer_not_complete")
	case p.Value == nil:
		return nil, errors.New("answer_without_value")
	}
	return p.Value, nil
}

// ---- ingest verdicts ----

type verdict string

const (
	vAcked     verdict = "acked"
	vRefusal   verdict = "typed_refusal"
	vTransport verdict = "transport"
	vRejected  verdict = "rejected"
	vMalformed verdict = "malformed"
)

var refusalCodes = map[string]bool{"unavailable": true, "timeout": true, "stale": true}

// classifyIngest classifies one attempt: 200 with a receipt for exactly this batch is an acknowledgement; a 503 with the
// typed retryable fault and a transport failure are retried with the same body; anything else is not retryable.
func classifyIngest(status int, body []byte, transportErr error, want model.ID) (verdict, string, model.Receipt) {
	var none model.Receipt
	if transportErr != nil {
		return vTransport, transportClass(transportErr), none
	}
	switch status {
	case 200:
		var r model.Receipt
		if json.Unmarshal(body, &r) != nil || r.BatchID != want || r.Cursor.Index == 0 || r.Cursor.Group == (model.ID{}) {
			return vMalformed, "status_200_without_receipt_for_this_batch", none
		}
		return vAcked, "status_200", r
	case 503:
		var f struct {
			Code      string `json:"code"`
			Retryable bool   `json:"retryable"`
		}
		if json.Unmarshal(body, &f) != nil || !f.Retryable || !refusalCodes[f.Code] {
			return vMalformed, "status_503_without_typed_retryable_fault", none
		}
		return vRefusal, "status_503_" + f.Code, none
	default:
		var f struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(body, &f)
		return vRejected, "status_" + strconv.Itoa(status) + "_" + safeToken(f.Code), none
	}
}
