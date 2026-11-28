// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Command gitlab-bridge is the reference receiver of the Soundpost event webhook
// (docs/operations/console-api.md section 9). It verifies the signature of every
// delivery, deduplicates by the delivery ID and mirrors three events into GitLab:
//
//	issue.new         creates a GitLab issue for the error issue (once)
//	issue.regressed   adds a note to that GitLab issue (creating it first if absent)
//	incident.opened   creates a GitLab issue for the incident (once)
//
// Every other event is acknowledged and ignored. The program is standard library
// only and imports nothing from Soundpost: it is meant to be copied, read and
// adapted. A request answers 2xx only after its action succeeded, and 5xx when
// GitLab failed, so Soundpost retries. Nothing but identifiers and links leaves
// Soundpost in the payload, and nothing but identifiers and links is written to
// GitLab.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	signatureWindow = 5 * time.Minute
	dedupTTL        = 25 * time.Hour
	dedupMax        = 100_000
	maxBody         = 64 << 10
	maxGitLabBody   = 256 << 10
	gitlabTimeout   = 10 * time.Second
	maxNotePages    = 5
)

// ProjectMapping maps one Soundpost project to the GitLab project its issues go to.
type ProjectMapping struct {
	GitLabProject string   `json:"gitlab_project"`
	Labels        []string `json:"labels"`
}

// Config is the bridge configuration. Secrets belong in the environment
// (SOUNDPOST_WEBHOOK_SECRET, SOUNDPOST_WEBHOOK_SECRET_PREVIOUS, GITLAB_TOKEN); the
// file fields exist for setups where the file itself is a protected secret.
type Config struct {
	Listen         string                    `json:"listen"`
	TLSCertFile    string                    `json:"tls_cert_file"`
	TLSKeyFile     string                    `json:"tls_key_file"`
	GitLabBaseURL  string                    `json:"gitlab_base_url"`
	GitLabCAFile   string                    `json:"gitlab_ca_file"`
	StateFile      string                    `json:"state_file"`
	Projects       map[string]ProjectMapping `json:"projects"`
	Secret         string                    `json:"secret"`
	PreviousSecret string                    `json:"previous_secret"`
	GitLabToken    string                    `json:"gitlab_token"`
}

func loadConfig(path string, env func(string) string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, errors.New("config unreadable")
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("config invalid: %v", err)
	}
	if v := env("SOUNDPOST_WEBHOOK_SECRET"); v != "" {
		c.Secret = v
	}
	if v := env("SOUNDPOST_WEBHOOK_SECRET_PREVIOUS"); v != "" {
		c.PreviousSecret = v
	}
	if v := env("GITLAB_TOKEN"); v != "" {
		c.GitLabToken = v
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8443"
	}
	if len(c.Secret) < 16 || c.PreviousSecret != "" && len(c.PreviousSecret) < 16 {
		return Config{}, errors.New("the webhook secret must be at least 16 bytes")
	}
	if c.GitLabToken == "" {
		return Config{}, errors.New("no GitLab token (GITLAB_TOKEN)")
	}
	u, err := url.Parse(c.GitLabBaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return Config{}, errors.New("gitlab_base_url must be an https URL without credentials")
	}
	c.GitLabBaseURL = strings.TrimRight(c.GitLabBaseURL, "/")
	if c.StateFile == "" {
		return Config{}, errors.New("state_file is required (it keeps the delivery IDs across a restart)")
	}
	if len(c.Projects) == 0 {
		return Config{}, errors.New("projects: no Soundpost project is mapped")
	}
	for id, m := range c.Projects {
		if !isHexID(id) || !validProjectPath(m.GitLabProject) || len(m.Labels) > 10 {
			return Config{}, errors.New("projects: a mapping is invalid")
		}
		for _, l := range m.Labels {
			if l == "" || len(l) > 50 || strings.ContainsAny(l, ",\r\n") {
				return Config{}, errors.New("projects: a label is invalid")
			}
		}
	}
	return c, nil
}

func isHexID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := range len(s) {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}

func validProjectPath(s string) bool {
	if s == "" || len(s) > 200 || strings.Contains(s, "//") || strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-' || c == '/') {
			return false
		}
	}
	return true
}

func validDeliveryID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- signature

// sign is the signature of one delivery: v1=hex(HMAC-SHA256(secret, "<ts>.<delivery>.<body>")).
func sign(secret []byte, ts, delivery string, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(ts))
	m.Write([]byte{'.'})
	m.Write([]byte(delivery))
	m.Write([]byte{'.'})
	m.Write(body)
	return "v1=" + hex.EncodeToString(m.Sum(nil))
}

// verify reports whether any presented v1 value matches the signature made with any
// configured secret. Every combination is compared (constant time each) so the
// time taken does not say which secret or value matched.
func verify(secrets [][]byte, header, ts, delivery string, body []byte) bool {
	var presented [][]byte
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, "v1=") {
			continue
		}
		if raw, err := hex.DecodeString(part[3:]); err == nil && len(raw) == sha256.Size && len(presented) < 4 {
			presented = append(presented, raw)
		}
	}
	ok := false
	for _, secret := range secrets {
		want, _ := hex.DecodeString(sign(secret, ts, delivery, body)[3:])
		for _, p := range presented {
			if hmac.Equal(want, p) {
				ok = true
			}
		}
	}
	return ok
}

// ---------------------------------------------------------------- dedup

// dedup remembers the delivery IDs whose action succeeded, for 25 hours (a retry
// budget is 24 hours), in bounded memory and in an append-only file so a restart
// keeps them. A delivery is added only after its action succeeded.
type dedup struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	path    string
	now     func() time.Time
	entries map[string]int64
	file    *os.File
	lines   int
}

func openDedup(path string, ttl time.Duration, max int, now func() time.Time) (*dedup, error) {
	d := &dedup{ttl: ttl, max: max, path: path, now: now, entries: map[string]int64{}}
	if err := d.load(); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *dedup) load() error {
	if err := os.MkdirAll(filepath.Dir(d.path), 0o700); err != nil {
		return err
	}
	if f, err := os.Open(d.path); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			ts, id, ok := strings.Cut(sc.Text(), " ")
			at, perr := strconv.ParseInt(ts, 10, 64)
			if ok && perr == nil && validDeliveryID(id) {
				d.entries[id] = at // a torn or foreign line is skipped
			}
		}
		_ = f.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	d.prune()
	return d.compact()
}

func (d *dedup) prune() {
	cutoff := d.now().Add(-d.ttl).Unix()
	for id, at := range d.entries {
		if at <= cutoff {
			delete(d.entries, id)
		}
	}
	for len(d.entries) > d.max {
		oldest, oldestAt := "", int64(1<<62)
		for id, at := range d.entries {
			if at < oldestAt {
				oldest, oldestAt = id, at
			}
		}
		delete(d.entries, oldest)
	}
}

// compact rewrites the file with the live entries and reopens it for appending.
func (d *dedup) compact() error {
	if d.file != nil {
		_ = d.file.Close()
		d.file = nil
	}
	ids := make([]string, 0, len(d.entries))
	for id := range d.entries {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return d.entries[ids[i]] < d.entries[ids[j]] })
	tmp := d.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, id := range ids {
		fmt.Fprintf(w, "%d %s\n", d.entries[id], id)
	}
	if err = w.Flush(); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, d.path)
	}
	if err != nil {
		return err
	}
	d.lines = len(ids)
	d.file, err = os.OpenFile(d.path, os.O_WRONLY|os.O_APPEND, 0o600)
	return err
}

func (d *dedup) has(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	at, ok := d.entries[id]
	return ok && at > d.now().Add(-d.ttl).Unix()
}

// add records a finished delivery durably before it returns.
func (d *dedup) add(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now().Unix()
	d.entries[id] = now
	if len(d.entries) > d.max {
		d.prune()
	}
	if d.lines >= 2*d.max {
		return d.compact()
	}
	if _, err := fmt.Fprintf(d.file, "%d %s\n", now, id); err != nil {
		return err
	}
	d.lines++
	return d.file.Sync()
}

func (d *dedup) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file != nil {
		_ = d.file.Close()
		d.file = nil
	}
}

// ---------------------------------------------------------------- GitLab

type gitlabClient struct {
	base  string
	token string
	http  *http.Client
}

func newGitLabClient(base, token string, roots *x509.CertPool) *gitlabClient {
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, DisableKeepAlives: true, ResponseHeaderTimeout: gitlabTimeout}
	return &gitlabClient{base: base, token: token, http: &http.Client{Transport: tr, Timeout: gitlabTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

var errGitLab = errors.New("gitlab request failed")

func (g *gitlabClient) do(ctx context.Context, method, path, query string, body any) (int, http.Header, []byte, error) {
	target := g.base + "/api/v4" + path
	if query != "" {
		target += "?" + query
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, nil, errGitLab
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return 0, nil, nil, errGitLab
	}
	req.Header.Set("PRIVATE-TOKEN", g.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.http.Do(req)
	if err != nil {
		return 0, nil, nil, errGitLab // the error text can quote the URL
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxGitLabBody+1))
	if err != nil || len(data) > maxGitLabBody {
		return 0, nil, nil, errGitLab
	}
	return resp.StatusCode, resp.Header, data, nil
}

type glIssue struct {
	IID         int    `json:"iid"`
	WebURL      string `json:"web_url"`
	Description string `json:"description"`
}

// hasMarker matches the marker as a whole token.
func hasMarker(text, marker string) bool {
	for from := 0; from < len(text); {
		i := strings.Index(text[from:], marker)
		if i < 0 {
			return false
		}
		end := from + i + len(marker)
		if end >= len(text) || !(text[end] >= '0' && text[end] <= '9' || text[end] >= 'a' && text[end] <= 'z' || text[end] >= 'A' && text[end] <= 'Z' || text[end] == '-' || text[end] == '_') {
			return true
		}
		from = end
	}
	return false
}

// find looks the issue up by its marker. The search is a hint: the match is made
// here, on the description.
func (g *gitlabClient) find(ctx context.Context, project, marker string) (glIssue, bool, error) {
	page := "1"
	for range 3 {
		q := url.Values{"search": {marker}, "in": {"description"}, "state": {"all"}, "per_page": {"20"}, "page": {page}}
		status, header, data, err := g.do(ctx, http.MethodGet, "/projects/"+url.PathEscape(project)+"/issues", q.Encode(), nil)
		if err != nil || status != http.StatusOK {
			return glIssue{}, false, errGitLab
		}
		var list []glIssue
		if json.Unmarshal(data, &list) != nil {
			return glIssue{}, false, errGitLab
		}
		for _, it := range list {
			if hasMarker(it.Description, marker) {
				if it.IID <= 0 {
					return glIssue{}, false, errGitLab
				}
				return it, true, nil
			}
		}
		next := strings.TrimSpace(header.Get("X-Next-Page"))
		if n, err := strconv.Atoi(next); err != nil || n <= 0 {
			return glIssue{}, false, nil
		}
		page = next
	}
	return glIssue{}, false, nil
}

func (g *gitlabClient) create(ctx context.Context, project, title, description string, labels []string) (glIssue, error) {
	body := map[string]string{"title": title, "description": description}
	if len(labels) > 0 {
		body["labels"] = strings.Join(labels, ",")
	}
	status, _, data, err := g.do(ctx, http.MethodPost, "/projects/"+url.PathEscape(project)+"/issues", "", body)
	var it glIssue
	if err != nil || status != http.StatusCreated && status != http.StatusOK || json.Unmarshal(data, &it) != nil || it.IID <= 0 {
		return glIssue{}, errGitLab
	}
	return it, nil
}

func (g *gitlabClient) hasNote(ctx context.Context, project string, iid int, token string) (bool, error) {
	for page := 1; page <= maxNotePages; page++ {
		q := url.Values{"per_page": {"100"}, "page": {strconv.Itoa(page)}}
		status, header, data, err := g.do(ctx, http.MethodGet, "/projects/"+url.PathEscape(project)+"/issues/"+strconv.Itoa(iid)+"/notes", q.Encode(), nil)
		if err != nil || status != http.StatusOK {
			return false, errGitLab
		}
		var notes []struct {
			Body string `json:"body"`
		}
		if json.Unmarshal(data, &notes) != nil {
			return false, errGitLab
		}
		for _, n := range notes {
			if hasMarker(n.Body, token) {
				return true, nil
			}
		}
		if next := strings.TrimSpace(header.Get("X-Next-Page")); next == "" {
			return false, nil
		}
	}
	return false, nil
}

func (g *gitlabClient) addNote(ctx context.Context, project string, iid int, body string) error {
	status, _, _, err := g.do(ctx, http.MethodPost, "/projects/"+url.PathEscape(project)+"/issues/"+strconv.Itoa(iid)+"/notes", "", map[string]string{"body": body})
	if err != nil || status != http.StatusCreated && status != http.StatusOK {
		return errGitLab
	}
	return nil
}

// ---------------------------------------------------------------- payload

// payload is section 9 of the console API contract: identifiers and links only.
type payload struct {
	Version    int    `json:"version"`
	DeliveryID string `json:"delivery_id"`
	Event      string `json:"event"`
	OccurredAt string `json:"occurred_at"`
	Org        string `json:"org"`
	Project    string `json:"project"`
	Incident   string `json:"incident"`
	Issue      string `json:"issue"`
	Release    string `json:"release"`
	Severity   string `json:"severity"`
	ReleaseID  string `json:"release_id"`
	Service    string `json:"service"`
	Revision   string `json:"revision"`
	URL        string `json:"url"`
}

func (p payload) validate() error {
	if p.Version != 1 || !validDeliveryID(p.DeliveryID) || !isHexID(p.Org) || !isHexID(p.Project) {
		return errors.New("payload invalid")
	}
	for _, id := range []string{p.Incident, p.Issue, p.Release, p.ReleaseID, p.Service} {
		if id != "" && !isHexID(id) {
			return errors.New("payload invalid")
		}
	}
	switch p.Severity {
	case "", "minor", "major", "critical":
	default:
		return errors.New("payload invalid")
	}
	if p.Revision != "" && (len(p.Revision) > 20 || strings.Trim(p.Revision, "0123456789") != "") {
		return errors.New("payload invalid")
	}
	if p.URL != "" {
		u, err := url.Parse(p.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(p.URL) > 512 || strings.ContainsAny(p.URL, " \r\n<>\"@") {
			return errors.New("payload invalid")
		}
	}
	return nil
}

// entity is the thing the event is about: kind and ID.
func (p payload) entity() (kind, id string) {
	switch {
	case p.Incident != "":
		return "incident", p.Incident
	case p.Issue != "":
		return "issue", p.Issue
	}
	return "", ""
}

// entityMatchesEvent holds for the three mirrored events only when the payload names
// the entity kind the event is about; the other events are not looked at.
func (p payload) entityMatchesEvent() bool {
	kind, _ := p.entity()
	switch p.Event {
	case "issue.new", "issue.regressed":
		return kind == "issue"
	case "incident.opened":
		return kind == "incident"
	}
	return true
}

func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// markerOf is the deterministic marker of one entity's GitLab issue. It is a
// function of identifiers only, so a retry, a restart or a second bridge instance
// finds the same issue.
func markerOf(org, kind, id string) string {
	sum := sha256.Sum256([]byte("soundpost.bridge.v1\x00" + org + "\x00" + kind + "\x00" + id))
	return "soundpost-bridge-" + hex.EncodeToString(sum[:16])
}

func linkTarget(raw string) string {
	return strings.NewReplacer("(", "%28", ")", "%29").Replace(raw)
}

func titleOf(p payload, kind, id string) string {
	if kind == "incident" {
		t := "Soundpost incident " + short(id)
		if p.Severity != "" {
			t += " (" + p.Severity + ")"
		}
		return t
	}
	return "Soundpost issue " + short(id)
}

func descriptionOf(p payload, kind, id, marker string) string {
	var b strings.Builder
	b.WriteString("Soundpost " + kind + " `" + short(id) + "`\n\n")
	b.WriteString("- ID: `" + id + "`\n- Org: `" + p.Org + "`\n- Project: `" + p.Project + "`\n")
	if p.Severity != "" {
		b.WriteString("- Severity: `" + p.Severity + "`\n")
	}
	if p.ReleaseID != "" {
		b.WriteString("- Release: `" + p.ReleaseID + "`\n")
	}
	if p.Service != "" {
		b.WriteString("- Service: `" + p.Service + "`\n")
	}
	if p.URL != "" {
		b.WriteString("\n[Open in Soundpost](" + linkTarget(p.URL) + ")\n")
	}
	b.WriteString("\nSoundpost reference: " + marker + "\n")
	return b.String()
}

func noteOf(p payload, kind, id string) string {
	var b strings.Builder
	b.WriteString("Soundpost " + kind + " `" + short(id) + "` regressed")
	if p.Revision != "" {
		b.WriteString(" (revision " + p.Revision + ")")
	}
	b.WriteString(".\n")
	if p.ReleaseID != "" {
		b.WriteString("\n- Release: `" + p.ReleaseID + "`\n")
	}
	if p.URL != "" {
		b.WriteString("\n[Open in Soundpost](" + linkTarget(p.URL) + ")\n")
	}
	b.WriteString("\nSoundpost delivery: " + p.DeliveryID + "\n")
	return b.String()
}

// ---------------------------------------------------------------- handler

type bridge struct {
	cfg      Config
	secrets  [][]byte
	gl       *gitlabClient
	seen     *dedup
	now      func() time.Time
	logf     func(format string, args ...any)
	mu       sync.Mutex
	inflight map[string]bool
}

func newBridge(cfg Config, gl *gitlabClient, seen *dedup, now func() time.Time) *bridge {
	b := &bridge{cfg: cfg, gl: gl, seen: seen, now: now, logf: log.Printf, inflight: map[string]bool{}}
	b.secrets = [][]byte{[]byte(cfg.Secret)}
	if cfg.PreviousSecret != "" {
		b.secrets = append(b.secrets, []byte(cfg.PreviousSecret))
	}
	return b
}

func reply(w http.ResponseWriter, status int, kv ...string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	_ = json.NewEncoder(w).Encode(m)
}

func (b *bridge) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /soundpost", b.handle)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { reply(w, http.StatusOK, "status", "ok") })
	return mux
}

func (b *bridge) handle(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		reply(w, http.StatusRequestEntityTooLarge, "status", "error", "code", "body_too_large")
		return
	}
	delivery, ts, sig := r.Header.Get("Soundpost-Delivery-ID"), r.Header.Get("Soundpost-Timestamp"), r.Header.Get("Soundpost-Signature")
	if !validDeliveryID(delivery) || ts == "" || sig == "" {
		reply(w, http.StatusUnauthorized, "status", "error", "code", "signature_missing")
		return
	}
	at, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		reply(w, http.StatusUnauthorized, "status", "error", "code", "timestamp_invalid")
		return
	}
	// Signature first, then the window: the order does not matter for safety, but a
	// forged request must not learn the window from the answer.
	if !verify(b.secrets, sig, ts, delivery, body) {
		b.logf("delivery %s: signature refused", delivery)
		reply(w, http.StatusUnauthorized, "status", "error", "code", "signature_invalid")
		return
	}
	if d := b.now().Sub(time.Unix(at, 0)); d > signatureWindow || d < -signatureWindow {
		b.logf("delivery %s: timestamp outside the window", delivery)
		reply(w, http.StatusUnauthorized, "status", "error", "code", "timestamp_stale")
		return
	}
	var p payload
	if err = json.Unmarshal(body, &p); err != nil || p.validate() != nil || p.DeliveryID != delivery || p.Event != r.Header.Get("Soundpost-Event") || !p.entityMatchesEvent() {
		reply(w, http.StatusBadRequest, "status", "error", "code", "payload_invalid")
		return
	}
	if b.seen.has(delivery) {
		reply(w, http.StatusOK, "status", "duplicate")
		return
	}
	b.mu.Lock()
	if b.inflight[delivery] {
		b.mu.Unlock()
		reply(w, http.StatusServiceUnavailable, "status", "error", "code", "in_progress")
		return
	}
	b.inflight[delivery] = true
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.inflight, delivery)
		b.mu.Unlock()
	}()

	outcome, err := b.process(r.Context(), p)
	if err != nil {
		b.logf("delivery %s: %s failed: %v", delivery, p.Event, err)
		reply(w, http.StatusBadGateway, "status", "error", "code", "gitlab_unavailable")
		return
	}
	if err = b.seen.add(delivery); err != nil {
		// The action is done and idempotent: a retry finds the issue by its marker.
		b.logf("delivery %s: state file: %v", delivery, err)
		reply(w, http.StatusInternalServerError, "status", "error", "code", "state_unavailable")
		return
	}
	b.logf("delivery %s: %s %s", delivery, p.Event, outcome)
	reply(w, http.StatusOK, "status", outcome)
}

// process performs the action of one event. It returns "created", "noted" or
// "ignored"; any error means GitLab did not (provably) do the work.
func (b *bridge) process(ctx context.Context, p payload) (string, error) {
	switch p.Event {
	case "issue.new", "issue.regressed", "incident.opened":
	case "test.ping":
		return "pong", nil
	default:
		return "ignored", nil
	}
	kind, id := p.entity()
	if kind == "" || kind == "incident" != (p.Event == "incident.opened") {
		return "", errors.New("event names no matching entity")
	}
	m, ok := b.cfg.Projects[p.Project]
	if !ok {
		return "ignored", nil
	}
	marker := markerOf(p.Org, kind, id)
	issue, found, err := b.gl.find(ctx, m.GitLabProject, marker)
	if err != nil {
		return "", err
	}
	created := false
	if !found {
		if issue, err = b.gl.create(ctx, m.GitLabProject, titleOf(p, kind, id), descriptionOf(p, kind, id, marker), m.Labels); err != nil {
			return "", err
		}
		created = true
	}
	if p.Event != "issue.regressed" {
		if created {
			return "created", nil
		}
		return "exists", nil
	}
	noted, err := b.gl.hasNote(ctx, m.GitLabProject, issue.IID, "Soundpost delivery: "+p.DeliveryID)
	if err != nil {
		return "", err
	}
	if !noted {
		if err = b.gl.addNote(ctx, m.GitLabProject, issue.IID, noteOf(p, kind, id)); err != nil {
			return "", err
		}
	}
	return "noted", nil
}

// ---------------------------------------------------------------- main

func main() {
	configPath := flag.String("config", "config.json", "path of the JSON configuration")
	plainHTTP := flag.Bool("http", false, "serve plain HTTP (only behind a TLS-terminating proxy); without it tls_cert_file and tls_key_file are required")
	flag.Parse()
	cfg, err := loadConfig(*configPath, os.Getenv)
	if err != nil {
		log.Fatalf("gitlab-bridge: %v", err)
	}
	var roots *x509.CertPool
	if cfg.GitLabCAFile != "" {
		pem, rerr := os.ReadFile(cfg.GitLabCAFile)
		roots = x509.NewCertPool()
		if rerr != nil || !roots.AppendCertsFromPEM(pem) {
			log.Fatal("gitlab-bridge: gitlab_ca_file is unreadable or holds no certificate")
		}
	}
	if !*plainHTTP && (cfg.TLSCertFile == "" || cfg.TLSKeyFile == "") {
		log.Fatal("gitlab-bridge: set tls_cert_file and tls_key_file, or pass -http behind a TLS proxy")
	}
	seen, err := openDedup(cfg.StateFile, dedupTTL, dedupMax, time.Now)
	if err != nil {
		log.Fatalf("gitlab-bridge: state file: %v", err)
	}
	defer seen.close()
	b := newBridge(cfg, newGitLabClient(cfg.GitLabBaseURL, cfg.GitLabToken, roots), seen, time.Now)
	srv := &http.Server{Addr: cfg.Listen, Handler: b.routes(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	log.Printf("gitlab-bridge: listening on %s for %d project(s)", cfg.Listen, len(cfg.Projects))
	if *plainHTTP {
		err = srv.ListenAndServe()
	} else {
		err = srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
	}
	log.Fatalf("gitlab-bridge: %v", err)
}
