// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package gitlab is the one-way GitLab integration of the console (docs/operations/
// console-api.md section 10): a small REST v4 client and the orchestration that
// creates at most one GitLab issue per incident or error issue.
//
// Nothing GitLab says is ever read back into Soundpost beyond the identity of the
// one issue the marker names (project path, IID and URL). The client speaks https
// only, never follows a redirect, never uses a proxy, never prints a token, URL or
// response into an error: every failure is a closed code.
package gitlab

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// Closed codes of a failed GitLab call. The first group is definite (the request
// had no effect or GitLab refused it), the second may have reached GitLab.
const (
	CodeUnauthorized  = "gitlab_unauthorized"
	CodeForbidden     = "gitlab_forbidden"
	CodeNotFound      = "gitlab_not_found"
	CodeInvalid       = "gitlab_invalid"
	CodeUnprocessable = "gitlab_unprocessable"
	CodeRateLimited   = "gitlab_rate_limited"
	CodeRedirect      = "gitlab_redirect_refused"
	CodeEgress        = "gitlab_egress_blocked"
	CodeUnreachable   = "gitlab_unreachable"
	CodeTLS           = "gitlab_tls_failed"

	CodeTimeout     = "gitlab_timeout"
	CodeCanceled    = "gitlab_canceled"
	CodeTransport   = "gitlab_transport_error"
	CodeServerError = "gitlab_server_error"
	CodeBadResponse = "gitlab_bad_response"
)

const (
	defaultTimeout   = 10 * time.Second
	maxResponseBytes = 256 << 10
	maxLookupPages   = 3
	maxScopes        = 16
)

// Error is a failed call. Unknown says the request may have reached GitLab and
// had an effect; otherwise it provably had none (or GitLab refused it).
type Error struct {
	Code    string
	Unknown bool
}

func (e *Error) Error() string { return e.Code }

func refused(code string) *Error { return &Error{Code: code} }
func unknown(code string) *Error { return &Error{Code: code, Unknown: true} }

// Config configures one client.
type Config struct {
	// BaseURL is the validated GitLab base URL (ValidBaseURL).
	BaseURL string
	// Token is the project or personal access token; sent only as PRIVATE-TOKEN.
	Token string
	// Egress is the outbound network policy.
	Egress Egress
	// RootCAs are extra trust roots (the system roots when nil). Verification can
	// never be disabled and TLS 1.2 is the floor.
	RootCAs *x509.CertPool
	// Timeout bounds one call; zero means 10 seconds.
	Timeout time.Duration
}

// Client is a GitLab REST v4 client for one connection.
type Client struct {
	base  string
	token string
	http  *http.Client
}

func validToken(t string) bool {
	if len(t) < 8 || len(t) > 512 {
		return false
	}
	for i := range len(t) {
		if t[i] <= ' ' || t[i] >= 0x7f {
			return false
		}
	}
	return true
}

// NewClient builds a client. It refuses a base URL ValidBaseURL would, an
// unusable token and an allow list that names a never-allowed range.
func NewClient(cfg Config) (*Client, error) {
	base, _, err := ValidBaseURL(cfg.BaseURL, cfg.Egress)
	if err != nil {
		return nil, err
	}
	if !validToken(cfg.Token) {
		return nil, errors.New("gitlab: token invalid")
	}
	if err = cfg.Egress.Validate(); err != nil {
		return nil, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            cfg.Egress.dialContext(timeout),
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.RootCAs},
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 32 << 10,
		ResponseHeaderTimeout:  timeout,
		TLSHandshakeTimeout:    timeout,
		ForceAttemptHTTP2:      false,
	}
	return &Client{base: base, token: cfg.Token, http: &http.Client{
		Transport: tr,
		Timeout:   timeout,
		// A redirect is never followed: the 3xx answer itself is the result.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// Close releases idle connections.
func (c *Client) Close() { c.http.CloseIdleConnections() }

// Issue is the identity of one GitLab issue.
type Issue struct {
	IID uint64
	URL string
}

// TokenInfo is what GET /personal_access_tokens/self says about the token.
type TokenInfo struct {
	// Active is false for a revoked or expired token.
	Active bool
	// Scopes are the token scopes (closed charset, bounded).
	Scopes []string
	// ExpiresAt is a YYYY-MM-DD date, "" when the token does not expire or GitLab
	// did not say.
	ExpiresAt string
}

// ValidProject reports whether s is a GitLab project path or numeric ID that may
// be stored on a link and used in a request path.
func ValidProject(s string) bool {
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

func (c *Client) do(ctx context.Context, method, path, query string, payload []byte) (int, http.Header, []byte, *Error) {
	target := c.base + "/api/v4" + path
	if query != "" {
		target += "?" + query
	}
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return 0, nil, nil, refused(CodeInvalid)
	}
	req.Header.Set("PRIVATE-TOKEN", c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "soundpost-gitlab/1")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	var connected atomic.Bool
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { connected.Store(true) }}))
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, nil, transportError(err, connected.Load(), ctx.Err())
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return 0, nil, nil, unknown(CodeTransport)
	}
	if len(data) > maxResponseBytes {
		return 0, nil, nil, unknown(CodeBadResponse)
	}
	return resp.StatusCode, resp.Header, data, statusError(resp.StatusCode)
}

// statusError maps a status to a closed code: nil for 2xx.
func statusError(status int) *Error {
	switch {
	case status >= 200 && status < 300:
		return nil
	case status >= 300 && status < 400:
		return refused(CodeRedirect)
	case status == 401:
		return refused(CodeUnauthorized)
	case status == 403:
		return refused(CodeForbidden)
	case status == 404:
		return refused(CodeNotFound)
	case status == 422:
		return refused(CodeUnprocessable)
	case status == 429:
		return refused(CodeRateLimited)
	case status == 408:
		return unknown(CodeTimeout)
	case status >= 400 && status < 500:
		return refused(CodeInvalid)
	}
	return unknown(CodeServerError)
}

// transportError classifies a failed exchange without printing it (it can quote the
// URL). Before a connection existed nothing was written: a definite non-delivery.
func transportError(err error, connected bool, ctxErr error) *Error {
	if errors.Is(err, errEgressBlocked) {
		return refused(CodeEgress)
	}
	timedOut := errors.Is(err, context.DeadlineExceeded) || errors.Is(ctxErr, context.DeadlineExceeded)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		timedOut = true
	}
	if !connected {
		if isTLSError(err) {
			return refused(CodeTLS)
		}
		return refused(CodeUnreachable)
	}
	switch {
	case timedOut:
		return unknown(CodeTimeout)
	case errors.Is(err, context.Canceled) || errors.Is(ctxErr, context.Canceled):
		return unknown(CodeCanceled)
	}
	return unknown(CodeTransport)
}

func isTLSError(err error) bool {
	var (
		rh *tls.RecordHeaderError
		cv *tls.CertificateVerificationError
		al tls.AlertError
	)
	if errors.As(err, &rh) || errors.As(err, &cv) || errors.As(err, &al) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "tls:") || strings.Contains(s, "x509:")
}

type apiIssue struct {
	IID         uint64 `json:"iid"`
	WebURL      string `json:"web_url"`
	Description string `json:"description"`
}

// validURL applies the link rules of model.ValidExternalOp to a GitLab web_url.
func validURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && len(raw) <= 512 && utf8.ValidString(raw)
}

func (a apiIssue) identity() (Issue, bool) {
	if a.IID == 0 || !validURL(a.WebURL) {
		return Issue{}, false
	}
	return Issue{IID: a.IID, URL: a.WebURL}, true
}

// HasMarker reports whether text holds marker as a whole token: the marker is
// fixed width, so the next character must not continue it.
func HasMarker(text, marker string) bool {
	for from := 0; from < len(text); {
		i := strings.Index(text[from:], marker)
		if i < 0 {
			return false
		}
		end := from + i + len(marker)
		if end >= len(text) || !isMarkerChar(text[end]) {
			return true
		}
		from = end
	}
	return false
}

func isMarkerChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

// FindByMarker looks for the issue whose description holds marker. The search is
// only a hint: the match is made here, exactly, on the description. found is false
// when the (bounded) search saw no such issue.
func (c *Client) FindByMarker(ctx context.Context, project, marker string) (issue Issue, found bool, err *Error) {
	if !ValidProject(project) || marker == "" {
		return Issue{}, false, refused(CodeInvalid)
	}
	page := "1"
	for range maxLookupPages {
		q := url.Values{"search": {marker}, "in": {"description"}, "state": {"all"}, "per_page": {"20"}, "page": {page}}
		status, header, data, e := c.do(ctx, http.MethodGet, "/projects/"+url.PathEscape(project)+"/issues", q.Encode(), nil)
		if e != nil {
			return Issue{}, false, e
		}
		if status != http.StatusOK {
			return Issue{}, false, unknown(CodeBadResponse)
		}
		var list []apiIssue
		if json.Unmarshal(data, &list) != nil {
			return Issue{}, false, unknown(CodeBadResponse)
		}
		for _, it := range list {
			if !HasMarker(it.Description, marker) {
				continue
			}
			id, ok := it.identity()
			if !ok {
				return Issue{}, false, unknown(CodeBadResponse)
			}
			return id, true, nil
		}
		next := strings.TrimSpace(header.Get("X-Next-Page"))
		if n, perr := strconv.Atoi(next); perr != nil || n <= 0 {
			return Issue{}, false, nil
		}
		page = next
	}
	return Issue{}, false, nil
}

// CreateIssue creates one issue. A 2xx whose body is not a usable issue is an
// unknown outcome: the issue may exist.
func (c *Client) CreateIssue(ctx context.Context, project, title, description string, labels []string) (Issue, *Error) {
	if !ValidProject(project) {
		return Issue{}, refused(CodeInvalid)
	}
	payload := map[string]string{"title": title, "description": description}
	if len(labels) > 0 {
		payload["labels"] = strings.Join(labels, ",")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return Issue{}, refused(CodeInvalid)
	}
	status, _, data, e := c.do(ctx, http.MethodPost, "/projects/"+url.PathEscape(project)+"/issues", "", raw)
	if e != nil {
		return Issue{}, e
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return Issue{}, unknown(CodeBadResponse)
	}
	var created apiIssue
	if json.Unmarshal(data, &created) != nil {
		return Issue{}, unknown(CodeBadResponse)
	}
	id, ok := created.identity()
	if !ok {
		return Issue{}, unknown(CodeBadResponse)
	}
	return id, nil
}

// Token asks GitLab about the token in use (GET /personal_access_tokens/self).
func (c *Client) Token(ctx context.Context) (TokenInfo, *Error) {
	status, _, data, e := c.do(ctx, http.MethodGet, "/personal_access_tokens/self", "", nil)
	if e != nil {
		return TokenInfo{}, e
	}
	if status != http.StatusOK {
		return TokenInfo{}, unknown(CodeBadResponse)
	}
	var v struct {
		Active    *bool    `json:"active"`
		Revoked   bool     `json:"revoked"`
		Scopes    []string `json:"scopes"`
		ExpiresAt *string  `json:"expires_at"`
	}
	if json.Unmarshal(data, &v) != nil || v.Active == nil {
		return TokenInfo{}, unknown(CodeBadResponse)
	}
	info := TokenInfo{Active: *v.Active && !v.Revoked}
	for _, s := range v.Scopes {
		if len(info.Scopes) < maxScopes && validScope(s) {
			info.Scopes = append(info.Scopes, s)
		}
	}
	if v.ExpiresAt != nil {
		if _, err := time.Parse("2006-01-02", *v.ExpiresAt); err == nil {
			info.ExpiresAt = *v.ExpiresAt
		}
	}
	return info, nil
}

func validScope(s string) bool {
	if s == "" || len(s) > 40 {
		return false
	}
	for i := range len(s) {
		if !(s[i] >= 'a' && s[i] <= 'z' || s[i] == '_') {
			return false
		}
	}
	return true
}

// ClosedCode reports whether code is one the client can produce; it is the
// vocabulary a stored link or an answer may carry.
func ClosedCode(code string) bool {
	switch code {
	case CodeUnauthorized, CodeForbidden, CodeNotFound, CodeInvalid, CodeUnprocessable, CodeRateLimited, CodeRedirect, CodeEgress, CodeUnreachable, CodeTLS,
		CodeTimeout, CodeCanceled, CodeTransport, CodeServerError, CodeBadResponse:
		return true
	}
	return false
}
