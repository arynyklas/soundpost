// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// Client submits batches to POST /ingest/v1/batches with the source credential
// and waits for the durable receipt. It never follows a redirect (the bearer
// credential must not leave the configured origin), never retries by itself
// (the callers' checkpoints and deterministic batch IDs make retries safe) and
// returns only typed, content-free errors: a transport error would otherwise
// quote the URL, and the server's body is never relayed.
type Client struct {
	base  string
	token []byte
	http  *http.Client
}

const maxReceiptBytes = 1 << 20

// ReadCredential reads the source credential file. On POSIX systems a file
// readable by group or others is refused: the credential is a secret and the
// reference to it is only a path.
func ReadCredential(path string) ([]byte, error) {
	if runtime.GOOS != "windows" {
		st, err := os.Stat(path)
		if err != nil {
			return nil, errors.New("agent: credential file unreadable")
		}
		if st.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("agent: credential file must not be readable by group or others")
		}
		if !st.Mode().IsRegular() {
			return nil, errors.New("agent: credential file is not a regular file")
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("agent: credential file unreadable")
	}
	tok := append([]byte(nil), bytes.TrimSpace(raw)...)
	clear(raw)
	if len(tok) == 0 || len(tok) > 4096 || bytes.ContainsAny(tok, " \t\r\n\x00") {
		return nil, errors.New("agent: credential file does not hold a single token")
	}
	return tok, nil
}

// NewClient builds the HTTPS client. caFile, when set, replaces the system
// roots; certificate verification can never be disabled.
func NewClient(server, caFile string, token []byte, timeout time.Duration) (*Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, errors.New("agent: ca file unreadable")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("agent: ca file holds no certificate")
		}
		tlsCfg.RootCAs = pool
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: tlsCfg, ResponseHeaderTimeout: timeout, MaxResponseHeaderBytes: 32 << 10, DisableKeepAlives: true}
	return &Client{
		base:  strings.TrimRight(server, "/"),
		token: append([]byte(nil), token...),
		http: &http.Client{
			Transport:     tr,
			Timeout:       timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// Admit posts one batch and returns its receipt. A refusal is a *model.Fault
// carrying the server's code and retryability; a transport failure is
// Unavailable with the detail "transport" (the outcome of the request is then
// unknown, and resubmitting the same batch is idempotent).
func (c *Client) Admit(ctx context.Context, b model.Batch) (model.Receipt, error) {
	body, err := json.Marshal(b)
	if err != nil {
		return model.Receipt{}, model.Fail(model.Invalid)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/ingest/v1/batches", bytes.NewReader(body))
	if err != nil {
		return model.Receipt{}, model.Fail(model.Invalid)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+string(c.token))
	req.Header.Set("User-Agent", "soundpost-agent")
	resp, err := c.http.Do(req)
	if err != nil {
		return model.Receipt{}, transportFault(ctx)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxReceiptBytes+1))
	if err != nil || len(raw) > maxReceiptBytes {
		return model.Receipt{}, transportFault(ctx)
	}
	if resp.StatusCode != http.StatusOK {
		return model.Receipt{}, refusal(resp, raw)
	}
	var r model.Receipt
	if model.StrictJSON(raw, &r) != nil || r.Version == 0 || r.BatchID != b.ID {
		return model.Receipt{}, model.Fail(model.Corrupt)
	}
	return r, nil
}

func transportFault(ctx context.Context) error {
	f := model.Fail(model.Unavailable)
	f.SafeDetail = "transport"
	f.Retryable = ctx.Err() == nil
	return f
}

// refusal maps a non-200 answer to a typed fault using only the status and the
// numeric/closed fields of the server's fault body.
func refusal(resp *http.Response, raw []byte) error {
	var body struct {
		Code      model.Code `json:"code"`
		Retryable bool       `json:"retryable"`
	}
	_ = json.Unmarshal(raw, &body)
	code := body.Code
	switch code {
	case model.Invalid, model.Unauthenticated, model.Forbidden, model.Conflict, model.TooLarge, model.Unsupported, model.Quota,
		model.Unavailable, model.Timeout, model.Cancelled, model.Stale, model.NotFound, model.Corrupt:
	default:
		code = model.Unavailable
	}
	f := model.Fail(code)
	f.SafeDetail = "http_" + strconv.Itoa(resp.StatusCode)
	f.Retryable = body.Retryable || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
	return f
}
