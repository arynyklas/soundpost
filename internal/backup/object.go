// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"soundpost/internal/durablefs"
	"soundpost/internal/model"
)

var (
	// ErrExists is returned by Create when the object is already there.
	ErrExists = errors.New("backup object exists")
	// ErrNotFound is returned by Open when the object is absent.
	ErrNotFound = errors.New("backup object not found")
)

// Destination is the object primitive for backups, exports and the restore
// authority. It is a destination only: nothing here is ever the system of
// record, and a successful Create never evicts or truncates a local replica.
// Create is atomic and create-only: the object appears whole or not at all, and
// an existing name is never overwritten (S3: If-None-Match: *). Reads and lists
// must be strongly consistent with completed creates.
type Destination interface {
	Create(ctx context.Context, name string, r io.Reader, size int64) error
	Open(ctx context.Context, name string) (io.ReadCloser, error)
	List(ctx context.Context, prefix string) ([]string, error)
}

var nameSegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ValidName admits only relative, slash-separated names of safe segments.
func ValidName(name string) error {
	if name == "" || len(name) > 240 {
		return model.Fail(model.Invalid)
	}
	for _, segment := range strings.Split(name, "/") {
		if !nameSegment.MatchString(segment) {
			return model.Fail(model.Invalid)
		}
	}
	return nil
}

func validPrefix(prefix string) error {
	if prefix == "" {
		return nil
	}
	if len(prefix) > 240 || strings.ContainsAny(prefix, "\x00\\") || strings.Contains(prefix, "..") || strings.HasPrefix(prefix, "/") || strings.Contains(prefix, "//") {
		return model.Fail(model.Invalid)
	}
	return nil
}

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// LocalDestination is a directory (an NFS/USB/other-volume mount in practice).
type LocalDestination struct{ root string }

func NewLocalDestination(root string) (*LocalDestination, error) {
	if root == "" {
		return nil, model.Fail(model.Invalid)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err = durablefs.MkdirAll(abs); err != nil {
		return nil, err
	}
	return &LocalDestination{root: abs}, nil
}

func (d *LocalDestination) path(name string) string {
	return filepath.Join(d.root, filepath.FromSlash(name))
}

// Create writes to a private temporary file, syncs it and publishes it with a
// hard link, which fails if the name exists: the only atomic create-only
// primitive the local filesystem offers.
func (d *LocalDestination) Create(ctx context.Context, name string, r io.Reader, size int64) (err error) {
	if err = ValidName(name); err != nil {
		return err
	}
	if size < 0 {
		return model.Fail(model.Invalid)
	}
	path := d.path(name)
	dir := filepath.Dir(path)
	if err = durablefs.MkdirAll(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return err
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}()
	n, err := io.Copy(tmp, io.LimitReader(ctxReader{ctx, r}, size+1))
	if err != nil {
		return err
	}
	if n != size {
		return model.Fail(model.Invalid) // body length differs from the declared size
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = os.Link(tmp.Name(), path); err != nil {
		if os.IsExist(err) {
			return ErrExists
		}
		return err
	}
	return durablefs.SyncFileAndDir(path)
}

func (d *LocalDestination) Open(ctx context.Context, name string) (io.ReadCloser, error) {
	if err := ValidName(name); err != nil {
		return nil, err
	}
	path := d.path(name)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	if err != nil || !info.Mode().IsRegular() {
		return nil, model.Fail(model.Unavailable)
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, model.Fail(model.Unavailable)
	}
	return f, nil
}

func (d *LocalDestination) List(ctx context.Context, prefix string) ([]string, error) {
	if err := validPrefix(prefix); err != nil {
		return nil, err
	}
	var out []string
	err := filepath.WalkDir(d.root, func(path string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() || !e.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(d.root, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		if ValidName(name) == nil && strings.HasPrefix(name, prefix) {
			out = append(out, name)
		}
		return nil
	})
	if err != nil {
		return nil, model.Fail(model.Unavailable)
	}
	sort.Strings(out)
	return out, nil
}

// ---- S3-compatible destination -------------------------------------------------

// S3Config describes a path-style S3-compatible bucket. Endpoints must be HTTPS;
// AllowInsecureLoopback permits plain HTTP only to a loopback address (tests,
// a local gateway). SecretKey is used only to sign requests and is never sent.
type S3Config struct {
	Endpoint, Region, Bucket, Prefix, AccessKey, SecretKey string
	Client                                                 *http.Client
	AllowInsecureLoopback                                  bool
}

type S3Destination struct {
	cfg      S3Config
	endpoint *url.URL
	client   *http.Client
	now      func() time.Time
}

// String, GoString and Format never include the secret key: S3Config and the
// destination built from it are the kind of value an operator-facing tool prints.
func (c S3Config) String() string {
	return "s3-config:" + c.Bucket + "@" + c.Endpoint + " (credentials masked)"
}
func (c S3Config) GoString() string           { return c.String() }
func (c S3Config) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

func (d S3Destination) String() string             { return d.cfg.String() }
func (d S3Destination) GoString() string           { return d.cfg.String() }
func (d S3Destination) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, d.cfg.String()) }

var bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

func NewS3Destination(cfg S3Config) (*S3Destination, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, model.Fail(model.Invalid)
	}
	switch u.Scheme {
	case "https":
	case "http":
		host := u.Hostname()
		ip := net.ParseIP(host)
		if !cfg.AllowInsecureLoopback || (host != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return nil, model.Fail(model.Invalid)
		}
	default:
		return nil, model.Fail(model.Invalid)
	}
	if !bucketName.MatchString(cfg.Bucket) || cfg.Region == "" || cfg.AccessKey == "" || cfg.SecretKey == "" || validPrefix(cfg.Prefix) != nil || strings.HasSuffix(cfg.Prefix, "/") {
		return nil, model.Fail(model.Invalid)
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{}
	}
	guarded := *client
	guarded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cfg.Client = nil
	return &S3Destination{cfg: cfg, endpoint: u, client: &guarded, now: time.Now}, nil
}

func (d *S3Destination) key(name string) string {
	if d.cfg.Prefix == "" {
		return name
	}
	return d.cfg.Prefix + "/" + name
}

const emptyPayload = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func (d *S3Destination) request(ctx context.Context, method, key string, query url.Values, body io.Reader, size int64, extra map[string]string, payload string) (*http.Request, error) {
	u := *d.endpoint
	u.Path = "/" + d.cfg.Bucket
	if key != "" {
		u.Path += "/" + key
	}
	u.RawQuery = strings.ReplaceAll(query.Encode(), "+", "%20")
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.ContentLength = size
	}
	now := d.now().UTC()
	req.Header.Set("X-Amz-Date", now.Format("20060102T150405Z"))
	req.Header.Set("X-Amz-Content-Sha256", payload)
	signed := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	for k, v := range extra {
		req.Header.Set(k, v)
		signed = append(signed, strings.ToLower(k))
	}
	sort.Strings(signed)
	req.Header.Set("Authorization", authorization(req, d.cfg.AccessKey, d.cfg.SecretKey, d.cfg.Region, "s3", payload, signed, now))
	return req, nil
}

func (d *S3Destination) Create(ctx context.Context, name string, r io.Reader, size int64) error {
	if err := ValidName(name); err != nil {
		return err
	}
	if size < 0 {
		return model.Fail(model.Invalid)
	}
	req, err := d.request(ctx, http.MethodPut, d.key(name), nil, io.LimitReader(ctxReader{ctx, r}, size), size, map[string]string{"If-None-Match": "*", "Content-Type": "application/octet-stream"}, "UNSIGNED-PAYLOAD")
	if err != nil {
		return err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return model.Fail(model.Unavailable)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	switch {
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusNoContent:
		return nil
	case resp.StatusCode == http.StatusPreconditionFailed:
		return ErrExists
	}
	return model.Fail(model.Unavailable) // includes 409 ConditionalRequestConflict: ambiguous, the caller re-reads
}

func (d *S3Destination) Open(ctx context.Context, name string) (io.ReadCloser, error) {
	if err := ValidName(name); err != nil {
		return nil, err
	}
	req, err := d.request(ctx, http.MethodGet, d.key(name), nil, nil, 0, nil, emptyPayload)
	if err != nil {
		return nil, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, model.Fail(model.Unavailable)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return resp.Body, nil
	case http.StatusNotFound:
		resp.Body.Close()
		return nil, ErrNotFound
	}
	resp.Body.Close()
	return nil, model.Fail(model.Unavailable)
}

type s3List struct {
	IsTruncated           bool   `xml:"IsTruncated"`
	NextContinuationToken string `xml:"NextContinuationToken"`
	Contents              []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
}

func (d *S3Destination) List(ctx context.Context, prefix string) ([]string, error) {
	if err := validPrefix(prefix); err != nil {
		return nil, err
	}
	full := prefix
	strip := ""
	if d.cfg.Prefix != "" {
		strip = d.cfg.Prefix + "/"
		full = strip + prefix
	}
	var out []string
	token := ""
	for {
		query := url.Values{"list-type": {"2"}}
		if full != "" {
			query.Set("prefix", full)
		}
		if token != "" {
			query.Set("continuation-token", token)
		}
		req, err := d.request(ctx, http.MethodGet, "", query, nil, 0, nil, emptyPayload)
		if err != nil {
			return nil, err
		}
		resp, err := d.client.Do(req)
		if err != nil {
			return nil, model.Fail(model.Unavailable)
		}
		var page s3List
		err = func() error {
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return model.Fail(model.Unavailable)
			}
			return xml.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&page)
		}()
		if err != nil {
			return nil, model.Fail(model.Unavailable)
		}
		for _, c := range page.Contents {
			name := strings.TrimPrefix(c.Key, strip)
			if ValidName(name) == nil && strings.HasPrefix(name, prefix) {
				out = append(out, name)
			}
		}
		if !page.IsTruncated || page.NextContinuationToken == "" {
			break
		}
		token = page.NextContinuationToken
	}
	sort.Strings(out)
	return out, nil
}

// authorization computes an AWS Signature Version 4 Authorization header. signed
// lists lowercase header names in sorted order; every one must be present on
// req (host is taken from the request). payloadHash is the hex SHA-256 of the
// body or UNSIGNED-PAYLOAD.
func authorization(req *http.Request, access, secret, region, service, payloadHash string, signed []string, now time.Time) string {
	now = now.UTC()
	date, stamp := now.Format("20060102"), now.Format("20060102T150405Z")
	var headers strings.Builder
	for _, name := range signed {
		value := ""
		if name == "host" {
			value = req.Host
			if value == "" {
				value = req.URL.Host
			}
		} else {
			value = strings.Join(strings.Fields(strings.Join(req.Header.Values(name), ",")), " ")
		}
		headers.WriteString(name + ":" + value + "\n")
	}
	uri := req.URL.EscapedPath()
	if uri == "" {
		uri = "/"
	}
	canonical := strings.Join([]string{req.Method, uri, canonicalQuery(req.URL), headers.String(), strings.Join(signed, ";"), payloadHash}, "\n")
	scope := date + "/" + region + "/" + service + "/aws4_request"
	digest := sha256.Sum256([]byte(canonical))
	toSign := "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + hex.EncodeToString(digest[:])
	key := []byte("AWS4" + secret)
	for _, part := range []string{date, region, service, "aws4_request"} {
		key = hmacSHA256(key, part)
	}
	signature := hex.EncodeToString(hmacSHA256(key, toSign))
	return "AWS4-HMAC-SHA256 Credential=" + access + "/" + scope + ", SignedHeaders=" + strings.Join(signed, ";") + ", Signature=" + signature
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func canonicalQuery(u *url.URL) string {
	values := u.Query()
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vs := append([]string(nil), values[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, strings.ReplaceAll(url.QueryEscape(k), "+", "%20")+"="+strings.ReplaceAll(url.QueryEscape(v), "+", "%20"))
		}
	}
	return strings.Join(parts, "&")
}

// VerifyConditionalCreate proves a destination honours create-only semantics:
// the first Create of a fresh name succeeds, a second one with different bytes
// is refused with ErrExists, and the first bytes are what reads back. A
// last-writer-wins store cannot be a restore authority. It leaves one small
// probe object behind (destinations never delete).
func VerifyConditionalCreate(ctx context.Context, d Destination) error {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	name := "probe/" + hex.EncodeToString(suffix[:])
	first, second := []byte("probe-first"), []byte("probe-second!")
	if err := d.Create(ctx, name, bytes.NewReader(first), int64(len(first))); err != nil {
		return err
	}
	if err := d.Create(ctx, name, bytes.NewReader(second), int64(len(second))); !errors.Is(err, ErrExists) {
		return model.Fail(model.Unsupported)
	}
	r, err := d.Open(ctx, name)
	if err != nil {
		return err
	}
	defer r.Close()
	got, err := io.ReadAll(io.LimitReader(r, 1<<10))
	if err != nil || !bytes.Equal(got, first) {
		return model.Fail(model.Unsupported)
	}
	return nil
}

var _ Destination = (*LocalDestination)(nil)
var _ Destination = (*S3Destination)(nil)
