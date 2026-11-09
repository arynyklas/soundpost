// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func createBytes(d Destination, name string, data []byte) error {
	return d.Create(context.Background(), name, bytes.NewReader(data), int64(len(data)))
}
func readAll(t *testing.T, d Destination, name string) []byte {
	t.Helper()
	r, err := d.Open(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	raw, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestNamesAreRelativeSlashSeparatedAndSafe(t *testing.T) {
	for _, ok := range []string{"a", "backups/0123/manifest.json", "authority/head/00000000000000000001", "a.b-c_d/e"} {
		if err := ValidName(ok); err != nil {
			t.Fatalf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", ".", "..", "../a", "a/../b", "/abs", "a//b", "a/", "a\\b", "a b", "a\x00b", "a/./b", ".hidden", strings.Repeat("a", 300), "C:/x", "a:b"} {
		if err := ValidName(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestLocalDestinationIsCreateOnlyAndAtomic(t *testing.T) {
	root := t.TempDir()
	d, err := NewLocalDestination(filepath.Join(root, "dest"))
	if err != nil {
		t.Fatal(err)
	}
	if err = createBytes(d, "backups/one/manifest.json", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, d, "backups/one/manifest.json"); string(got) != "first" {
		t.Fatalf("read back %q", got)
	}
	if err = createBytes(d, "backups/one/manifest.json", []byte("second")); !errors.Is(err, ErrExists) {
		t.Fatalf("overwrite not refused: %v", err)
	}
	if got := readAll(t, d, "backups/one/manifest.json"); string(got) != "first" {
		t.Fatal("a refused create changed the object")
	}
	if _, err = d.Open(context.Background(), "backups/one/absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing object: %v", err)
	}
	_ = createBytes(d, "backups/two/obj", []byte("x"))
	_ = createBytes(d, "authority/ROOT", []byte("y"))
	names, err := d.List(context.Background(), "backups/")
	if err != nil || !sort.StringsAreSorted(names) || len(names) != 2 || names[0] != "backups/one/manifest.json" || names[1] != "backups/two/obj" {
		t.Fatalf("list: %v %v", names, err)
	}
	// Exactly one racing creator wins and the winner's bytes are intact.
	payloads := make([][]byte, 8)
	var wg sync.WaitGroup
	errs := make([]error, len(payloads))
	for i := range payloads {
		payloads[i] = bytes.Repeat([]byte{byte('a' + i)}, 1<<16)
		wg.Add(1)
		go func() { defer wg.Done(); errs[i] = createBytes(d, "authority/head/1", payloads[i]) }()
	}
	wg.Wait()
	winners := 0
	for i, err := range errs {
		if err == nil {
			winners++
			if !bytes.Equal(readAll(t, d, "authority/head/1"), payloads[i]) {
				t.Fatal("the winning object is not the winner's bytes")
			}
		} else if !errors.Is(err, ErrExists) {
			t.Fatalf("loser got %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("%d creators won", winners)
	}
}

type failingReader struct {
	data []byte
	n    int
}

func (f *failingReader) Read(p []byte) (int, error) {
	if f.n >= len(f.data) {
		return 0, errors.New("source failed")
	}
	n := copy(p, f.data[f.n:])
	f.n += n
	return n, nil
}

func TestLocalDestinationNeverPublishesAPartialObject(t *testing.T) {
	root := t.TempDir()
	d, _ := NewLocalDestination(root)
	ctx := context.Background()
	data := bytes.Repeat([]byte("z"), 4096)
	if err := d.Create(ctx, "a/failed", &failingReader{data: data}, int64(len(data))+10); err == nil {
		t.Fatal("a source that failed mid-stream was accepted")
	}
	if err := d.Create(ctx, "a/short", bytes.NewReader(data), int64(len(data))+1); err == nil {
		t.Fatal("a body shorter than its declared size was accepted")
	}
	if err := d.Create(ctx, "a/long", bytes.NewReader(data), int64(len(data))-1); err == nil {
		t.Fatal("a body longer than its declared size was accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := d.Create(cancelled, "a/cancelled", bytes.NewReader(data), int64(len(data))); err == nil {
		t.Fatal("a cancelled create succeeded")
	}
	for _, name := range []string{"a/failed", "a/short", "a/long", "a/cancelled"} {
		if _, err := d.Open(ctx, name); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s is visible after a failed create: %v", name, err)
		}
	}
	names, _ := d.List(ctx, "")
	if len(names) != 0 {
		t.Fatalf("failed creates left objects: %v", names)
	}
	var leftovers []string
	_ = filepath.WalkDir(root, func(path string, e os.DirEntry, err error) error {
		if err == nil && !e.IsDir() {
			leftovers = append(leftovers, path)
		}
		return nil
	})
	if len(leftovers) != 0 {
		t.Fatalf("failed creates left temporary files: %v", leftovers)
	}
}

// ---- S3-compatible destination ----

// fakeS3 is a strongly consistent path-style object store honouring the one
// conditional write the backup primitives need (If-None-Match: *).
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	seen    []*http.Request
	secret  string
	fail    int // fail the next n requests with 500
	maxKeys int
}

func newFakeS3(secret string) (*fakeS3, *httptest.Server) {
	f := &fakeS3{objects: map[string][]byte{}, secret: secret, maxKeys: 2}
	return f, httptest.NewServer(f)
}

type listResult struct {
	XMLName               xml.Name `xml:"ListBucketResult"`
	IsTruncated           bool     `xml:"IsTruncated"`
	NextContinuationToken string   `xml:"NextContinuationToken,omitempty"`
	Contents              []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	clone := r.Clone(context.Background())
	f.seen = append(f.seen, clone)
	if f.fail > 0 {
		f.fail--
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=ACCESSKEY/") || !strings.Contains(auth, "/us-east-1/s3/aws4_request") || !strings.Contains(auth, "SignedHeaders=") || !strings.Contains(auth, "Signature=") || r.Header.Get("X-Amz-Date") == "" || r.Header.Get("X-Amz-Content-Sha256") == "" {
		http.Error(w, "unsigned", http.StatusForbidden)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/bucket")
	switch {
	case r.Method == http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		if int64(len(body)) != r.ContentLength {
			http.Error(w, "short body", http.StatusBadRequest)
			return
		}
		if _, ok := f.objects[path]; ok && r.Header.Get("If-None-Match") == "*" {
			http.Error(w, "exists", http.StatusPreconditionFailed)
			return
		}
		if r.Header.Get("If-None-Match") != "*" {
			http.Error(w, "create-only required", http.StatusBadRequest)
			return
		}
		f.objects[path] = body
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet && (path == "" || path == "/") && r.URL.Query().Get("list-type") == "2":
		prefix := "/" + r.URL.Query().Get("prefix")
		var keys []string
		for k := range f.objects {
			if strings.HasPrefix(k, prefix) {
				keys = append(keys, strings.TrimPrefix(k, "/"))
			}
		}
		sort.Strings(keys)
		start := 0
		if token := r.URL.Query().Get("continuation-token"); token != "" {
			for start < len(keys) && keys[start] <= token {
				start++
			}
		}
		res := listResult{}
		for i := start; i < len(keys) && i < start+f.maxKeys; i++ {
			res.Contents = append(res.Contents, struct {
				Key string `xml:"Key"`
			}{keys[i]})
		}
		if start+f.maxKeys < len(keys) {
			res.IsTruncated = true
			res.NextContinuationToken = keys[start+f.maxKeys-1]
		}
		_ = xml.NewEncoder(w).Encode(res)
	case r.Method == http.MethodGet:
		body, ok := f.objects[path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<Error><Code>NoSuchKey</Code></Error>`))
			return
		}
		_, _ = w.Write(body)
	default:
		http.Error(w, "unsupported", http.StatusMethodNotAllowed)
	}
}

func newS3(t *testing.T, server *httptest.Server, prefix string) *S3Destination {
	t.Helper()
	d, err := NewS3Destination(S3Config{Endpoint: server.URL, Region: "us-east-1", Bucket: "bucket", Prefix: prefix, AccessKey: "ACCESSKEY", SecretKey: "SECRETKEY-MUST-NEVER-LEAK", Client: server.Client(), AllowInsecureLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestS3DestinationCreateOnlyOpenAndPaginatedList(t *testing.T) {
	fake, server := newFakeS3("SECRETKEY-MUST-NEVER-LEAK")
	defer server.Close()
	d := newS3(t, server, "installation-1")
	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		if err := createBytes(d, fmt.Sprintf("authority/head/%020d", i), []byte(fmt.Sprintf("record %d", i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := createBytes(d, "authority/head/00000000000000000003", []byte("forged")); !errors.Is(err, ErrExists) {
		t.Fatalf("conditional create was not honoured: %v", err)
	}
	if got := readAll(t, d, "authority/head/00000000000000000003"); string(got) != "record 3" {
		t.Fatalf("object replaced by a refused create: %q", got)
	}
	if _, err := d.Open(ctx, "authority/head/absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing object: %v", err)
	}
	names, err := d.List(ctx, "authority/head/")
	if err != nil || len(names) != 5 || names[0] != "authority/head/00000000000000000001" || names[4] != "authority/head/00000000000000000005" {
		t.Fatalf("list did not follow pagination or strip the prefix: %v %v", names, err)
	}
	// The configured prefix is part of every stored key; the caller never sees it.
	for key := range fake.objects {
		if !strings.HasPrefix(key, "/installation-1/") {
			t.Fatalf("object stored outside the configured prefix: %s", key)
		}
	}
	// A transient server failure is an error, never "exists" or "not found".
	fake.mu.Lock()
	fake.fail = 1
	fake.mu.Unlock()
	if err = createBytes(d, "x/new", []byte("n")); err == nil || errors.Is(err, ErrExists) || errors.Is(err, ErrNotFound) {
		t.Fatalf("server error misclassified: %v", err)
	}
	// Every request was signed and carried no secret key material.
	for _, r := range fake.seen {
		for k, v := range r.Header {
			if strings.Contains(strings.Join(v, ","), "SECRETKEY-MUST-NEVER-LEAK") {
				t.Fatalf("secret key sent in header %s", k)
			}
		}
		if strings.Contains(r.URL.String(), "SECRETKEY") {
			t.Fatal("secret key in URL")
		}
	}
}

func TestS3DestinationRefusesInsecureEndpointsAndBadConfig(t *testing.T) {
	good := S3Config{Endpoint: "https://s3.example.test", Region: "us-east-1", Bucket: "bucket", AccessKey: "a", SecretKey: "s"}
	if _, err := NewS3Destination(good); err != nil {
		t.Fatal(err)
	}
	plain := good
	plain.Endpoint = "http://s3.example.test"
	if _, err := NewS3Destination(plain); err == nil {
		t.Fatal("a cleartext remote endpoint was accepted")
	}
	loopback := good
	loopback.Endpoint = "http://203.0.113.9:9000"
	loopback.AllowInsecureLoopback = true
	if _, err := NewS3Destination(loopback); err == nil {
		t.Fatal("AllowInsecureLoopback accepted a non-loopback address")
	}
	for name, mutate := range map[string]func(*S3Config){
		"no bucket":    func(c *S3Config) { c.Bucket = "" },
		"no region":    func(c *S3Config) { c.Region = "" },
		"no key":       func(c *S3Config) { c.AccessKey = "" },
		"no secret":    func(c *S3Config) { c.SecretKey = "" },
		"bad prefix":   func(c *S3Config) { c.Prefix = "../x" },
		"userinfo url": func(c *S3Config) { c.Endpoint = "https://u:p@s3.example.test" },
	} {
		c := good
		mutate(&c)
		if _, err := NewS3Destination(c); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// The signer is pinned to the published AWS Signature Version 4 test vector
// ("get-vanilla"); a self-consistent but wrong signer would fail here.
func TestSigV4MatchesPublishedVector(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.amazonaws.com/", nil)
	req.Header.Set("X-Amz-Date", "20150830T123600Z")
	got := authorization(req, "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1", "service", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", []string{"host", "x-amz-date"}, time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC))
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got != want {
		t.Fatalf("signature mismatch\n got: %s\nwant: %s", got, want)
	}
}

// overwriting is a destination without conditional create: unusable as an authority.
type overwriting struct{ objects map[string][]byte }

func (o *overwriting) Create(ctx context.Context, name string, r io.Reader, size int64) error {
	raw, _ := io.ReadAll(r)
	o.objects[name] = raw
	return nil
}
func (o *overwriting) Open(ctx context.Context, name string) (io.ReadCloser, error) {
	raw, ok := o.objects[name]
	if !ok {
		return nil, ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(raw)), nil
}
func (o *overwriting) List(ctx context.Context, prefix string) ([]string, error) { return nil, nil }

func TestConditionalCreateIsVerifiedNotAssumed(t *testing.T) {
	ctx := context.Background()
	local, _ := NewLocalDestination(t.TempDir())
	if err := VerifyConditionalCreate(ctx, local); err != nil {
		t.Fatalf("local destination: %v", err)
	}
	_, server := newFakeS3("x")
	defer server.Close()
	if err := VerifyConditionalCreate(ctx, newS3(t, server, "p")); err != nil {
		t.Fatalf("s3 destination: %v", err)
	}
	if err := VerifyConditionalCreate(ctx, &overwriting{objects: map[string][]byte{}}); err == nil {
		t.Fatal("a last-writer-wins store was accepted as a restore authority")
	}
}

// S3Config and the destination built from it hold the signing secret; no way of
// printing either (an operator-facing tool printing its config, a %#v in a log
// line) may render it.
func TestS3ConfigAndDestinationNeverFormatTheSecret(t *testing.T) {
	const secret = "SECRET-KEY-THAT-MUST-NEVER-PRINT"
	cfg := S3Config{Endpoint: "https://s3.example.test", Region: "us-east-1", Bucket: "bucket", Prefix: "p", AccessKey: "ACCESSKEY", SecretKey: secret}
	d, err := NewS3Destination(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{"config": cfg, "config pointer": &cfg, "destination": d, "destination value": *d} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			if out := fmt.Sprintf(verb, value); strings.Contains(out, secret) || strings.Contains(out, fmt.Sprintf("%x", secret)) {
				t.Fatalf("%s formatted with %s renders the secret: %s", name, verb, out)
			}
		}
	}
	if got := fmt.Sprint(cfg); !strings.Contains(got, "bucket") {
		t.Fatalf("the masked form names nothing useful: %q", got)
	}
}
