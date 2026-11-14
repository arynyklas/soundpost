// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestSourceAuditRecordsOnlyNamesAndHashes(t *testing.T) {
	var buf bytes.Buffer
	z := gzip.NewWriter(&buf)
	w := tar.NewWriter(z)
	body := []byte("package fixture\nfunc AuthoredExample() {}\n")
	if e := w.WriteHeader(&tar.Header{Name: "source/promql/example.go", Size: int64(len(body)), Mode: 0600}); e != nil {
		t.Fatal(e)
	}
	if _, e := w.Write(body); e != nil {
		t.Fatal(e)
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256(buf.Bytes())
	p := SourceProfile{ID: "promql-prometheus-3.1.0", SourceSHA256: hex.EncodeToString(hash[:])}
	audit, e := AuditSource(context.Background(), p, bytes.NewReader(buf.Bytes()))
	if e != nil {
		t.Fatal(e)
	}
	if len(audit.Files) != 1 || len(audit.Symbols) != 1 || audit.Symbols[0].Name != "AuthoredExample" {
		t.Fatalf("unexpected source metadata: %+v", audit)
	}
	p.SourceSHA256 = "wrong"
	if _, e = AuditSource(context.Background(), p, bytes.NewReader(buf.Bytes())); e == nil {
		t.Fatal("altered source digest accepted")
	}
}
