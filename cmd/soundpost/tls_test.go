// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

func TestLocalTLSStableIdentity(t *testing.T) {
	dir := t.TempDir()
	cert, key, err := localTLS(dir, "127.0.0.1:8443")
	if err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tls.LoadX509KeyPair(cert, key); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(first)
	if block == nil {
		t.Fatal("missing certificate")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err = parsed.VerifyHostname("localhost"); err != nil {
		t.Fatal(err)
	}
	cert2, key2, err := localTLS(dir, "127.0.0.1:8443")
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(cert2)
	if err != nil {
		t.Fatal(err)
	}
	if cert != cert2 || key != key2 || !bytes.Equal(first, second) {
		t.Fatal("restart replaced installation TLS identity")
	}
}
