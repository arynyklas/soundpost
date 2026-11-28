//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/httpapi"
)

// tlsNode is the real product HTTP server (the composition's own routes: batch
// ingest, receipts, the canonical profile view) over the already open backend,
// served on a loopback listener whose certificate chains to a private CA this
// fixture generated. Clients verify that chain against the CA: nothing in the
// fixture skips certificate verification.
type tlsNode struct {
	URL    string
	CAFile string
	dir    string
	server *http.Server
}

func startTLSNode(app *appcore.App) (*tlsNode, error) {
	fail := func(what string) (*tlsNode, error) { return nil, errors.New(what) }
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return fail("fixture_ca_key_unavailable")
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "soundpost native export fixture CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if e != nil {
		return fail("fixture_ca_unavailable")
	}
	caCert, e := x509.ParseCertificate(caDER)
	if e != nil {
		return fail("fixture_ca_unavailable")
	}
	leafKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return fail("fixture_leaf_key_unavailable")
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	leafDER, e := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if e != nil {
		return fail("fixture_leaf_unavailable")
	}
	keyDER, e := x509.MarshalECPrivateKey(leafKey)
	if e != nil {
		return fail("fixture_leaf_key_unavailable")
	}
	pair, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if e != nil {
		return fail("fixture_leaf_unavailable")
	}
	dir, e := os.MkdirTemp("", "soundpost-native-export-ca-")
	if e != nil {
		return fail("fixture_ca_file_unavailable")
	}
	node := &tlsNode{dir: dir, CAFile: filepath.Join(dir, "ca.pem")}
	if e = os.WriteFile(node.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); e != nil {
		os.RemoveAll(dir)
		return fail("fixture_ca_file_unavailable")
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		os.RemoveAll(dir)
		return fail("fixture_listener_unavailable")
	}
	node.server = httpapi.NewServer("", app.Auth, nil, app.Register)
	node.server.TLSConfig.Certificates = []tls.Certificate{pair}
	node.URL = "https://" + listener.Addr().String()
	go node.server.Serve(tls.NewListener(listener, node.server.TLSConfig))
	return node, nil
}

func (n *tlsNode) close() {
	if n == nil {
		return
	}
	if n.server != nil {
		n.server.Close()
	}
	if n.dir != "" {
		os.RemoveAll(n.dir)
	}
}
