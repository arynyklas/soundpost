// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
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
	"net/url"
	"os"
	"strings"
	"time"
)

// distCA is a throwaway cluster certificate authority that can issue member leaves.
type distCA struct {
	template *x509.Certificate
	key      *ecdsa.PrivateKey
	pem      []byte
}

func newDistCA(commonName string, serial int64) (*distCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(6 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &distCA{template: template, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}

// issue creates a leaf with the member's URI identity and loopback dial names, like distPKI does.
func (ca *distCA) issue(n distNode, serial int64) (certPEM, keyPEM []byte, err error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	identity, _ := url.Parse("spiffe://soundpost/node/" + n.identity)
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "generic fixture node"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(6 * time.Hour), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, URIs: []*url.URL{identity}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	raw, err := x509.CreateCertificate(rand.Reader, leaf, ca.template, &private.PublicKey, ca.key)
	if err != nil {
		return nil, nil, err
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), nil
}

// processPKI is the PKI of a three-process cluster: the files each member reads at start.
type processPKI struct {
	dir, caFile string
	ca          *distCA
	certs, keys map[uint64]string
	serial      int64
	material    []string // base64 bodies of every private key issued since the cluster started
}

func (p *processPKI) nextSerial() int64 { p.serial++; return 1000 + p.serial }

// replaceLeaf issues a new leaf for one member from ca and replaces that member's files.
func (p *processPKI) replaceLeaf(ca *distCA, n distNode) error {
	certPEM, keyPEM, err := ca.issue(n, p.nextSerial())
	if err != nil {
		return err
	}
	if err = os.WriteFile(p.certs[n.id], certPEM, 0o600); err != nil {
		return err
	}
	if err = os.WriteFile(p.keys[n.id], keyPEM, 0o600); err != nil {
		return err
	}
	p.material = append(p.material, base64Body(keyPEM))
	return nil
}

// mtlsRotator is a cluster whose member certificates are files it can replace between restarts.
type mtlsRotator interface {
	// rotateMTLS runs docs/operations/upgrade.md "mTLS certificate rotation": a leaf rotation
	// under the same CA, then a CA rotation (bundle, new leaves, bundle without the old CA),
	// calling roll to restart exactly one member at a time after its files changed.
	rotateMTLS(roll func(id uint64, label string) error, report map[string]any) error
}

func (c *processCluster) rotateMTLS(roll func(id uint64, label string) error, report map[string]any) error {
	p := c.pki
	// Leaf rotation (same CA).
	for _, n := range distNodes {
		if err := p.replaceLeaf(p.ca, n); err != nil {
			return err
		}
		if err := roll(n.id, "leaf"); err != nil {
			return err
		}
	}
	report["mtls_leaf_rotation"] = "each member rolled onto a new leaf of the same CA, one at a time, cluster ready and converged after each"

	// CA rotation: (1) bundle of old and new CA, (2) new leaves, (3) bundle without the old CA.
	newCA, err := newDistCA("Soundpost distributed smoke CA (rotated)", 2)
	if err != nil {
		return err
	}
	oldCA := p.ca
	// A leaf of the old CA that must stop being accepted once the old CA is gone.
	oldCert, oldKey, err := oldCA.issue(distNodes[2], p.nextSerial())
	if err != nil {
		return err
	}
	if err = os.WriteFile(p.caFile, append(append([]byte(nil), oldCA.pem...), newCA.pem...), 0o600); err != nil {
		return err
	}
	for _, n := range distNodes {
		if err = roll(n.id, "ca_bundle"); err != nil {
			return err
		}
	}
	for _, n := range distNodes {
		if err = p.replaceLeaf(newCA, n); err != nil {
			return err
		}
		if err = roll(n.id, "ca_new_leaf"); err != nil {
			return err
		}
	}
	if err = os.WriteFile(p.caFile, newCA.pem, 0o600); err != nil {
		return err
	}
	for _, n := range distNodes {
		if err = roll(n.id, "ca_old_removed"); err != nil {
			return err
		}
	}
	p.ca = newCA
	report["mtls_ca_rotation"] = "bundle (old+new CA) -> new-CA leaves -> new CA only, each phase rolled one member at a time, cluster ready and converged after each"

	// The old CA is really out: a member's peer listener refuses a client presenting an old-CA leaf
	// and accepts one from the new CA.
	if refused, err := peerRefusesClient(c.peer[1], newCA, oldCert, oldKey); err != nil || !refused {
		return &smokeFailure{Stage: "mtls_rotation", Code: "old_ca_leaf_still_accepted"}
	}
	newCert, newKey, err := newCA.issue(distNodes[2], p.nextSerial())
	if err != nil {
		return err
	}
	if refused, err := peerRefusesClient(c.peer[1], newCA, newCert, newKey); err != nil || refused {
		return &smokeFailure{Stage: "mtls_rotation", Code: "new_ca_leaf_refused"}
	}
	report["mtls_old_ca_leaf_refused_after_removal"] = true
	c.keys = append(c.keys, p.material...)
	return nil
}

// peerRefusesClient dials a member's peer listener presenting the given client leaf and reports
// whether the server answered with a TLS alert (certificate refused) rather than accepting it.
func peerRefusesClient(address string, trusted *distCA, certPEM, keyPEM []byte) (bool, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return false, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(trusted.pem) {
		return false, errors.New("trust bundle")
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{Certificates: []tls.Certificate{pair}, RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13})
	if err != nil {
		if strings.Contains(err.Error(), "remote error: tls:") {
			return true, nil
		}
		return false, err // an unreachable listener must not read as "accepted"
	}
	defer conn.Close()
	// TLS 1.3 reports a refused client certificate on the first read after the handshake.
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write([]byte{0})
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	return err != nil && strings.Contains(err.Error(), "remote error: tls:"), nil
}
