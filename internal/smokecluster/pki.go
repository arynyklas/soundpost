// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package smokecluster

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Certificates writes a private CA and four node identities (spiffe URIs
// node-1..node-4) under dir. It returns the CA path and, per node id, the
// certificate and private-key paths.
func Certificates(dir string) (string, map[uint64][2]string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", nil, err
	}
	now := time.Now()
	authority := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Soundpost private smoke CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, authority, authority, &key.PublicKey, key)
	if err != nil {
		return "", nil, err
	}
	ca := filepath.Join(dir, "ca.pem")
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		return "", nil, err
	}
	pairs := map[uint64][2]string{}
	for id := uint64(1); id <= 4; id++ {
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", nil, err
		}
		identity, _ := url.Parse("spiffe://soundpost/node/node-" + strconv.FormatUint(id, 10))
		certificate := &x509.Certificate{SerialNumber: big.NewInt(int64(id + 1)), Subject: pkix.Name{CommonName: "generic fixture node"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, URIs: []*url.URL{identity}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
		bytes, err := x509.CreateCertificate(rand.Reader, certificate, authority, &private.PublicKey, key)
		if err != nil {
			return "", nil, err
		}
		encoded, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			return "", nil, err
		}
		certPath := filepath.Join(dir, fmt.Sprintf("node-%d.pem", id))
		keyPath := filepath.Join(dir, fmt.Sprintf("node-%d.key", id))
		if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: bytes}), 0600); err != nil {
			return "", nil, err
		}
		if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0600); err != nil {
			return "", nil, err
		}
		pairs[id] = [2]string{certPath, keyPath}
	}
	return ca, pairs, nil
}
