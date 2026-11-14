// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/arynyklas/soundpost/internal/durablefs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// localTLS creates a stable, explicitly trustable single-host TLS identity.
// Operators must distribute its public certificate through a trusted channel or
// configure an externally issued certificate; no client disables verification.
func localTLS(dir, listen string) (string, string, error) {
	certPath, keyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	_, ce := os.Stat(certPath)
	_, ke := os.Stat(keyPath)
	if ce == nil && ke == nil {
		if e := durablefs.SyncFileAndDir(keyPath); e != nil {
			return "", "", e
		}
		if e := durablefs.SyncFileAndDir(certPath); e != nil {
			return "", "", e
		}
		return certPath, keyPath, nil
	}
	if !os.IsNotExist(ce) || !os.IsNotExist(ke) {
		return "", "", os.ErrInvalid
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return "", "", e
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, e := rand.Int(rand.Reader, serialLimit)
	if e != nil {
		return "", "", e
	}
	host, _, e := net.SplitHostPort(listen)
	if e != nil {
		return "", "", e
	}
	template := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Soundpost local installation"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}
	if ip := net.ParseIP(host); ip != nil && !ip.IsUnspecified() {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else if host != "" && host != "0.0.0.0" && host != "::" {
		template.DNSNames = append(template.DNSNames, host)
	}
	der, e := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if e != nil {
		return "", "", e
	}
	rawKey, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return "", "", e
	}
	if e = exclusiveFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rawKey})); e != nil {
		return "", "", e
	}
	if e = exclusiveFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); e != nil {
		return "", "", e
	}
	return certPath, keyPath, nil
}
func exclusiveFile(path string, b []byte) error {
	return durablefs.Exclusive(path, b)
}
