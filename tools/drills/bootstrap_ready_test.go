// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

// A bootstrap node that exits before it is ready (a release whose embedded UI bundle is empty refuses to
// start: that looked like "bootstrap_ready: timeout" on one lab host and nothing else) is reported at
// once, with the closed reason the process printed.
func TestBootstrapReadinessFailsAtOnceWhenTheNodeExitsAndNamesItsReason(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}, &x509.Certificate{SerialNumber: big.NewInt(1)}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close() // nothing answers there, as nothing answers for a node that is gone
	site := newDCSite("https://"+address, cert, time.Second)
	for name, c := range map[string]struct {
		output, want string
	}{
		"names its reason":   {"soundpost: startup or service failed (reason=ui_bundle_invalid)\n", "bootstrap_ready: exited_before_ready_reason_ui_bundle_invalid"},
		"no reason printed":  {"soundpost: startup or service failed\n", "bootstrap_ready: exited_before_ready"},
		"unsafe reason text": {"reason=Not-A-Token\n", "bootstrap_ready: exited_before_ready"},
	} {
		logs := &dcLog{}
		_, _ = logs.Write([]byte(c.output))
		done := make(chan struct{})
		close(done)
		started := time.Now()
		err := dcWaitSiteReady(site, done, logs, 30*time.Second)
		var failure *dcFailure
		if !errors.As(err, &failure) || err.Error() != c.want {
			t.Errorf("%s: %v, want %s", name, err, c.want)
		}
		if took := time.Since(started); took > 5*time.Second {
			t.Errorf("%s: the exit was noticed after %v", name, took)
		}
	}
}
