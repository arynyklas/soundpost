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
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// This file adds to the three-process cluster what the reference journeys need after a node loss (07.07#16, node_loss_journeys.go):
// every member serves one shared TLS leaf that the applications and the browser trust (the journeys pin it), the operator can add
// `serve` flags to every member (the native symbolication sandbox needs its delegated cgroup), and a member can be stopped
// CLEANLY, because the in-process storage scan of the journeys needs a member's data directory to itself.

// dcPublicTLS is the TLS material of the members' public listeners: one CA and one leaf for 127.0.0.1/localhost that every member
// serves (`serve --tls-cert/--tls-key`), as the single node of the journeys does. The member-to-member mTLS is unrelated (dcPKI).
type dcPublicTLS struct {
	ca, cert, key string
	caCert        *x509.Certificate
}

// dcNewPublicTLS writes a fresh public CA and leaf into dir (private, under an allowlisted root).
func dcNewPublicTLS(dir string) (*dcPublicTLS, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Soundpost failure drills public CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(6 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(6 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return nil, err
	}
	p := &dcPublicTLS{ca: filepath.Join(dir, "ca.pem"), cert: filepath.Join(dir, "leaf.pem"), key: filepath.Join(dir, "leaf.key"), caCert: caCert}
	for path, block := range map[string]*pem.Block{p.ca: {Type: "CERTIFICATE", Bytes: caDER}, p.cert: {Type: "CERTIFICATE", Bytes: leafDER}, p.key: {Type: "EC PRIVATE KEY", Bytes: keyDER}} {
		if err = os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// serveArgs is the command line of one member: its node file and data directory, the public TLS when the cluster has one, and the
// operator's own flags (Env.ServeArgs) last.
func (c *dcCluster) serveArgs(id uint64) []string {
	args := []string{"serve", "--mode=distributed", "--node-id", strconv.FormatUint(id, 10), "--cluster-config", filepath.Join(c.work, "node-"+strconv.FormatUint(id, 10)+".json"), "--data-dir", c.data[id], "--listen", c.public[id]}
	if c.opts.public != nil {
		args = append(args, "--tls-cert", c.opts.public.cert, "--tls-key", c.opts.public.key)
	}
	if c.env != nil {
		args = append(args, c.env.ServeArgs...)
	}
	return args
}

// memberTrust waits until one member listens and returns the certificate a client of its public listener must trust: the
// self-signed one the member made for itself, or the CA of the shared public TLS.
func (c *dcCluster) memberTrust(id uint64, done <-chan struct{}) (*x509.Certificate, error) {
	if c.opts.public == nil {
		return dcWaitCertificate(c.data[id], c.public[id], done, 60*time.Second)
	}
	if err := dcWaitListening(c.public[id], done, 60*time.Second); err != nil {
		return nil, err
	}
	return c.opts.public.caCert, nil
}

// dcWaitListening waits until something accepts connections on addr; a process that exited first fails at once.
func dcWaitListening(addr string, done <-chan struct{}, limit time.Duration) error {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			return &dcFailure{Stage: "server_start", Code: "exited_before_listening"}
		default:
		}
		if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return &dcFailure{Stage: "server_start", Code: "timeout"}
}

// shutdown asks one member to stop (SIGTERM) and waits for it to leave by itself with exit status 0: a shutdown, not a loss (stop
// in loss.go is the SIGKILL of a member's process group). The member is marked down BEFORE the signal, so nothing targets it
// while it leaves.
func (c *dcCluster) shutdown(id uint64) error {
	p, err := c.proc(id)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.down[id] = true
	c.mu.Unlock()
	if err = p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	select {
	case <-p.done:
	case <-time.After(60 * time.Second):
		return &dcFailure{Stage: "stop", Code: "process_did_not_exit"}
	}
	c.mu.Lock()
	delete(c.procs, id)
	c.mu.Unlock()
	if p.cmd.ProcessState == nil || !p.cmd.ProcessState.Success() {
		return &dcFailure{Stage: "stop", Code: "exit_status_not_zero"}
	}
	return nil
}
