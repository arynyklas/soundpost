// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	raft "go.etcd.io/raft/v3"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/replica"
	"github.com/arynyklas/soundpost/internal/smokecluster"
)

// A three-voter in-process cluster whose node identities the test chooses: the
// restored cluster of a disaster restore must carry fresh ones, under the very same
// certificate authority (the case in which only the identities keep an old node out).

type testCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	path string
	next int64
}

func newTestCA(t *testing.T, dir string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Soundpost cluster backup test CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ca.pem")
	if err = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return &testCA{key: key, cert: cert, path: path, next: 2}
}

// issue writes a certificate carrying the node identity URI SAN and returns its certificate and key paths.
func (c *testCA) issue(t *testing.T, dir, identity string) (string, string) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("spiffe://soundpost/node/" + identity)
	now := time.Now()
	c.next++
	template := &x509.Certificate{SerialNumber: big.NewInt(c.next), Subject: pkix.Name{CommonName: "generic fixture node"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, URIs: []*url.URL{uri}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, c.cert, &private.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, identity+".pem"), filepath.Join(dir, identity+".key")
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

var voters = []uint64{1, 2, 3}

// quietRaft silences the consensus library's election chatter (65 groups per voter log at INFO).
func quietRaft() { raft.SetLogger(&raft.DefaultLogger{Logger: log.New(io.Discard, "", 0)}) }

type rig struct {
	t       *testing.T
	root    string
	seed    string
	ca      *testCA
	prefix  string
	certs   map[uint64][2]string
	relays  *smokecluster.Relays
	targets map[uint64]string
	members replica.Members
	mu      sync.Mutex
	apps    map[uint64]*appcore.App
}

// identity is the node identity of voter id: prefix-id.
func (r *rig) identity(id uint64) string { return fmt.Sprintf("%s-%d", r.prefix, id) }

func newRig(t *testing.T, root, seed string, ca *testCA, prefix string) *rig {
	t.Helper()
	quietRaft()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	relays, err := smokecluster.NewRelays(voters...)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, root: root, seed: seed, ca: ca, prefix: prefix, certs: map[uint64][2]string{}, relays: relays, targets: map[uint64]string{}, apps: map[uint64]*appcore.App{}}
	r.members = replica.Members{Revision: 1}
	for _, id := range voters {
		cert, key := ca.issue(t, root, r.identity(id))
		r.certs[id] = [2]string{cert, key}
		r.members.Nodes = append(r.members.Nodes, replica.Member{ID: id, Address: "https://" + relays.Address(id), NodeIdentity: r.identity(id), FailureDomain: fmt.Sprintf("%s-domain-%d", prefix, id)})
	}
	t.Cleanup(r.closeAll)
	return r
}

func (r *rig) nodeDir(id uint64) string { return filepath.Join(r.root, fmt.Sprintf("node-%d", id)) }

func (r *rig) config(id uint64) appcore.NodeConfig {
	return appcore.NodeConfig{NodeID: id, PeerListen: r.targets[id], PeerSourceIP: smokecluster.PeerSourceIP(id), Certificate: r.certs[id][0], PrivateKey: r.certs[id][1], CA: r.ca.path, Seed: r.seed, Members: r.members, InitialLeader: 1}
}

// open starts the listed voters concurrently (each waits for a quorum of the others).
func (r *rig) open(ids ...uint64) error {
	if err := smokecluster.AssignPeers(r.relays, r.targets, ids...); err != nil {
		return err
	}
	type opened struct {
		id  uint64
		app *appcore.App
		err error
	}
	results := make(chan opened, len(ids))
	for _, id := range ids {
		config := r.config(id)
		go func() {
			raw, err := json.Marshal(config)
			if err != nil {
				results <- opened{id: id, err: err}
				return
			}
			var decoded appcore.NodeConfig
			if err = json.Unmarshal(raw, &decoded); err != nil {
				results <- opened{id: id, err: err}
				return
			}
			if err = os.MkdirAll(r.nodeDir(id), 0o700); err != nil {
				results <- opened{id: id, err: err}
				return
			}
			app, err := appcore.OpenDistributed(r.nodeDir(id), decoded)
			results <- opened{id: id, app: app, err: err}
		}()
	}
	var failure error
	for range ids {
		o := <-results
		if o.err != nil {
			failure = errors.Join(failure, fmt.Errorf("node %d: %w", o.id, o.err))
			continue
		}
		r.mu.Lock()
		r.apps[o.id] = o.app
		r.mu.Unlock()
	}
	return failure
}

func (r *rig) app(id uint64) *appcore.App {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.apps[id]
}

func (r *rig) closeAll() {
	r.mu.Lock()
	apps := r.apps
	r.apps = map[uint64]*appcore.App{}
	r.mu.Unlock()
	for _, app := range apps {
		_ = app.Close()
	}
	r.relays.Close()
}

// peerStatus asks a node's peer listener for a group's readiness with a client certificate and
// returns the HTTP status: 200 for a member of the group's membership, 403 for anyone else.
func peerStatus(t *testing.T, listen, group, certificate, key string) int {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(certificate, key)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, InsecureSkipVerify: true}}}
	defer client.CloseIdleConnections()
	response, err := client.Get("https://" + listen + "/internal/raft/v1/ready/" + group)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode
}
