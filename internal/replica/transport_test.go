// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"soundpost/internal/model"
)

// gateMachine is a testMachine whose Apply can be parked, standing in for a
// state machine that waits on a lock held by an unrelated slow operation.
type gateMachine struct {
	testMachine
	gmu     sync.Mutex
	armed   bool
	gate    chan struct{}
	entered chan struct{}
}

func newGateMachine() *gateMachine {
	return &gateMachine{testMachine: testMachine{rows: map[string]string{}}, gate: make(chan struct{}), entered: make(chan struct{}, 1)}
}
func (m *gateMachine) arm() { m.gmu.Lock(); m.armed = true; m.gmu.Unlock() }
func (m *gateMachine) release() {
	m.gmu.Lock()
	defer m.gmu.Unlock()
	if m.armed {
		m.armed = false
		close(m.gate)
	}
}
func (m *gateMachine) Apply(c CommittedEntry) error {
	m.gmu.Lock()
	park := m.armed && c.Entry.Kind != Noop
	m.gmu.Unlock()
	if park {
		select {
		case m.entered <- struct{}{}:
		default:
		}
		<-m.gate
	}
	return m.testMachine.Apply(c)
}

func testPKI(t *testing.T, nodes int) (*x509.CertPool, []tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	authority := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "replica transport test CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, authority, authority, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	certificates := make([]tls.Certificate, nodes)
	for i := range certificates {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		identity, _ := url.Parse(fmt.Sprintf("spiffe://soundpost/node/node-%d", i+1))
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: "replica transport test node"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, URIs: []*url.URL{identity}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		certificates[i] = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	return roots, certificates
}

// mtlsCluster is three real voters wired through the production MTLS transport
// and the production HTTP/2 server configuration, one listener per node.
type mtlsCluster struct {
	transports []*MTLS
	groups     [][]*Group       // [node-1][group]
	machines   [][]*gateMachine // [node-1][group]
}

func newMTLSCluster(t *testing.T, groupCount int) *mtlsCluster {
	t.Helper()
	roots, certificates := testPKI(t, 3)
	listeners := make([]net.Listener, 3)
	members := Members{Revision: 1}
	for i := range listeners {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners[i] = l
		members.Nodes = append(members.Nodes, Member{ID: uint64(i + 1), Address: "https://" + l.Addr().String(), NodeIdentity: fmt.Sprintf("node-%d", i+1), FailureDomain: fmt.Sprintf("test-disk-%d", i+1)})
	}
	ids := make([]model.ID, groupCount)
	for i := range ids {
		ids[i] = model.NewID()
	}
	c := &mtlsCluster{}
	for i := range listeners {
		transport, err := NewMTLS(uint64(i+1), fmt.Sprintf("node-%d", i+1), certificates[i], roots, "")
		if err != nil {
			t.Fatal(err)
		}
		server := &http.Server{Handler: transport, TLSConfig: transport.ServerTLS(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
		go func() { _ = server.Serve(tls.NewListener(listeners[i], server.TLSConfig)) }()
		c.transports = append(c.transports, transport)
		var groups []*Group
		var machines []*gateMachine
		for _, id := range ids {
			machine := newGateMachine()
			g, err := Open(Config{ID: uint64(i + 1), Group: id, Directory: t.TempDir(), Members: members, Machine: machine, Transport: transport, TickInterval: 20 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			if err = transport.Register(g); err != nil {
				t.Fatal(err)
			}
			groups = append(groups, g)
			machines = append(machines, machine)
		}
		c.groups = append(c.groups, groups)
		c.machines = append(c.machines, machines)
		t.Cleanup(func() {
			// Parked appliers hold their group lock: release them before closing.
			for _, m := range machines {
				m.release()
			}
			server.Close()
			transport.Close()
			for _, g := range groups {
				g.Close()
			}
		})
	}
	return c
}

// A group whose receiving handler is parked (an applier waiting on a lock held by
// an unrelated slow operation, a slow disk) must not delay any other group's
// messages to the same peer. Consensus groups share one connection per peer, not
// one ordered delivery queue: with a single queue the parked request is awaited
// until its timeout while every other group's heartbeats, votes and appends wait
// behind it, so leaders lose their quorum on a perfectly healthy network.
func TestParkedGroupHandlerDoesNotStarveOtherGroupsToTheSamePeer(t *testing.T) {
	c := newMTLSCluster(t, 2)
	parked, free := 0, 1
	for group := range 2 {
		if err := c.groups[0][group].Campaign(); err != nil {
			t.Fatal(err)
		}
	}
	ready, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for group := range 2 {
		for {
			if _, err := c.groups[0][group].ReadIndex(ready); err == nil {
				break
			} else if ready.Err() != nil {
				t.Fatalf("group %d never elected a leader on node 1: %v", group, err)
			}
		}
	}
	// Both followers park their next applied entry of the parked group.
	c.machines[1][parked].arm()
	c.machines[2][parked].arm()
	propose, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if _, err := c.groups[0][parked].Propose(propose, Entry{ID: model.NewID(), Kind: Data, Payload: []byte("parked")}); err != nil {
		t.Fatalf("leader commit of the parked group's entry: %v", err)
	}
	for _, node := range []int{1, 2} {
		select {
		case <-c.machines[node][parked].entered:
		case <-time.After(5 * time.Second):
			t.Fatalf("node %d never started applying the parked group's entry", node+1)
		}
	}
	// With both followers' handlers for the parked group blocked, a different
	// group must still commit well inside the five-second request timeout.
	started := time.Now()
	freeCtx, freeStop := context.WithTimeout(context.Background(), 2*time.Second)
	defer freeStop()
	if _, err := c.groups[0][free].Propose(freeCtx, Entry{ID: model.NewID(), Kind: Data, Payload: []byte("free")}); err != nil {
		t.Fatalf("an unrelated group could not commit while another group's peer handler was parked (waited %v): %v", time.Since(started), err)
	}
}
