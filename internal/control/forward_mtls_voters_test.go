// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// mtlsVoterNetwork is the three control voters over the production transport (replica.MTLS and the
// HTTP/2 server configuration it supplies), one loopback listener per voter, every hop
// authenticated by a certificate the cluster's CA issued for the voter. Nothing in it is in memory:
// a follower's proposal reaches the leader as a TLS request, and the leader names the proposer from
// the certificate that authenticated it.
type mtlsVoterNetwork struct {
	t          *testing.T
	list       []net.Listener
	transports map[uint64]*replica.MTLS
	mu         sync.Mutex
	proposals  map[string]int // forwarded proposals the voters served, by the identity in the client certificate
}

func newMTLSVoterNetwork(t *testing.T) *mtlsVoterNetwork {
	t.Helper()
	roots, certs := voterPKI(t, 3)
	n := &mtlsVoterNetwork{t: t, transports: map[uint64]*replica.MTLS{}, proposals: map[string]int{}}
	for i := range 3 {
		id := uint64(i + 1)
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		n.list = append(n.list, l)
		transport, err := replica.NewMTLS(id, fmt.Sprintf("voter-%d", id), certs[i], roots, "")
		if err != nil {
			t.Fatal(err)
		}
		n.transports[id] = transport
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/internal/raft/v1/propose/") && r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.PeerCertificates[0].URIs) > 0 {
				n.mu.Lock()
				n.proposals[r.TLS.PeerCertificates[0].URIs[0].Path]++
				n.mu.Unlock()
			}
			transport.ServeHTTP(w, r)
		}), TLSConfig: transport.ServerTLS(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}
		go func() { _ = server.Serve(tls.NewListener(l, server.TLSConfig)) }()
		t.Cleanup(func() {
			server.Close()
			transport.Close()
		})
	}
	return n
}

func (n *mtlsVoterNetwork) members() replica.Members {
	members := replica.Members{Revision: 1}
	for i, l := range n.list {
		id := uint64(i + 1)
		members.Nodes = append(members.Nodes, replica.Member{ID: id, Address: "https://" + l.Addr().String(), NodeIdentity: fmt.Sprintf("voter-%d", id), FailureDomain: fmt.Sprintf("disk-%d", id)})
	}
	return members
}
func (n *mtlsVoterNetwork) transport(id uint64) replica.Transport { return n.transports[id] }
func (n *mtlsVoterNetwork) attach(id uint64, g *replica.Group) error {
	return n.transports[id].Register(g)
}

// forwardedFrom is how many proposals the leader served that arrived over TLS from voter id.
func (n *mtlsVoterNetwork) forwardedFrom(id uint64) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.proposals[fmt.Sprintf("/node/voter-%d", id)]
}

// voterPKI is a CA and one server and client certificate per voter, each naming the voter in its
// URI SAN the way the product's node certificates do.
func voterPKI(t *testing.T, nodes int) (*x509.CertPool, []tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	authority := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "control voter test CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
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
	certs := make([]tls.Certificate, nodes)
	for i := range certs {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		identity, _ := url.Parse(fmt.Sprintf("spiffe://soundpost/node/voter-%d", i+1))
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: "control voter test node"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, URIs: []*url.URL{identity}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		certs[i] = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	return roots, certs
}

// 10.01#13: the follower-side half of control redaction over the real mesh. Voter 1 leads; voters 2
// and 3 propose their own commands (a session created by a login, and the redaction pass that
// commits the scrubbed-audit record, which has to go through the leader) and every one of them
// reaches the leader as a TLS request from that voter's certificate (counted at the leader's TLS
// layer). The commands commit on all three voters and leave one control state; after the passes no
// voter's journal holds the erased payload. Which voter a committed entry names as its proposer is
// not asserted here: the replica package asserts it over the same MTLS transport (proposer_test.go).
func TestAFollowerForwardsControlCommandsToTheLeaderOverTheMTLSMesh(t *testing.T) {
	mesh := newMTLSVoterNetwork(t)
	v := newControlVotersOn(t, mesh, replica.Cadence{})
	const erased, kept = "CANARYMTLSERASED7c41e0d2b86a", "CANARYMTLSKEPT51f0aa93c7d4"
	leader := v.fx[1]
	leader.seedAll(leader.newSeed(leader.project, erased), 50)
	leader.seedAll(leader.newSeed(leader.otherProject, kept), 50)
	v.await(2, v.mustRevision(1))
	v.await(3, v.mustRevision(1))
	if got := mesh.forwardedFrom(2) + mesh.forwardedFrom(3); got != 0 {
		t.Fatalf("the leader's own writes were forwarded %d times", got)
	}

	// A session created on a follower: a control command proposed on voter 2.
	before := mesh.forwardedFrom(2)
	if _, err := v.fx[2].svc.Login(context.Background(), "owner@example.test", "a long test password 2026", ""); err != nil {
		t.Fatalf("login on a follower over the mTLS mesh: %v", err)
	}
	if got := mesh.forwardedFrom(2); got <= before {
		t.Fatalf("voter 2's login committed without a proposal arriving from voter 2's certificate (%d -> %d): it was not forwarded over TLS", before, got)
	}

	leader.saga(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{leader.project}})
	v.await(2, v.mustRevision(1))
	v.await(3, v.mustRevision(1))
	leader.pass()
	for _, id := range []uint64{2, 3} {
		before := mesh.forwardedFrom(id)
		v.fx[id].pass() // the follower's pass commits its record through the leader
		if got := mesh.forwardedFrom(id); got <= before {
			t.Fatalf("voter %d's redaction pass committed without a proposal arriving from its certificate (%d -> %d)", id, before, got)
		}
		if err := v.stores[id].ScrubErased(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	for id := uint64(1); id <= 3; id++ {
		v.await(id, v.mustRevision(1))
	}
	for id := uint64(1); id <= 3; id++ {
		if hits := v.fx[id].raftHits(erased); len(hits) != 0 {
			t.Fatalf("voter %d holds the erased payload after its pass over the mesh: %v", id, hits)
		}
		if !v.fx[id].stateHolds(kept) { // the journal no longer keeps the state (compact snapshot, D86): the state does
			t.Fatalf("voter %d lost a payload no deletion covers", id)
		}
		if got := v.stores[id].ResidualStores(); len(got) != 0 {
			t.Fatalf("voter %d after its own pass: %v", id, got)
		}
	}
	for _, id := range []uint64{2, 3} {
		if v.fx[1].canonicalState() != v.fx[id].canonicalState() {
			t.Fatalf("voter %d diverged from the leader after commands it forwarded over the mesh", id)
		}
	}
}
