// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	raft "go.etcd.io/raft/v3"
	pb "go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
	"soundpost/internal/model"
)

const raftPath = "/internal/raft/v1/"

type outbound struct {
	group   model.ID
	message *pb.Message
}
type MTLS struct {
	mu          sync.RWMutex
	id          uint64
	identity    string
	certificate tls.Certificate
	roots       *x509.CertPool
	dialer      *net.Dialer
	groups      map[model.ID]*Group
	queues      map[uint64]chan outbound
	clients     map[string]*http.Client
	stop        chan struct{}
	once        sync.Once
	workers     sync.WaitGroup
}

func NewMTLS(id uint64, identity string, certificate tls.Certificate, roots *x509.CertPool, sourceIP string) (*MTLS, error) {
	if id == 0 || identity == "" || len(certificate.Certificate) == 0 || roots == nil {
		return nil, ErrInvalid
	}
	cert, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || certificateIdentity(cert) != identity {
		return nil, ErrInvalid
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if sourceIP != "" {
		ip := net.ParseIP(sourceIP)
		if ip == nil {
			return nil, ErrInvalid
		}
		dialer.LocalAddr = &net.TCPAddr{IP: ip}
	}
	return &MTLS{id: id, identity: identity, certificate: certificate, roots: roots, dialer: dialer, groups: map[model.ID]*Group{}, queues: map[uint64]chan outbound{}, clients: map[string]*http.Client{}, stop: make(chan struct{})}, nil
}
func certificateIdentity(c *x509.Certificate) string {
	if c == nil {
		return ""
	}
	found := ""
	for _, u := range c.URIs {
		if u.Scheme == "spiffe" && u.Host == "soundpost" && strings.HasPrefix(u.Path, "/node/") && u.RawQuery == "" && u.Fragment == "" {
			name := strings.TrimPrefix(u.Path, "/node/")
			if name == "" || strings.Contains(name, "/") || found != "" {
				return ""
			}
			found = name
		}
	}
	return found
}
func (t *MTLS) ServerTLS() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{t.certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: t.roots, NextProtos: []string{"h2", "http/1.1"}}
}
func (t *MTLS) Register(g *Group) error {
	if g == nil || g.id != t.id {
		return ErrInvalid
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.groups[g.group] != nil {
		return ErrConflict
	}
	t.groups[g.group] = g
	return nil
}
func (t *MTLS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if strings.HasPrefix(r.URL.Path, proposalPath) {
		t.serveProposal(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, readinessPath) {
		t.serveReadiness(w, r)
		return
	}
	if r.Method != "POST" || !strings.HasPrefix(r.URL.Path, raftPath) || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	identity := certificateIdentity(r.TLS.PeerCertificates[0])
	var group model.ID
	if group.UnmarshalText([]byte(strings.TrimPrefix(r.URL.Path, raftPath))) != nil {
		http.Error(w, "invalid", http.StatusBadRequest)
		return
	}
	t.mu.RLock()
	g := t.groups[group]
	t.mu.RUnlock()
	if g == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	members := g.transportMembers()
	var sender uint64
	for _, m := range members.Nodes {
		if m.NodeIdentity == identity {
			sender = m.ID
		}
	}
	if sender == 0 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxReadyBytes+1))
	if err != nil || len(raw) > maxReadyBytes {
		http.Error(w, "invalid", http.StatusBadRequest)
		return
	}
	message := &pb.Message{}
	if proto.Unmarshal(raw, message) != nil || message.GetFrom() != sender || message.GetTo() != t.id || raft.IsLocalMsg(message.GetType()) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err = g.Step(r.Context(), message); err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (t *MTLS) Send(group model.ID, m *pb.Message) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	g := t.groups[group]
	if g == nil || m == nil || m.GetFrom() != t.id {
		return ErrInvalid
	}
	queue := t.queues[m.GetTo()]
	if queue == nil {
		queue = make(chan outbound, 128)
		t.queues[m.GetTo()] = queue
		t.workers.Add(1)
		go t.deliver(queue)
	}
	select {
	case <-t.stop:
		return ErrUnavailable
	case queue <- outbound{group: group, message: m}:
		return nil
	default:
		return ErrUnavailable
	}
}
func (t *MTLS) deliver(queue <-chan outbound) {
	defer t.workers.Done()
	for {
		select {
		case <-t.stop:
			return
		case out := <-queue:
			t.mu.RLock()
			g := t.groups[out.group]
			t.mu.RUnlock()
			if g == nil {
				continue
			}
			members := g.transportMembers()
			var target Member
			for _, m := range members.Nodes {
				if m.ID == out.message.GetTo() {
					target = m
				}
			}
			err := t.sendOne(out, target)
			g.ReportDelivery(out.message.GetTo(), out.message.GetType() == pb.MsgSnap, err)
		}
	}
}
func (t *MTLS) sendOne(out outbound, target Member) error {
	client, err := t.peerClient(target)
	if err != nil {
		return err
	}
	raw, err := proto.Marshal(out.message)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, "POST", strings.TrimSuffix(target.Address, "/")+raftPath+out.group.String(), bytes.NewReader(raw))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-protobuf")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return ErrUnavailable
	}
	return nil
}
func (g *Group) ReportDelivery(to uint64, snapshot bool, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failed || g.closed {
		return
	}
	if err != nil {
		g.raw.ReportUnreachable(to)
	}
	if snapshot {
		status := raft.SnapshotFinish
		if err != nil {
			status = raft.SnapshotFailure
		}
		g.raw.ReportSnapshot(to, status)
	}
	if g.processReady() != nil {
		g.fail()
	}
}
func (t *MTLS) Close() error {
	t.once.Do(func() { close(t.stop) })
	t.workers.Wait()
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, client := range t.clients {
		client.CloseIdleConnections()
	}
	return nil
}
