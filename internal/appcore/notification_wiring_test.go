// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify/providers"
)

// privateHostAddress is a non-loopback private IPv4 address of this host: the
// production egress policy never lets loopback be reached, so a real receiver
// must listen on a private interface.
func privateHostAddress(t *testing.T) netip.Addr {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipnet.IP)
		if ok && ip.Unmap().Is4() && ip.Unmap().IsPrivate() && !ip.IsLoopback() {
			return ip.Unmap()
		}
	}
	t.Skip("no private (RFC 1918) IPv4 interface on this host: the egress policy forbids loopback receivers")
	return netip.Addr{}
}

// receiver is a TLS webhook receiver on a private interface with its own CA.
type receiver struct {
	url   string
	roots *x509.CertPool
	addr  netip.Addr
	mu    sync.Mutex
	posts []post
}

type post struct {
	header http.Header
	body   []byte
}

func (r *receiver) received() []post {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]post(nil), r.posts...)
}

func newReceiver(t *testing.T) *receiver {
	t.Helper()
	ip := privateHostAddress(t)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "soundpost test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "receiver"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.IP(ip.AsSlice())}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	r := &receiver{roots: x509.NewCertPool(), addr: ip}
	r.roots.AddCert(ca)
	listener, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.posts = append(r.posts, post{header: req.Header.Clone(), body: body})
		r.mu.Unlock()
		w.Header().Set("Soundpost-Receipt-ID", "receiver-receipt-1")
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Listener.Close()
	server.Listener = listener
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	r.url = "https://" + listener.Addr().String() + "/hook"
	return r
}

func (n *workerNode) webhookDestination(endpoint, secret string, enabled bool) model.ID {
	n.t.Helper()
	id := model.NewID()
	raw, _ := json.Marshal(auth.DestinationConfig{Type: "webhook", Endpoint: endpoint, Enabled: enabled})
	n.command("destination", auth.AdminPayload{ID: id, Config: raw, Secret: secret})
	return id
}

func (n *workerNode) notificationSender(r *receiver) appcore.NotificationConfig {
	n.t.Helper()
	cfg := appcore.NotificationConfig{PublicOrigin: "https://soundpost.example.test", StateDir: filepath.Join(n.t.TempDir(), "notify"), RootCAs: r.roots}
	cfg.Egress.AllowPrefixes = []netip.Prefix{netip.PrefixFrom(r.addr, 32)}
	return cfg
}

// A rule fires, its condition is consumed and routed to the organization's enabled
// destination, and the REAL signed webhook provider delivers it to a TLS receiver
// under the system principal (no session): the signature verifies with the sealed
// destination secret, a second pass sends nothing, the attempt time was stamped once.
func TestWorkersDeliverARoutedNotificationToAWebhookReceiver(t *testing.T) {
	n := newWorkerNode(t)
	recv := newReceiver(t)
	n.setDestinationEnabled(n.dest, false)
	secret := "destination signing secret 0123456789"
	dest := n.webhookDestination(recv.url, secret, true)
	disabled := n.webhookDestination(recv.url+"-disabled", secret, false)
	cfg := n.notificationSender(recv)
	sender, err := n.app.NotificationSender(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rule := n.alertRule()
	w, err := n.app.NewWorkers(n.config(func(c *appcore.WorkerConfig) {
		c.Rules, c.Routing, c.Sender = staticRules{rule}, n.app.OrgRouting(), sender
	}))
	if err != nil {
		t.Fatal(err)
	}
	rep := n.tick(w)
	if rep.Submitted == 0 || rep.Attempted != 1 {
		t.Fatalf("pass: %+v", rep)
	}
	got := recv.received()
	if len(got) != 1 {
		t.Fatalf("receiver got %d posts, want 1", len(got))
	}
	p := got[0]
	ts, err := strconv.ParseInt(p.header.Get(providers.HeaderTimestamp), 10, 64)
	if err != nil {
		t.Fatalf("timestamp header: %v", err)
	}
	if want := providers.Sign([]byte(secret), ts, p.header.Get(providers.HeaderDeliveryID), p.body); p.header.Get(providers.HeaderSignature) != want {
		t.Fatal("the signature does not verify with the destination's sealed secret")
	}
	var body struct {
		EventKind string `json:"event_kind"`
		Org       string `json:"org_id"`
		Entity    struct {
			Kind string `json:"kind"`
		} `json:"entity"`
		Link string `json:"link"`
	}
	if err = json.Unmarshal(p.body, &body); err != nil || body.Org != n.org.String() || body.Entity.Kind != "condition" || body.Link == "" {
		t.Fatalf("body %s (%v)", p.body, err)
	}
	if got := n.deliveries(control.DeliveryAccepted); len(got) != 1 || got[0].Recipient == nil || *got[0].Recipient != dest {
		t.Fatalf("settled deliveries %+v: want exactly one, to %s (never to the disabled %s)", got, dest, disabled)
	}
	if rep = n.tick(w); rep.Attempted != 0 || len(recv.received()) != 1 {
		t.Fatalf("second pass: %+v, %d posts", rep, len(recv.received()))
	}
	stamps, err := os.ReadDir(cfg.StateDir)
	if err != nil || len(stamps) != 1 {
		t.Fatalf("attempt stamps %v: %v", stamps, err)
	}
	system := 0
	if err = n.app.Control.View(n.ctx, func(st model.ControlState) error {
		for _, a := range st.Audits {
			if a.Principal == auth.SystemPrincipal(n.org) && len(a.Action) > 15 && a.Action[:15] == "notify.delivery" {
				system++
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if system == 0 {
		t.Fatal("no delivery transition is audited as the system principal")
	}
}

// A destination of a channel the node has not configured is a visible failure: the
// delivery fails with channel_unconfigured and nothing is sent anywhere.
func TestWorkersFailAVisibleDeliveryForAnUnconfiguredChannel(t *testing.T) {
	n := newWorkerNode(t)
	recv := newReceiver(t)
	n.setDestinationEnabled(n.dest, false)
	id := model.NewID()
	raw, _ := json.Marshal(auth.DestinationConfig{Type: "smtp", Address: "ops@example.test", Enabled: true})
	n.command("destination", auth.AdminPayload{ID: id, Config: raw, Secret: "relay password 0123456789"})
	sender, err := n.app.NotificationSender(n.notificationSender(recv))
	if err != nil {
		t.Fatal(err)
	}
	rule := n.alertRule()
	w, err := n.app.NewWorkers(n.config(func(c *appcore.WorkerConfig) {
		c.Rules, c.Routing, c.Sender = staticRules{rule}, n.app.OrgRouting(), sender
	}))
	if err != nil {
		t.Fatal(err)
	}
	if rep := n.tick(w); rep.Attempted != 1 {
		t.Fatalf("pass: %+v", rep)
	}
	var failed []string
	for _, d := range n.deliveries(control.DeliveryFailed) {
		failed = append(failed, d.Code)
	}
	if len(failed) != 1 || failed[0] != "channel_unconfigured" || len(recv.received()) != 0 {
		t.Fatalf("failed deliveries %v, posts %d", failed, len(recv.received()))
	}
}

// Routing is the organization's own enabled destinations: with none configured nothing
// is decided, a disabled one is never a route, and an enabled one is picked up at once.
func TestOrgRoutingFollowsTheOrganizationsEnabledDestinations(t *testing.T) {
	n := newWorkerNode(t)
	n.setDestinationEnabled(n.dest, false)
	routing := n.app.OrgRouting()
	if _, found, err := routing.Routing(n.ctx, n.admin(), n.project); err != nil || found {
		t.Fatalf("a disabled destination routed: found=%t err=%v", found, err)
	}
	live := n.webhookDestination("https://hooks.example.test/live", "destination signing secret 0123456789", true)
	binding, found, err := routing.Routing(n.ctx, n.admin(), n.project)
	if err != nil || !found || len(binding.Recipients) != 1 || binding.Recipients[0] != live || binding.Revision != 1 {
		t.Fatalf("binding %+v found=%t err=%v", binding, found, err)
	}
	other := model.NewID()
	n.addProject(other)
	again, found, err := routing.Routing(n.ctx, n.adminFor(other), other)
	if err != nil || !found || again.Policy == binding.Policy {
		t.Fatalf("a second project must route to the same destinations under its own policy: %+v found=%t err=%v", again, found, err)
	}
	if err = n.app.Control.Update(n.ctx, func(st *model.ControlState) error {
		if st.RetiredOrgs == nil {
			st.RetiredOrgs = map[string]model.ID{}
		}
		st.RetiredOrgs[n.org.String()] = model.NewID()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, found, err = routing.Routing(n.ctx, n.admin(), n.project); err != nil || found {
		t.Fatalf("a retired organization routed: found=%t err=%v", found, err)
	}
}

func (n *workerNode) setDestinationEnabled(id model.ID, enabled bool) {
	n.t.Helper()
	raw, _ := json.Marshal(auth.DestinationConfig{Type: "webhook", Endpoint: "https://hooks.example.test/notify", Enabled: enabled})
	n.command("destination", auth.AdminPayload{ID: id, Config: raw})
}

// An incident opened by the runner's own principal is decided into the outbox and
// delivered to the webhook receiver with no human session anywhere in the pass: the
// notification is about the incident entity, its delivery is audited as system:runner,
// and a second pass sends nothing.
func TestWorkersDeliverAnIncidentOpenedBySystemRunner(t *testing.T) {
	n := newWorkerNode(t)
	recv := newReceiver(t)
	n.setDestinationEnabled(n.dest, false)
	secret := "destination signing secret 0123456789"
	dest := n.webhookDestination(recv.url, secret, true)
	sender, err := n.app.NotificationSender(n.notificationSender(recv))
	if err != nil {
		t.Fatal(err)
	}
	admin, err := n.app.Auth.AuthorizeSystem(n.ctx, n.org, []model.ID{n.project}, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	incident := model.NewID()
	opened, err := n.app.Incidents.Act(n.ctx, admin, incidents.Action{CommandID: model.NewID(), Type: incidents.TypeOpen, Origin: incidents.OriginSystem, Target: incidents.Target{Project: n.project, Incident: incident},
		Impact: &incidents.Impact{Condition: model.NewID(), Episode: model.NewID(), Severity: incidents.SeverityMajor, State: incidents.ConditionFiring, Freshness: incidents.FreshnessFresh}}, model.UnixNano(workerNow))
	if err != nil || opened.Status != incidents.StatusOpen {
		t.Fatalf("open: %+v %v", opened, err)
	}
	w, err := n.app.NewWorkers(n.config(func(c *appcore.WorkerConfig) { c.Routing, c.Sender = n.app.OrgRouting(), sender }))
	if err != nil {
		t.Fatal(err)
	}
	rep := n.tick(w)
	if rep.Submitted == 0 || rep.Attempted != 1 {
		t.Fatalf("pass: %+v", rep)
	}
	got := recv.received()
	if len(got) != 1 {
		t.Fatalf("receiver got %d posts, want 1", len(got))
	}
	var body struct {
		EventKind string `json:"event_kind"`
		Entity    struct {
			Kind string   `json:"kind"`
			ID   model.ID `json:"id"`
		} `json:"entity"`
	}
	ts, _ := strconv.ParseInt(got[0].header.Get(providers.HeaderTimestamp), 10, 64)
	if want := providers.Sign([]byte(secret), ts, got[0].header.Get(providers.HeaderDeliveryID), got[0].body); got[0].header.Get(providers.HeaderSignature) != want {
		t.Fatal("bad signature")
	}
	if err = json.Unmarshal(got[0].body, &body); err != nil || body.Entity.Kind != "incident" || body.Entity.ID != incident {
		t.Fatalf("body %s (%v)", got[0].body, err)
	}
	if acc := n.deliveries(control.DeliveryAccepted); len(acc) != 1 || *acc[0].Recipient != dest {
		t.Fatalf("accepted %+v", acc)
	}
	if rep = n.tick(w); rep.Attempted != 0 || len(recv.received()) != 1 {
		t.Fatalf("second pass: %+v, %d posts", rep, len(recv.received()))
	}
}
