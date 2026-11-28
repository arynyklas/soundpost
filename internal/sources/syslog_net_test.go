// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sources

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

var netClock = time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)

func netPolicy(t testing.TB, name string, spec SyslogSpec) SourcePolicy {
	spec.Tags = []string{"myapp"}
	return SourcePolicy{
		Name: name, Kind: KindSyslog, Class: ClassStructured, Revision: 1, Resource: testResource(),
		Labels: model.Labels{{Name: "source", Value: "app"}}, Templates: testTemplates(t),
		Syslog: &spec, clock: func() time.Time { return netClock },
	}
}

func loopback(network string) SyslogListen {
	return SyslogListen{Network: network, Address: "127.0.0.1:0"}
}

// the two framings a syslog daemon sends: RFC 3164 and RFC 5424
func bsd(msg string) string { return "<14>Nov 15 10:00:00 h myapp: " + msg }
func rfc5424(msg string) string {
	return "<14>1 2026-11-15T10:00:00Z h myapp 12 ID47 - " + msg
}
func octets(m string) string { return fmt.Sprintf("%d %s", len(m), m) }

func startNet(t *testing.T, p SourcePolicy) *SyslogReceiver {
	t.Helper()
	r, err := StartSyslogReceiver(p)
	if err != nil {
		t.Fatalf("start receiver: %v", err)
	}
	t.Cleanup(CloseSyslogReceivers)
	return r
}

func sendUDP(t *testing.T, addr net.Addr, msgs ...string) {
	t.Helper()
	c, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, m := range msgs {
		if _, err := c.Write([]byte(m)); err != nil {
			t.Fatal(err)
		}
	}
}

func sendTCP(t *testing.T, addr net.Addr, raw string) {
	t.Helper()
	c, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
}

// itemsWanted waits until the receiver has received n entries in total
// (receipt is asynchronous); the entries of a committed range stay until the
// next read releases them.
func itemsWanted(t *testing.T, r *SyslogReceiver, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.mu.Lock()
		got := r.next
		r.mu.Unlock()
		if got >= uint64(n) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("receiver has received %d entries, want %d", got, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// cyclesUntil runs source cycles until done reports true (the data arrives
// asynchronously through the sockets).
func cyclesUntil(t *testing.T, pump *Pump, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for {
		if _, err := pump.Cycle(context.Background()); err != nil {
			t.Fatalf("cycle: %v", err)
		}
		if done() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the expected data never arrived")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func sorted(l []string) []string {
	out := append([]string(nil), l...)
	sort.Strings(out)
	return out
}

type testPKI struct {
	t    *testing.T
	ca   *x509.Certificate
	key  *ecdsa.PrivateKey
	dir  string
	caPE string
	n    int64
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	p := &testPKI{t: t, ca: ca, key: key, dir: t.TempDir(), n: 1}
	p.caPE = filepath.Join(p.dir, "ca.pem")
	if err := os.WriteFile(p.caPE, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

// issue returns a certificate/key file pair signed by the test CA; a client
// certificate when client is set, otherwise a server certificate for 127.0.0.1.
func (p *testPKI) issue(client bool) (certFile, keyFile string) {
	p.t.Helper()
	p.n++
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		p.t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(p.n), Subject: pkix.Name{CommonName: "peer"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	if client {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		tpl.IPAddresses = nil
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.ca, &key.PublicKey, p.key)
	if err != nil {
		p.t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	certFile = filepath.Join(p.dir, fmt.Sprintf("c%d.pem", p.n))
	keyFile = filepath.Join(p.dir, fmt.Sprintf("k%d.pem", p.n))
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		p.t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0600); err != nil {
		p.t.Fatal(err)
	}
	return certFile, keyFile
}

func (p *testPKI) clientConfig(withCert bool) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(p.ca)
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if withCert {
		c, k := p.issue(true)
		cert, err := tls.LoadX509KeyPair(c, k)
		if err != nil {
			p.t.Fatal(err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg
}

func sendTLS(t *testing.T, addr net.Addr, cfg *tls.Config, raw string) {
	t.Helper()
	c, err := tls.Dial("tcp", addr.String(), cfg)
	if err != nil {
		return // a refused handshake is the expected outcome for an unauthenticated sender
	}
	defer c.Close()
	c.Write([]byte(raw))
	// a TLS 1.3 server rejects the missing client certificate after the client's
	// handshake returned: reading surfaces it, and orders the close after it
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	c.Read(make([]byte, 1))
}

// One source, all three transports. Every message is classified like a line of a
// syslog file: the approved ones become records, the others are counted by
// reason, and their text is neither kept nor exported.
func TestNetworkSyslogUDPTCPTLS(t *testing.T) {
	pki := newTestPKI(t)
	cert, key := pki.issue(false)
	p := netPolicy(t, "netsys", SyslogSpec{Listen: []SyslogListen{loopback("udp"), loopback("tcp"), {Network: "tls", Address: "127.0.0.1:0", CertFile: cert, KeyFile: key}}})
	r := startNet(t, p)
	store, dir := mustStore(t)
	server := newRecorder()
	pump := newPump(t, p, store, server)
	addrs := r.Addrs()

	sendUDP(t, addrs[0], rfc5424("service started unit alpha"), bsd("password reset for CANARY-SECRET-1"), "<14>Nov 15 10:00:00 h otherapp: service started unit beta", "not a syslog frame")
	sendTCP(t, addrs[1], bsd("service started unit beta")+"\n"+octets(rfc5424("request status 503")))
	sendTLS(t, addrs[2], pki.clientConfig(false), octets(rfc5424("request status 200"))+octets(bsd("service started unit beta")))

	want := []string{"request status 200", "request status 503", "service started unit alpha", "service started unit beta", "service started unit beta"}
	cyclesUntil(t, pump, func() bool { return len(server.lines()) >= len(want) })
	if got := sorted(server.lines()); !reflect.DeepEqual(got, want) {
		t.Fatalf("lines %q, want %q", got, want)
	}
	cp, _ := store.Load("netsys")
	if cp.Counters[DropUnknownTemplate] != 1 || cp.Counters[DropUnapprovedSource] != 1 || cp.Counters[DropBadFrame] != 1 || cp.Pending != nil || cp.Admitted != 5 {
		t.Fatalf("checkpoint %+v", cp)
	}
	if l := server.kinds(model.Loss); len(l) != 0 {
		t.Fatalf("a healthy receiver reported a loss: %+v", l)
	}
	for rid, n := range server.ids() {
		if n != 1 {
			t.Fatalf("record %s admitted %d times", rid, n)
		}
	}
	wire, _ := json.Marshal(server.batches)
	for place, text := range map[string]string{"wire": string(wire), "state": everyByteUnder(t, dir)} {
		if strings.Contains(text, "CANARY-SECRET") || strings.Contains(text, "otherapp") || strings.Contains(text, "not a syslog frame") {
			t.Fatalf("%s carries a message that was not approved", place)
		}
	}
}

// A lost acknowledgement rebuilds the pending range exactly; messages that
// arrive in between are not folded into it and are read afterwards.
func TestNetworkSyslogLostAckRebuildsTheSameRange(t *testing.T) {
	p := netPolicy(t, "netack", SyslogSpec{Listen: []SyslogListen{loopback("tcp")}})
	r := startNet(t, p)
	store, _ := mustStore(t)
	server := newRecorder()
	pump := newPump(t, p, store, server)

	sendTCP(t, r.Addrs()[0], bsd("service started unit alpha")+"\n")
	itemsWanted(t, r, 1)
	server.failBefore = true
	if _, err := pump.Cycle(context.Background()); err == nil {
		t.Fatal("a rejected batch was acknowledged")
	}
	cp, _ := store.Load("netack")
	if cp.Pending == nil || cp.Pending.Records != 1 || cp.Pending.To.Offset != 1 || cp.Position.Offset != 0 {
		t.Fatalf("the intent was not recorded durably before the submit: %+v", cp)
	}
	first := cp.Pending.Group

	sendTCP(t, r.Addrs()[0], bsd("service started unit beta")+"\n")
	itemsWanted(t, r, 2)
	server.failBefore = false
	if _, err := pump.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := server.lines(); !reflect.DeepEqual(got, []string{"service started unit alpha"}) {
		t.Fatalf("the retry must resubmit exactly the pending range, got %q", got)
	}
	if cp, _ := store.Load("netack"); cp.Position.Offset != 1 || cp.Counters[DropRebuilt] != 0 || cp.Pending != nil {
		t.Fatalf("after the retry %+v (first group %s)", cp, first)
	}
	cyclesUntil(t, pump, func() bool { return len(server.lines()) >= 2 })
	if got := server.lines(); !reflect.DeepEqual(got, []string{"service started unit alpha", "service started unit beta"}) {
		t.Fatalf("lines %q", got)
	}
	for rid, n := range server.ids() {
		if n != 1 {
			t.Fatalf("record %s admitted %d times", rid, n)
		}
	}
}

// What cannot survive a restart is declared: a received but uncommitted range
// and everything sent while the agent was down are one `shutdown` loss; the new
// epoch then continues, and the gap is reported once.
func TestNetworkSyslogRestartIsDeclaredAsAGap(t *testing.T) {
	p := netPolicy(t, "netrestart", SyslogSpec{Listen: []SyslogListen{loopback("tcp")}})
	r := startNet(t, p)
	store, _ := mustStore(t)
	server := newRecorder()
	pump := newPump(t, p, store, server)

	sendTCP(t, r.Addrs()[0], bsd("service started unit alpha")+"\n")
	cyclesUntil(t, pump, func() bool { return len(server.lines()) == 1 })
	if len(server.kinds(model.Loss)) != 0 {
		t.Fatalf("a first start is not a gap: %+v", server.kinds(model.Loss))
	}
	// received, read, never acknowledged
	sendTCP(t, r.Addrs()[0], bsd("request status 503")+"\n")
	itemsWanted(t, r, 2)
	server.failBefore = true
	if _, err := pump.Cycle(context.Background()); err == nil {
		t.Fatal("expected the rejected batch to fail the cycle")
	}
	server.failBefore = false

	CloseSyslogReceivers()
	r2 := startNet(t, p)
	if r2.Epoch() == r.Epoch() {
		t.Fatal("a restarted receiver kept its epoch")
	}
	sendTCP(t, r2.Addrs()[0], bsd("service started unit beta")+"\n")
	cyclesUntil(t, pump, func() bool { return len(server.lines()) >= 2 })
	if got := server.lines(); !reflect.DeepEqual(got, []string{"service started unit alpha", "service started unit beta"}) {
		t.Fatalf("lines %q", got)
	}
	losses := lossesOf(server)
	if len(losses) != 1 || losses[0].Reason != "shutdown" || losses[0].Signal != model.Log || losses[0].Count < 1 || losses[0].End < losses[0].Start {
		t.Fatalf("the restart must be exactly one shutdown gap: %+v", losses)
	}
	cp, _ := store.Load("netrestart")
	if cp.Position.File != r2.Epoch() || cp.Counters[DropRebuilt] != 1 {
		t.Fatalf("checkpoint after the restart %+v", cp)
	}
	pump.Cycle(context.Background())
	sendTCP(t, r2.Addrs()[0], bsd("service started unit alpha")+"\n")
	cyclesUntil(t, pump, func() bool { return len(server.lines()) >= 3 })
	if len(lossesOf(server)) != 1 {
		t.Fatalf("the restart gap was reported again: %+v", lossesOf(server))
	}
}

// A datagram that finds the buffer full is lost, and the loss is exposed with
// its exact count; a marker that a read already took is never changed, so a
// retry is identical and a later loss is a gap of its own.
func TestNetworkSyslogUDPOverflowIsAnExactGap(t *testing.T) {
	p := netPolicy(t, "netfull", SyslogSpec{Listen: []SyslogListen{loopback("udp")}, BufferRecords: 16})
	r := startNet(t, p)
	store, _ := mustStore(t)
	server := newRecorder()
	pump := newPump(t, p, store, server)
	rec, reason := r.classify([]byte(bsd("service started unit alpha")))
	if rec == nil {
		t.Fatalf("fixture line dropped: %s", reason)
	}
	for range 18 { // 16 fit, 2 are lost
		r.offer(rec, "", false)
	}
	server.failBefore = true // this read is taken but not acknowledged
	if _, err := pump.Cycle(context.Background()); err == nil {
		t.Fatal("expected the rejected batch to fail the cycle")
	}
	for range 3 { // lost after the range was handed out
		r.offer(rec, "", false)
	}
	server.failBefore = false
	if _, err := pump.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(server.lines()); n != 16 {
		t.Fatalf("%d records, want 16", n)
	}
	if got := lossesOf(server); len(got) != 1 || got[0].Reason != "queue_full" || got[0].Count != 2 {
		t.Fatalf("first range: %+v", got)
	}
	if _, err := pump.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := lossesOf(server)
	if len(got) != 2 || got[1].Reason != "queue_full" || got[1].Count != 3 {
		t.Fatalf("the later loss must be its own exact gap, got %+v", got)
	}
}

// Losses are counted exactly even when more distinct gaps pile up than the
// receiver keeps markers for: the surplus is carried into the next marker.
func TestNetworkSyslogOverflowAccountingBeyondTheMarkerCap(t *testing.T) {
	p := netPolicy(t, "netcarry", SyslogSpec{Listen: []SyslogListen{loopback("udp")}, BufferRecords: 16})
	p.MaxRecords = 512
	r := startNet(t, p)
	store, _ := mustStore(t)
	server := newRecorder()
	pump := newPump(t, p, store, server)
	rec, _ := r.classify([]byte(bsd("service started unit alpha")))
	for range 16 {
		r.offer(rec, "", false)
	}
	const lost = maxMarkers + 3
	for range lost {
		r.offer(rec, "", false)
		r.mu.Lock()
		r.frozen = r.next // as if a read had taken everything so far: this marker is final
		r.mu.Unlock()
	}
	for range 4 {
		if _, err := pump.Cycle(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	var total uint64
	for _, l := range lossesOf(server) {
		if l.Reason != "queue_full" {
			t.Fatalf("loss %+v", l)
		}
		total += uint64(l.Count)
	}
	if total != lost || len(server.lines()) != 16 {
		t.Fatalf("lost %d datagrams, reported %d (records %d)", lost, total, len(server.lines()))
	}
}

// TCP and TLS senders are not dropped when the buffer is full: the connection is
// not read until the source has committed, so nothing is lost.
func TestNetworkSyslogTCPBackpressureIsLossless(t *testing.T) {
	p := netPolicy(t, "nettcp", SyslogSpec{Listen: []SyslogListen{loopback("tcp")}, BufferRecords: 16})
	p.MaxRecords = 8
	r := startNet(t, p)
	store, _ := mustStore(t)
	server := newRecorder()
	pump := newPump(t, p, store, server)
	var sb strings.Builder
	for i := range 100 {
		unit := []string{"alpha", "beta"}[i%2]
		sb.WriteString(bsd("service started unit "+unit) + "\n")
	}
	sendTCP(t, r.Addrs()[0], sb.String())
	cyclesUntil(t, pump, func() bool { return len(server.lines()) >= 100 })
	if n := len(server.lines()); n != 100 {
		t.Fatalf("%d records, want 100", n)
	}
	if l := server.kinds(model.Loss); len(l) != 0 {
		t.Fatalf("flow control lost data: %+v", l)
	}
	for rid, n := range server.ids() {
		if n != 1 {
			t.Fatalf("record %s admitted %d times", rid, n)
		}
	}
}

// Octet-counted and newline-delimited frames, and over-long messages that are
// skipped without desynchronizing the stream or being buffered.
func TestNetworkSyslogFraming(t *testing.T) {
	p := netPolicy(t, "netframe", SyslogSpec{Listen: []SyslogListen{loopback("udp"), loopback("tcp")}})
	p.MaxLineBytes = 64
	r := startNet(t, p)
	store, dir := mustStore(t)
	server := newRecorder()
	pump := newPump(t, p, store, server)
	long := bsd("service started unit alpha " + strings.Repeat("CANARY-LONG", 12))
	stream := octets(bsd("service started unit alpha")) + octets(long) + bsd("request status 200") + "\n" + long + "\n" + octets(bsd("request status 503")) + "7 abc"
	sendTCP(t, r.Addrs()[1], stream)
	sendUDP(t, r.Addrs()[0], long, bsd("service started unit beta"))
	want := []string{"request status 200", "request status 503", "service started unit alpha", "service started unit beta"}
	cyclesUntil(t, pump, func() bool { return len(server.lines()) >= len(want) })
	cp, _ := store.Load("netframe")
	for deadline := time.Now().Add(5 * time.Second); cp.Counters[DropOversizeLine] < 3 && time.Now().Before(deadline); cp, _ = store.Load("netframe") {
		pump.Cycle(context.Background())
		time.Sleep(5 * time.Millisecond)
	}
	if got := sorted(server.lines()); !reflect.DeepEqual(got, want) {
		t.Fatalf("lines %q, want %q", got, want)
	}
	if cp.Counters[DropOversizeLine] != 3 {
		t.Fatalf("oversize drops %d, want 3 (octet, newline, datagram): %+v", cp.Counters[DropOversizeLine], cp.Counters)
	}
	if strings.Contains(everyByteUnder(t, dir), "CANARY-LONG") {
		t.Fatal("an over-long message reached the state directory")
	}
}

// A TLS listener with a client CA accepts only senders that present a
// certificate that CA signed.
func TestNetworkSyslogTLSClientCertificate(t *testing.T) {
	pki := newTestPKI(t)
	cert, key := pki.issue(false)
	p := netPolicy(t, "nettls", SyslogSpec{Listen: []SyslogListen{{Network: "tls", Address: "127.0.0.1:0", CertFile: cert, KeyFile: key, ClientCAFile: pki.caPE}}})
	r := startNet(t, p)
	store, _ := mustStore(t)
	server := newRecorder()
	pump := newPump(t, p, store, server)
	sendTLS(t, r.Addrs()[0], pki.clientConfig(false), octets(bsd("service started unit alpha")))
	sendTLS(t, r.Addrs()[0], pki.clientConfig(true), octets(bsd("service started unit beta")))
	cyclesUntil(t, pump, func() bool { return len(server.lines()) >= 1 })
	time.Sleep(100 * time.Millisecond)
	pump.Cycle(context.Background())
	if got := server.lines(); !reflect.DeepEqual(got, []string{"service started unit beta"}) {
		t.Fatalf("lines %q: only the sender with a client certificate may be accepted", got)
	}
}

// A listener that cannot be bound is a typed failure of the source, not an empty
// source.
func TestNetworkSyslogBindFailureIsTyped(t *testing.T) {
	first := netPolicy(t, "netbind", SyslogSpec{Listen: []SyslogListen{loopback("tcp")}})
	r := startNet(t, first)
	taken := SyslogListen{Network: "tcp", Address: r.Addrs()[0].String()}
	second := netPolicy(t, "netbind2", SyslogSpec{Listen: []SyslogListen{taken}})
	store, _ := mustStore(t)
	_, err := newPump(t, second, store, newRecorder()).Cycle(context.Background())
	se, ok := AsError(err)
	if !ok || se.Status != StatusUnknown || se.Reason != ReasonListenFailed {
		t.Fatalf("got %v, want unknown/listen_failed", err)
	}
	if cp, _ := store.Load("netbind2"); cp.Health.Status != StatusUnknown || cp.Health.Reason != ReasonListenFailed {
		t.Fatalf("health %+v", cp.Health)
	}
	// a TLS listener with an unusable certificate fails the same way
	bad := netPolicy(t, "netbind3", SyslogSpec{Listen: []SyslogListen{{Network: "tls", Address: "127.0.0.1:0", CertFile: filepath.Join(t.TempDir(), "no.pem"), KeyFile: filepath.Join(t.TempDir(), "no.key")}}})
	if _, err := StartSyslogReceiver(bad); err == nil {
		t.Fatal("a TLS listener without a certificate started")
	}
}

func TestNetworkSyslogPolicyValidation(t *testing.T) {
	ok := func() SourcePolicy {
		return netPolicy(t, "netpol", SyslogSpec{Listen: []SyslogListen{loopback("udp"), {Network: "tcp", Address: "[::1]:6514"}}})
	}
	if err := ok().Validate(); err != nil {
		t.Fatalf("baseline rejected: %v", err)
	}
	for name, mutate := range map[string]func(*SourcePolicy){
		"path and listeners":   func(p *SourcePolicy) { p.Syslog.Path = "/var/log/syslog" },
		"neither":              func(p *SourcePolicy) { p.Syslog.Listen = nil },
		"host name":            func(p *SourcePolicy) { p.Syslog.Listen[0].Address = "localhost:514" },
		"no port":              func(p *SourcePolicy) { p.Syslog.Listen[0].Address = "127.0.0.1" },
		"port out of range":    func(p *SourcePolicy) { p.Syslog.Listen[0].Address = "127.0.0.1:70000" },
		"unknown network":      func(p *SourcePolicy) { p.Syslog.Listen[0].Network = "sctp" },
		"tls without key pair": func(p *SourcePolicy) { p.Syslog.Listen[1] = SyslogListen{Network: "tls", Address: "127.0.0.1:6514"} },
		"relative certificate": func(p *SourcePolicy) {
			p.Syslog.Listen[1] = SyslogListen{Network: "tls", Address: "127.0.0.1:6514", CertFile: "c.pem", KeyFile: "/k.pem"}
		},
		"certificate on udp": func(p *SourcePolicy) { p.Syslog.Listen[0].CertFile = "/c.pem" },
		"start at end":       func(p *SourcePolicy) { p.Syslog.StartAt = StartEnd },
		"rotated paths":      func(p *SourcePolicy) { p.Syslog.Rotated = []string{"/var/log/syslog.1"} },
		"tiny buffer":        func(p *SourcePolicy) { p.Syslog.BufferRecords = 5 },
		"huge buffer":        func(p *SourcePolicy) { p.Syslog.BufferRecords = maxNetBuffer + 1 },
		"too many listeners": func(p *SourcePolicy) {
			p.Syslog.Listen = append(p.Syslog.Listen, loopback("udp"), loopback("tcp"), loopback("udp"))
		},
		"duplicate listener": func(p *SourcePolicy) { p.Syslog.Listen = append(p.Syslog.Listen, p.Syslog.Listen[1]) },
		"buffer on a file source": func(p *SourcePolicy) {
			p.Syslog.Listen, p.Syslog.Path, p.Syslog.BufferRecords = nil, "/var/log/syslog", 64
		},
		"tls and tcp share a port": func(p *SourcePolicy) {
			p.Syslog.Listen = append(p.Syslog.Listen, SyslogListen{Network: "tls", Address: "[::1]:6514", CertFile: "/c.pem", KeyFile: "/k.pem"})
		},
	} {
		p := ok()
		mutate(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: policy accepted", name)
		}
	}
}
