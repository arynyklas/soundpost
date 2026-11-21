// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
)

// smallSendBuffer gives every accepted connection a tiny kernel send buffer so a
// client that stops reading blocks the server's writes after a few frames
// instead of after megabytes.
type smallSendBuffer struct{ net.Listener }

func (l smallSendBuffer) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetWriteBuffer(2048)
	}
	return c, err
}

// A real TCP client that opens a live stream and then never reads again must be
// dropped by the per-frame write deadline: the server closes the connection and
// the live service releases the stream, instead of buffering for it or waiting
// for it forever.
func TestLiveStalledTCPReaderIsDroppedByTheWriteDeadline(t *testing.T) {
	const deadline = 300 * time.Millisecond
	t.Cleanup(httpapi.SetLiveWriteTimeoutForTest(deadline))
	e := newLiveEnv(t, func(l *query.LiveLimits) { l.ReplayWindow = 400 * time.Millisecond })
	p := model.NewID()
	org := e.org("live org", p)
	alice := e.user(org, "alice@example.test")
	e.grant(org, alice, p, true, auth.Read)
	src := e.logSource(org, p)
	ticket := e.mustTicket(alice, e.body(org, p, `{app="web"}`))

	stall := httptest.NewUnstartedServer(e.server.Config.Handler)
	stall.Listener = smallSendBuffer{stall.Listener}
	stall.StartTLS()
	t.Cleanup(stall.Close)

	raw, err := net.Dial("tcp", stall.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(1024)
	}
	pool := x509.NewCertPool()
	pool.AddCert(stall.Certificate())
	conn := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: "example.com"})
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	req := e.request(alice, "GET", "/api/v1/live?ticket="+ticket, nil, map[string]string{"Origin": stall.URL})
	req.URL, _ = url.Parse(stall.URL + "/api/v1/live?ticket=" + ticket)
	req.Host = req.URL.Host
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("stream did not open: %v %v", resp, err)
	}
	// Read the open event, then stop reading for good.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	opened := false
	for line := ""; !opened; {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("no open event: %v", err)
		}
		if line = strings.TrimSpace(l); line == "event: open" {
			opened = true
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
	if u := e.svc.Usage(); u.Streams != 1 || u.Attached != 1 {
		t.Fatalf("one open stream expected: %+v", u)
	}

	// Commit records until the connection backs up and the server drops the
	// consumer (the handler detaches; the stream itself lapses with its replay
	// window).
	released := time.Time{}
	names := []string{"alice", "bob", "carol", "dave", "erin", "frank", "grace"}
	start := time.Now()
	for i := 0; i < 400 && released.IsZero(); i++ {
		e.admit(src, names[i%len(names)])
		if e.svc.Usage().Attached == 0 {
			released = time.Now()
		}
	}
	for released.IsZero() && time.Since(start) < 10*time.Second {
		if e.svc.Usage().Attached == 0 {
			released = time.Now()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if released.IsZero() {
		t.Fatalf("a stalled reader is still attached after %v: %+v", time.Since(start), e.svc.Usage())
	}
	e.idle(t) // the detached stream lapses with its replay window and everything is released

	// The server closed the socket: draining what was already queued ends in EOF
	// or a reset, never in our own read deadline.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.Copy(io.Discard, br)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("the stalled connection is still open after its stream was released")
	}
}
