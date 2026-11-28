// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/hmac"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/notify/providers"
)

// webhookWire is the part of the product's webhook body (internal/notify/providers/webhook.go webhookBody) the receiver reads. Every
// member is a closed word or an identifier; the body never carries telemetry.
type webhookWire struct {
	DeliveryID string `json:"delivery_id"`
	EventKind  string `json:"event_kind"`
	Org        string `json:"org_id"`
	Entity     struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	} `json:"entity"`
	Impact struct {
		Source    string `json:"source"`
		Freshness string `json:"freshness"`
	} `json:"impact"`
}

// webhookReceiver is the notification destination of every organization: it verifies each delivery exactly as a customer receiver must
// (the signature over timestamp, delivery id and the exact body, the timestamp within the 5 minute replay window, the body naming the
// signed delivery id), answers 204 with a receipt id, and records one Notification line per delivery, valid or not. A delivery that
// fails verification is answered 401 and recorded with sig_ok false; the validator fails the gate on it.
type webhookReceiver struct {
	secret []byte
	now    func() time.Time

	mu   sync.Mutex
	seen map[string]int
	out  io.Writer

	total, verified, bad atomic.Int64
}

func newWebhookReceiver(secret string, out io.Writer, now func() time.Time) *webhookReceiver {
	return &webhookReceiver{secret: []byte(secret), now: now, seen: map[string]int{}, out: out}
}

func (r *webhookReceiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	if err != nil {
		http.Error(w, "body", http.StatusBadRequest)
		return
	}
	at := r.now()
	id := req.Header.Get(providers.HeaderDeliveryID)
	ok := false
	if ts, perr := strconv.ParseInt(req.Header.Get(providers.HeaderTimestamp), 10, 64); perr == nil && id != "" {
		skew := at.Sub(time.Unix(ts, 0))
		if skew < 0 {
			skew = -skew
		}
		want := providers.Sign(r.secret, ts, id, body)
		ok = skew <= providers.ReplayWindow && hmac.Equal([]byte(want), []byte(req.Header.Get(providers.HeaderSignature)))
	}
	var wire webhookWire
	parsed := json.Unmarshal(body, &wire) == nil
	if ok && (!parsed || wire.DeliveryID != id) {
		ok = false // a body that does not name the signed delivery is not the product's delivery
	}

	r.mu.Lock()
	r.seen[id]++
	attempt := r.seen[id]
	line := Notification{TMS: at.UnixMilli(), Delivery: id, Entity: wire.Entity.ID, Org: wire.Org, Kind: wire.EventKind,
		Source: wire.Impact.Source, Freshness: wire.Impact.Freshness, Attempt: attempt, SigOK: ok}
	fmt.Fprintf(r.out, "%s\n", mustJSON(line))
	r.mu.Unlock()

	r.total.Add(1)
	if !ok {
		r.bad.Add(1)
		http.Error(w, "signature", http.StatusUnauthorized)
		return
	}
	r.verified.Add(1)
	w.Header().Set(providers.HeaderReceiptID, fmt.Sprintf("rcpt-%s-%d", id, attempt))
	w.WriteHeader(http.StatusNoContent)
}

// startWebhook listens with the leaf the server role generated (the destinations' egress allow-list and CA name this very address) and
// appends to path. The returned stop closes the listener and the file.
func startWebhook(pw PlanWebhook, path string) (*webhookReceiver, func()) {
	cert, err := tls.X509KeyPair([]byte(pw.CertPEM), []byte(pw.KeyPEM))
	must(err, "webhook leaf")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	must(err, "notifications file")
	ln, err := net.Listen("tcp", pw.Listen)
	must(err, "webhook listen")
	rcv := newWebhookReceiver(pw.Secret, f, time.Now)
	srv := &http.Server{Handler: rcv, ReadHeaderTimeout: 30 * time.Second}
	go srv.Serve(tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}))
	return rcv, func() {
		srv.Close()
		rcv.mu.Lock()
		f.Close()
		rcv.mu.Unlock()
	}
}
