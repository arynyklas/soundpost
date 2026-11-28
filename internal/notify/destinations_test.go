// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package notify_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

const (
	canaryPlain   = "CANARY-SECRET-0d9e7a41b3c5"
	canaryHook    = "CANARY-HOOK-PATH-77aa"
	canaryChat    = "-100987654321"
	canaryMailbox = "canary.mailbox"
)

type destFake struct {
	mu      sync.Mutex
	recs    map[[2]model.ID]notify.DestinationRecord
	secrets map[[2]model.ID]string
	reads   int
	srcErr  error
	rdErr   error
}

func newDestFake() *destFake {
	return &destFake{recs: map[[2]model.ID]notify.DestinationRecord{}, secrets: map[[2]model.ID]string{}}
}

func (f *destFake) put(org, id model.ID, rec notify.DestinationRecord, secret string) {
	rec.HasSecret = secret != ""
	f.recs[[2]model.ID{org, id}] = rec
	if secret != "" {
		f.secrets[[2]model.ID{org, id}] = secret
	}
}

func (f *destFake) Destination(_ context.Context, _ auth.Scope, org, id model.ID) (notify.DestinationRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.srcErr != nil {
		return notify.DestinationRecord{}, false, f.srcErr
	}
	r, ok := f.recs[[2]model.ID{org, id}]
	return r, ok, nil
}

func (f *destFake) Read(_ context.Context, _ auth.Scope, ref notify.SecretRef) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.rdErr != nil {
		return nil, f.rdErr
	}
	return []byte(f.secrets[[2]model.ID{ref.Org, ref.ID}]), nil
}

func deliveryFor(org, recipient model.ID) notify.Delivery {
	r := recipient
	return notify.Delivery{ID: model.ID{0xde, 1}, Key: notify.IntentKey{Org: org, Entity: incident, Kind: notify.KindOpen, Recipient: &r}}
}

var rid = model.ID{0xd1, 0x07}

func TestDestinationResolveIsOrgScopedAndValidated(t *testing.T) {
	a, b := newNode(t), newNode(t)
	f := newDestFake()
	f.put(a.org, rid, notify.DestinationRecord{Type: "webhook", Endpoint: "https://hooks.example.test/" + canaryHook, Enabled: true}, canaryPlain)
	reg, err := notify.NewDestinations(f, f)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	d, err := reg.Resolve(ctx, a.scope(), deliveryFor(a.org, rid), notify.ChannelWebhook)
	if err != nil || d.Org != a.org || d.Secret == nil || d.Secret.Org != a.org {
		t.Fatalf("%+v %v", d, err)
	}
	// another organization's delivery under this scope: Forbidden, no source access
	var fault *model.Fault
	if _, err = reg.Resolve(ctx, a.scope(), deliveryFor(b.org, rid), notify.ChannelWebhook); !errors.As(err, &fault) || fault.Code != model.Forbidden {
		t.Fatalf("cross-org delivery: %v", err)
	}
	// the same recipient id in the other organization does not exist there
	if _, err = reg.Resolve(ctx, b.scope(), deliveryFor(b.org, rid), notify.ChannelWebhook); !errors.Is(err, notify.ErrNoDestination) {
		t.Fatalf("other org: %v", err)
	}
	// wrong channel for the destination, shared queue entry, unknown recipient
	if _, err = reg.Resolve(ctx, a.scope(), deliveryFor(a.org, rid), notify.ChannelSMTP); !errors.Is(err, notify.ErrNoDestination) {
		t.Fatalf("channel mismatch: %v", err)
	}
	q := deliveryFor(a.org, rid)
	q.Key.Recipient = nil
	if _, err = reg.Resolve(ctx, a.scope(), q, notify.ChannelWebhook); !errors.Is(err, notify.ErrNoDestination) {
		t.Fatalf("queue: %v", err)
	}
	if _, err = reg.Resolve(ctx, a.scope(), deliveryFor(a.org, model.ID{9}), notify.ChannelWebhook); !errors.Is(err, notify.ErrNoDestination) {
		t.Fatalf("unknown: %v", err)
	}
	// disabled
	f.put(a.org, rid, notify.DestinationRecord{Type: "webhook", Endpoint: "https://hooks.example.test/x", Enabled: false}, "")
	if _, err = reg.Resolve(ctx, a.scope(), deliveryFor(a.org, rid), notify.ChannelWebhook); !errors.Is(err, notify.ErrDestinationDisabled) {
		t.Fatalf("disabled: %v", err)
	}
	// invalid stored destinations never resolve
	for name, rec := range map[string]notify.DestinationRecord{
		"http":      {Type: "webhook", Endpoint: "http://hooks.example.test/x", Enabled: true},
		"userinfo":  {Type: "webhook", Endpoint: "https://user:pw@hooks.example.test/x", Enabled: true},
		"query":     {Type: "webhook", Endpoint: "https://hooks.example.test/x?token=1", Enabled: true},
		"fragment":  {Type: "webhook", Endpoint: "https://hooks.example.test/x#f", Enabled: true},
		"no host":   {Type: "webhook", Endpoint: "https:///x", Enabled: true},
		"empty":     {Type: "webhook", Enabled: true},
		"chat text": {Type: "telegram", Address: "not a chat", Enabled: true},
		"chat url":  {Type: "telegram", Address: "https://t.me/x", Enabled: true},
		"mail crlf": {Type: "smtp", Address: "a@example.test\r\nBcc: x@example.test", Enabled: true},
		"mail name": {Type: "smtp", Address: "Eve <e@example.test>", Enabled: true},
		"mail two":  {Type: "smtp", Address: "a@example.test,b@example.test", Enabled: true},
	} {
		f.put(a.org, rid, rec, "")
		ch := notify.Channel(rec.Type)
		if _, err = reg.Resolve(ctx, a.scope(), deliveryFor(a.org, rid), ch); !errors.Is(err, notify.ErrDestinationInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, rec := range []notify.DestinationRecord{
		{Type: "telegram", Address: "@soundpost_ops", Enabled: true},
		{Type: "telegram", Address: canaryChat, Enabled: true},
		{Type: "smtp", Address: "oncall+x@example.test", Enabled: true},
	} {
		f.put(a.org, rid, rec, "")
		if _, err = reg.Resolve(ctx, a.scope(), deliveryFor(a.org, rid), notify.Channel(rec.Type)); err != nil {
			t.Errorf("%+v: %v", rec, err)
		}
	}
	// a source outage is unavailable, and says nothing else
	f.srcErr = errors.New("db down " + canaryPlain)
	_, err = reg.Resolve(ctx, a.scope(), deliveryFor(a.org, rid), notify.ChannelTelegram)
	if err == nil || strings.Contains(err.Error(), canaryPlain) {
		t.Fatalf("source error: %v", err)
	}
}

func TestDestinationSecretCrossOrgIsForbiddenAndIndistinguishableFromMissing(t *testing.T) {
	a, b := newNode(t), newNode(t)
	f := newDestFake()
	f.put(a.org, rid, notify.DestinationRecord{Type: "webhook", Endpoint: "https://hooks.example.test/x", Enabled: true}, canaryPlain)
	f.put(a.org, model.ID{0xd1, 0x08}, notify.DestinationRecord{Type: "webhook", Endpoint: "https://hooks.example.test/y", Enabled: true}, "")
	reg, _ := notify.NewDestinations(f, f)
	ctx := context.Background()

	got, err := reg.Read(ctx, a.scope(), notify.SecretRef{Org: a.org, ID: rid})
	if err != nil || string(got) != canaryPlain {
		t.Fatalf("own secret: %q %v", got, err)
	}
	f.reads = 0
	// b's scope naming a's secret; and b's scope naming a's org inside the ref
	cross := []notify.SecretRef{{Org: a.org, ID: rid}}
	// missing in own org, destination without a secret, and a foreign destination named under own org
	missing := []notify.SecretRef{{Org: b.org, ID: rid}, {Org: b.org, ID: model.ID{0x77}}}
	noSecret := notify.SecretRef{Org: a.org, ID: model.ID{0xd1, 0x08}}
	shape := func(ref notify.SecretRef, scope auth.Scope) (model.Code, string) {
		_, err := reg.Read(ctx, scope, ref)
		var fault *model.Fault
		if !errors.As(err, &fault) {
			t.Fatalf("%+v: not a fault: %v", ref, err)
		}
		return fault.Code, fault.SafeDetail
	}
	c0, d0 := shape(cross[0], b.scope())
	if c0 != model.Forbidden {
		t.Fatalf("cross-org code %s", c0)
	}
	for _, m := range missing {
		if c, d := shape(m, b.scope()); c != c0 || d != d0 {
			t.Fatalf("missing differs from cross-org: %s/%s vs %s/%s", c, d, c0, d0)
		}
	}
	if c, d := shape(noSecret, a.scope()); c != c0 || d != d0 {
		t.Fatalf("no-secret differs: %s/%s", c, d)
	}
	if f.reads != 0 {
		t.Fatalf("the sealed reader was reached %d times for refused refs", f.reads)
	}
	// a reader failure quoting the secret surfaces as unavailable without its text
	f.rdErr = errors.New("decrypt failed for " + canaryPlain)
	_, err = reg.Read(ctx, a.scope(), notify.SecretRef{Org: a.org, ID: rid})
	if err == nil || strings.Contains(err.Error(), canaryPlain) {
		t.Fatalf("reader error: %v", err)
	}
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != model.Unavailable {
		t.Fatalf("reader error code: %v", err)
	}
}

func TestDestinationCanariesNeverAppearInAnyRendering(t *testing.T) {
	a := newNode(t)
	f := newDestFake()
	endpoint := "https://hooks.example.test/" + canaryHook
	f.put(a.org, rid, notify.DestinationRecord{Type: "webhook", Endpoint: endpoint, Enabled: true}, canaryPlain)
	reg, _ := notify.NewDestinations(f, f)
	d, err := reg.Resolve(context.Background(), a.scope(), deliveryFor(a.org, rid), notify.ChannelWebhook)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("destination", "dest", d, "view", d.View())
	js, _ := json.Marshal(d)
	jv, _ := json.Marshal(d.View())
	jp, _ := json.Marshal(&d)
	all := strings.Join([]string{
		fmt.Sprint(d), fmt.Sprintf("%v %+v %#v %s %q", d, d, d, d, d), fmt.Sprintf("%v %+v", &d, &d), buf.String(), string(js), string(jv), string(jp), fmt.Sprint(d.View()), fmt.Sprintf("%+v", d.View()),
	}, "\n")
	for _, c := range []string{canaryPlain, canaryHook, "?token", "/" + canaryHook} {
		if strings.Contains(all, c) {
			t.Fatalf("%q leaked:\n%s", c, all)
		}
	}
	if d.View().Display != "hooks.example.test" {
		t.Fatalf("view: %+v", d.View())
	}
	// e-mail and chat targets stay out of every rendering too
	for _, rec := range []notify.DestinationRecord{
		{Type: "smtp", Address: canaryMailbox + "@example.test", Enabled: true},
		{Type: "telegram", Address: canaryChat, Enabled: true},
	} {
		f.put(a.org, rid, rec, canaryPlain)
		d, err = reg.Resolve(context.Background(), a.scope(), deliveryFor(a.org, rid), notify.Channel(rec.Type))
		if err != nil {
			t.Fatal(err)
		}
		js, _ = json.Marshal(d)
		out := fmt.Sprintf("%v %+v %#v %s %s", d, d, d, d, js)
		if strings.Contains(out, canaryMailbox) || strings.Contains(out, canaryChat) || strings.Contains(out, canaryPlain) {
			t.Fatalf("leak: %s", out)
		}
	}
	// no Destination or SecretRef error string carries a canary either
	f.srcErr = errors.New(canaryPlain)
	_, err = reg.Resolve(context.Background(), a.scope(), deliveryFor(a.org, rid), notify.ChannelSMTP)
	_, err2 := reg.Read(context.Background(), a.scope(), notify.SecretRef{Org: a.org, ID: rid})
	if strings.Contains(fmt.Sprint(err, err2), canaryPlain) {
		t.Fatal("source error text leaked")
	}
}

// TestDestinationDeliveryCarriesNoFreeText proves a delivery has nowhere for a
// telemetry-supplied chat, token or URL: it holds typed identifiers and enums
// only, so the destination can only come from the org registry.
func TestDestinationDeliveryCarriesNoFreeText(t *testing.T) {
	seen := map[reflect.Type]bool{}
	var walk func(path string, t reflect.Type)
	walk = func(path string, ty reflect.Type) {
		if seen[ty] {
			return
		}
		seen[ty] = true
		switch ty.Kind() {
		case reflect.String:
			if ty.PkgPath() == "" {
				t.Errorf("%s is a free-text string", path)
			}
		case reflect.Pointer, reflect.Slice, reflect.Array:
			walk(path+"[]", ty.Elem())
		case reflect.Map:
			t.Errorf("%s is a map", path)
		case reflect.Interface:
			t.Errorf("%s is an interface", path)
		case reflect.Struct:
			for i := range ty.NumField() {
				f := ty.Field(i)
				walk(path+"."+f.Name, f.Type)
			}
		}
	}
	walk("Delivery", reflect.TypeOf(notify.Delivery{}))
}

func TestDestinationConstructorRequiresBothSeams(t *testing.T) {
	f := newDestFake()
	if _, err := notify.NewDestinations(nil, f); err == nil {
		t.Fatal("nil source accepted")
	}
	if _, err := notify.NewDestinations(f, nil); err == nil {
		t.Fatal("nil secret reader accepted")
	}
}
