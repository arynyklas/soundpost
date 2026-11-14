// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"errors"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"testing"
)

type bootstrapCleanupFault struct{ *control.Store }

func (bootstrapCleanupFault) RemoveBootstrapFile() error { return errors.New("unlink fault") }
func TestBootstrapCleanupFailureNeverAcknowledgesOrRestoresToken(t *testing.T) {
	store, e := control.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	service, e := auth.NewService(auth.AuthDependencies{Control: bootstrapCleanupFault{store}})
	if e != nil {
		t.Fatal(e)
	}
	activateAuthControl(t, store, t.TempDir())
	token, e := store.BootstrapToken()
	if e != nil {
		t.Fatal(e)
	}
	session, e := service.Bootstrap(context.Background(), token, "cleanup@example.test", "bootstrap cleanup password 2026")
	if e == nil || session.Token != "" {
		t.Fatal("failed required cleanup acknowledged")
	}
	if _, e = service.Bootstrap(context.Background(), token, "cleanup@example.test", "bootstrap cleanup password 2026"); e == nil {
		t.Fatal("consumed authority restored after cleanup failure")
	}
	if _, e = service.Login(context.Background(), "cleanup@example.test", "bootstrap cleanup password 2026", ""); e != nil {
		t.Fatal("durable account lost after ambiguous bootstrap", e)
	}
}
