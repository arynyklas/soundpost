// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"testing"
)

// Constructor initialization may use only the narrow pristine-root transition;
// arbitrary feature transactions remain unavailable before Raft activation.
type constructorWithoutFeatureWrites struct {
	*control.Store
	updates int
}

func (s *constructorWithoutFeatureWrites) Update(context.Context, func(*model.ControlState) error) error {
	s.updates++
	return model.Fail(model.Unavailable)
}
func TestBearerConstructorUsesOnlyPristineInitialization(t *testing.T) {
	disk, err := control.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	store := &constructorWithoutFeatureWrites{Store: disk}
	service, err := auth.NewService(auth.AuthDependencies{Control: store})
	if err != nil {
		t.Fatal("pristine constructor failed", err)
	}
	if store.updates != 0 {
		t.Fatal("constructor invoked arbitrary feature Update")
	}
	first, err := service.BearerDigest(auth.SourceBearer, "source fixture")
	if err != nil {
		t.Fatal(err)
	}
	again, err := auth.NewService(auth.AuthDependencies{Control: store})
	if err != nil {
		t.Fatal(err)
	}
	second, err := again.BearerDigest(auth.SourceBearer, "source fixture")
	if err != nil || first != second || store.updates != 0 {
		t.Fatal("constructor replaced installed authority")
	}
	token, err := disk.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Bootstrap(context.Background(), token, "before-activation@example.test", "before activation password 2026"); err == nil {
		t.Fatal("preactivation feature transaction acknowledged")
	}
	if err = disk.View(context.Background(), func(st model.ControlState) error {
		if st.BootstrapHash == "" || len(st.Users) != 0 || len(st.Sessions) != 0 {
			t.Fatal("unavailable preactivation bootstrap mutated state")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
