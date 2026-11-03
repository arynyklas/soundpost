// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/httpapi"
	"soundpost/internal/ingest"
	"soundpost/internal/model"
	"soundpost/internal/policy"
	"soundpost/internal/storage"
	"time"
)

type App struct {
	Control *control.Store
	Auth    *auth.Service
	Storage *storage.Engine
	Ingest  *ingest.Service
}

func Open(dir string) (*App, error) {
	c, e := control.Open(dir)
	if e != nil {
		return nil, e
	}
	a, e := auth.NewService(auth.AuthDependencies{Control: c})
	if e != nil {
		c.Close()
		return nil, e
	}
	var initialized bool
	if e = c.View(context.Background(), func(st model.ControlState) error { initialized = st.DataInitialized; return nil }); e != nil {
		c.Close()
		return nil, e
	}
	if initialized {
		info, err := os.Stat(filepath.Join(dir, "data", "apply.db"))
		if err != nil || !info.Mode().IsRegular() {
			c.Close()
			return nil, model.Fail(model.Corrupt)
		}
	}
	engine, e := storage.Open(filepath.Join(dir, "data"), a)
	if e != nil {
		c.Close()
		return nil, e
	}
	fail := func(err error) (*App, error) { engine.Close(); c.Close(); return nil, err }
	if !initialized {
		if e = c.Update(context.Background(), func(st *model.ControlState) error { st.DataInitialized = true; return nil }); e != nil {
			return fail(e)
		}
	}
	if e = c.BindAdmissionOwner(engine); e != nil {
		return fail(e)
	}
	if e = a.BindSourceBarrier(engine); e != nil {
		return fail(e)
	}
	p, e := policy.New(a, nil)
	if e != nil {
		return fail(e)
	}
	i, e := ingest.New(a, p, c, engine)
	if e != nil {
		return fail(e)
	}
	if e = a.DrainSourceFences(context.Background()); e != nil {
		return fail(e)
	}
	return &App{Control: c, Auth: a, Storage: engine, Ingest: i}, nil
}
func (a *App) Close() error {
	e := a.Storage.Close()
	other := a.Control.Close()
	if e != nil {
		return e
	}
	return other
}
func (a *App) Register(mux *http.ServeMux) { httpapi.RegisterIngestRoutes(mux, a.Auth, a.Ingest) }
func (a *App) RunFences(ctx context.Context) {
	timer := time.NewTicker(200 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			_ = a.Auth.DrainSourceFences(ctx)
		}
	}
}
