// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"soundpost/internal/artifacts"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/exports"
	"soundpost/internal/httpapi"
	"soundpost/internal/ingest"
	"soundpost/internal/model"
	"soundpost/internal/policy"
	"soundpost/internal/releases"
	"soundpost/internal/storage"
	"time"
)

type App struct {
	Control     *control.Store
	Auth        *auth.Service
	Storage     *storage.Engine
	Ingest      *ingest.Service
	Releases    *releases.Service
	Artifacts   *artifacts.Service
	Cache       *auth.Cache
	Exports     *exports.Service
	replication *replicatedApp
}

func Open(dir string) (*App, error) { return open(dir, nil) }
func open(dir string, options *replicationOptions) (*App, error) {
	c, e := openControl(dir, options)
	if e != nil {
		return nil, e
	}
	a, e := auth.NewService(auth.AuthDependencies{Control: c})
	if e != nil {
		c.Close()
		return nil, e
	}
	r, e := NewReleaseService(c, a)
	if e != nil {
		c.Close()
		return nil, e
	}
	var initialized bool
	if e = c.View(context.Background(), func(st model.ControlState) error { initialized = st.DataInitialized; return nil }); e != nil {
		c.Close()
		return nil, e
	}
	if initialized && (options == nil || !options.fresh) {
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
	var exportService *exports.Service
	fail := func(err error) (*App, error) {
		if exportService != nil {
			exportService.Close()
		}
		engine.Close()
		c.Close()
		return nil, err
	}
	if e = c.BindAdmissionOwner(engine); e != nil {
		return fail(e)
	}
	if e = a.BindSourceBarrier(engine); e != nil {
		return fail(e)
	}
	artifactService, e := NewArtifactService(c, a, engine)
	if e != nil {
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
	// Until a retention service owns historical-range and entity deletion, the
	// delete generation is derived from authoritative revoked/retired sources.
	cache, e := auth.NewCache(a, a.SourceLifecycleGenerations(), 4096, time.Minute)
	if e != nil {
		return fail(e)
	}
	exportService, e = exports.New(a, cache, a.SourceLifecycleGenerations(), engine)
	if e != nil {
		exportService = nil
		return fail(e)
	}
	out := &App{Control: c, Auth: a, Storage: engine, Ingest: i, Releases: r, Artifacts: artifactService, Cache: cache, Exports: exportService}
	startupTimeout := 20 * time.Second
	if options != nil {
		startupTimeout = 60 * time.Second
	}
	startup, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()
	if e = out.enableReplication(startup, dir, options); e != nil {
		out.CloseReplication()
		return fail(e)
	}
	if !initialized {
		if e = c.Update(startup, func(st *model.ControlState) error { st.DataInitialized = true; return nil }); e != nil {
			out.CloseReplication()
			return fail(e)
		}
	}
	if e = c.ValidateArtifactReferences(startup); e != nil {
		out.CloseReplication()
		return fail(e)
	}
	if e = a.DrainSourceFences(startup); e != nil {
		out.CloseReplication()
		return fail(e)
	}
	return out, nil
}
func (a *App) Close() error {
	replicationErr := a.CloseReplication()
	a.Exports.Close()
	e := a.Storage.Close()
	other := a.Control.Close()
	if e != nil {
		return e
	}
	if replicationErr != nil {
		return replicationErr
	}
	return other
}
func (a *App) Register(mux *http.ServeMux) {
	httpapi.RegisterIngestRoutes(mux, a.Auth, a.Ingest)
	httpapi.RegisterCapabilityRoutes(mux, a.Auth)
	httpapi.RegisterExportRoutes(mux, a.Auth, a.Exports)
	a.RegisterArtifactRoutes(mux)
}
func (a *App) RunFences(ctx context.Context) {
	timer := time.NewTicker(200 * time.Millisecond)
	defer timer.Stop()
	reconcile := time.NewTicker(5 * time.Second)
	defer reconcile.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			_ = a.Auth.DrainSourceFences(ctx)
		case <-reconcile.C:
			reconciliation, cancel := context.WithTimeout(ctx, 2*time.Second)
			_ = a.Control.ReconcileAdmissions(reconciliation)
			cancel()
		}
	}
}
