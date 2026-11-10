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
	"soundpost/internal/link"
	"soundpost/internal/model"
	"soundpost/internal/policy"
	"soundpost/internal/query"
	"soundpost/internal/query/profile"
	"soundpost/internal/releases"
	"soundpost/internal/retention"
	"soundpost/internal/storage"
	"soundpost/profiles"
	"time"
)

type App struct {
	Control      *control.Store
	Auth         *auth.Service
	Storage      *storage.Engine
	Ingest       *ingest.Service
	Releases     *releases.Service
	Artifacts    *artifacts.Service
	Cache        *auth.Cache
	Exports      *exports.Service
	Retention    *retention.Service
	Query        *query.Engine
	Investigator *httpapi.Investigator
	replication  *replicatedApp
}

func Open(dir string) (*App, error) { return open(dir, nil) }

// OpenForActivation opens a root a disaster restore built, for `soundpost backup
// activate`. It differs from Open in one respect only: while the restore hold is
// armed the artifact-reference validation is deferred to App.RestoreReady, which
// activation calls right after the hold is lifted (see openWith).
func OpenForActivation(dir string) (*App, error) {
	return openWith(dir, nil, storage.HostMeter(), storage.DefaultPressureConfig(), true)
}

// OpenWithPressure is Open with an explicit disk meter and thresholds in place of the host
// volume's meter and the approved 80/90/95 defaults, so the admission levels can be driven
// through the real ingest path deterministically (the deletion smoke does). A nil meter is
// the "this platform has no meter" case: the engine is bound unmetered (see openWith).
func OpenWithPressure(dir string, meter storage.DiskMeter, pressure storage.PressureConfig) (*App, error) {
	return openWith(dir, nil, meter, pressure, false)
}
func open(dir string, options *replicationOptions) (*App, error) {
	return openWith(dir, options, storage.HostMeter(), storage.DefaultPressureConfig(), false)
}
func openWith(dir string, options *replicationOptions, meter storage.DiskMeter, pressure storage.PressureConfig, forActivation bool) (*App, error) {
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
	// Deletion suppression, disk-pressure admission and the single retention
	// service: the control store is the one authority for deletion fences, and the
	// service's delete generation is what every warm cache entry, cursor and
	// export ticket binds to. The restore authority, if any, is installed on the
	// service by the operator (Service.UseAuthority) before deletions that need it.
	if e = engine.BindDeletions(c); e != nil {
		return fail(e)
	}
	// A platform with no meter (HostMeter() == nil) runs unmetered, visibly: the
	// pressure status reports Unmetered and the warning ring says so. A meter that
	// exists but errors still fails closed inside the engine.
	if meter == nil {
		e = engine.BindPressureUnmetered(pressure.Now)
	} else {
		e = engine.BindPressure(filepath.Join(dir, "data"), meter, pressure)
	}
	if e != nil {
		return fail(e)
	}
	ret, e := retention.New(retention.Config{Control: c, Data: engine, Base: a.SourceLifecycleGenerations(), Pressure: engine})
	if e != nil {
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
	cache, e := auth.NewCache(a, ret, 4096, time.Minute)
	if e != nil {
		return fail(e)
	}
	exportService, e = exports.New(a, cache, ret, engine)
	if e != nil {
		exportService = nil
		return fail(e)
	}
	// The owned C06 query engine. It reads through the same storage scanner and
	// scope revalidation as exports, binds its cursors and result cache to the
	// delete generation, and runs the pinned engine profiles embedded in the
	// binary (never a loose directory, never an upstream engine).
	profileFiles, e := profiles.Query()
	if e != nil {
		return fail(e)
	}
	registry, e := profile.Load(profileFiles)
	if e != nil {
		return fail(e)
	}
	queryEngine, e := query.New(engine, a, registry, query.DefaultLimits(), query.WithDeleteGenerations(ret), query.WithTickets(cache), query.WithResultCache(cache))
	if e != nil {
		return fail(e)
	}
	resolver, e := link.New(a, engine, nil)
	if e != nil {
		return fail(e)
	}
	investigator, e := httpapi.NewInvestigator(a, queryEngine, resolver)
	if e != nil {
		return fail(e)
	}
	out := &App{Control: c, Auth: a, Storage: engine, Ingest: i, Releases: r, Artifacts: artifactService, Cache: cache, Exports: exportService, Retention: ret, Query: queryEngine, Investigator: investigator}
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
	// A restored root holds its engine closed until activation lifts the restore
	// hold, and artifact-reference validation reads blob bytes through that engine,
	// so on a perfectly good restore it could only fail. Opening for activation
	// defers it (App.RestoreReady runs it once the hold is lifted); every other
	// open, and an activation root whose hold is already lifted, validates here.
	if !(forActivation && engine.RestoreReady() != nil) {
		if e = c.ValidateArtifactReferences(startup); e != nil {
			out.CloseReplication()
			return fail(e)
		}
	}
	if e = a.DrainSourceFences(startup); e != nil {
		out.CloseReplication()
		return fail(e)
	}
	return out, nil
}
func (a *App) Close() error {
	replicationErr := a.CloseReplication()
	a.Retention.Close()
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

// The three methods below make *App the backup.Activation of a restored root
// opened with OpenForActivation (the CLI passes the App itself).

// CommitQuotaReconciliation applies the restore's verified quota certificate.
func (a *App) CommitQuotaReconciliation(ctx context.Context, cert storage.QuotaReconciliation) error {
	return a.Storage.CommitQuotaReconciliation(ctx, cert)
}

// RestoreDeletions applies the authority's ledger (control import and a tombstone
// barrier in every data group).
func (a *App) RestoreDeletions(ctx context.Context, authority retention.Authority) error {
	return a.Retention.Restore(ctx, authority)
}

// RestoreReady reports whether the restore hold is lifted and, only then, runs
// the artifact-reference validation OpenForActivation had to defer: it reads blob
// bytes through the engine, which refuses everything while the hold is armed.
func (a *App) RestoreReady() error {
	if err := a.Storage.RestoreReady(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return a.Control.ValidateArtifactReferences(ctx)
}
func (a *App) Register(mux *http.ServeMux) {
	httpapi.RegisterIngestRoutes(mux, a.Auth, a.Ingest)
	httpapi.RegisterCapabilityRoutes(mux, a.Auth)
	httpapi.RegisterExportRoutes(mux, a.Auth, a.Exports)
	httpapi.RegisterQueryRoutes(mux, a.Auth, a.Query)
	httpapi.RegisterInvestigateRoutes(mux, a.Auth, a.Investigator)
	a.RegisterArtifactRoutes(mux)
}

// RunFences drives the background loops a serving process needs: source fences,
// admission reconciliation and the retention worker (deletion fences, physical
// erasure, gated expiry, snapshots and journal truncation, disk pressure). It
// returns when ctx ends.
func (a *App) RunFences(ctx context.Context) {
	if a.Retention != nil {
		_ = a.Retention.Start(ctx)
	}
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
