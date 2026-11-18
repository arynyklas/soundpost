// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"net/http"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/ingest"
	"github.com/arynyklas/soundpost/internal/model"
)

// PreflightForTest exposes the bridge's check of the children against the
// source policy to the external tests.
func PreflightForTest(p model.SourcePolicy, batches []ingest.Batch) error {
	return preflight(p, batches)
}

// RegisterPreviousReleaseInputRoutesForTest mounts the input bridge as the
// releases before request.v2 behaved: the batch and record identifiers they
// minted, and no lookup of earlier identities. A request sent through it leaves
// in the ledger what such a release left there.
func RegisterPreviousReleaseInputRoutesForTest(mux *http.ServeMux, a *auth.Service, in InputAdmitter, cfg InputAdapterConfig) {
	b := &inputBridge{auth: a, in: in, cfg: cfg.resolved(), legacyOnly: true}
	mux.HandleFunc("POST "+adapterPrometheusWritePath, b.handle("prometheus_write", model.Metric, b.decodeRemoteWrite))
	mux.HandleFunc("POST "+adapterLokiPushPath, b.handle("loki_push", model.Log, b.decodeLokiPush))
	mux.HandleFunc("POST "+adapterConditionsPath, b.handle("conditions", model.Condition, b.decodeConditions))
}
