// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
//
// Development-only reference driver. It is compiled INSIDE the pinned upstream
// module tree by the oracle Dockerfiles (which copy only *.go). This nested
// module keeps its build-tagged upstream imports out of the product module's
// dependency graph and `go mod tidy`.
module github.com/arynyklas/soundpost/conformance/query/oracles/evaluation

go 1.27.3
