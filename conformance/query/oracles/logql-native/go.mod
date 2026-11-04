// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
//
// Development-only reference driver (and its bridge/ subpackage). It is compiled
// INSIDE the pinned upstream module tree by the oracle Dockerfile (which copies
// only *.go). This nested module keeps its build-tagged upstream imports out of
// the product module's dependency graph and `go mod tidy`.
module soundpost/conformance/query/oracles/logql-native

go 1.27.3
