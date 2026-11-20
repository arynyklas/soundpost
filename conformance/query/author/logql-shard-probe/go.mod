// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
//
// Development-only probe of the pinned Loki 3.5.2 shard and replica machinery. It is
// compiled INSIDE the pinned upstream module tree by
// conformance/query/author/native-oracle.sh build-loki-shard-probe (which copies only
// *.go). This nested module keeps its build-tagged upstream imports out of the product
// module's dependency graph and `go mod tidy`.
module github.com/arynyklas/soundpost/conformance/query/author/logql-shard-probe

go 1.27.3
