<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Reference application estate

A small, generic, working order-handling system used to exercise Soundpost end to end. These are
functioning programs with deliberate, deterministic failure modes, not telemetry injectors; every
signal they produce comes from the committed custom SDKs delivering to a real `soundpost serve` node.

| Part | Directory | Runtime | SDK |
| --- | --- | --- | --- |
| Gateway (HTTPS, static files, `/api/orders` proxy) | `gateway/` | Bun | `packages/bun` |
| Web app (order form, receipt rendering) | `web/` | browser, built with Vite 7 + `packages/build` | `packages/browser` |
| Orders API | `api/` | Python (WSGI) + PostgreSQL | `sdk/python` |
| Jobs scheduler/worker | `jobs/` | Python | `sdk/python` jobs |
| Model/dependency fixture (uninstrumented third party) | `dependency/` | Python stdlib HTTPS | none |

## Behaviours (known by construction)

* `POST /api/orders` for `sku-100`: gateway -> API -> PostgreSQL (`db.execute`/`postgres`) and the
  HTTP dependency (`http.call`/`dependency`), answered priced.
* `sku-404` has no catalog row: the API answers `200` with `total_cents: null`, and `formatReceipt` in
  `web/src/receipt.ts` throws at a fixed source location in the shipped (minified) build.
* Job `reference.catalog.refresh` run `1`: the dependency answers `503 warming_up` to the first request
  carrying the run id, so attempt 1 fails and attempt 2 succeeds; the failed attempt stays recorded.
* Canaries `CANARY_BODY_7f3a` (browser request note), `CANARY_PROMPT_9b2f` (system prompt sent to the
  dependency) and `CANARY_SQL_LITERAL_5d1e` (literal in the SQL text) flow through the apps and must never
  appear in anything Soundpost stores, serves or logs.

## Running

The acceptance run is `go run ./tools/smoke journeys --artifact-dir <dir>` (see
`docs/acceptance/reference-journeys.md` for prerequisites, the rows it evaluates and its recorded
result). It builds nothing from the network, uses only local images, runs everything on loopback, and
removes the PostgreSQL container it creates.

`compose.yaml` starts only the two backing services (PostgreSQL and the dependency) from local images;
the SDK-bearing apps run as host processes because they use the committed SDK source trees and the
per-source configuration the smoke provisions. Each app takes `--config <json>`: the source's real
credential, server-signed policy, pinned trusted keys, resource and descriptor as issued by
`POST /api/v1/sources`. `pysite.sh` assembles the private pure-Python site directory the Python apps use.
