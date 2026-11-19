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
result). It builds nothing from the network, runs everything on loopback, and removes what it creates. With a container runtime
(`--pg-image`/`--dependency-image` optional) PostgreSQL and the dependency come from `compose.yaml`; on a host without one,
`--pg-local DIR` starts an unprivileged PostgreSQL 16 server from an installation directory and the dependency runs as a host
process, and `--symbolicate-cgroup-root DIR` gives the node's native symbolication sandbox its delegated cgroup (see
`docs/acceptance/reference-journeys.md`).

## What `compose.yaml` is (and is not)

`compose.yaml` is the **backing services only**: PostgreSQL 16 and the uninstrumented dependency, each from a content-pinned image
(`name@sha256:<digest>` defaults; `REFERENCE_PG_IMAGE`/`REFERENCE_PYTHON_IMAGE` may name another image by id or digest, never a tag;
`pull_policy: never`, so a run never reaches a registry). It does **not** start the product node or the SDK-bearing apps: those are
host processes of the acceptance smoke, because they use the committed SDK source trees and the per-source configuration the smoke
provisions. Each app takes `--config <json>`: the source's real credential, server-signed policy, pinned trusted keys, resource
and descriptor as issued by `POST /api/v1/sources` by the running node, which only the smoke provisions. `pysite.sh` assembles the
private hash-locked Python site directory the Python apps use. The node's own container recipes are `deploy/compose.single.yaml`
and `deploy/compose.distributed.yaml`.

To start the two services by hand: put a leaf certificate and key in a directory (`leaf.pem`, `leaf.key`, readable by uid 65534) and run
`REFERENCE_PG_PASSWORD=<random> REFERENCE_TLS_DIR=<dir> docker compose -f examples/reference/compose.yaml up --detach --wait`
after loading the two images (`docker pull postgres@sha256:92620dad...` and the python digest named in the file, or `docker load`).
