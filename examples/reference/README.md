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
result). It runs everything on loopback and removes what it creates. With a container runtime it builds the estate's three first-party
images from this tree (offline) and runs the whole reference estate from `compose.yaml` (below); it needs
`--symbolicate-cgroup-root DIR`, an empty cgroup v2 subtree owned by root that the node container gets mounted for its native symbolication sandbox
(`docs/acceptance/reference-journeys.md`). On a host without a container runtime, `--pg-local DIR` starts an unprivileged PostgreSQL 16
server from an installation directory and runs the whole estate as host processes (the original mode, kept working).

## `compose.yaml`: the whole reference estate

`compose.yaml` covers the **whole reference estate**, one service per part:

| Service | What it is | Image |
| --- | --- | --- |
| `init`, `handover` | prepare the node's private TLS copy, data directory and the web volume; give the node's data to the operator | pinned python image |
| `node` | `soundpost serve --mode=single` over HTTPS | `REFERENCE_NODE_IMAGE`: `deploy/Dockerfile` over the release binary |
| `provision` | waits for the node, bootstraps its owner, creates the organizations, users and sources, writes every application's source configuration | `REFERENCE_TOOLS_IMAGE`: `Dockerfile.tools` (the smoke binary) |
| `webbuild` | the Vite build (`packages/build`), uploads the private source map, stages the page | `REFERENCE_ESTATE_IMAGE`: `Dockerfile.estate` |
| `api`, `jobs`, `gateway` | the Python API, the jobs scheduler/worker (on demand: `docker compose run --rm jobs`), the Bun gateway | `REFERENCE_ESTATE_IMAGE` |
| `postgres`, `dependency` | PostgreSQL 16 (`log_statement=all`) and the uninstrumented HTTPS dependency | pinned `postgres` and `python` digests |

**Per-source credentials are provisioned at run time**, never written to the file: the `provision` service waits for the node, then the
credential, server-signed policy, pinned trusted keys, resource and descriptor each application takes in `--config <json>` (as issued by
`POST /api/v1/sources`) go to the `cfg` volume, which only the applications mount, read-only; the applications start after it.

**Images.** Third-party images default to `name@sha256:<digest>` (`REFERENCE_PG_IMAGE`/`REFERENCE_PYTHON_IMAGE` may name another by id or
digest, never a tag). The three first-party images are built from this tree and have no digest until they are built, so a run names each by the
id of the image it built (`sha256:<64 hex>`, the variables above have no default). Every service says `pull_policy: never`: a run never
reaches a registry. `tools/smoke journeys` builds the images offline (`--estate-wheels DIR` holds the hash-locked wheels for the estate
image's interpreter) and refuses an unpinned one.

**The node's one deviation: uid 0, no capabilities.** The node container runs as uid 0 with `cap_drop: ALL`, a read-only root and
`no-new-privileges`, in the host's cgroup namespace with the cgroup v2 subtree `REFERENCE_CGROUP_ROOT` (empty, **owned by root**, with the
`memory` and `pids` controllers: `mkdir /sys/fs/cgroup/<name>` as root) mounted at the same path. Why: the node's native symbolication sandbox
creates private child groups there and moves its worker into them. The kernel lets a process move another into a cgroup only if the writer may
write `cgroup.procs` of the common ancestor of the source and destination cgroups; the node's own container cgroup lives under
`system.slice`, so a nonroot container user gets `EACCES` (measured on Docker 26.1.5, cgroup v2, also with the container's cgroup namespace
private, where the worker's cgroup path is rejected for containing `..`). Root without `CAP_DAC_OVERRIDE` writes only what root owns, hence a
root-owned subtree; the smoke refuses any other. What isolation still holds: no capability at all, read-only root filesystem,
`no-new-privileges`, not privileged, no Docker socket, pid and network namespaces not shared, every published port on loopback, only the
node's own data, its private TLS copy and that one cgroup subtree mounted; the symbolication worker itself still runs under its own seccomp
filter, cgroup limits (256 MiB, no swap, 64 pids), CPU limit and no-file/no-network/no-exec denial. The other services run as uid 65534
with a read-only root and no capability. The shipped `deploy/` recipes are unchanged and nonroot (symbolication there needs the systemd
unit's delegated cgroup, `docs/operations/symbolication.md`).

To run it by hand: put `ca.pem`, `leaf.pem` and `leaf.key` (world readable; the leaf naming `127.0.0.1`, `localhost`, `node`, `api`,
`gateway`, `dependency`) in a directory, build or load the three images, and run `docker compose -f examples/reference/compose.yaml up --detach`
with `REFERENCE_PG_PASSWORD`, `REFERENCE_TLS_DIR`, `REFERENCE_NODE_PORT`, `REFERENCE_GATEWAY_PORT`, `REFERENCE_CGROUP_ROOT` and the three
`REFERENCE_*_IMAGE` ids set (the header of the file lists every variable). `pysite.sh` assembles the hash-locked Python site directory for
the host-process mode. The node's own container recipes for installing it are `deploy/compose.single.yaml` and `deploy/compose.distributed.yaml`.
