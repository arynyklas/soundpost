<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Fresh-install matrix (acceptance 07.08)

`go run ./tools/smoke fresh-install-matrix` installs the **produced** artifacts the way a user does and writes
`fresh-install-matrix.json` (one row per line below, the digest of every artifact it used, the SBOM digests). It
exits nonzero when a row failed. A row whose prerequisite is missing on the host is recorded `not_run` with the exact
reason, never `passed` (`classifyMatrixRow`, pinned by `TestClassifyMatrixRowNeverTurnsAnUnmetPrerequisiteIntoAPass` and
`TestOnlyPublishedURLsIsRecordedNotRunWithoutRunning`, which fails if any row other than `published_urls` is hard-coded
`not_run`).

```sh
go run ./build release --out dist/release --version 1.0.0 --arch amd64 --web-dist web/dist --archive go.tar.gz
go run ./build sbom --version 1.0.0 --created 2026-11-19T00:00:00Z --out dist/sbom
go run ./build artifacts --release dist/release --out dist/art --sbom dist/sbom > dist/art.json
go run ./tools/smoke fresh-install-matrix --artifact-dir out --release dist/release --artifacts dist/art --web-dist web/dist \
  --root . --bun bun --python python3 \
  --chrome <chrome-for-testing>/chrome --node-linux <node22>/bin/node --pg-image <postgres:16 image id or name@sha256:digest> \
  --symbolicate-cgroup-root <delegated cgroup v2 subtree>
```

| Row | What it does | `not_run` when |
| --- | --- | --- |
| `digests` | re-hashes every artifact against `artifacts.json` | never |
| `image_binary`, `perf_helper_image_binary` | the only file of each image's only layer is the release binary it names | never |
| `wheel_fresh_venv` | `python -m venv`, `pip install --no-index --no-deps` of the wheel, import, version | the interpreter is missing or cannot make a venv (Debian without `python3-venv`: `ensurepip`) |
| `npm_fresh_project` | each tarball unpacked into a new `node_modules`, the entries imported with Bun | Bun or the installed `@noble` packages are missing |
| `install_single`, `install_distributed` | the install smokes against the release binary | never |
| `container_install` | the release's server image archive is loaded into Docker with `docker load -i` exactly as released (its `manifest.json` is part of the archive, image ID checked against the archive's config digest) and `install-single --container` runs against it: nonroot, read-only root, no capability, bootstrap, authenticated ingest and query, kill and restart with the same receipts | there is no usable OCI runtime |
| `reference_journeys` | the journeys smoke (reference estate, real PostgreSQL 16, real Chrome, the node's native symbolication) against the produced binary; every required row must be satisfied | no Chrome, no Node 22, no PostgreSQL backend (`--pg-image` needs Docker, `--pg-local` does not), no Bun or Python |
| `native_profile_install` | the release's helper image started by the shipped Compose `native` profile with only `CAP_PERFMON`, against a CPU-burning container; real samples, the typed denied cases and the container's applied configuration audited ([distributed.md](../operations/distributed.md#evidence-the-helper-image-under-an-oci-runtime)) | no Docker/compose, hybrid cgroups, or `perf_event_paranoid` 3 (the denial is observed and recorded, no sample can be collected) |
| `published_urls` | nothing is published: always `not_run`; paths and digests are recorded instead | always |

Host setup the rows assume (none of it is changed by the smoke): `kernel.perf_event_paranoid` of 2 or lower for the
helper's positive capture (the operator sets it; the smoke reads it), the matrix started inside a transient systemd unit
with `Delegate=memory pids DelegateSubgroup=main` for the node's symbolication sandbox, and the user in the `docker`
group. The module cache must hold every module of `go.sum` (`go run ./build release` runs the Go tool with
`GOPROXY=off`, `GOENV=off` and a `GOPATH` under `$HOME`).
