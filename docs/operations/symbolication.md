# Build-scoped source-map symbolication

Copyright 2026 Aryn Yklas. SPDX-License-Identifier: Apache-2.0.

This module implements owned source-map v3 symbolication, not native ELF/DWARF symbols. The native ELF artifact variant and complete native symbol backend remain separate gates. There is no upstream telemetry engine, remote-map fetch or URL/file-path fallback.

## Application hook and identity

`app.NewSymbolicator(symbolicate.Config)` composes the actual `app.Artifacts` reader without adding a shared App field or HTTP route. The C07 entry is `Service.Resolve(ctx, scope, buildID, []model.Frame)`. The scope must select exactly one project, matching the artifact store's existing lookup contract. `Frame.Artifact` carries the actual canonical 32-lowercase-hex ArtifactID returned by the artifact upload service. A generated path, release display label, content hash or missing upload association returns `artifact_unavailable`, preserving the original sanitized frame. The uploader/build integration must supply the real ArtifactID; this module does not invent that association.

The service independently obtains `scope.ArtifactReadScope` using the same actual credential/elevation, calls protected `Artifacts.Lookup`, and obtains the authoritative immutable manifest. It checks the requested BuildID and the reference's org/project/source/root/build/debug ID/generated SHA-256/map SHA-256/path/retention against the durable blob receipt. Artifact identity and the manifest remain actual authorized metadata, not caller-provided packed manifests. The verified retained-map hash can differ from the original upload map hash because the artifact service removes source content and unknown extensions; both identities are retained and checked in their proper roles.

The worker receives only a closed versioned DTO containing verified bytes/hashes and one generated position. It never receives a command, URL, file path to open, credentials, release label or artifact-store access. Source-map paths are inert code identities interpreted only by the owned decoder. Original sanitized frames are retained for every unresolved result. `reason` is a bounded enum, never an OS error, raw map, source canary or host path.

Default results contain no source contents. `ResolveWithOptions(..., Options{IncludeSources:true})` is explicit and uses `GetSources`, requiring the artifact backend's additional `raw.read` plus named source-reader grant. Only the selected source line, at most 4096 UTF-8 bytes, can be returned. Missing/ambiguous source context is not guessed. Private source bytes are never put in the map cache.

The service-owned cache is bounded to 64 MiB and 16 entries (a configured smaller byte limit is allowed), keyed by organization/project/source/build/root, actual visibility fingerprint, policy epoch and retained-map hash. There is no mutable global cache. Current artifact reference and `Scope.RevalidateArtifact` are checked before a cached byte release and again after each worker result, including the private grant. A warmed cache is not deletion, retention, revocation or elevation authority. At most two workers run concurrently per Service, with a five-second request budget.

**Per-call frame budget.** One `Resolve` call shares a single five-second wall budget, and each worker run may use a fresh sandbox launch, so work per call is bounded explicitly. Identical lookups (same artifact ID, line and column) within a call cost one worker run; repeats copy the first result and keep their own original frame. At most 64 distinct lookups (`MaxResolvedFrames`) are processed per call; later distinct frames are returned unresolved with reason `frame_limit` (frames that duplicate an in-budget lookup still resolve). Invalid, unmapped and otherwise rejected frames do not consume the budget. If the wall budget is exhausted anyway, remaining frames carry reason `deadline`. Every unresolved frame (`frame_limit`, `deadline`, any other non-`resolved` reason) keeps its original sanitized form with no resolved position. Cached map bytes are returned and stored as copies, so callers cannot mutate the cache.

## Required sandbox: explicit backend selection

No mode is selected implicitly. Missing required restrictions return `sandbox_unavailable`; native launch failure never falls back to OCI. `GOMEMLIMIT=192MiB` and `GOGC=50` are runtime tuning only, **not OS security boundaries**. `RLIMIT_AS` is deliberately not used for a Go worker's virtual-address reservation. The hard memory configuration is exactly **268435456 bytes (256 MiB)**, never silently increased. Linux memory-controller hard limits have the kernel's documented reclaim/OOM and temporary-overage semantics; this is not a claim that every instantaneous accounting sample is mathematically below the limit.

Both backends require a Linux amd64 or arm64 worker, working cgroup v2 memory/swap/PID controllers, and seccomp thread synchronization. The child independently reads its actual current controller files before reading the DTO and requires `memory.max=268435456`, `memory.swap.max=0`, `pids.max=64`. A Docker CLI accepting flags or a HostConfig record alone is insufficient. The worker installs `PR_SET_NO_NEW_PRIVS`, a checked `SECCOMP_FILTER_FLAG_TSYNC` allowlist over all runtime threads, and `RLIMIT_CPU` soft/hard 5 seconds, core/file-size limits zero, descriptor limit 64. Syscalls for opening/statting source files, sockets/connect, execution, process inspection, namespaces and mounts are not allowed. Only supplied standard streams and Go-owned eventfd/epoll descriptors are available for I/O; launchers pass no ExtraFiles or host file mounts. Runtime thread creation is allowed only with `CLONE_THREAD`; clone3 inside the worker returns ENOSYS. No privilege, kernel sysctl, mount, setcap or unconfined seccomp change is made.

The parent bounds startup/process wall time to five seconds and frame processing, including DTO decoding/map parsing, to 100 ms. The child has independent five-second process and 100-ms frame watchdogs as well. Each frame uses a fresh one-shot process, cancellation kills/reaps it, and OCI cleanup forcibly removes the named container. Refusal, OOM, corrupt bytes, invalid map and deadline all retain the original frame. The decoder retains the existing aggregate 32-MiB/1024-file/depth-8 and segment/node limits. A legal large map can still exceed a worker's CPU/memory budget and be safely unresolved; no successful decoding of every ceiling-sized map is promised.

### Native mode

Trusted operator JSON:

```json
{
  "mode": "native",
  "worker_path": "/private/bin/soundpost-symbolicate",
  "worker_sha256": "<64 lowercase hex of the actual Linux binary>",
  "cgroup_root": "/sys/fs/cgroup/<already-delegated-empty-subtree>",
  "cache_bytes": 67108864
}
```

An administrator must already have delegated the relevant controllers/subtree to the service account. The launcher only creates a private child group there, sets and reads back its limits, and uses Go `UseCgroupFD` / `CLONE_INTO_CGROUP` so the worker is charged from birth. Post-start migration would leave initial memory charges outside the worker group and is not used. Missing delegation, controller files, clone-into-cgroup permission, readable standard cgroup mount or seccomp support fails closed. Unsupported native platforms fail closed. Absence of profiler tracefs access says nothing about whether these independent sandbox facilities are available. Do not mount/reconfigure controllers or weaken privileges merely to turn a failed probe green.

### Explicit OCI mode

OCI is an operator-selected alternative using an already authorized Docker-compatible runtime, not an automatic escape from native sandbox failure. The service account must already be permitted to use that runtime; do not grant daemon access globally to deploy this module.

```json
{
  "mode": "oci",
  "oci_runtime": "/absolute/path/to/docker",
  "oci_image": "sha256:<64 lowercase hex immutable LOCAL image ID>",
  "worker_sha256": "<64 lowercase hex of the exact first-party binary>",
  "cache_bytes": 67108864
}
```

`oci_image` must be a local immutable image ID, not a tag. The launcher verifies the local image label `org.soundpost.worker.sha256` against configured binary provenance, then verifies the actual worker's pre-sandbox executable hash handshake. Use only the first-party scratch Dockerfile in `cmd/soundpost-symbolicate/Dockerfile` and the verified static binary. The fixed entrypoint is `/soundpost-symbolicate`; request data cannot select a command. Launch flags are fixed: `--pull=never --network=none --read-only --memory=268435456 --memory-swap=268435456 --pids-limit=64 --cap-drop=ALL --security-opt=no-new-privileges --user=65534:65534`, no TTY, no host mount, and no Docker socket inside the worker. The same child seccomp/CPU/watchdog checks still apply. Do not pass `--privileged`, `seccomp=unconfined` or extra capabilities.

Parent-only build/image preparation (not worker-run verification):

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$PRIVATE_CTX/soundpost-symbolicate" ./cmd/soundpost-symbolicate
sha256sum "$PRIVATE_CTX/soundpost-symbolicate"
# Supply the observed hash, not a literal placeholder:
docker build --network=none --pull=false --file cmd/soundpost-symbolicate/Dockerfile --build-arg WORKER_SHA256="$WORKER_SHA256" --tag soundpost-symbolicate:qualification "$PRIVATE_CTX"
docker image inspect --format '{{.Id}}' soundpost-symbolicate:qualification
```

Keep the build context private and limited to that binary; configure the returned immutable ID and observed binary hash. Arm64 needs its own actual build and qualification. No image publication is needed or authorized by this procedure.

## Parent qualification and actual fixture

The worker implementation author did not run tests/builds/formatters/probes. A skipped environment-gated test is not qualification. Set the private operator-config file and actual Vite fixture directory, then the parent runs:

```sh
node fixtures/artifacts/generate.mjs "$PRIVATE_VITE_DIR"
SOUNDPOST_SOURCEMAP_FIXTURE_DIR="$PRIVATE_VITE_DIR" SOUNDPOST_SYMBOLICATE_TEST_CONFIG="$PRIVATE_SANDBOX_JSON" go test ./internal/symbolicate -count=1
```

Use the repository-pinned actual Node22 binary for the generator. Tests with `Actual` exercise the configured fixed binary, real forbidden file/network/exec syscalls, an actual memory allocation until OS OOM kill, timeout kill/reap plus fresh worker, and actual Vite thrown positions through real auth/artifact storage. The memory probe must report actual `memory.events:oom_kill` or OCI `State.OOMKilled`, not just allocation failure, an exit code or configured flags. CPU's installed RLIMIT is additional to the exercised wall watchdog; independently inspect/qualify it for each target runtime if claiming a separate CPU-kill result.

The owned fixture opens **private preprovisioned** real application state, uploads the actual Vite map through the artifact service with a real independent artifact-write grant, and invokes the C07 service through an ephemeral local verified-TLS handler with real artifact-read authentication. It deliberately does not install a shared production HTTP route. Private configuration:

```json
{
  "state_dir": "<private preprovisioned app state>",
  "manifest_file": "<exact manifest for actual simple.mjs and its map>",
  "uploader_token_file": "<private artifacts.write server token>",
  "reader_token_file": "<private artifacts.read server token>",
  "sandbox": { "mode": "oci", "oci_runtime": "<absolute runtime>", "oci_image": "sha256:<actual image ID>", "worker_sha256": "<actual binary hash>" }
}
```

The source must be actually registered for the manifest BuildID, and the immutable debug/path slot must be unused or an exact retry. The manifest's generated/map hashes and size must equal those of `simple.mjs`/`simple.mjs.map`; the fixture refuses manufactured or mismatched evidence. Credentials stay in private files, never command arguments or stdout. The manifest defaults to no private source content.

```sh
go run ./fixtures/artifacts/symbolicate --config "$PRIVATE_FIXTURE_JSON" --artifact-dir "$PRIVATE_VITE_DIR" --endpoint-env SOUNDPOST_FIXTURE_API --restart-worker --inject-timeout --sandbox-probes
```

Here `--endpoint-env` names an initially unset variable assigned **only inside this local fixture process** to its ephemeral verified-TLS endpoint, then removed. Existing/external endpoint values are rejected; no customer/public endpoint is contacted. `--inject-timeout` kills a real busy worker and the next real Vite resolution runs in a fresh worker. The optional sandbox probes include an actual OS memory kill. Success is asserted against `simple.ts:4:8`, not fabricated stack mappings, and output excludes raw generated paths, map bytes, credentials and source canaries. An actual backend restart/publication/kill-restart gate for artifact09.01 remains separate and mandatory.

## Primary implementation references

- Linux kernel [cgroup-v2 delegation and memory controller](https://docs.kernel.org/admin-guide/cgroup-v2.html): delegation, `CLONE_INTO_CGROUP`, `memory.max`, swap, `pids.max`, OOM events, and the fact that preexisting memory charges do not move with process migration.
- Linux kernel [seccomp BPF](https://docs.kernel.org/userspace-api/seccomp_filter.html): architecture checks, unprivileged filter installation with no-new-privileges, inherited filters and syscall-surface limitations. Seccomp alone is not a complete sandbox; here it is combined with controller limits, protected IPC, fixed binaries and lifecycle bounds.
- Linux kernel [no-new-privileges](https://docs.kernel.org/userspace-api/no_new_privs.html): unprivileged setting, inheritance and irreversible restriction, without claiming it revokes existing privileges.
- Docker [resource constraints](https://docs.docker.com/engine/containers/resource_constraints/): hard memory limit and equal memory/memory-swap values disabling swap; kernel support must actually exist.

Primary-source semantics are not an executed result for this workstation or another target. Parent-run actual probes, readable generated frames, worker restart/timeout evidence and independent review remain the release qualification gate.
