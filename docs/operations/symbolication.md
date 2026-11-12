# Build-scoped source-map symbolication

Copyright 2026 Aryn Yklas. SPDX-License-Identifier: Apache-2.0.

This module implements owned source-map v3 symbolication, not native ELF/DWARF symbols. The native ELF artifact variant and complete native symbol backend remain separate gates. There is no upstream telemetry engine, remote-map fetch or URL/file-path fallback.

## Application hook and identity

`app.NewSymbolicator(symbolicate.Config)` composes the actual `app.Artifacts` reader without adding a shared App field or HTTP route. The C07 entry is `Service.Resolve(ctx, scope, buildID, []model.Frame)`. The scope must select exactly one project, matching the artifact store's existing lookup contract. `Frame.Artifact` carries the actual canonical 32-lowercase-hex ArtifactID returned by the artifact upload service. A generated path, release display label, content hash or missing upload association returns `artifact_unavailable`, preserving the original sanitized frame. The uploader/build integration must supply the real ArtifactID; this module does not invent that association.

The service independently obtains `scope.ArtifactReadScope` using the same actual credential/elevation, calls protected `Artifacts.Lookup`, and obtains the authoritative immutable manifest. It checks the requested BuildID and the reference's org/project/source/root/build/debug ID/generated SHA-256/map SHA-256/path/retention against the durable blob receipt. Artifact identity and the manifest remain actual authorized metadata, not caller-provided packed manifests. The verified retained-map hash can differ from the original upload map hash because the artifact service removes source content and unknown extensions; both identities are retained and checked in their proper roles.

The worker receives only a closed versioned DTO containing verified bytes/hashes and one generated position. It never receives a command, URL, file path to open, credentials, release label or artifact-store access. Source-map paths are inert code identities interpreted only by the owned decoder. Original sanitized frames are retained for every unresolved result. `reason` is a bounded enum, never an OS error, raw map, source canary or host path.

Default results contain no source contents. `ResolveWithOptions(..., Options{IncludeSources:true})` is explicit and uses `GetSources`, requiring the artifact backend's additional `raw.read` plus named source-reader grant. Only the selected source line, at most 4096 UTF-8 bytes, can be returned. Missing/ambiguous source context is not guessed. Private source bytes are never put in the map cache.

The service-owned cache is bounded to 64 MiB and 16 entries (a configured smaller byte limit is allowed), keyed by organization/project/source/build/root, actual visibility fingerprint, policy epoch, the organization's **delete generation** and retained-map hash. There is no mutable global cache. `symbolicate.New(reader, deletes, config)` takes the `auth.DeleteGenerations` authority (`app.NewSymbolicator` passes the retention service); a service without one is not built, and a generation that cannot be read fails the frame closed as `artifact_unavailable` before any byte is read. Any deletion Begin or completion, retirement, artifact GC or erasure advances the generation, so entries read under an older one are unreachable and are dropped on the organization's next request. The generation is only a cache binding; on every request, warm or cold, the current artifact reference and `Scope.RevalidateArtifact` are checked before a cached byte release and again after each worker result, including the private grant. That fence (`ValidateArtifactState`) refuses an artifact root covered by a begun deletion (`entity` naming the root, `retire_project`, `retire_org`; fencing, complete or failed phases) exactly as it refuses an absent artifact, so no consumer depends on the storage engine's own gate; a held deletion has not begun and hides nothing, a hold placed later never restores a read, and a `historical_range` predicate never covers an artifact. A read answered `not_found` after the fence (a deletion committing in between) is reported as `artifact_unavailable`, never as corruption. A warmed cache is not deletion, retention, revocation or elevation authority. Warm bytes of a deleted root can remain in process memory, never served, until the organization's next symbolication request or LRU eviction. At most two workers run concurrently per Service, with a five-second request budget.

**Per-call frame budget.** One `Resolve` call shares a single five-second wall budget, and each worker run may use a fresh sandbox launch, so work per call is bounded explicitly. Identical lookups (same artifact ID, line and column) within a call cost one worker run; repeats copy the first result and keep their own original frame. At most 64 distinct lookups (`MaxResolvedFrames`) are processed per call; later distinct frames are returned unresolved with reason `frame_limit` (frames that duplicate an in-budget lookup still resolve). Invalid, unmapped and otherwise rejected frames do not consume the budget. If the wall budget is exhausted anyway, remaining frames carry reason `deadline`. Every unresolved frame (`frame_limit`, `deadline`, any other non-`resolved` reason) keeps its original sanitized form with no resolved position. Cached map bytes are returned and stored as copies, so callers cannot mutate the cache.

## The served process: `soundpost serve`

`appcore.Open` installs a typed frame resolver, never a nil one: with no operator configuration every frame of `POST /api/v1/evidence/frames` answers `reason=sandbox_unavailable` with the original frame kept (the response `state` is `incomplete`, reason `frames_unmapped`; the handler's `symbolicator_not_wired` state only describes a build that has no resolver at all). The artifact store, the caller's scope and any child process are not touched on that path, so the answer is identical for an existing artifact, a deleted one and another organization's.

`soundpost serve` then calls `App.ConfigureSymbolicator` right after opening the application and before the routes are registered. It builds the service over `app.Artifacts` (the same protected reader the artifact routes use, so every lookup and byte read passes the org/project/grant/retention/deletion fence) and `app.Retention` (the delete-generation authority), **after** the startup capability probe passed. The probe launches the selected backend three times and requires the worker to report that the forbidden operation was denied: opening a file, creating a network socket and `exec`. Any other outcome (launch refused, deadline, worker failure, wrong provenance hash) leaves the typed `sandbox_unavailable` resolver; the server still serves everything else. The memory/CPU/timeout qualification probes allocate until the kernel kills the child and stay explicit operator actions (`symbolicate.Probe`).

Flags (all on `soundpost serve`; nothing is read from a request):

| Flag | Default | Meaning |
| --- | --- | --- |
| `--symbolicate-sandbox` | `auto` | `auto` selects the native sandbox that **re-executes the running `soundpost` binary** as its worker (`soundpost --worker-v1`, `--probe-v1`; these two exact argument vectors are handled before any other start-up work, so the release stays one static binary). The worker identity is the SHA-256 of that binary, and the child re-checks it in the handshake. `off` disables symbolication explicitly: no probe, no child, frames answer `sandbox_unavailable`. |
| `--symbolicate-cgroup-root` | the process's own cgroup | The already delegated, empty cgroup v2 subtree in which the native sandbox creates its private child groups. A subtree that still holds processes, or has no `memory`/`pids` controllers delegated, fails the probe. |
| `--symbolicate-config` | none | Private JSON (mode `0600`; refused when group- or world-writable, unknown fields or a mode other than `native`/`oci` refused) selecting an explicit backend exactly as documented below, e.g. the pinned OCI image. Exclusive with `--symbolicate-cgroup-root`; ignored only by `--symbolicate-sandbox=off`, which conflicts with it. |

Serve prints one line to stderr, `symbolicator: ready (sandbox probes passed)` or `symbolicator: <state> (<reason code>): ...`. Reason codes are static (`disabled_by_operator`, `config_unreadable`, `config_not_private`, `config_invalid`, `worker_unresolvable`, `worker_unreadable`, `probe_<file|network|exec>_<sandbox_unavailable|worker_failure|deadline|resource_limit>`); a path, hash, OS error or map content is never printed.

The default native mode needs a delegated cgroup v2 subtree. On a host that offers none to the service account (for example a developer shell without a `systemd --user` delegation) the probe fails and frames answer `sandbox_unavailable`; do not mount or reconfigure controllers or weaken privileges to change that, and do not expect an OCI fallback: select OCI explicitly with `--symbolicate-config`. The shipped `deploy/systemd/soundpost.service` satisfies the delegation: `Delegate=memory pids` plus `DelegateSubgroup=main` keeps the server in its own sub-cgroup so the delegated parent holds no processes, `--symbolicate-cgroup-root=/sys/fs/cgroup/system.slice/soundpost.service` names that parent, and `ProtectControlGroups=yes` stays on with `ReadWritePaths=` re-opening only that one cgroup (with `ProtectControlGroups=yes` alone the whole `/sys/fs/cgroup` is read-only and the launcher fails with `EROFS`; measured with systemd 255). systemd lists `memory pids` in the parent's `cgroup.controllers` but leaves its `cgroup.subtree_control` empty, so the launcher itself writes `+memory +pids` there before creating a child (the delegatee's own right; the kernel refuses it with `EBUSY` while the parent still holds processes, and the child's limits are still written and read back).

Two further properties of the shipped hardening matter to the worker, both measured with systemd 255 and the unit's full directive set (every `[Service]` hardening directive passed to a transient system unit): `RestrictNamespaces=yes` removes `clone3` (hence the staged launch above, with the namespace restriction unchanged), and `SystemCallFilter=@system-service` does not contain `seccomp(2)` (it is in systemd's `@sandbox` group), so the worker's own filter installation failed with `EPERM` and every probe reported `probe_file_sandbox_unavailable` until the unit also listed `SystemCallFilter=seccomp`. With `NoNewPrivileges=yes` that call can only restrict the calling process further.

## Required sandbox: explicit backend selection

No mode is selected implicitly. Missing required restrictions return `sandbox_unavailable`; native launch failure never falls back to OCI. `GOMEMLIMIT=192MiB` and `GOGC=50` are runtime tuning only, **not OS security boundaries**. `RLIMIT_AS` is deliberately not used for a Go worker's virtual-address reservation. The hard memory configuration is exactly **268435456 bytes (256 MiB)**, never silently increased. Linux memory-controller hard limits have the kernel's documented reclaim/OOM and temporary-overage semantics; this is not a claim that every instantaneous accounting sample is mathematically below the limit.

Both backends require a Linux amd64 or arm64 worker, working cgroup v2 memory/swap/PID controllers, and seccomp thread synchronization. The child independently reads its actual current controller files before reading the DTO and requires `memory.max=268435456`, `memory.swap.max=0`, `pids.max=64`. A Docker CLI accepting flags or a HostConfig record alone is insufficient. The worker installs `PR_SET_NO_NEW_PRIVS`, a checked `SECCOMP_FILTER_FLAG_TSYNC` allowlist over all runtime threads, and `RLIMIT_CPU` soft/hard 5 seconds, core/file-size limits zero, descriptor limit 64. Syscalls for opening/statting source files, sockets/connect, execution, process inspection, namespaces and mounts are not allowed. Only supplied standard streams and Go-owned eventfd/epoll descriptors are available for I/O; launchers pass no ExtraFiles or host file mounts. Runtime thread creation is allowed only with `CLONE_THREAD`; clone3 inside the worker returns ENOSYS. No privilege, kernel sysctl, mount, setcap or unconfined seccomp change is made.

The parent bounds startup/process wall time to five seconds and frame processing, including DTO decoding/map parsing, to 100 ms; in OCI mode the parent's frame wait is 100 ms plus a fixed 400 ms transport allowance, because the request and reply cross the runtime client, daemon and shim stdio chain (measured at 96 to 162 ms per round trip on an idle host, so a bare 100 ms made most OCI frames answer `deadline`). The worker's own 100 ms watchdog is unchanged and still the authoritative processing bound; native mode has no allowance. The child has independent five-second process and 100-ms frame watchdogs as well. Each frame uses a fresh one-shot process (in OCI mode a fresh container per frame: cold start was 384 to 560 ms over 20 idle runs, and there is no warm worker), cancellation kills/reaps it, and OCI cleanup forcibly removes the named container. If that first remove finds nothing because a killed `run` client's request had not yet reached the daemon, the remove is retried in the background every 200 ms for at most five seconds, so a container created late is still removed. At startup in OCI mode, `soundpost serve` also sweeps leftovers of a process that could not clean up (a killed server or test binary): only containers named exactly `soundpost-symbolicate-<32 hex>`, whose image is exactly the configured immutable image ID, in state `created` or `exited`, and at least 30 seconds old, each removed by its exact ID with a plain `rm <id>` (never `--force`, never a prune or a name glob). Refusal, OOM, corrupt bytes, invalid map and deadline all retain the original frame. The decoder retains the existing aggregate 32-MiB/1024-file/depth-8 and segment/node limits. A legal large map can still exceed a worker's CPU/memory budget and be safely unresolved; no successful decoding of every ceiling-sized map is promised.

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

An administrator must already have delegated the relevant controllers/subtree to the service account. The launcher only creates a private child group there, sets and reads back its limits, and places the worker in it before the worker's own code runs. Where `clone3` can be called it uses Go `UseCgroupFD` / `CLONE_INTO_CGROUP`, so the worker is charged from birth. Where it cannot (systemd's `RestrictNamespaces=yes`, which the shipped unit sets, makes `clone3` return `ENOSYS`; probed with `clone3(NULL, 0)`, which answers `EINVAL` when the call is allowed) the launch is **staged**: the same binary is started with the exact vector `--stage-worker-v1` or `--stage-probe-v1`, which does nothing but block on an inherited pipe (descriptor 3). The parent writes that process's pid into the new group's `cgroup.procs`, reads `cgroup.procs` back to prove membership, and only then writes one release byte; the process then `exec`s `/proc/self/exe` (the image that was started, not a path looked up again) with `--worker-v1` or `--probe-v1`. A failed migration or verification leaves the process blocked and it is killed; a closed pipe, a parent that died, or the five-second process bound ends it without running a worker. Everything the worker image maps or allocates after the `exec` is charged to the limited group. What is **not** charged to it is the staging process before the `exec`: its runtime start-up (15360 kB resident for the `soundpost` binary in the one measurement) belongs to the parent's cgroup until the release; the kernel does not move preexisting charges on migration. Post-start migration of a *running* worker is never used. Missing delegation, controller files, clone-into-cgroup or migration permission, readable standard cgroup mount or seccomp support fails closed. Unsupported native platforms fail closed. Absence of profiler tracefs access says nothing about whether these independent sandbox facilities are available. Do not mount/reconfigure controllers or weaken privileges merely to turn a failed probe green.

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
