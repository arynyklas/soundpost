<!-- Copyright 2026 Aryn Yklas -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Host and system metric collection

`internal/host` collects CPU, memory, load, filesystem, process-count and
cgroup metrics from operating-system primitives, outside Kubernetes. It is
policy-bound: nothing is read unless the operator's `HostPolicy` allows the
group, and every group that cannot deliver reports a *capability* instead of
a zero.

```go
batch, caps, err := host.Collect(ctx, host.HostPolicy{
    Allow:       host.AllGroups(),
    Filesystems: []host.FilesystemTarget{{Alias: "data", Path: "/var/lib/app"}},
})
```

`err` is returned only for an invalid policy or a cancelled context. Every
other failure becomes a `Capability` (group, filesystem alias, status, reason,
method). `batch.Records(res)` and `caps.Records(...)` convert the result to
model metric and capability records.

## OS capability matrix

| Group | Linux | Windows | macOS (darwin) | Other OS |
| --- | --- | --- | --- | --- |
| cpu | `/proc/stat` | `GetSystemTimes` (user, system, idle) | unsupported, `requires_cgo` (Mach `host_statistics`) | unsupported |
| memory | `/proc/meminfo` | `GlobalMemoryStatusEx` (total, available) | sysctl `hw.memsize`, `vm.page_free_count` x `hw.pagesize` (total, free only) | unsupported |
| load | `/proc/loadavg` | unsupported, `os_unsupported` | sysctl `vm.loadavg` | unsupported |
| filesystem | `statfs` | `GetDiskFreeSpaceEx` (no inode counts) | `statfs` | unsupported |
| process_count | `/proc` directory names | `EnumProcesses` (PIDs only) | sysctl `kern.proc.all` length only | unsupported |
| cgroup | cgroup v2 only | unsupported | unsupported | unsupported |

Verification status, stated plainly: Linux is run against fixtures and the
real `/proc`, `/sys/fs/cgroup` of a WSL2 host; Windows is run on the Windows
toolchain, but its smoke did not run the process-count, journal or
permission-denied rows (`system-logs.md` lists them as **not run** there), so
the Windows `process_count` cell above is implemented, not smoke-verified;
**macOS is compiled and vetted only, never run** (no macOS machine
was available, and the CPU group is not implemented there); other OSes are
only compile-checked (`GOOS=freebsd`).

## Metric catalogue

Names are API. Units are model unit codes.

| Metric | Type | Unit | Labels | Source and notes |
| --- | --- | --- | --- | --- |
| `host_cpu_seconds_total` | counter | `seconds` | `mode`: user, nice, system, idle, iowait, irq, softirq, steal | aggregate `cpu ` line of `/proc/stat`, USER_HZ=100. guest/guest_nice are already inside user/nice and are not emitted. Fields absent on old kernels are skipped, never zeroed. Windows: user, system (kernel minus idle), idle only. |
| `host_cpu_logical_count` | gauge | `1` | none | number of `cpuN` lines; Windows: `runtime.NumCPU`. Omitted if none is found. |
| `host_load_average` | gauge | `1` | `window`: 1m, 5m, 15m | `/proc/loadavg` |
| `host_memory_bytes` | gauge | `bytes` | `state`: total, available, free, buffers, cached, swap_total, swap_free | `/proc/meminfo` kB x 1024. MemTotal, MemAvailable, MemFree are required; if any is missing nothing is emitted. buffers, cached, swap_* only when present. Windows: total, available. macOS: total, free. |
| `host_filesystem_bytes` | gauge | `bytes` | `mount` (operator alias), `state`: size, free, available | blocks x `f_frsize` (`f_bsize` when frsize is 0); free is `bfree`, available is `bavail` (space usable by an unprivileged writer) |
| `host_filesystem_inodes` | gauge | `1` | `mount`, `state`: total, free | only when `f_files != 0`; never a fake zero for filesystems without inodes |
| `host_processes_total` | gauge | `1` | none | count of purely numeric names in `/proc` (directory names only). Windows count includes the System Idle Process (PID 0). |
| `host_cgroup_cpu_seconds_total` | counter | `seconds` | `mode`: user, system | `cpu.stat` `user_usec`, `system_usec` / 1e6 |
| `host_cgroup_memory_bytes` | gauge | `bytes` | `state`: current, limit, swap_current | `memory.current`; `memory.max` (a number only: `max` = unlimited emits nothing); `memory.swap.current` only if the file exists |
| `host_cgroup_memory_oom_kills_total` | counter | `1` | none | `memory.events` `oom_kill` (absent on kernels that do not report it: skipped) |
| `host_cgroup_pids` | gauge | `1` | `state`: current, limit | `pids.current`; `pids.max` (number only) |

All samples carry labels sorted by name. Records are float samples; each
record has a fresh ID and `ObservedAt` is the batch time.

### Label allow-list for the server-side SourcePolicy

Every label value comes from a closed in-code enum or the operator alias, so
a source policy can allow-list them. `SourcePolicy.Labels` must contain:

| Label | Values |
| --- | --- |
| `mode` | `user`, `nice`, `system`, `idle`, `iowait`, `irq`, `softirq`, `steal` |
| `window` | `1m`, `5m`, `15m` |
| `state` | `total`, `available`, `free`, `buffers`, `cached`, `swap_total`, `swap_free`, `size`, `current`, `limit`, `swap_current` |
| `mount` | exactly the aliases configured in `HostPolicy.Filesystems` |

The source policy `Kinds` must include `metric` and `capability`. A value
that is not allow-listed is refused at admission, which is intended.

## Policy

`HostPolicy.Validate` rejects with a typed `invalid` fault: an unknown or
duplicate group; a filesystem alias that is not `^[a-z][a-z0-9_]{0,31}$` or
is duplicated; an empty, relative or NUL-containing path (Windows requires a
drive-absolute path such as `X:\data`; UNC and drive-relative paths are
rejected); more than 16 filesystems.

A group not in `Allow` is `denied` with reason `policy` and produces no
samples. Filesystem allowed with no target configured is one capability with
empty scope, `denied`, `no_target_configured`.

## Capabilities

`Capability{Group, Scope, Status, Reason, Method}`; `Scope` is the filesystem
alias (empty otherwise). Status is `supported`, `unsupported`, `denied` or
`unknown`. Reasons are a closed lowercase set: `policy`, `permission_denied`,
`not_present`, `read_failed`, `parse_failed`, `os_unsupported`,
`cgroup_v2_required`, `process_visibility_restricted`,
`no_target_configured`, `cancelled`, `requires_cgo`.

A missing, unreadable or unparseable source is `unknown` (or `denied` for a
permission error); it is never turned into a zero sample. Examples: missing
`/proc/meminfo` is `unknown/not_present` and emits no memory samples; a
truncated `/proc/stat` is `unknown/parse_failed`.

Wire form (`Capabilities.Records`): one `capability` record per group, signal
`metric`, runtime `soundpost-agent`, version `1`. The wire record has no group
field, so its `method` is group-qualified (`cpu:procfs_stat`,
`filesystem:statfs`, `cgroup:policy`) and no two groups share a method. The
wire vocabulary has no
`unknown`, so `unknown` is sent as `error`; a supported group sends reason
`ok`. Coverage fields are `complete` only for supported groups and `unknown`
otherwise. The wire record has no scope, so a group with several filesystem
scopes is reported `supported` only when every scope is; otherwise the first
non-supported scope speaks for the group. `Expires` is `at + ttl`.

## Privacy exclusions and what is not collected

- No command lines, environment, process names, executable paths, or any
  `/proc/<pid>/` file is read or opened. The process count lists the `/proc`
  directory names only. On Windows `EnumProcesses` returns PIDs and no
  process is opened; on macOS only the length of `kern.proc.all` is used.
- Filesystem paths never appear in samples, labels, capabilities or errors;
  only the operator alias does. Mount tables are read only to detect `hidepid`
  on `/proc`; no mount point is emitted.
- The agent's own cgroup path is used to locate files and is never emitted.
  Only the fixed files `cpu.stat`, `memory.current`, `memory.max`,
  `memory.swap.current`, `memory.events`, `pids.current`, `pids.max` are read,
  and `..` in the cgroup path is rejected.
- Not collected: per-process or per-thread metrics, network, disk I/O,
  pressure (PSI), temperatures, GPU, per-CPU series, per-cgroup children,
  container or pod identities, hostnames, users.
- Reads are bounded to 1 MiB; a larger source is reported unreadable instead
  of truncated.

## Honest limits

- `process_count` on Linux: if `/proc` is mounted with `hidepid` (1, 2,
  `noaccess`, `invisible`, `ptraceable`) and the agent is not exempt, the
  count would silently be partial, so the group is `unknown /
  process_visibility_restricted` and emits nothing. Exempt means: euid 0
  (assumed to hold `CAP_SYS_PTRACE`; a root agent in a container without it may
  still see a partial list) or membership of the mount's `gid=` group. The
  `/proc` mount is taken from `/proc/self/mountinfo`; if none is found the
  group is `unknown/parse_failed`.
- cgroup requires cgroup v2 mounted at `/sys/fs/cgroup` (cgroup2fs). v1 and
  hybrid hosts are `unsupported/cgroup_v2_required`; no cgroup mount is
  `unsupported/not_present`; an unreadable file is `denied/permission_denied`
  and emits no cgroup samples. A cgroup without some controller files (for
  example the root cgroup has no `memory.*`) reports only the metrics whose
  files exist; if none exist it is `unsupported/not_present`.
- The cgroup reported is the agent's own, not the host's or a container
  parent's; limits inherited from a parent cgroup are not visible here.
- CPU counters are cumulative since boot; rates and busy fractions are
  derived by the consumer. `iowait` is not reliable on every kernel.
- macOS has no CPU group (cgo is required), no `available` memory figure, and
  is compiled-not-run. Windows has no load average and no inode counts.
- Filesystem figures come from `statfs`/`GetDiskFreeSpaceEx` of the configured
  path; network and overlay filesystems report what the kernel reports.
- The agent that starts the collection chooses the interval; this package
  takes one point-in-time pass per call.

## Fixtures

`tools/fixtures/host/proc` and `tools/fixtures/host/cgroup` are plain-text
files shaped like real `/proc` and cgroup v2 files. They contain no host
identities. The empty files named with digits in `proc/` are process-name
stand-ins: only their names are used.
