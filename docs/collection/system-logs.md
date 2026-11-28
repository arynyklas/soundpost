<!-- Copyright 2026 Aryn Yklas -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# System log collection

`soundpost-agent` reads local log sources (a text file, a syslog-framed file,
the systemd journal) and submits typed, policy-approved records to the
installation's C03 ingest route. The code is `internal/sources` (acquisition,
templates, checkpoints) and `internal/agent` (configuration, HTTPS client, the
run loop). The agent produces batches; it never decides admission and keeps no
second copy of an ingestion engine.

## What is exported

The default source class is `structured`: a log line becomes a record only if
it matches a **registered template revision** of the installation's source
policy, and every captured field is a typed value that the policy lists as
approved for that field.

```
registered template   "service started unit {unit}"   unit: string, approved {"alpha","beta"}
source line           "service started unit alpha"    -> template service.started r1, unit="alpha"
source line           "service started unit gamma"    -> dropped (unapproved_value)
source line           "password reset for carol"      -> dropped (unknown_template)
```

A line that matches no registered template, or whose captured value is not
approved, is counted by reason and dropped. Its bytes exist only in a bounded
acquisition buffer that is zeroed once the line has been classified. They are
never copied into a record, an export queue, a checkpoint, an error, a log
line, a capability record or a command line.

Closed drop reasons (counters in the checkpoint; the set contains no content):
`unknown_template`, `unapproved_value`, `oversize_value`, `oversize_line`,
`invalid_utf8`, `unapproved_source`, `bad_timestamp`, `non_text_message`,
`bad_frame`, `pending_rebuilt`.

Matching: a template's `Line` is the pattern (`{field}` placeholders match by
their declared type: `int64` is a canonical decimal integer, `bool`, `null`,
otherwise any text). When several templates match one message the one with the
most literal text wins, then declaration order. Every record is checked with
the same `model.ValidateRecord` the server applies, so what the agent exports
is what the server accepts; the server validates again at admission.

Records carry the source's configured stream labels (for example
`source="app"`), the registered resource identity, the template's severity
(never the log's own), and the source's timestamp when the source has one
(journal `__REALTIME_TIMESTAMP`, a syslog timestamp, or a configured
`time_layout` prefix of a file line); otherwise the time of the read.

### Restricted raw

Text is only exported by an explicit `restricted_raw` source: the policy needs
an owner, rationale, expiry and a maximum size, a template whose field has
sensitivity `restricted_raw` (for example `raw {message}` with no approved
value list), and the same grant in the installation's source policy. The agent
refuses to read at all after the grant expires (`denied/raw_grant_expired`). A
`structured` source cannot hold a raw field (policy validation fails), and raw
content is never written to the checkpoint directory, even when the server
refuses a batch (nothing in the pending intent is content).

## Adapters

| Kind | Reads | Selection | Position |
| --- | --- | --- | --- |
| `file` | one append-only text file | the path; optional `time_layout`; `rotated` paths | file identity + byte offset + tail hash |
| `syslog` | syslog-framed messages (RFC 3164, rsyslog RFC 3339 file format, RFC 5424, each with optional `<PRI>`): from a file written by the local syslog daemon, or from the network (UDP, TCP, TLS) | the path (file) or `listen` addresses (network), and a **required** list of approved tags; `rotated` paths (file only) | file: as `file`; network: receiver epoch + sequence |
| `journal` | the systemd journal through `journalctl` | **required** approved `SYSLOG_IDENTIFIER` and/or `_SYSTEMD_UNIT` matches, passed to the journal as match arguments | the journal cursor |

- `StartAt` is `end` by default: history that predates the agent is not swept
  in. `beginning` starts at the first byte or entry.
- The syslog adapter reads a file (`path`) or listens on the network
  (`listen`), never both. It reads the tag and message of a line and skips the
  host name and process id; neither is ever returned.
- Network syslog (`listen`: a list of `{network: udp|tcp|tls, address:
  "IP:port", cert_file, key_file, client_ca_file}`; `buffer_records`, default
  4096). UDP is one message per datagram (RFC 5426); TCP and TLS accept RFC
  6587 octet counting or newline framing (RFC 5425 for TLS; `client_ca_file`
  requires and verifies a client certificate). Addresses are IP literals; a
  non-loopback listener is open to whoever can reach it, so use TLS with a
  client CA or a firewall. Every message is classified on arrival with the file
  rules (framing, tag allowlist, registered template, approved values); only the
  typed record of an approved message, or the drop reason of any other, is kept
  (in memory, in a bounded sequence-numbered buffer; nothing received is
  written to disk). The position is (receiver epoch, last committed sequence),
  so the checkpoint rules above hold unchanged: the pending range is rebuilt
  identically after a lost acknowledgement. What a memory-only receiver cannot
  replay is declared: a UDP datagram that finds the buffer full is a loss
  `queue_full` with the exact count; TCP/TLS senders are not dropped (the
  connection is not read while the buffer is full); the first read after the
  agent restarted (new epoch) reports one loss `shutdown` (count 1, a lower
  bound) for the uncommitted range and everything sent while it was down.
  `start_at` is `beginning` only (a stream has no history). The listeners start
  at the first read of the source (or `sources.StartSyslogReceiver`) and live
  until the process ends. A listener that cannot bind is `unknown/listen_failed`
  (`denied/permission_denied` for a privileged port). Capability method:
  `syslog_net:<name>`. A `-once` run only listens for the duration of the cycle.
- The journal adapter runs `journalctl` with a fixed argument vector (never a
  shell), a three-variable environment (not the agent's), and
  `--output-fields=MESSAGE,PRIORITY,SYSLOG_IDENTIFIER,_SYSTEMD_UNIT`, so fields
  such as `_CMDLINE` are never delivered. Entries of unapproved units are
  never delivered either: the journal filters them. Identifiers and units are
  validated against a closed character set (no leading dash, no space) so a
  match cannot become an option. `journalctl` nulls fields over 4 KiB; those
  entries are dropped as `oversize_line`.
- Only regular files are opened (a FIFO or device is refused before opening).
  Lines longer than `max_line_bytes` (default 8192) are counted once and
  skipped to their newline without being buffered. Only newline-terminated
  lines are consumed, except at the end of a rotated predecessor.

## Checkpoints: advance only after the receipt

Each source has a durable checkpoint in the agent's state directory
(`<name>.checkpoint.json`, written atomically with fsync, SHA-256 protected;
a corrupt file is an error, never a silent restart at "end"). A checkpoint has
a **committed position** and, while a batch is in flight, a **pending range**.

1. `sources.Read(ctx, policy, checkpoint)` returns the admissible records of
   the next range and a checkpoint that *describes* the range (`Pending`:
   target position, scanned count, record count, reason counters, gaps and a
   range identifier). The committed position is unchanged.
2. The pending range is stored durably **before** anything is submitted
   (`Store.Prepare`). It holds positions, counts and identifiers only.
3. The batches are built deterministically from the range: record and batch
   identifiers derive from the range identifier, observed times from the
   source (or the recorded range time). The agent submits them and waits for
   the receipts.
4. Only `Store.Commit(receipts...)` moves the committed position, and only if
   the receipts cover exactly the batches of the pending range (matching
   batch ids, a non-empty cursor). A range with no admissible record and no
   gap has nothing to submit and is committed without a receipt.

A lost acknowledgement or a restart therefore re-reads exactly the pending
range, produces byte-identical batches and resubmits them; the server's
receipt ledger returns the original receipt for the same batch id and bytes.
Records are neither skipped nor admitted twice, and lines that arrived while
the agent was down are not folded into the in-flight range. If a source no
longer reproduces the recorded range (it was not append-only) the range is
replaced and `pending_rebuilt` is counted; this is the one case where a
duplicate logical admission is possible, and it is visible.

A batch the server refuses permanently (for example the policy changed) is not
spooled and not skipped: the source stays at its position and every cycle
reports the typed failure. Nothing is persisted from the refused content.

## Rotation, truncation and permission denial

Position is identity based: a file is recognized by its identity (device and
inode, or the Windows file index) and the SHA-256 of the 64 bytes before the
committed offset (the *tail*).

| Situation | Result |
| --- | --- |
| rename rotation, predecessor listed in `rotated` | the predecessor is finished first, then the new file is read from byte zero. No loss, no duplicate (exercised on WSL2/Linux only; see the Windows and OS-scope caveats under verification below) |
| copytruncate (file truncated after a copy) | the copy is found by the tail hash and finished; then the truncated live file is read from the start. No loss, no duplicate (exercised on WSL2/Linux only; file rotation on Windows is not run) |
| predecessor deleted or not listed; or file replaced in place (inode reuse); or truncated with no copy | unread bytes are lost: a `loss` record with reason `truncated`, signal `log` and count 1 (a **lower bound**, the true number is unknown) is exported with the same batch discipline, and reading restarts at byte zero of the live file |
| live file missing | `unknown/not_present`; nothing is invented, no position is created |
| open denied | `denied/permission_denied`; the position does not move, and the health is recorded. Reading resumes where it stopped when access returns. Denial is not a loss |
| `rotated` path unreadable and the continuation not found | `denied/permission_denied`, not a gap: nothing is declared lost that may still exist (implemented; no test exercises it) |

Journal: the cursor is the position. A resume uses `journalctl --cursor`
(inclusive) and requires the first entry returned to be the committed cursor
entry. If it is a different entry (the cursor was vacuumed: `journalctl`
silently seeks to the nearest survivor), or nothing comes back at all, the
entries in between are lost and are exposed as a `loss` record with reason
`truncated`, signal `log`, count 1 (a lower bound), with the same batch
discipline as a file gap; reading continues at the oldest survivor, or from the
current second when nothing survives, so the gap is reported once. This was
checked against systemd 257 (`--after-cursor` returns every survivor silently;
`--cursor` of a missing entry returns a different first entry or nothing).
Permission denial (`journalctl` says
"insufficient permissions", or hints that it is not showing messages of other
users and the system) is `denied/permission_denied`; a missing `journalctl` is
`unsupported/not_present`; any other failure is `unknown/journal_failed`. A
changed policy that no longer selects the committed entry reports one
conservative gap.

## Capabilities

Every cycle the agent sends `capability` records: one per host metric group
(see `host.md`) and one per log source with signal `log`, method
`file_tail:<name>`, `syslog_file:<name>`, `syslog_net:<name>` or `journalctl:<name>`, status
`supported`, `denied`, `unsupported` or `error` (an unknown state; the wire
vocabulary has no `unknown`) and a reason. A source that cannot be read is
therefore an explicit stored state, never an empty source. Coverage fields are
`complete` for a supported source and `unknown` otherwise; records expire after
three host intervals (at least one minute) so a silent agent is visible.

## Agent

```
soundpost-agent -config /etc/soundpost/agent.json          # run
soundpost-agent -config /etc/soundpost/agent.json -once    # one cycle; exit 1 if any component failed
soundpost-agent -config /etc/soundpost/agent.json -validate
```

The configuration is strict JSON (unknown fields are errors). The server must
be an `https` origin; `ca_file` replaces the system roots; certificate
verification can not be disabled; redirects are never followed (the bearer
credential must not leave the configured origin); there is no proxy. The
credential is read from `credential_file` (a reference, never inline); on POSIX
a file readable by group or others is refused. The state directory holds the
checkpoints and `identity.json` (a random producer id and host pseudonym; no
host name, address or machine id). The agent logs reason codes and counters,
never an error text, path, message or credential.

`org`, `project`, `source`, `policy_revision` and the resource ids must match
the installation's source onboarding; log sources take `policy_revision` and
the resource from the top level.

Host samples are point-in-time and are not replayed: a host batch the server
did not accept is counted and reported as a `loss` record (signal `metric`,
reason `transport`, with the count and window) once the server accepts data
again.

## Verification state

Run on a Linux (WSL2) host: unit and integration tests (including a real node
for the lost-acknowledgement drill), `go run ./tools/smoke host-collection`
(real node over HTTPS, real journal events through `logger`, real
CPU/filesystem/process deltas), and the compiled agent as a separate process.
Run on a Windows 11 host: the same smoke with the in-process agent (file and
syslog sources, real CPU and filesystem deltas, policy-denied capability; the
process-count, journal and permission-denied rows need `sleep`, `journalctl`
and POSIX permissions and were **not run** there).

**Not run:** macOS (compiled only); the compiled agent binary on Windows; a
vacuumed journal against a real journald that rotated by itself (the gap was
exercised with a fake `journalctl` and the real systemd 257 `journalctl`
behaviour for missing cursors, not a size-limit vacuum of the system journal);
network syslog on Windows/macOS and from real network devices (loopback senders
only); `hidepid` hosts; file rotation on Windows; any non-WSL2 Linux except the
one Debian 13 VM named in `host.md`.
