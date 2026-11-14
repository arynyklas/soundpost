<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# No-send shadow ingestion and parity (plan 08 task 02)

`tools/adoption shadow` replays a recorded capture of what an existing source delivered into an **isolated** Soundpost instance, folds condition events into the owned condition lifecycle, lets the owned shadow policy twin decide what it *would* send, and compares the answers with the legacy system's. It never sends a notification, never opens a network connection and never touches a legacy sender.

**Status: generic tooling proven against synthetic fixtures only.** No customer system, inventory, hostname or credential was used to build or test it. Nothing here is customer acceptance. Running it against real sources and replaying sanitized real query shapes needs the owning environment's separate authorization and is **not done** (see [prerequisites](#prerequisites-for-an-authorized-run)).

## Command

```
go run ./tools/adoption shadow --mapping FILE --policy FILE --source-policy FILE --capture FILE \
  --workdir EXISTING_DIRECTORY --report NEW_FILE --public-summary NEW_FILE [--timeout 5m]
```

All inputs are strict JSON (unknown fields are an error). `--workdir` must exist; the tool creates a scratch directory inside it, provisions the destination there and deletes it on exit. `--report` (private, full) and `--public-summary` (closed, counters and booleans only) are created exclusively with mode 0600 and never overwritten. The private report is written whenever a report exists, including a failed run (evidence); the public summary is written only when the run succeeded. Exit status is non-zero for every refusal, a policy violation by a delivery, a failed reconciliation and a cancelled or timed-out run.

The same behaviour is available as `RunShadow(ctx, SourceMapping, SoundpostDestination, ShadowPolicy) (ShadowReport, error)`.

## Trust boundaries

* **No sending, by construction.** `ShadowPolicy` carries `external_delivery`, `enabled_senders`, `accept_raw_sources` and `disable_legacy_senders` only so that a configuration that tries to turn one on is refused with an explicit error (`ErrShadowExternalDelivery`, `ErrShadowRawSource`, `ErrShadowLegacySender`) instead of being ignored. The only legal values are `false`/empty. The destination has no sender field, `shadow.go` and `parity.go` import no `net*`, `os/exec`, `syscall` or `plugin` package (a test parses the imports), and decisions come from `notify.ShadowEvaluator`, which never stores, claims or sends. A run reports `normal_deliveries_sent` and `external_send_attempts` as 0 and the decisions it *would* have delivered separately.
* **Legacy senders are never disabled or modified.** The tool has no write path to them; a policy asking for it is refused.
* **No arbitrary raw-source acceptance.** The destination source policy class must be `structured`; `restricted_raw` is refused. A delivery whose `original_source` is not the mapped source, or whose adapter is not declared, is rejected with the explicit reasons `unmapped_source` / `undeclared_adapter`, counted as a policy violation and makes the run return `ErrShadowPolicyFailed` (the full report is still returned). Telemetry labels are data: a label naming another project or org is not authority and is dropped by the owned source policy.
* **Signed mapping, verified before use.** A `SourceMapping` binds one original source and its version to org, project, source-policy revision and digest, resource identity, timestamp bounds and adapter declarations. It carries no read access. It is signed with ed25519 (`ShadowSignMapping`); the run holds only trusted public keys (`trusted_keys` of the policy, base64) and refuses an unsigned, tampered, wrongly-keyed, unknown-key, not-yet-valid or expired mapping before anything else of it is looked at. Key custody, rotation and revocation are the operator's; trust is exactly the policy's key list.
* **Isolated destination.** The CLI always provisions a fresh in-process Soundpost instance (org, project, one source with the given source policy, one reader scoped to exactly that project with read permission). The source policy file must hash (canonical JSON, SHA-256) to the mapping's `source_policy_sha256` and match its revision. Ingest authority is one source credential and read authority is one project-scoped scope created by the operator-side provisioner, never derived from labels. Embedding `RunShadow` against another instance is possible through the Go API only; the CLI does not and **pointing a shadow run at a production instance is not implemented and not authorized here**.
* **Private vs public output.** `ShadowReport` can name conditions, case IDs and original-source labels and must stay private. `ShadowPublicSummary` has only integer and boolean fields (a test pins this) and `customer_acceptance` is always false.

## Adapters: version and feature declaration

Every configured adapter must carry a concrete `version` (a digit-bearing token; `*`, `1.*`, `any`, `latest`, `compatible` and the like are refused) and an explicit non-empty `features` list drawn from its kind's closed vocabulary; an empty or wildcard declaration, an unknown kind or feature, a repeated kind or feature, a missing/incomplete Loki template binding (or a binding on another kind) is refused (`ErrShadowAdapter`).

| kind | translator | features |
|------|-----------|----------|
| `openmetrics` | `queryinput.DecodeOpenMetrics` | counter, gauge, histogram, summary, created_timestamp, exemplar_trace_link, help_text_discard |
| `remote_write_v1` / `remote_write_v2` | `queryinput.DecodeRemoteWrite` | float_samples, stale_markers, native_histograms, exemplar_trace_link, help_text_discard |
| `loki_push` | `queryinput.DecodeLokiPush` | stream_labels, structured_metadata, duplicate_lines_preserved (+ a `loki` template binding) |
| `condition_events` | `conditions.Reduce` | sequence_ordering, timestamp_ordering |
| `log_file` | `sources.Read`, `sources.BuildBatches` (owned file source) | templated_lines, unmatched_lines_dropped_by_reason, duplicate_lines_preserved (+ a `file` template binding) |

Enforced gates: `native_histograms`, `exemplar_trace_link` and `help_text_discard` set the owned adapter's profile (a source feature that is not declared is rejected by the adapter); a delivery containing stale markers or native histograms through an adapter that does not declare them is rejected as `undeclared_feature`. The other features are descriptive: they state what the source is declared to produce and are carried into the report and ledger.

## Capture format

`--capture` is `{"deliveries":[{"id","original_source","adapter","received_at_ns","body"}],"parity":{...}}`. `body` is base64 of the exact wire body (snappy remote-write, OpenMetrics text, Loki push JSON/gzip/snappy-protobuf per the binding, or the raw bytes of a log file for `log_file`) or, for `condition_events`, JSON `{"events":[{"condition","epoch","sequence","at_ns","status","severity","labels"}]}` (status: pending, firing, recovering, recovered/resolved, unknown; at most 512 events, unknown fields or trailing data make the delivery `malformed_body`). A `log_file` body must end with a newline and have at most 512 lines. Deliveries are replayed in file order, so a delayed or retried delivery is represented by its position. `id` is the source-side delivery identifier and is carried into the ledger.

`log_file` replays the body through the owned file source (`sources.Read`, `sources.BuildBatches`) as a structured source: the binding names the source, its stream labels, its registered templates (which the destination source policy must also register) and an optional leading time layout. Every line is classified by those templates; a line that matches none or carries an unapproved or oversize value is dropped with the source's own closed reason (`source_unknown_template`, `source_unapproved_value`, ...). Equal lines are distinct records. Because the owned source gives each read a fresh random batch identity, a byte-identical re-delivery is recognized by the SHA-256 of its body and counted `duplicate_retry` instead of being admitted twice; a re-delivery of an *edited* file is new data.

## Ledger and reconciliation

Every received source unit (a decoded metric point or log line, a scanned file line, an exact duplicate the adapter collapsed, a condition event) gets one ledger row: adapter and declared adapter version, original source and version, delivery ID, ordinal, kind, a stable 64-hex dedup ID (derived from the mapping digest and the record, file-body or event identity), outcome and reason. Deliveries rejected as a whole get one `delivery` row with a reason. Reasons are a closed vocabulary: `unmapped_source`, `undeclared_adapter`, `undeclared_feature`, `body_too_large`, `delivery_limit`, `malformed_body`, `file_too_many_lines`, `grant_unavailable`, `decode_<queryinput reason>`, `source_<sources reason>`, `admission_<fault code>`, `duplicate_retry`, `exact_duplicate_collapsed`, `late_version`, `duplicate_event`, `conflicting_replay`, `invalid_event`. The report also states how many batches were actually submitted to the owned ingest path (`batches_submitted`): a retry whose records were all admitted before is not resubmitted.

`received` is counted independently while decoding; `admitted` and `dropped` are tallied from the rows. The run fails (`ErrShadowReconcile`) unless, for the records and for every adapter, received = admitted + dropped, dropped equals the sum of its per-reason counts, and every tally equals the same tally recomputed from the ledger; delivery tallies reconcile the same way. A deterministic ledger digest is reported. The ledger is in memory and is part of the private report; it is not a durable store.

## Version ordering

Condition events are ordered by the owned reducer (`conditions.Reduce`): by source sequence within a producer epoch, an old or duplicate event never overwrites newer state, a conflicting replay of an accepted (epoch, sequence) is rejected, and an unknown status is never a recovery. A v3 firing is not overwritten by a delayed or retried v2 recovered; both show up as `late_version` rows. Every event, late ones included, is also fed to `notify.ShadowEvaluator`, whose own source-version ordering must independently produce no decision for late history. Metric and log retries are idempotent: a batch whose records are all already admitted is not resubmitted and is counted as `duplicate_retry`; distinct log records with an equal timestamp and line are never merged. Native histograms, stale markers and their exact IEEE bits are admitted as declared and are checked end to end through the owned query engine.

## Parity

The optional `parity` section is the legacy system's answer and is compared exactly, never by count alone: query cases (language, pinned profile, enabled feature list, expression, instant or range; expected exact value bits per sample, canonical native-histogram JSON, exact log lines in engine order, or an explicit unsupported reason = the engine's typed fault code), lifecycle answers (source version, phase, optional freshness per listed condition), legacy notification decisions (compared through `notify.CompareParity`; every legacy recipient set maps onto the single synthetic `shadow-recipient`, the shared queue is the empty recipient) and exact expected drop/reject reason tallies. A nil section is not compared; a case that cannot be evaluated (unknown profile or feature set, ambiguous evaluation, duplicate case ID) refuses the run before any delivery. Queries always run in the mapped project through the destination's reader; a case has no project field.

## Prerequisites for an authorized run

All of these are operator-side and not provided here: authorization from the owning environment for the exact sources; a captured set of source deliveries (with the source's own delivery IDs) obtained under that authorization; the original source's concrete version and feature set; the source policy the production project would use (and its digest); an ed25519 mapping signing key held outside this repository and its public half in the shadow policy; the legacy system's answers for the query shapes and conditions to compare (sanitized); an external private location for the report. The product-side expected results (exact values, versions, unsupported reasons) are only as good as those legacy answers; this tool cannot establish that a capture or an answer is truthful or complete.

## Not covered

No pull/scrape adapter (the owned `internal/sources` scrape and syslog/journal paths are never called: a test pins that the shadow tools use only `sources.Read`, `BuildBatches` and the types they need, and the scrape path blocks private and loopback egress by design and would reach customer networks), no retained history import, no durable ledger, no use of the control-group condition service or outbox (the lifecycle is the owned pure reducer in process; condition events are not persisted in the destination), no deadman, cutover or rollback (later tasks), no real-customer parity result, no performance or volume qualification.
