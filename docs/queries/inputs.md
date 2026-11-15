<!-- Copyright 2026 Aryn Yklas -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Migration input translators

`internal/adapters/queryinput` turns three external wire formats into Soundpost
admission batches (`ingest.Batch`): OpenMetrics text, Prometheus remote-write
v1/v2 and Loki push. They are isolated development/migration adapters. No
external schema type leaves the package, no product read route or storage layout
becomes upstream-compatible, and nothing here scrapes remote URLs.

```go
DecodeOpenMetrics(ctx, grant, r, cfg)            ([]ingest.Batch, error)
DecodeRemoteWrite(ctx, grant, version, r, cfg)   ([]ingest.Batch, error)
DecodeLokiPush(ctx, grant, r, cfg)               ([]ingest.Batch, error)
Normalize(batch, cfg)                            (ingest.Batch, NormalizationReport, error)
```

Every decoder authenticates against the supplied `policy.SourceGrant`: the
profile's project and source must be exactly what the grant covers, and the org
comes from the grant. A body can never choose its scope. Returned batches hold
one canonical-owner virtual slot (`model.OwnerSlot`), at most 512 records and
3 MiB, and carry deterministic identities: the batch ID derives from the request
bytes, the profile identity, the slot and the chunk index; metric record IDs
derive from series, timestamp and exact point content; log record IDs derive
from the request and the entry ordinal. A retried request therefore regenerates
identical IDs. Submit through `policy.Normalize` and C03 durable admission; the
decoder does not bypass either.

## InputProfile

The profile pins everything that could silently change data: source mapping
(`Project`, `Source`, `Producer`, `PolicyRevision`, `Resource`), `Limits`
(wire body, decoded body, series, samples, labels, label bytes, line bytes,
streams, histogram buckets), inclusive `MinTimestamp`/`MaxTimestamp`, name mode,
out-of-order mode, histogram mode, exemplar mode, HELP mode, the default
timestamp/unit and the Loki template mapping. Every enumeration is explicit; the
zero value is invalid.

Duplicate handling is not configurable. Identical metric points at one
series/timestamp collapse (counted in the report), differing points are a
`conflicting_duplicate` rejection, and distinct log records are never merged:
timestamp and line are not identity. This mirrors the owner-shard invariant, so
a profile cannot weaken it.

## What each format may carry

| Kind | OpenMetrics | Remote-write v1 | Remote-write v2 | Loki push |
|---|---|---|---|---|
| float samples, exact bits (ordinary NaN payload, ±0, ±Inf) | text numbers; NaN is the canonical NaN | exact | exact | n/a |
| stale marker `0x7ff0000000000002` | not expressible in text | sample becomes `stale` | sample becomes `stale` | n/a |
| native integer histograms (counts/deltas above 2^53) | no | yes | yes | n/a |
| native float histograms | no | yes | yes | n/a |
| custom-bucket histograms (`schema -53`) | no | rejected: not in the v1 schema | yes | n/a |
| histogram stale marker | no | stale sample | stale sample | n/a |
| start/created timestamp | `_created` | no | `start_timestamp` | n/a |
| unit | `# UNIT` | metadata unit | metadata unit | n/a |
| metric type | `# TYPE` | metadata | metadata | n/a |
| exemplars | `# {labels} v ts` | yes | yes | n/a |
| structured metadata | n/a | n/a | n/a | declared template fields only |
| stream labels | n/a | n/a | n/a | yes, kept apart from metadata |

The native model keeps an exemplar only as a trace/span link. `ExemplarsReject`
(the safe default) rejects any input with an exemplar; `ExemplarsTraceLink` keeps
`trace_id`/`span_id` (128-bit and 64-bit hex) and counts the discarded value,
timestamp and other labels in the report. An exemplar without a trace ID, an
exemplar that matches no sample or more than one, and exemplar-only series are
`unrepresentable`. HELP text has no native home: `HelpReject` or `HelpDiscard`
(counted). Types `gaugehistogram`, `info`, `stateset` are `unrepresentable`;
`summary` maps to `unknown` and is counted.

OpenMetrics integer sample values that float64 cannot hold exactly are rejected,
not rounded. Timestamps are exact: seconds with at most nine fractional digits
become integer nanoseconds, anything finer is `unrepresentable`. Quoted UTF-8
metric names are not supported.

Remote-write decoding rejects unknown protobuf fields, unpacked/packed mixtures
that exceed limits, empty label values, duplicate labels, a series that mixes
samples and histograms, and a histogram that fails the native model's shape
validation. Snappy is the published block format, implemented here; a declared
decoded length is checked against the profile limit and a 22x expansion bound
before any allocation.

Loki lines enter a registered template: the line fills `LineField`, structured
metadata keys must be listed in `MetadataFields`, stream labels stay stream
labels. Lines are capped at 4096 bytes (the native scalar cap). Whether a raw or
unregistered line is admissible is decided by the source policy when the batch
goes through `policy.Normalize`: a structured source rejects unregistered values,
only a restricted-raw source accepts raw lines through its raw template.

## Errors and report

Every failure is `*queryinput.Error` with a closed `Reason` (`malformed`,
`too_large`, `limit_exceeded`, `duplicate_label`, `invalid_name`,
`timestamp_out_of_range`, `out_of_order`, `conflicting_duplicate`,
`unrepresentable`, `scope_mismatch`, `malformed_compression`, `invalid_profile`,
`cancelled`). `errors.As` also yields the matching `*model.Fault`. Detail strings
are static tokens; input content never appears in an error or report.
`NormalizationReport` is bounded reason/count data delivered through
`InputProfile.Report`.

## Corpus

`conformance/query/cases/input-normalization.json` holds the rows;
`conformance/query/fixtures/adapters/` holds the semantic inputs, which the test
harness encodes into the real wire formats. Expected values are authored from
the format specifications; no upstream parser output was recorded, and every row
says so in `binding_scope`.

## HTTP bridge routes

`internal/httpapi/input_adapters.go` mounts three POST-only migration bridges
(`httpapi.RegisterInputAdapterRoutes`): `/adapters/v1/prometheus/write`,
`/adapters/v1/loki/push` and `/adapters/v1/conditions`. They are explicit input
bridges, not an upstream backend: no read route, storage layout or admin API of
Prometheus or Loki is promised.

- **Authority.** A bearer source credential only; a cookie, an `Origin` or an
  `X-Soundpost-Source` header is refused. Project, source, policy revision and
  producer (the credential ID) come from the authenticated source, never from the
  body or a header. The resource of every record is the only entry of the source
  policy's registry per dimension, or an explicit `X-Soundpost-Service`,
  `-Environment`, `-Build`, `-Instance` header; the source policy still decides
  at admission whether that resource may be emitted.
- **Wire selection.** Remote-write: `Content-Type: application/x-protobuf`
  with optional `;proto=io.prometheus.write.v2.Request` for v2, and
  `Content-Encoding: snappy`. Loki: `application/json` (plain or
  `Content-Encoding: gzip`) or `application/x-protobuf` with
  `Content-Encoding: snappy`; the log template is `X-Soundpost-Template` plus
  `X-Soundpost-Template-Revision` (or the policy's only template),
  `X-Soundpost-Line-Field` (default `line`) and `X-Soundpost-Metadata-Fields`.
  Conditions: `application/json`. Anything else is 415.
- **ACK after every child receipt.** The decoded request becomes one-slot child
  batches (see above); each is admitted under a freshly resolved grant. The sender
  gets 200 only when every child has a durable receipt. Otherwise the answer is
  the retryable status (429/503) of the first retryable child failure, or the
  first failure's final status, with a body naming every child:
  `{"adapter","admitted","failed","children":[{"batch_id","route_slot","records","status":"admitted|failed|not_attempted","receipt","fault"}]}`.
  A failing child does not stop the others; an authority or cancellation failure
  does (the remaining children are `not_attempted`).
- **Partial-retry identity.** Child batch IDs derive from the request body and the
  authenticated scope, so the same request retried after a lost response yields
  the same children and the ledger answers each already-durable child with its
  original receipt: nothing is duplicated, and an identical body from another
  project's source gets different identities and lands only in its own project.
- **Defaults.** Seven days of backfill and one hour of future skew, native
  histograms preserved, exemplars and HELP text rejected (`InputAdapterConfig`
  can choose `ExemplarsTraceLink` / `HelpDiscard`; the owner decision on those two
  modes is open, see 02.08-W6). The v2 reply carries
  `X-Prometheus-Remote-Write-{Samples,Histograms,Exemplars}-Written`.

## Condition webhook

`POST /adapters/v1/conditions` takes a closed, versioned body of C04 condition
events and nothing else (`queryinput.DecodeConditions`):

```json
{"version":1,"events":[{
  "condition":"checkout-latency", "epoch":"2026-11-15.1", "sequence":"42",
  "event_time_ns":"1700000000000000000",
  "status":"firing", "severity":"critical",
  "labels":{"job":"api"}, "links":[]}]}
```

Unknown fields, duplicate keys, trailing data, free text, URLs and annotations
are rejected; `condition` and `epoch` are the source's own names
(`[A-Za-z0-9_.:-]`, at most 128 bytes); `sequence` is optional, a canonical
decimal string at least 1 (without it the event is ordered by time and can never
overwrite a newer sequenced one); `status` is `firing`, `recovered` or `unknown`
(unknown is never a recovery) and `severity` one of `info`, `warning`, `error`,
`critical`, the values admission accepts; labels must be approved by the source
policy. Condition and epoch identities are derived from the names and bound to
the authenticated project and source, so equal names from two sources never
collide. One `(condition, epoch, sequence)` is one event: an identical repeat
collapses, different content is a conflict and the whole request is rejected
before admission.
