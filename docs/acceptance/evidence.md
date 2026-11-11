<!-- Copyright 2026 Aryn Yklas -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Protected application investigation: evidence acceptance (task 09.06)

This is the cross-module acceptance of the artifact, symbolication, replay and
profile evidence paths with the scope, deletion and restore lifecycle. It has two
halves that deliberately differ in reach, and every row that cannot be satisfied is
reported as `NOT SATISFIED` with its reason. Nothing is mocked into a success.

| Half | Where | What it drives |
| --- | --- | --- |
| In-process acceptance | `tests/acceptance/evidence_test.go`, `TestEvidenceRealFrameReplayAndScopeLifecycle` | A real in-process node (`appcore.Open`: control Raft group, auth, C03 admission, C05 storage, artifact service, retention saga) behind real HTTPS (`httpapi.NewServer(..., app.Register)`), every read and write through the committed scope-first routes with a real session cookie and CSRF binding. |
| Subprocess smoke | `go run ./tools/smoke evidence` (`tools/smoke/evidence.go`, `RunEvidence`) | A real `soundpost serve` subprocess over HTTPS: real bootstrap and login, the same routes. It can only reach what the served process exposes, so it exits non-zero today. |

## Running

```sh
# Real Vite-generated throwing map and its thrown position (Node 22 + repository Vite).
node fixtures/artifacts/generate.mjs "$FIXTURE_DIR"

# In-process acceptance. The symbolication sandbox is the documented OCI mode and is
# derived from the local image tag below (override with SOUNDPOST_SYMBOLICATE_IMAGE);
# without a usable image the typed sandbox_unavailable answer is asserted instead.
SOUNDPOST_SOURCEMAP_FIXTURE_DIR="$FIXTURE_DIR" go test ./tests/acceptance -run TestEvidence -count=1 -v

# Smoke against a real served process (builds ./cmd/soundpost unless --binary is given).
go run ./tools/smoke evidence --artifact-dir "$OUT" --fixture-dir "$FIXTURE_DIR"
```

A missing fixture directory is a failure, not a skip. The sandbox image is the one
built by `docs/operations/symbolication.md` (`soundpost-symbolicate:qualification`);
the test reads its immutable ID and worker-hash label with `docker image inspect`
and the service independently re-verifies them (label and executable-hash
handshake). If the host is loaded, the sandbox's own 100 ms frame / 5 s call bounds
can answer the typed `deadline`; the test retries the request (the bounds are never
widened) and reports how many attempts it needed.

`tools/smoke/main.go` must register the smoke (parent-owned):

```go
case "evidence":
	smoke, stage = "evidence", "evidence_dispatch"
	return RunEvidence(os.Args[2:])
```

## Rows

Required rows must all be satisfied for the smoke to exit zero. The in-process test
fails (not merely reports) on any contradiction; its `NOT SATISFIED` rows are the
documented gaps and are asserted to be the typed unavailable answer, never a
canned success.

| Row | In-process test | Served-process smoke |
| --- | --- | --- |
| `artifact_upload_read_policy`: real multipart upload of the Vite map, `sourcesContent` canary stripped, private-source read refused, telemetry-only reader refused | satisfied | satisfied |
| `error_occurrence_ingest`: real occurrence with exact build and artifact frame over HTTPS, message-bearing payload refused without echo | satisfied | satisfied |
| `frame_real_mapping`: thrown generated position resolves to the known original `simple.ts:4:8` | satisfied with the OCI sandbox (typed `sandbox_unavailable` otherwise) | NOT SATISFIED: `soundpost serve` has no symbolicator configuration (`symbolicator_not_wired`) |
| `frame_scope_and_build_exactness` | satisfied | (covered by the frames request above) |
| `release_registry_view` | satisfied | not exercised (no registration route) |
| `issue_evidence_of_ingested_error` | NOT SATISFIED: nothing groups an admitted occurrence into a `GroupingIssue` | not exercised |
| `trace_view_and_link` | satisfied | not exercised |
| `investigate_replay_profile_links` | NOT SATISFIED: `/api/v1/investigate` answers `grant_not_built` for replay and profile | not exercised |
| `replay_closed_format_stream_and_gap` | satisfied (explicit `missing_chunk` gap, masked text only) | closed-format ingest satisfied; stream NOT SATISFIED |
| `replay_real_recorder_chunks` | NOT SATISFIED: the recorder's own chunks are refused by the Go validator (known cross-language gap) | NOT SATISFIED (same) |
| `replay_admission_indexes_chunks` | NOT SATISFIED: ingest never calls `replays.Validate`/`Record` (the test runs the index step itself) | NOT SATISFIED: the replay is unreadable after real-route admission |
| `profile_assembler_export_view` | satisfied (real assembler and exporter, real HTTPS route) | NOT SATISFIED: a served process cannot be given a profile |
| `profile_real_capture_or_sdk` | NOT SATISFIED: constructed sanitized events, no perf capture, no SDK profile reaches the backend | NOT SATISFIED (same) |
| `isolation_same_ids_other_org` | satisfied (15 route variants, byte-identical to random IDs) | satisfied (7 variants) |
| `lifecycle_grant_revoke_halts_stream` | satisfied (mid-stream: typed `revoke`/`authority_revoked`, nothing after) | revoke denies later reads; mid-stream NOT SATISFIED (no readable replay) |
| `lifecycle_deletion_halts_stream` | satisfied (C12 entity deletion of a replay and an artifact root mid-stream: typed `revoke`/`deleted`) | satisfied for `retire_project` through `POST /api/v1/admin/deletions` (202 fencing) while a reader has a replay open: the stream ends with one typed `revoke`/`authority_revoked`, nothing after, and a re-read answers 404; the entity mode is not driven over HTTP by the smoke |
| `restore_keeps_current_deletion_authority`, `restore_old_credentials_inactive`, `restore_deleted_not_revived` | satisfied (restore from the pre-deletion backup; activation applies the authority's current head; old sessions, source credential and accounts inactive; deleted replay and artifact not revived by restore, a retried chunk, a receipt lookup or a re-upload) | NOT SATISFIED: needs a post-backup deletion |
| `canary_responses_logs`, `canary_storage_scan` | satisfied (the storage scan requires a positive control, else it reports inconclusive) | responses and process log |

Canaries: a distinct sentinel in the source map `sourcesContent`, in replay node
text and in an error `message` field is asserted absent from every HTTP response,
the process log and (in-process) every file of the live and restored data roots.

## Wiring the parent must add (not edited here)

There is no `internal/app`; the wiring package is `internal/appcore` and
`internal/appcore/app.go` is parent-owned. The test sets `app.Evidence` itself before
`app.Register`; for a served process `openWith` needs, after `out` is built:

```go
// Operator-selected sandbox (never implicit). Config is the private JSON of
// docs/operations/symbolication.md, read from a new serve flag
// --symbolicate-config; absent flag keeps the typed symbolicator_not_wired state.
if cfg != nil {
	sym, e := out.NewSymbolicator(*cfg)
	if e != nil {
		out.CloseReplication()
		return fail(e)
	}
	out.Evidence = httpapi.NewEvidence(sym, r, r)
}
```

and, for the replay path, the ingest route must call
`replays.Service.ValidateJSON(grant, raw)` before the durable append and
`Record(grant, project, chunk, retainUntil)` after it (the receipt's replay
`SignalDeadlines` entry supplies `retainUntil`), and register the replay service as a
retention `References` source (`docs/protocol/replay-v1.md`).
