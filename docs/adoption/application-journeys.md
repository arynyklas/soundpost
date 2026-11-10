<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Application journey verification

`tools/adoption/{journeys,artifacts,assertions}.go` verify that real application traffic is visible in Soundpost the way the adoption plan requires, from the product's own scoped reads. They are generic: caller-supplied names and IDs only, no hostname, service or customer name is built in. **Nothing in this repository has run against a customer system.** Product approval is not customer authorization; every real-customer step below is an operator task that needs its own owning-environment grant.

## What is verified

Five required sections; a section that is not configured **fails** (`expectation_missing`), it is never skipped.

| Section | Contract shape | Passes only when the product reports |
| --- | --- | --- |
| `gateway_dependency` | gateway → real model/dependency | one parentless request-root span and, for every named dependency, a span of the named alias/kind/operation that is a descendant of that root **by parent span ID**, ended, unique and not clock-contradicting. A trace ID alone is never a pass. |
| `frontend_api_db` | frontend → API → DB with a mapped release and error | the ordered chain (root, then each hop a **direct** child of the previous) in the trace; the release binding the expected build to exactly one debug artifact whose ID, debug ID and SHA-256 are the expected ones; the symbolicated frame resolved exactly (source, line, column) with the expected map hash; a stored issue occurrence mapped to that build and release with known ancestry. |
| `scheduler_retry` | background failure → retry/recovery | both explicit attempt IDs in one run's history: the failed attempt still failed (original terminal fact and effective state), a **different** succeeded attempt with a higher ordinal that started after the failure ended, the run `recovered` with the recovery as its final attempt, no duplicate attempt IDs, optional link from the failed attempt to its cause trace. An erased, overwritten or corrected-away failed attempt fails. |
| `replay_privacy` | replay of the real browser session | an unbroken ordered stream (`open` … checkpoint … `end`) for the named replay, every node text masked (`""`/`[masked]`), and none of the caller's sentinel values (typed into protected fields during the real session) anywhere in any released line. At least one sentinel of 6+ bytes is required; a privacy check without a canary is refused. |
| `runtime_capability` | native/runtime capability evidence | typed rows. Each is `exercised` (a `supported` capability record **and** samples of that method in the profile), `unavailable` or `denied`; the observed status must equal the status the caller expects. The runtime name is caller-supplied (a Bun gateway is verified as Bun; nothing assumes Node). |

### Inaccessible third-party internals

A dependency's `third_party_internals` declares, with a mandatory reason, that spans below it are not observable. The verifier reports a row with status `unavailable` and `basis: declared`; it is **never** counted as passed evidence and never turned into spans. If spans really do exist below the dependency they are real evidence and the row is `exercised` / `observed`. The same discipline applies to a missing local build map and to capability rows with no profile: `declared` rows can only be `unavailable`/`denied` with a reason.

### Local build map cross-check

`frontend.map_file` (CLI) / `MapBytes` (library) is the operator's own build output. When present the verifier hashes it, requires the hash to equal `debug_sha256`, decodes it with the product's source-map decoder and requires it to place the generated frame exactly at the expected original position, so the expectation is not hand-typed trivia. When absent nothing is claimed and an `unavailable` row records that.

## Trust boundaries

- **Reads only.** The verifier performs scoped POST reads of the committed investigation routes (`/api/v1/traces/view`, `/evidence/{release,frames,issue}`, `/jobs/view`, `/replays/stream`, `/profiles/view`). It never writes to the product, never contacts the application and never reaches the customer by any other path.
- **Credential.** One bearer, read from an environment variable named by `--bearer-env` (default `SOUNDPOST_JOURNEY_BEARER`), never accepted in a file or flag, never printed, never in any report. It is sent only to the exact `--server` origin, over https or over http to a loopback host. Redirects are not followed (a redirect is a failed read), proxies are not used, responses are size-bounded, and a failed response contributes only a status class (`target_not_found`, `credential_denied`, `read_failed`), never its body.
- **Scope.** Every read is made under the `--org`/`--project` you name and every response must echo exactly that org, project and requested ID (`scope_mismatch` otherwise). Another tenant's IDs are the product's one indistinguishable not-found. The token needs: `telemetry.read` (traces, jobs), organization admin (release registry and issue evidence), `artifacts.read` (symbolication), `replay.read` and `profiles.read`. A view the credential cannot see is `view_not_ready`, never an empty pass.
- **Authorization.** `adoption journeys` requires `--authorization`: a private read-only grant (same `Authorization` shape as intake) with a validity interval, an `Authority`, and **exactly one** scope whose `EvidenceURL` equals `--server` and whose only collector is `product-journey-read`. Anything else is refused before any read or output. A grant is an operator assertion, not cryptographic identity; authenticate its issuer outside this tool.
- **Private vs public.** `journeys.json` (the detailed `JourneyReport`: IDs, reasons, per-check detail) goes to the exclusive-create `--private-output` directory under the same containment rules as intake (outside every repository, owner-only; on Windows the operator confirms the NTFS ACL with `--private-directory-acl-confirmed`). Only `JourneyPublicSummary` may leave it: section pass/fail enums, check counts, row-status counts, counts per closed failure code, and `CustomerAcceptance`, which is always `false`. It has no identifier or free-text field; the projection re-selects kinds and codes from fixed enums and drops anything else.
- **Failures are reports.** A failed acceptance writes both outputs and exits non-zero. A cancelled or timed-out run is an error with no report.

## Running

```
SOUNDPOST_JOURNEY_BEARER=<token> adoption journeys \
  --server https://<soundpost-host> --org <org-id> --project <project-id> \
  --expected <private-expected-links.json> --authorization <private-grant.json> \
  --private-output <external-private-directory> --public-summary <new-summary-file> \
  [--private-directory-acl-confirmed] [--timeout 2m]
```

(The parent dispatches `journeys` to `runJourneys` with the flags that follow it.) `--timeout` is positive and at most one hour.

### Expected links (synthetic placeholders)

```json
{
  "gateway": {
    "trace": "<32-hex>", "window": {"start_ns": 1700000000000000000, "end_ns": 1700000060000000000},
    "root": {"operation": "<request operation>", "span_kind": "server"},
    "dependencies": [{"name": "<label>", "span": {"operation": "<call op>", "span_kind": "client", "dependency_alias": "<alias>"},
                      "third_party_internals": {"reason": "<why not observable>"}}]
  },
  "frontend": {
    "trace": "<32-hex>", "window": {"start_ns": 0, "end_ns": 0},
    "chain": [{"operation": "<ui op>"}, {"operation": "<api op>"}, {"operation": "<db op>", "dependency_alias": "<alias>"}],
    "release": "<id>", "build": "<id>", "issue": "<id>", "artifact": "<id>",
    "debug_id": "<debug id>", "debug_sha256": "<64 lowercase hex of the uploaded map>",
    "frame": {"module_id": "<generated module>", "function": "<fn>", "line": 5, "column": 10},
    "original": {"source": "<project-relative source>", "line": 42, "column": 7},
    "map_file": "<local build output .map>"
  },
  "scheduler": {"job": "<id>", "run": "<id>", "failed_attempt": "<id>", "recovery_attempt": "<id>", "failure_trace": "<optional id>"},
  "replay": {"replay": "<id>", "sentinels": ["<canary typed into protected fields>"]},
  "capabilities": {"rows": [
    {"name": "<label>", "profile": "<id>", "window": {"start_ns": 0, "end_ns": 0}, "runtime": "<runtime name>", "method": "runtime_cpu"},
    {"name": "<label>", "runtime": "<runtime name>", "method": "native_cpu", "expect": "unavailable", "reason": "<why>"}
  ]}
}
```

All windows are positive half-open nanosecond ranges. The file is private operator input and may contain real IDs; never commit it.

## Limits of this verification (stated, not hidden)

- The frontend error → trace linkage is not read: the committed issue evidence view exposes build, release and ancestry but no trace/span ID, so the verifier proves the error is mapped to the build/release and the frame to the exact source, and the trace chain separately, not that the same request produced all three.
- The artifact **debug ID** is verified through the release record (`debug_artifacts`), because no committed read returns the artifact manifest; the symbolicator's own `identity_mismatch` refusal is the in-product binding of debug ID to frame.
- Attempt ordering assumes a retry starts after the failed attempt's terminal time; a genuinely overlapping retry would need a different contract.
- A profile read is one window per row (rows sharing profile and window share one read).
- `incomplete` product states are accepted only where the committed route reports them for a fully usable section (an issue with occurrence detail not built, a release with unresolved ancestry, a job whose health evidence is incomplete but whose attempts are ready, a profile that is partial but holds the record and samples). Partial trace spans never pass.

## What is synthetic-only

`tools/adoption/journeys_test.go` exercises the verdict logic with: spans analyzed by the real `traces.CriticalPath`, positions looked up by the real source-map decoder, attempts reduced by the real `jobs.Reduce`, and the real `internal/httpapi` wire types, served in-process and over loopback HTTP whose handlers decode each request with `DisallowUnknownFields` as the real routes do. The httpapi handlers, authorization, storage and symbolicator worker are **not** exercised by these tests, and no customer system, hostname, path, credential or inventory is touched, discovered or assumed. A green suite proves the verifier decides correctly on well-formed evidence; it is not customer acceptance and the summary never claims it.

## Not done here (authorization-blocked, belongs to the owning environment)

- SDK integration patches in the authorized application repositories (their own conventions, approvals and PR workflows).
- Controlled real requests through all three actual paths and inspection of actual server data and a real browser investigation against the real builds.
- The gateway's concurrent Bun request/start-stop profiler acceptance against its real Bun build.
- Any customer-side production change, cutover or disruptive drill.
