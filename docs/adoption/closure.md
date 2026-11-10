<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Adoption closure and the independent deadman

`CloseAdoption` (`tools/adoption/closure.go`) decides whether an adoption can be **closed** from operator-supplied evidence. Closure needs three things, all fresh at the caller's clock:

1. a verified ready gate covering every required criterion;
2. legacy-history obligations that do not block (see [legacy-history.md](legacy-history.md));
3. an independent deadman proof from a real outage in which all Soundpost processes were stopped.

Evidence defects are blockers in the returned report (`closed=false`, nil error). Only an unusable call is an error: no clock, an invalid scope, an age bound outside 1 second to 30 days, a cancelled context.

Closure never deletes, exports or imports history and never certifies a customer. After closure, retention continues until the history owner completes the obligations through a separately authorized, audited action performed outside this tool.

## Trust boundaries and what is synthetic

- **Everything in this repository's tests is synthetic**: generated ed25519 keys, labels, digests and times, in-process evaluation and temporary directories. No customer system, hostname, path, credential or inventory is read, contacted, discovered or assumed. The public summary's `customer_acceptance` is always `false`.
- **The tool does not run or observe the outage.** It judges a signed record of one. Stopping all Soundpost processes in an authorized isolated environment, observing a real deadman alert arrive through the independent operator route, reading legacy history during the outage and confirming all three journeys recovered are operator steps that need the owning environment's separate authorization. They are not done here.
- **The clock and trust root are the caller's.** `ClosureLedger.Now` and `ClosureLedger.Trust` are not part of the JSON file; a file that supplies `now` or a trust root is refused as unknown fields. The CLI uses the process UTC clock and reads the trusted public keys from a *separate* file (`--trusted-keys`). The trust root must be held by the operator and must not come from the product's own storage.
- **The signer is not the product.** The proof is signed with ed25519 by the deadman's own attestor, which runs in the deadman's failure domain and holds a key the product never has. A proof signed by the product's key, or by any key not in the trust root, is refused.
- **The ready gate is plain evidence.** `ClosureGate` carries the gate digest, when it was verified and the criteria it covers. Closure trusts the operator's mapping and does not re-verify the gate; its value is only as strong as that mapping (below).
- Verification order is fixed: signature first, content second. A proof that fails verification contributes no facts, not even a decoded field.
- Private input and the `ClosureReport` stay in the operator-controlled private directory. Only the closed public summary may be published.

## Mapping a verified ready gate into the ledger

The readiness tool's verified gate output is mapped by the operator into `gate`:

| `gate` field | Source |
| --- | --- |
| `digest` | The gate record's SHA-256 digest (64 lowercase hex). |
| `verified_at` | The time the gate was verified (not the time of mapping). |
| `criteria` | The criteria the verified gate covered, written with these names. Names outside the list are refused (`gate_criterion_unknown`) rather than ignored; each required name must appear. |

Required criteria: `journey_gateway_dependency`, `journey_frontend_api_db`, `journey_scheduler_retry`, `source_policy`, `query_profile`, `tenant_isolation_matrix`, `delivery_policy`, `deletion_restore`, `external_deadman_failure_domain`, `retention_export_record`. An incomplete gate, an unverified gate, a stale one or a future-dated one blocks. The closure tool has no dependency on the readiness tool's types; the mapping is a human or script step, and the mapping script must be reviewed as part of the evidence.

## Deadman proof

The attestor signs one `ClosureDeadmanProof` (`ClosureSignProof` builds the envelope: `key_id`, exact `payload` bytes, ed25519 `signature` over `"soundpost/adoption/deadman-proof/v1\0" || payload`).

| Section | What closure requires |
| --- | --- |
| `purpose`, `scope` | Purpose constant and `scope` equal to the ledger's `scope` (1-64 characters of `a-z 0-9 . _ / -`). A proof for another scope is `deadman_proof_wrong_scope`. |
| `issued_at`, `expires_at` | Issued not after the clock, not expired at the clock, issued within the evidence age bound, lifetime at most 30 days. |
| `product_domain`, `deadman_domain` | Four recorded labels each: process, host, cluster, credential. **Every** dimension must differ (case-insensitive after trimming). A deadman that shares the product's process, host, cluster or credential is `deadman_shares_*_domain`; unrecorded labels are `deadman_domain_unrecorded`. |
| `outage` | `started_at`/`ended_at` at least one minute apart, ended before the proof was issued; `processes_observed` > 0 and `processes_stopped` equal to it, with a `stop_evidence_digest`. |
| `delivery` | `route` = `independent_operator` (an operator-owned route through no Soundpost process, host, cluster or credential; `product_channel` and anything else is `deadman_route_not_independent`), a receipt digest and an observation time **inside** the outage window. |
| `history_read` | Legacy history observed readable **and still read-only** inside the outage window, with a receipt digest. |
| `recoveries[]` | Exactly one entry for each of `gateway_dependency`, `frontend_api_db`, `scheduler_retry`, each recovered after the outage ended and not after the proof was issued, each with an evidence digest. |

## Blocker vocabulary

Gate: `gate_missing`, `gate_future_dated`, `gate_stale`, `gate_criterion_missing`, `gate_criterion_unknown`.
Deadman: `deadman_proof_missing`, `deadman_proof_unsigned`, `deadman_proof_untrusted_key`, `deadman_proof_bad_signature`, `deadman_proof_malformed`, `deadman_proof_expired`, `deadman_proof_future_dated`, `deadman_proof_stale`, `deadman_proof_wrong_scope`, `deadman_domain_unrecorded`, `deadman_shares_process_domain`, `deadman_shares_host_domain`, `deadman_shares_cluster_domain`, `deadman_shares_credential_domain`, `outage_window_invalid`, `outage_not_all_processes_stopped`, `deadman_delivery_missing`, `deadman_route_not_independent`, `deadman_delivery_outside_outage`, `outage_history_read_missing`, `outage_history_read_outside_window`, `journeys_not_recovered`.
History blockers are listed in [legacy-history.md](legacy-history.md) and appear under the `history` area.

## Output

`ClosureReport` (private) includes the blockers, missing criteria, which proof facts were established, the nested `HistoryReport` and, only when closed, an evidence digest (SHA-256 over scope, gate digest, proof payload digest and history report digest).

`ClosurePublicSummary` (public, closed shape) carries only: schema version, `closed`, evaluation / gate-verified / outage **dates at UTC day granularity** (`YYYY-MM-DD`), criteria required and covered counts, journeys recovered, booleans (deadman independent, delivery during outage, history readable during outage, history clear), obligation counts, the gate, proof, history and evidence digests (validated 64-character hex, otherwise empty; the evidence digest only when closed), blockers as pairs from closed enums, and `customer_acceptance: false`. No label, scope, key ID, path, identifier or time of day is copied from private evidence; a test with canary strings and a reflection check on the shape enforce this.

## Command

```
go run ./tools/adoption closure --mode close --ledger <private-closure-ledger.json> --trusted-keys <trust.json> \
  --private-output <external-private-directory> --public-summary <new-summary-file> \
  [--private-directory-acl-confirmed] [--timeout 2m]
go run ./tools/adoption closure --mode history --ledger <private-history.json> \
  --private-output <external-private-directory> --public-summary <new-summary-file>
```

`--trusted-keys` is required for `close` and refused for `history`. The ledger JSON is `ClosureLedger` (`scope`, `max_evidence_age_seconds`, `gate`, `history`, `deadman_proof`); the trust file is `{"keys":{"<key_id>":"<base64 ed25519 public key>"}}`. Outputs (`closure.json` or `history.json`, and the summary) are created exclusively; a blocked decision is written and then returns a non-zero error. The private directory must already exist outside every checkout with owner-only permissions.

## Not done by this tool

Stopping all Soundpost processes in an authorized isolated outage and observing real external deadman delivery; publishing real sanitized closure evidence; the deletion or export action itself; any customer-side change. Lack of that authorization is reported as outstanding, never relabelled as success.
