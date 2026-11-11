# Soundpost selected requirements

Date: 2026-11-03. This is the portable product intake, not a capability claim. Aryn Yklas approved the complete design/contracts and selected subagent-driven implementation with m1 implementers and m2 reviewers on 2026-11-03. Soundpost is the selected name. Registry reservations and legal naming clearance are not claimed.

## Provenance and precedence

This document extracts the product requirements from the owner's earlier discussion as recorded in the received handoff, with direct owner clarifications from this session taking precedence. The original customer inventory and infrastructure instructions are deliberately excluded. The [active research digest](../../research/2026-11-03-primary-source-research.md) separates relevant evidence from superseded comparisons; the [historical archive](../../research/archive/2026-11-03-primary-source-research.md) preserves all four public-source reports verbatim. Historical recommendations, names and open questions do not override the selected requirements here. Public upstream release references are compatibility targets, not a public inventory of a customer's deployments. No original implementation or test corpus has been imported.

The customer's gateway, application and job acceptance journeys are expressed below with generic identifiers. An authorized adoption exercise will bind them to the real customer systems in private records, not public product defaults. No infrastructure rollout is authorized by this document.

**Direct owner clarification:** Soundpost defines its own contracts throughout, not just its own Sentry alternative. There is no minimum Sentry-compatible backend, OTLP receiver, copied product schema or upstream HTTP/API/UI compatibility obligation. In response to an explicit clarification question the owner chose **Keep PromQL/LogQL languages**: full language compatibility remains, implemented by Soundpost's own engines and exposed through Soundpost's own interfaces.

## Binding requirements

| ID | Requirement |
|---|---|
| R01 | Independent self-hosted OSS product; Apache-2.0 first-party server, SDKs, SSO, isolation, replay and profiling. No paid-only feature gate for this scope. Ordinary infrastructure primitives and suitably licensed libraries are permitted. |
| R02 | Native unified alert/incident/ownership and application investigation experience. Keep/Sentry were functional reference points, not contracts to clone. Covers all environments, not only Kubernetes; not an integration dashboard or reskin. |
| R03 | Own telemetry ingestion, indexing, storage layouts, query execution and rule evaluation engines. No third-party telemetry engine or production fallback for difficult queries. |
| R04 | Full PromQL and LogQL language compatibility, not a dashboard-driven subset. Pin upstream versions and feature/configuration profiles; test the entire language, including gated extensions. Soundpost defines its own query interfaces and result envelopes; upstream HTTP/API compatibility is not required. |
| R05 | Fully custom Python and TypeScript browser/Node capture/instrumentation SDKs and custom wire protocol, not Sentry/OTel SDK wrappers. Standards references and ordinary runtime libraries are allowed; no Sentry/OTLP ingestion promise is implied. |
| R06 | Native metrics, systems logs, real critical-path distributed traces, grouped application errors, source-mapped browser stacks, releases, regressions, and correlated background jobs/runs/attempts. Trace IDs alone are not trace coverage. |
| R07 | Session replay is included. Explicit project opt-in; mask all text/inputs before buffering or serialization. No screenshots, canvas contents or network bodies by default. Masked structure is still sensitive. |
| R08 | Profiling includes a product-owned native Linux CPU/off-CPU sampling engine, not merely runtime-only or timer profiling. Exclude heap/local/object contents; state temporary reads versus persisted/transmitted data. |
| R09 | Truthful per-runtime/browser/OS/build coverage. Python, Node and an explicitly tested Bun path are required. Unsupported is not zero activity; timing spans and long tasks are not sampled CPU or full off-CPU stacks. |
| R10 | Multiple strongly isolated organizations, with team/project query authorization, and explicitly authorized audited instance-admin cross-organization investigation. Labels and dashboard visibility are not security boundaries. |
| R11 | Complete single-host and distributed modes. Single host is non-HA. Ingest ACK means durable admission; distributed mode survives any one ingest/storage node failure without loss of ACKed data. No guarantee for SDK data killed before ACK. |
| R12 | Separate linked alert condition, recurring error issue and human incident lifecycles. Incident resolution does not repair a source; job recovery does not erase failed attempts. Late/duplicate events cannot manufacture regressions or overwrite newer source state. |
| R13 | Best-effort admins, not staffed on-call. Urgent interruptions plus shared queue/digests; exception urgency derives from grouped impact/rate/regression, not every occurrence. |
| R14 | ACK pauses reminders only, not failure/evidence state. Materially worse impact may notify again. Snooze/maintenance are separate, reasoned, expiring, audited actions. |
| R15 | Default collection is structured metadata and approved message templates. Raw/unknown sources require explicit restricted-source policy. Regex scrubbing is not proof that arbitrary text is safe. |
| R16 | Default exclusions: bodies, AI prompts/responses, credentials, full SQL/parameters, locals, heap and object contents. Explicit policies also cover messages, paths, URLs, source artifacts and breadcrumbs. Privacy covers SDK buffers, transport, storage, queries, notification payloads and diagnostics. |
| R17 | Build existing-source adapters and verify cutover before retiring old normal notifications. One canonical new lifecycle/normal notification policy. Independent external deadman remains outside this product's failure domain. |
| R18 | Legacy history remains read-only until retention/export obligations finish. No mandatory full historical importer, no silent deletion, and visible cutover/history boundaries. |
| R19 | Acceptance journey: gateway request to actual model/dependency, distinguishing observable dependency spans from inaccessible dependency internals; includes the supported Bun runtime path. |
| R20 | Acceptance journey: maintained frontend to API to database, with exact release/source-map identity, correlated trace/error context and privacy. |
| R21 | Acceptance journey: scheduled/background run to failed attempt to retry/recovery, with persistent failure history and correct current health. |
| R22 | Acceptance includes adversarial cross-organization denial plus pipeline outage/recovery and acknowledged-ingestion node-failure drills. |
| R23 | One shared architecture/specification and separate independently testable plans for engines, SDK/capture, investigation UI, incident workflow, deployment/conformance and customer adoption. Preserve all scope; a first vertical slice is not the complete product. |
| R24 | Obtain full design approval before product implementation. Approved on 2026-11-03; execution uses m1 implementation subagents and m2 reviewers. Product ownership does not authorize customer production changes. |

## Decisions not inherited

Core language, frontend framework, database, transport encoding, WAL/replication design, grouping algorithm, timing policies, resource budgets and deployment topology were not approved in the source discussion. The design must choose and justify them as proposals, not retroactively attribute them to the owner. Replay, native sampling, full query compatibility and own engines are settled scope and are not alternatives to reopen.

## Research status

Research establishes source-backed feasibility and limitations, not exercised runtime compatibility, performance, legal clearance, security assurance or conformance. In particular: Bun's pinned inspector subset is not full Node inspector compatibility; browsers do not provide a universal ordinary-page sampler; Linux raw DWARF stack dumps can expose application contents; Loki AGPL code/tests cannot silently become Apache code through translation. Preserve source/license provenance and prove the actual implementation later.
