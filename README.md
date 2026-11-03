# Soundpost

Self-hosted observability and incident investigation, designed as an independent Apache-2.0 product.

**Status: design for approval. No server, SDK, sampler or runnable product is implemented in this repository yet.** Repository initialization and design preparation are authorized; product implementation is gated on owner approval of the complete design and selection of an execution method. Proposed budgets and support matrices are targets, not benchmark or compatibility claims.

## Product scope

Owned telemetry ingestion, indexing, storage, query and evaluation engines; full version-pinned PromQL/LogQL **language** semantics; native metrics/logs/traces, grouped errors, source maps, releases and jobs; custom Python and TypeScript browser/Node/Bun SDKs and protocol; privacy-first opt-in replay; runtime profiling and a native Linux CPU/off-CPU sampler; project-authorized multi-organization investigation; durable single-host and distributed operation; separate linked alert/error/incident lifecycles with urgent delivery plus queue/digest.

Soundpost defines its own contracts, models, APIs and experience. Compatibility with Sentry envelopes, OTLP or other products' backend HTTP interfaces is not required. Specific source adapters support verified migration without defining the native architecture.

## Design documents

- [Selected requirements and direct owner clarifications](docs/superpowers/specs/2026-11-03-soundpost-requirements.md)
- [Complete proposed architecture](docs/superpowers/specs/2026-11-03-soundpost-design.md)
- [Shared module and protocol contracts](docs/superpowers/specs/2026-11-03-soundpost-contracts.md)
- [Subsystem plan index and requirement coverage](docs/superpowers/plans/2026-11-03-soundpost-plan-index.md)
- [Active research digest](docs/research/2026-11-03-primary-source-research.md), with superseded comparisons preserved separately for provenance
- [Design review and verification record](docs/superpowers/specs/2026-11-03-soundpost-review.md)

Customer systems are adoption targets, not hardcoded product defaults. Private deployment inventory and credentials do not belong in public documentation or fixtures. No customer production changes are authorized by this design.

Copyright 2026 Aryn Yklas. Licensed under [Apache-2.0](LICENSE). Package handles, domain availability and trademark clearance are not claimed.
