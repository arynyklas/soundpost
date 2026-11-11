<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Error grouping and releases

Soundpost's release graph and error-group identity are owned Apache-2.0 implementations by Aryn Yklas. Human labels and build timestamps never establish ancestry.

## Grouping identity

`issues.Fingerprint(version, org, project, occurrence)` is a pure SHA-256 operation over a domain-separated, length-delimited encoding. The organization, project, nonzero grouping version, exception class, safe in-app frame identities and approved error code all participate. Scope is also retained independently in storage keys.

Supply C02-authorized organization/project IDs and a C04-admitted occurrence. The pure function does **not** authenticate a caller or approve arbitrary strings merely because they are syntactically safe. Source admission owns approval of class/code/template/frame metadata. This function does not load artifacts, query another project's symbol metadata, fetch runtime URLs, inspect exception graphs, or read messages, values or locals.

For framed errors, the caller supplies frames **innermost/newest first**. At most eight in-app frames are used, preserving order. Each code identity consists of module ID, project-relative artifact identity and function symbol. Line/column, build/release labels, occurrence ID, handled/fatal flags, non-in-app frames and other volatile occurrence metadata do not affect grouping. An unsafe selected in-app identity fails rather than silently falling back to a raw path or message. This algorithm requires stable symbol identities; it does not infer identity from a line number when a symbol is unavailable.

Without an in-app frame, the fallback is mechanism/class/approved template identity, still scoped/versioned and including the approved error code. An unknown mechanism is treated as an inert safe identifier; no thrown object is inspected. Absent and present template/code values are encoded distinctly. Input version zero and zero scope IDs are invalid. Changing a nonzero grouping version changes the hash namespace.

## Immutable release identity

`App.Releases` is composed over the application's existing control store and auth service. `Register(ctx, scope, release, expectedControlRevision, commandID)` commits through the actual C05 `RegisterRelease` handler. A new release has entity revision zero; subsequent display-label edits supply the current entity revision as well as the current control revision. The returned entity revision advances on each admitted registration/update. Original command receipts remain available after later renames and restarts.

The service constructor requires an injected action clock. App composition supplies the wall clock outside deterministic apply. Register/rename and migration command envelopes carry that admission timestamp and the request-context correlation ID (or command ID when no request context exists). Their audit action times are independent of immutable build time and migration evidence event time. Command retries retain the original committed audit instead of stamping another action.

Release ID, organization/project, build ID, parents, build time and debug-artifact identity/hash are immutable. Only the display label can change. Parent and artifact collections are canonicalized as sets; their serialization order does not express ancestry. Duplicate parents/artifact IDs, self-parenting, cycles, stale revisions and immutable-field changes reject without committing. An unresolved parent is allowed, but registering that parent later cannot complete a cycle. Artifact bytes and symbol resolution are separate authorized services; registering a debug-artifact identity does not grant access to its content.

Debug artifacts form an identity set keyed by the complete `ArtifactID`: an ID occurs once even if a caller supplies different debug IDs/hashes for it. Distinct artifact IDs have distinct canonical sort keys; their debug metadata cannot make ordering ambiguous. Persisted SHA-256/fingerprint DTO fields use the canonical hex-string `model.Hash` representation; the pure Fingerprint API continues to return `[32]byte`.

`Graph` and `Relation(graph, a, b)` report `same`, `ancestor`, `descendant`, `concurrent` or `unknown`. Known siblings/disconnected complete roots are concurrent. Missing nodes/ancestors, wrong-scope identities and corrupt cycles are unknown. Labels such as `v9`/`v10` and timestamps cannot turn unknown into an ordering.

## Explicit grouping migrations

A grouping-version change uses `MigrateGrouping(ctx, scope, migration, expectedControlRevision, commandID)`. It additionally checks the source issue's entity revision. The migration supplies explicit old/new issue IDs, new nonzero version/fingerprint, reason and event time. The new target must not already exist: an existing issue is never silently merged.

One control transaction appends links to the old and new issues, creates the migration record and commits an actor/command/reason/target audit. The old issue retains its original grouping identity, workflow, occurrences, late history and resolution/release frontiers; only its migration link and entity revision advance. The target starts as a separate open issue with no copied occurrences. Command retries do not duplicate that history or audit. `GroupingIssue(ctx, scope, project, issueID)` keeps the original issue/history addressable after migration and restart.

The current administrative surface requires a **real, revalidated organization-admin scope**. Matching an organization label is not authorization; `issues.write`, source credentials, forged scopes and scopes from another authority do not grant this administration capability. Every project must exist in that authorized organization, and a project-restricted scope cannot escape its projects. Safe grouping-version changes therefore cannot be triggered by telemetry senders. This task does not introduce user-defined raw-message/regex fingerprint rules, automatic merges, or a second notification/lifecycle owner.

The C07 recurring-error evidence reducer is separate from migration administration. It extends the existing closed `ApplyIssueEvidence` dispatcher (the lifecycle arms live in `internal/control/issue_evidence.go`, bound by `Store.BindReleases`); it must not register a competing handler or rewrite migration/history state. The reducer service itself is not yet constructed by `internal/appcore` (see `issues.md`). Release/grouping commands do not change source admission, quota or retention state.
