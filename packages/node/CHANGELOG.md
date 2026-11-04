# Changelog

## 0.1.0 — 2026-11-03

- Expose policy-first capture and explicit non-consuming uncaughtExceptionMonitor leases; preserve prior handlers and default fatal/rejection behavior.
- Add native error cause/group graphs and explicit episode association; report original JS frame capability limits without unsafe stack reads.
- Match rethrow episodes by weak error identity and monitor mechanism, preserving pending arms across unrelated failures.
- Correct the ESM-entrypoint fatal fixture's arm to its native unhandledRejection origin; separately test ordinary callback-origin rethrow with strict identity matching.
- Add native HTTPS flush/close, context-isolated exporter suppression and opt-in encrypted backend spool ownership without changing fatal handlers.
- Add owned native HTTP/Express5/fetch/pg8 and closed worker-context adapters with per-client Node AsyncLocalStorage, streaming response lifetimes and unchanged fatal semantics.
- Add real compiled Node22/24 critical-path/worker/HTTPS/PostgreSQL fixtures and behavior tests; qualification is not inferred from a Bun test runner.
- Add manual job attempts with separate Node async-local run context, original callback outcomes and real C03/C05 process fixtures; Node22/24 qualification remains independently parent-run.
- Correct HTTP client spans to follow IncomingMessage body completion and preserve native no-consumer draining; keep transport errors application-owned without requiring runtime-specific request close events.
- Use native fetch Headers input inference without DOM ambient types; add separate actual Node22/24 and Bun HTTP lifecycle regression fixtures.
