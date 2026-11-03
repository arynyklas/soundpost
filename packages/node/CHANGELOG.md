# Changelog

## 0.1.0 — 2026-11-03

- Expose policy-first capture and explicit non-consuming uncaughtExceptionMonitor leases; preserve prior handlers and default fatal/rejection behavior.
- Add native error cause/group graphs and explicit episode association; report original JS frame capability limits without unsafe stack reads.
- Match rethrow episodes by weak error identity and monitor mechanism, preserving pending arms across unrelated failures.
- Correct the ESM-entrypoint fatal fixture's arm to its native unhandledRejection origin; separately test ordinary callback-origin rethrow with strict identity matching.
