# Changelog

## 0.1.0 — 2026-11-03

- Expose policy-first error graphs and explicit non-destructive global error/rejection listener leases.
- Use only available intrinsic native error brands and native event descriptors; retain explicit original-frame/aggregate-boundary limitations.
- Bind pending episodes to weak error identity and event source; actual browser fixture now covers unrelated rejection interleaving before error rethrow.
- Add cookie-free source-header HTTPS delivery with exact durable/historical receipt validation and bounded flush; prohibit disk spools and unread page-exit ACKs.
- Add explicit synchronous-only browser context, native spans, navigation commit timing, allowlisted fetch and closed worker propagation without guessed async parents.
- Add actual browser→Express→HTTP→PostgreSQL fixtures and exact driver/build checks; real Safari is not replaced by Playwright WebKit.
- Add manual job attempts with synchronous-only actual context and explicit terminal/error rebinding across await; author overlapping-job/real-browser C03/C05 fixtures without ambient-link or scheduler-health fiction.
- Add the owned replay recorder (`src/replay/`): capture only when project policy, deployment opt-in and explicit consent are all true; traverse the DOM directly into closed structural `ReplayNode`s (constant `"[masked]"` text/input masks, 8 CSS px quantized rectangles, inert tag enum, opaque frames/editable/textarea/select/media, 20,000-node cap with gap); `Client.startReplay`/`setReplayConsent` delegate to it and revocation destroys pending replay state without touching other queue entries.
