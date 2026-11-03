# @soundpost/browser

Copyright 2026 Aryn Yklas. Apache-2.0.

Policy-first local capture plus explicit `installHooks(client, targetWindow?)`. Owned addEventListener callbacks observe actual global errors and unhandled rejections, reading only native ErrorEvent/PromiseRejectionEvent descriptors, never messages or event-provided getters. They do not assign `onerror`/`onunhandledrejection`, preventDefault, stop propagation, or change default reporting. Close removes only owned listeners and is idempotent; client close releases its own leases (maximum eight).

Native Error branding uses intrinsic Error.isError where available, else UnknownError/native_brand_unavailable. Original frames remain safe_original_stack_unavailable and unsafe aggregate containers retain their explicit limitation. `lease.useEpisode(episode, error, "uncaught_exception" | "unhandled_rejection")` binds weak object identity plus exact event source on this Window lease; an unrelated rejection cannot consume an error-event arm, nor can another thrown object. `clearEpisode(episode)` cancels pending association. Primitive rethrows reject arming rather than inventing identity. Browser fatal=False denotes reporting without process-termination evidence. The actual browser fixture tests real cross-source interleaving; approved browser matrix rows, source-mapped frames, delivery and replay remain separate unmet gates.
