# @soundpost/bun

Copyright 2026 Aryn Yklas. Apache-2.0.

Policy-first local capture with native error branding through Bun's own `node:util.types` compatibility implementation. Explicit `installHooks(client)` returns a bounded owned lease whose capability reports `fatalMonitor: false`, `reason: "bun_fatal_monitor_unavailable"`. It installs no fatal/rejection listeners: Node monitor registration alone is not Bun qualification, and a consuming listener would change application behavior. `useEpisode` rejects with that limitation rather than pretending to arm fatal monitoring. Close is idempotent; client close releases its own leases.

Safe manual cause/group extraction is implemented; original JS frames report `safe_original_stack_unavailable`. See ../core/README.md for graph/episode/privacy boundaries. Bun1.3.14 actual child-process on/off qualification remains parent-owned and independent from Node. No HTTP/flush ACK, fatal delivery, replay, spans, profiling or full original/source-mapped stack support is claimed.
