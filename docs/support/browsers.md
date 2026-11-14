<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Browser support and qualification status

Status: **no browser row is qualified.** The frozen qualification targets are Chrome 142.0.7444.59, Edge 142.0.3595.53, Firefox 144.0.2 and Safari 26.0.1. None is installed on the qualification host, so every core, replay and sample-capability row for them is `not_exercised`. Playwright WebKit is not a Safari release.

Measured (non-required, different build): real headless Linux Chrome 156.0.8078.80 via Playwright.

- Replay recorder (`fixtures/sdk/replay/recorder.spec.ts`): pre-buffer canaries, consent and revocation behavior pass.
- JS Self-Profiling (`fixtures/sdk/profiles/browser.spec.ts`): supported with the `Document-Policy: js-profiling` header (genuine samples); **denied** without it (`document_policy_missing`); **unsupported** when the `Profiler` constructor is absent (Firefox/Safari emulation) and in dedicated workers; second concurrent start is denied. Denied and unsupported rows carry no sample count: an unavailable sampler is never shown as zero CPU.
- Browser core critical path needs the private backend fixture environment and was not run.

Chrome 156 never qualifies Chrome 142.
