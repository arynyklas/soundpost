<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Browser support and qualification status

Status: **no browser row is qualified.** The frozen qualification targets are Chrome 142.0.7444.59, Edge 142.0.3595.53, Firefox 144.0.2 and Safari 26.0.1. None is installed on the qualification host, so every core, replay and sample-capability row for them is `not_exercised`. Playwright WebKit is not a Safari release.

Measured (non-required, different build): real headless Linux Chrome 156.0.8078.80 via Playwright.

- Replay recorder (`fixtures/sdk/replay/recorder.spec.ts`): pre-buffer canaries, consent and revocation behavior pass.
- JS Self-Profiling (`fixtures/sdk/profiles/browser.spec.ts`): supported with the `Document-Policy: js-profiling` header (genuine samples); **denied** without it (`document_policy_missing`); **unsupported** when the `Profiler` constructor is absent (Firefox/Safari emulation) and in dedicated workers; second concurrent start is denied. Denied and unsupported rows carry no sample count: an unavailable sampler is never shown as zero CPU.
- Browser core critical path needs the private backend fixture environment and was not run.

Observed on the Linux VM sp-q-d12 (lane 4 wave 29), still not a qualification (no browser row is qualified until the gate says so):

- **Firefox 144.0.2 (stock Mozilla build)**, driven by Playwright's WebDriver BiDi channel through `fixtures/sdk/firefox` (a launcher that answers only the two BiDi commands stock Firefox 144 lacks, `browser.setDownloadBehavior` and `emulation.setScreenSettingsOverride`; every page behavior is Firefox's own): hooks fixture (`hooks/browser-run.mjs --engine firefox`: 5 safe captures, 0 canaries, prior handler order kept), replay recorder spec 4/4, browser critical path (`critical --mode browser --browsers Firefox=...`, Express on Node 22.21.1 and 24.11.0, PostgreSQL 15.20, private CA installed through Firefox's enterprise policy file), profiling rows `Profiler removed` and `dedicated worker` (Firefox has no `Profiler` constructor: `unsupported`, zero samples; the rows that need the Chromium API are skipped on Firefox).
- Firefox replay **viewer** spec: 2 of 10 rows pass (the control rows); the other 8 stop in the harness, not in the viewer: Playwright's BiDi frame evaluation is an `eval` that the viewer's production CSP blocks (`EvalError: call to eval() blocked by CSP`). Chromium evaluates through CDP, which is not subject to the page CSP. Firefox viewer inertness is therefore **not** observed.
- Chrome for Testing 142.0.7444.59: browser critical path with Node 22.21.1 and 24.11.0 (PostgreSQL 15.20) passes.

Chrome 156 never qualifies Chrome 142.
