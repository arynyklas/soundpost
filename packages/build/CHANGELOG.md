# Changelog

Copyright 2026 Aryn Yklas. SPDX-License-Identifier: Apache-2.0.

## 0.1.0 (unreleased)

- `uploadArtifacts`, `createUploadConfig`, `soundpostVite` (Vite 7.x) and `soundpostWebpack` (webpack 5.x).
- Content-bound debug IDs, private maps, source-content-off by default, C07 limit/indexed/traversal/oversize rejection before upload, credential sealed in a closure.
- Qualified only against the actual Vite 7.3.7 and webpack 5.112.2 builds exercised by `test/artifacts.test.ts`; no other bundler/version is claimed.
