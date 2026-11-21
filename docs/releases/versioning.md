<!-- Copyright 2026 Aryn Yklas -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Versioning

- Releases use semantic versions `MAJOR.MINOR.PATCH`; `0.0.0-unreleased` is the placeholder for the current tree, which has never passed the whole-product gate and must not be published.
- The version string is an explicit input to `build release`, `build sbom` and `build gate` and is recorded in `release.json`; the gate fails if `release.json` names a different version or commit.
- Wire contracts (C01-C12) and the on-disk/snapshot formats carry their own schema versions. A release may change a schema only with a forward migration and a tested rollback path; a release that cannot read the previous release's data must say so in its notes and is a MAJOR change.
- npm, PyPI and Go module versions are published together from one commit and one version. Handles are claimed only after `handle_check` passes and the owner approves.
- Pre-1.0 releases make no compatibility promise beyond what the release notes state.
