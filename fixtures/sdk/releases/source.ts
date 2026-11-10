// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Real throwing release fixture. The throw statement must stay on line 6 so the
// source-map assertions have one known original line (column 8, zero-based).
export function soundpostReleaseThrow(): never {
  throw new Error("soundpost release fixture");
}
soundpostReleaseThrow();
