// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
export function throwingFixture(): never {
  throw new Error("soundpost fixture throw");
}
throwingFixture();
