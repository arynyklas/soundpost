// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package issues

import "soundpost/internal/model"

// C07 DTOs live in the leaf model so control never imports feature reducers.
// Lifecycle evidence processing is distinct from the grouping migration command.
type Evidence = model.GroupingEvidence
type Issue = model.GroupingIssue
type GroupingMigration = model.GroupingMigration
