// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

// Producers are the producers a served node runs, in order: stages of the
// leader-only background runner that turn ingested evidence into control state.
// Ingested errors become issues, every open issue episode gets an incident, and
// ingested job attempts become job books.
func (a *App) Producers() []Producer {
	return []Producer{a.IssueProducer(), a.IncidentProducer(), a.JobProducer()}
}
