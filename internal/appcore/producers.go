// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

// Producers are the producers a served node runs, in order: stages of the
// leader-only background runner that turn ingested evidence into control state.
// Ingested errors become issues, unprocessed error evidence about to expire from
// the 90-day journal is declared as a gap before it can be lost, every open issue
// episode gets an incident, the issue lifecycle's effect intents are acknowledged
// once their incident exists, ingested job attempts become job books, and the source maps that retained profiles name are held.
func (a *App) Producers() []Producer {
	return []Producer{a.IssueProducer(), a.JournalExpiryProducer(), a.IncidentProducer(), a.IssueEffectProducer(), a.JobProducer(), a.ProfileMapProducer()}
}
