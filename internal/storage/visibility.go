// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

var unpartitionedSubject = []model.Kind{""}
var profileSubject = []model.Kind{model.Profile}

func partitionedSubject(kind model.Kind) bool {
	return kind == model.CapabilityKind || kind == model.Loss
}
func storageSubjects(kind model.Kind) []model.Kind {
	if partitionedSubject(kind) {
		return signalKinds
	}
	return unpartitionedSubject
}
func scopeSubjects(scope auth.Scope, kind model.Kind) []model.Kind {
	if scope.Permission() == profilesRead && partitionedSubject(kind) {
		return profileSubject
	}
	return storageSubjects(kind)
}
func validSubject(kind, subject model.Kind) bool {
	if partitionedSubject(kind) {
		return subject.Valid()
	}
	return subject == ""
}
func recordSubject(r model.Record) model.Kind { return payloadSubject(&r.Payload) }
func payloadSubject(p *model.Payload) model.Kind {
	if p.Capability != nil {
		return p.Capability.Signal
	}
	if p.Loss != nil {
		return p.Loss.Signal
	}
	return ""
}
func allowsSubject(scope auth.Scope, kind, subject model.Kind) bool {
	return scope.Permission() != profilesRead || !partitionedSubject(kind) || subject == model.Profile
}
func pageNamespace(org, project model.ID, kind model.Kind, raw bool, source model.ID, subject model.Kind) []byte {
	prefix := namespace(org, project, kind, raw, source)
	if partitionedSubject(kind) {
		prefix = append(prefix, signalCode(subject))
	}
	return prefix
}
