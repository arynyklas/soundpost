// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model_test

import (
	"context"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/model"
	"testing"
)

func TestAuditPreservesObservedOutcomeAndCorrelation(t *testing.T) {
	requestID := model.NewID()
	audit := model.ControlAudit{ID: model.NewID(), Principal: model.NewID(), Action: "owned operation", Reason: "safe reason", Time: 1800000000000000000, RequestID: requestID, Outcome: model.AuditFailed}
	raw, err := json.Marshal(audit)
	if err != nil {
		t.Fatal(err)
	}
	var decoded model.ControlAudit
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.RequestID != requestID || decoded.RequestID == decoded.ID || decoded.Outcome != model.AuditFailed {
		t.Fatal("audit encoding synthesized allowed outcome or audit-ID correlation")
	}
	commandID := model.NewID()
	if got := model.RequestCorrelationID(context.Background(), commandID); got != commandID {
		t.Fatal("non-HTTP command lost its correlation")
	}
	ctx := model.WithRequestID(context.Background(), requestID)
	if got := model.RequestCorrelationID(ctx, commandID); got != requestID {
		t.Fatal("request context correlation was replaced")
	}
}
