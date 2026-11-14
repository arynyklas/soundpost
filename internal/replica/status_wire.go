// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/model"
)

type statusWire struct {
	Group       model.ID       `json:"group"`
	ID          model.Uint64   `json:"node"`
	Leader      model.Uint64   `json:"leader"`
	Term        model.Uint64   `json:"term"`
	Commit      model.Uint64   `json:"physical_commit"`
	Applied     model.Uint64   `json:"physical_applied"`
	Last        model.Uint64   `json:"physical_last"`
	Application model.Cursor   `json:"application_cursor"`
	Revision    model.Revision `json:"revision"`
	Failed      bool           `json:"failed"`
	Members     Members        `json:"members"`
}

func (s Status) MarshalJSON() ([]byte, error) {
	return json.Marshal(statusWire{Group: s.Group, ID: model.Uint64(s.ID), Leader: model.Uint64(s.Leader), Term: model.Uint64(s.Term), Commit: model.Uint64(s.Commit), Applied: model.Uint64(s.Applied), Last: model.Uint64(s.LastIndex), Application: s.ApplicationCursor, Revision: s.Revision, Failed: s.Failed, Members: s.Members})
}
func (s *Status) UnmarshalJSON(raw []byte) error {
	var wire statusWire
	if model.StrictJSON(raw, &wire) != nil {
		return ErrInvalid
	}
	*s = Status{Group: wire.Group, ID: uint64(wire.ID), Leader: uint64(wire.Leader), Term: uint64(wire.Term), Commit: uint64(wire.Commit), Applied: uint64(wire.Applied), LastIndex: uint64(wire.Last), ApplicationCursor: wire.Application, Revision: wire.Revision, Failed: wire.Failed, Members: wire.Members}
	return nil
}
