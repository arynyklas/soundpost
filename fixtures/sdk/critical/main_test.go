//go:build unix

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

const pinned = "postgres@sha256:92620daddcd947f8d5ab5ba66e848702fe443d87fed30c4cea8e389fd78dfc55"

// An evidence row names the PostgreSQL it ran against by the pinned image digest in every mode. A server reached by --pg-dsn is the
// operator's, so the row says that it is, and the digest it carries is the one the operator states the server was started from, which
// must be the pin: never a free-text sentence, never another image.
func TestPostgresRecordIsAlwaysTheDigest(t *testing.T) {
	got, err := postgresRecord(pinned, "", "")
	if err != nil || got["postgres_image"] != pinned || got["postgres_server"] != "container_started_by_tool" {
		t.Fatalf("a container the tool started: %v %v", got, err)
	}
	got, err = postgresRecord(pinned, "postgres://u@10.0.0.9/reference", pinned)
	if err != nil || got["postgres_image"] != pinned || got["postgres_server"] != "dsn" || got["postgres_image_attestation"] != "operator" {
		t.Fatalf("a DSN server started from the pin: %v %v", got, err)
	}
	for _, v := range got {
		if strings.Contains(v, " ") {
			t.Errorf("no free-text value in the row: %q", v)
		}
	}
}

func TestPostgresRecordRefusesWhatItCannotNameByDigest(t *testing.T) {
	for name, c := range map[string]struct{ image, dsn, startedFrom string }{
		"a DSN without the image it was started from": {pinned, "postgres://u@h/db", ""},
		"a DSN started from another digest":           {pinned, "postgres://u@h/db", "postgres@sha256:" + strings.Repeat("1", 64)},
		"a DSN started from a tag":                    {pinned, "postgres://u@h/db", "postgres:16"},
		"a DSN started from a bare id prefix":         {pinned, "postgres://u@h/db", "92620daddcd9"},
		"the started-from image without a DSN":        {pinned, "", pinned},
		"a pin that is a tag":                         {"postgres:16", "", ""},
		"a pin that is a bare id prefix":              {"92620daddcd9", "", ""},
		"a pin with an uppercase digest":              {"postgres@sha256:" + strings.Repeat("A", 64), "", ""},
	} {
		if got, err := postgresRecord(c.image, c.dsn, c.startedFrom); err == nil {
			t.Errorf("%s must be refused, got %v", name, got)
		}
	}
}
