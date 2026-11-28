// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

func TestUpgradeRefusesBadUsage(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"finalize"},
		{"contract-indexes"},
		{"contract-indexes", "--url", "http://host:1", "--email", "a@b.c", "--password-file", "p", "--reason", "r"},
		{"contract-indexes", "--url", "https://host:1/path", "--email", "a@b.c", "--password-file", "p", "--reason", "r"},
		{"contract-indexes", "--url", "https://host:1", "--email", "a@b.c", "--password-file", "p"},
		{"contract-indexes", "--url", "https://host:1", "--email", "a@b.c", "--password-file", "p", "--reason", "r", "--command-id", "nope"},
		{"contract-indexes", "--url", "https://host:1", "--email", "a@b.c", "--password-file", "p", "--reason", "r", "extra"},
	} {
		var out bytes.Buffer
		if err := runUpgrade(args, &out); !errors.Is(err, errUpgradeUsage) && err == nil {
			t.Errorf("%v: accepted", args)
		}
	}
}

func TestUpgradeFailureLineNamesTheRefusal(t *testing.T) {
	refused := &upgradeRefused{status: 415, fault: model.Fault{Code: model.Unsupported, SafeDetail: "layout_unsupported_by:node-b,node-c"}}
	got := failureLine([]string{"soundpost", "upgrade", "contract-indexes"}, fmt.Errorf("wrapped: %w", refused))
	if !strings.Contains(got, "layout_unsupported_by:node-b,node-c") || !strings.Contains(got, "code=unsupported") {
		t.Fatalf("the operator is not told why: %q", got)
	}
	if got := failureLine([]string{"soundpost", "upgrade"}, errors.New("open /secret/path: denied")); strings.Contains(got, "/secret/path") {
		t.Fatalf("a path leaked: %q", got)
	}
}
