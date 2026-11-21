// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"context"
	"strings"
	"testing"
)

// The S3 destination deletes with a signed DELETE; an absent object is not an error. The local one
// removes the file and is idempotent too.
func TestDestinationsDeleteAnObjectAndTolerateAnAbsentOne(t *testing.T) {
	ctx := context.Background()
	fake, server := newFakeS3("SECRETKEY-MUST-NEVER-LEAK")
	defer server.Close()
	local, err := NewLocalDestination(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, d := range map[string]interface {
		Destination
		Deleter
	}{"s3": newS3(t, server, ""), "local": local} {
		if err := d.Create(ctx, "backups/x/obj/a", strings.NewReader("payload"), 7); err != nil {
			t.Fatal(name, err)
		}
		if err := d.Delete(ctx, "backups/x/obj/a"); err != nil {
			t.Fatal(name, err)
		}
		if err := d.Delete(ctx, "backups/x/obj/a"); err != nil {
			t.Fatalf("%s: deleting an absent object: %v", name, err)
		}
		if names, err := d.List(ctx, "backups/"); err != nil || len(names) != 0 {
			t.Fatalf("%s: %v %v left after the delete", name, names, err)
		}
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	signed := 0
	for _, r := range fake.seen {
		if r.Method == "DELETE" && strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
			signed++
		}
	}
	if signed != 2 {
		t.Fatalf("%d signed DELETE requests, want 2", signed)
	}
}
