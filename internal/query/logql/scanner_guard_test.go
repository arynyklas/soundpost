// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"strings"
	"testing"

	jsonparser "github.com/arynyklas/soundpost/third_party/jsonparser/v1.1.1"
)

func recovered(fn func()) (value any) {
	defer func() { value = recover() }()
	fn()
	return nil
}

// Only a Go runtime fault raised inside the vendored scanner is a scanner fault.
// A panic from our own code, whether the callback the scanner invokes or the
// guarded closure itself, is a bug that must surface rather than become a
// "Malformed JSON error" stage error on the line.
func TestGuardScannerSurfacesPanicsThatAreNotScannerFaults(t *testing.T) {
	if got := recovered(func() { guardScanner(func() { panic("closure bug") }) }); got != "closure bug" {
		t.Fatalf("panic in the guarded closure was swallowed or altered: %v", got)
	}
	var calls int
	got := recovered(func() {
		guardScanner(func() {
			jsonparser.EachKey([]byte(`{"a":1}`), func(int, []byte, jsonparser.ValueType, error) {
				calls++
				panic("callback bug")
			}, []string{"a"})
		})
	})
	if calls != 1 || got != "callback bug" {
		t.Fatalf("panic in the scanner callback was swallowed (calls=%d): %v", calls, got)
	}
	var nilMap map[string]int
	if got = recovered(func() { guardScanner(func() { nilMap["x"] = 1 }) }); got == nil {
		t.Fatal("a runtime fault in our own code was swallowed")
	}
}

func TestGuardScannerStillContainsScannerFaultsAndClassifiesNestedSearch(t *testing.T) {
	// The empty quoted key inside an array element is the one place the pinned
	// reference scanner itself faults: searchKeys indexes past the path.
	var fault scannerFault
	if got := recovered(func() {
		fault = guardScanner(func() {
			jsonparser.EachKey([]byte(`{"a":[[1],[2]]}`), func(int, []byte, jsonparser.ValueType, error) {}, []string{"a", "[0]", ""})
		})
	}); got != nil {
		t.Fatalf("scanner fault escaped: %v", got)
	}
	if !fault.happened || !fault.nested {
		t.Fatalf("nested scanner fault not contained and classified: %+v", fault)
	}
}

// The scanner's package path is derived from the scanner itself, not spelled as
// the vendored directory's escaped version string.
func TestScannerPackageIsDerivedFromTheVendoredSymbol(t *testing.T) {
	if scannerPackage == "" || !strings.Contains(scannerPackage, "jsonparser") {
		t.Fatalf("scanner package not derived: %q", scannerPackage)
	}
}
