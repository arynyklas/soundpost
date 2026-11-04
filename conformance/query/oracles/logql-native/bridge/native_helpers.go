//go:build soundpost_logql_oracle

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Independently authored development-only access bridge, compiled only inside
// the exact upstream source module. No upstream implementation is reproduced.
package log

import (
	"bytes"
	"text/template"
)

// SoundpostNativeTemplate invokes the actual pinned function registry and the
// actual pinned compiler's template executor. No clock replacement is made.
func SoundpostNativeTemplate(source, line string, ts int64, input any) (string, string, error) {
	functions := addLineAndTimestampFunctions(func() string { return line }, func() int64 { return ts })
	parsed, err := template.New("line").Option("missingkey=zero").Funcs(functions).Parse(source)
	if err != nil {
		return "", "parse", err
	}
	var output bytes.Buffer
	if err = parsed.Execute(&output, input); err != nil {
		return "", "execution", err
	}
	return output.String(), "", nil
}
