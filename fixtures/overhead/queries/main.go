// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: queries server|ingest|query|summarize [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "server":
		runServer(os.Args[2:]) // server.go
	case "ingest":
		runIngest(os.Args[2:]) // ingest.go
	case "query":
		runQuery(os.Args[2:]) // query.go
	case "summarize":
		runSummarize(os.Args[2:]) // summarize.go
	default:
		fmt.Fprintf(os.Stderr, "queries: unknown role %q\n", os.Args[1])
		os.Exit(2)
	}
}
