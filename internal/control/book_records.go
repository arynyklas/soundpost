// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"

	"github.com/arynyklas/soundpost/internal/model"
)

// The job and issue books are records of the ledger (ledger.go): a worker's update writes one record, and
// a reader that wants one record or the records of one project reads them from there, not from an
// assembly of every record of every project.

// bookTable is the ledger table of a book, or -1 for a book that is not one of the ledger's.
func bookTable(book model.Book) int {
	switch book {
	case model.BookJobs:
		return tableJobBooks
	case model.BookIssues:
		return tableIssueBooks
	case model.BookGroupingIssues:
		return tableGroupingIssues
	case model.BookJobPositions:
		return tableJobPositions
	case model.BookRuleBooks:
		return tableRuleBooks
	case model.BookRuleOutputs:
		return tableRuleOutputs
	}
	return -1
}

// bookKeys lists the keys of a book that start with prefix, in key order.
func (l *ledgerTx) bookKeys(table int, prefix string) []string {
	var out []string
	l.each(table, []byte(prefix), func(key, _ []byte) bool {
		out = append(out, string(key))
		return true
	})
	return out
}

// bookRecord is a copy of the record under key.
func (l *ledgerTx) bookRecord(table int, key string) ([]byte, bool) {
	raw := l.t[table].Get([]byte(key))
	if raw == nil {
		return nil, false
	}
	return bytes.Clone(raw), true
}

// ledgerBookSource is model.BookSource over the job and issue books of the ledger of one transaction.
type ledgerBookSource struct{ l *ledgerTx }

func (s ledgerBookSource) BookKeys(book model.Book, prefix string) []string {
	if table := bookTable(book); table >= 0 {
		return s.l.bookKeys(table, prefix)
	}
	return nil
}

func (s ledgerBookSource) BookRecord(book model.Book, key string) ([]byte, bool) {
	if table := bookTable(book); table >= 0 {
		return s.l.bookRecord(table, key)
	}
	return nil, false
}
