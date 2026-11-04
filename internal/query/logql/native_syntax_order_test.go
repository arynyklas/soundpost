// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"soundpost/internal/query/syntax"
	"strings"
	"testing"
)

// TestNativeSyntaxErrorOrdering replays observations of the pinned reference's
// parse-stage rejections. The reference scans demand-driven: the first token its
// grammar cannot accept is the error, and a lexical failure later in the text is
// never reached. Every rejected row must fail with the observed Soundpost code
// and, where the native text exposes a byte offset, the observed start position;
// an accepted row (a comment hides the rest of the line) must stay accepted.
func TestNativeSyntaxErrorOrdering(t *testing.T) {
	raw, err := os.ReadFile("testdata/native-syntax-errors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Rows []struct {
			ID         string
			Expression string
			Accepted   bool
			Semantic   string
			StartByte  *int `json:"start_byte"`
		}
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Rows) < 9640 {
		t.Fatalf("native syntax observations shrank to %d rows", len(f.Rows))
	}
	p := testProfile(t)
	for _, row := range f.Rows {
		t.Run(row.ID, func(t *testing.T) {
			_, err := parseCheck(t, row.Expression, p)
			if row.Accepted {
				if err != nil {
					t.Fatalf("native accepts %q: %v", row.Expression, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted %q", row.Expression)
			}
			var d *syntax.LanguageError
			if !errors.As(err, &d) {
				t.Fatalf("not an owned diagnostic: %v", err)
			}
			if d.Code != row.Semantic {
				t.Errorf("%q: code=%s want %s (start %d)", row.Expression, d.Code, row.Semantic, d.Range.StartByte)
			}
			if row.StartByte != nil && d.Range.StartByte != *row.StartByte {
				t.Errorf("%q: start=%d want %d (code %s)", row.Expression, d.Range.StartByte, *row.StartByte, d.Code)
			}
		})
	}
}

// TestSyntaxErrorOrderFollowsTheGrammarNotTheScanner pins the rules the native
// observations imply, on heads the observation file does not contain: the first
// token the grammar cannot accept is the error, a scanner failure surfaces only
// for a token the parser actually reads, and a malformed literal that is read
// outranks a grammar error at the same token.
func TestSyntaxErrorOrderFollowsTheGrammarNotTheScanner(t *testing.T) {
	p := testProfile(t)
	const unexpected = "syntax.unexpected-token"
	for _, tc := range []struct{ source, code, at string }{
		// A bad token after the first grammar error is never scanned.
		{"{app=\"api\"} foo `x", unexpected, "foo"},
		{"{app=\"api\"} | json | unwrap x \"y", unexpected, "unwrap"},
		{"sum({app=\"api\"}) `x", unexpected, ")"},
		{"{app=\"api\"} [5m] `x", unexpected, "["},
		// A scanner failure on the token the parser reads is the error.
		{"{app=\"api\"} |= \"x", "syntax.string", "\"x"},
		{"vector(1) + `x", "syntax.string", "`"},
		{"{app=\"api\"} [5x] $", "syntax.duration", "5x"},
		// Unknown characters are identifiers: a name where a name fits.
		{"{app=\"api\"} | logfmt $, ~ y=\"b\"", unexpected, "y"},
		{"{app=\"api\"} | json ^ x=\"a\"", unexpected, "x"},
		{"{app=\"api\"} | a > 5 d ^", unexpected, "^"},
		// Reserved words are never names; function words are names unless called.
		{"{app=\"api\"} | json and x", unexpected, "x"},
		{"{app=\"api\",on=\"x\"}", unexpected, "on"},
		{"sum by x ({app=\"api\"})", unexpected, "sum"},
		{"sum(rate({app=\"api\"}[5m])) ^ by (a)", unexpected, "by"},
		// Contexts: ranges and unwraps exist only inside a range aggregation, a
		// metric argument is not a bare log expression, a string is no operand.
		{"{app=\"api\"} [5m] $", unexpected, "["},
		{"rate({app=\"api\"}) $", unexpected, ")"},
		{"\"x\" + 1", unexpected, "\"x\""},
		{"sum_over_time({app=\"api\"} | unwrap n |= \"x\" [5m])", unexpected, "|= "},
		{"sum_over_time({app=\"api\"} | unwrap n | json [5m])", unexpected, "json"},
	} {
		_, err := parseCheck(t, tc.source, p)
		var d *syntax.LanguageError
		if !errors.As(err, &d) {
			t.Errorf("%q: not an owned diagnostic: %v", tc.source, err)
			continue
		}
		if want := strings.Index(tc.source, tc.at); d.Code != tc.code || d.Range.StartByte != want {
			t.Errorf("%q: got %s at %d, want %s at %d (%q)", tc.source, d.Code, d.Range.StartByte, tc.code, want, tc.at)
		}
	}
	for _, source := range []string{
		`{rate="x"} | sum="y" | ip="z" | bytes>5`,
		`{app="api"} | json $ | json é`,
		"{app=\"api\"} | a=\"b\" (c=\"d\")",
	} {
		expr, err := Parse(source, p)
		if err != nil || expr == nil {
			t.Errorf("%q rejected: %v", source, err)
		}
	}
}

// TestNativeLexicalRulesBeyondTheObservedHeads pins the scanner rules the
// observation file implies on queries it does not contain. The `[` range token
// is read up to the first `]` when requested and must be exactly a duration; its
// failure is reported at the character column of the `[` (hs3-0144 shows that a
// multi-byte character before it counts once). Numbers follow the Go scanner:
// `1x` is a number and a word, and so is a malformed duration spelling (`5ss`).
// Label names are never charset-checked, but a bare json or logfmt name is also
// the extraction key and must be one.
func TestNativeLexicalRulesBeyondTheObservedHeads(t *testing.T) {
	p := testProfile(t)
	const unexpected = "syntax.unexpected-token"
	for _, tc := range []struct {
		source, code string
		start        int
	}{
		// range token: unterminated, padded, fractional, nested and sub-query forms
		{`sum(rate({job="x"} | logfmt [`, "syntax.duration", 29},
		{`rate({job="x"} [ 1m ])`, "syntax.duration", 16},
		{`rate({job="x"} [1.5m])`, "syntax.duration", 16},
		{`rate({job="x"} [1m:5s])`, "syntax.duration", 16},
		{`rate({job="é"} [x])`, "syntax.duration", 16},
		{`count_over_time({job="x"} | json ; [ 1h`, "syntax.duration", 36},
		// the grammar, not the scanner, decides where a range may stand
		{`{job="x"} | json [ 5m ]`, "syntax.duration", 18},
		// numbers and durations
		{`rate({job="x"}[5m] offset 5ss)`, unexpected, 26},
		{`rate({job="x"}[5m] offset 5)`, unexpected, 26},
		{`sum(1x rate({job="x"}[5m]))`, unexpected, 5},
		{`1..2 + 3`, unexpected, 2},
		{`2 ( 1 )`, unexpected, 2},
		{`sum(rate({job="x"}[5m] offset 1m offset 2m))`, unexpected, 33},
		// signs belong to number literals only
		{`sum(- rate({job="x"}[5m]))`, unexpected, 6},
		{`1 - - - 2`, unexpected, 6},
		// grammar shapes
		{`{job="x",}`, unexpected, 9},
		{`sum by (a,) (rate({job="x"}[5m]))`, unexpected, 10},
		{`{job="x"} | n > "s"`, unexpected, 16},
		{`sum_over_time({job="x"} | json | unwrap n [5m] | n > 1)`, unexpected, 47},
	} {
		_, err := parseCheck(t, tc.source, p)
		var d *syntax.LanguageError
		if !errors.As(err, &d) {
			t.Errorf("%q: not an owned diagnostic: %v", tc.source, err)
			continue
		}
		if d.Code != tc.code || d.Range.StartByte != tc.start {
			t.Errorf("%q: got %s at %d, want %s at %d", tc.source, d.Code, d.Range.StartByte, tc.code, tc.start)
		}
	}
	for _, source := range []string{
		`{ @ = "x" } | json | é = "y" | label_format a = $ | drop ?, é`,
		`{job="x"} | json é="a.b" | logfmt ü="k"`,
		`rate({job="x"}[5m] offset 1h30m)`,
		`sum(1) + sum by (a) (2 + 3)`,
	} {
		if _, err := parseCheck(t, source, p); err != nil {
			t.Errorf("%q rejected: %v", source, err)
		}
	}
	for _, source := range []string{
		`{job="x"} | json é`,
		`{job="x"} | logfmt a, ü`,
		`{job="x"} | logfmt a="a.b"`,
		`{job="x"} | json a="["`,
	} {
		_, err := parseCheck(t, source, p)
		var d *syntax.LanguageError
		if !errors.As(err, &d) || d.Code != unexpected {
			t.Errorf("%q: want %s, got %v", source, unexpected, err)
		}
	}
}

// TestLabelFilterOperandSpellings pins the operand rules the op11 observations
// imply, on spellings the file does not contain. A label-filter number is the
// float parser's value with its error ignored (`0x10` and `0o17` are 0, `010`
// is ten, `1e999` is +Inf); a metric-expression literal that the float parser
// refuses is a syntax.number rejection; `0b` is a scanner error everywhere. A byte quantity is
// read only from the alphabet B i k K M G T P, so a lower-case `b` ends the
// quantity and starts a word (`1kb` is `1k` and `b`, `1.5KiB` is one token);
// ip() is a value of `=` and `!=` only, and a regular expression operator
// reports the `ip` token itself, while a line filter keeps its own diagnostic.
func TestLabelFilterOperandSpellings(t *testing.T) {
	p := testProfile(t)
	for _, tc := range []struct {
		operand string
		typ     string
		value   float64
	}{
		{"0x10", "number", 0}, {"0o17", "number", 0}, {"0x1.8p1", "number", 3},
		{"010", "number", 10}, {"1_000", "number", 1000}, {"0X1F", "number", 0},
		{"1e999", "number", math.Inf(1)},
		{"1e3", "number", 1000}, {".5", "number", 0.5},
		{"1.5KiB", "bytes", 1536}, {"2GB", "bytes", 2e9}, {"3k", "bytes", 3000},
		{"1h30m", "duration", float64(90 * 60 * 1000000000)},
	} {
		expr, err := Parse(`{job="a"} | x >= `+tc.operand, p)
		if err != nil {
			t.Errorf("%s: %v", tc.operand, err)
			continue
		}
		f := expr.(*LogExpr).Stages[0].Filter
		if f.Type != tc.typ || f.Number != tc.value {
			t.Errorf("%s: got %s %v, want %s %v", tc.operand, f.Type, f.Number, tc.typ, tc.value)
		}
	}
	for _, tc := range []struct {
		source, code string
		at           string
	}{
		// a lower-case b is a word of its own: after `x = 1kb` a filter named b needs an operator
		{`{job="a"} | x > 0B1`, "syntax.number", "0B1"},
		{`rate({job="a"}[5m]) > 0b1`, "syntax.number", "0b1"},
		{`rate({job="a"}[5m]) > 0X1F`, "syntax.number", ""},
		{`topk(0o2, rate({job="a"}[5m]))`, "syntax.number", ""},
		{`vector(1e999)`, "syntax.number", ""},
		{`{job="a"} | x = 1kb`, "syntax.unexpected-token", ""},
		{`{job="a"} | x < 4mb y="1"`, "syntax.unexpected-token", "y"},
		{`{job="a"} | x < 1GB b`, "syntax.unexpected-token", ""},
		{`{job="a"} | x =~ ip("1.1.1.1")`, "syntax.unexpected-token", "ip"},
		{`{job="a"} | x !~ ip("1.1.1.1")`, "syntax.unexpected-token", "ip"},
		{`{job="a"} | x > ip("1.1.1.1")`, "syntax.unexpected-token", "ip"},
		{`{job="a"} |~ ip("1.1.1.1")`, "ip.operator-invalid", "|~"},
		{`{job="a"} !~ ip("1.1.1.1")`, "ip.operator-invalid", "!~"},
	} {
		_, err := parseCheck(t, tc.source, p)
		var d *syntax.LanguageError
		if !errors.As(err, &d) {
			t.Errorf("%q: not an owned diagnostic: %v", tc.source, err)
			continue
		}
		if d.Code != tc.code {
			t.Errorf("%q: code %s, want %s", tc.source, d.Code, tc.code)
		}
		if tc.at != "" {
			if want := strings.Index(tc.source, tc.at); d.Range.StartByte != want {
				t.Errorf("%q: start %d, want %d", tc.source, d.Range.StartByte, want)
			}
		}
	}
	for _, source := range []string{`{job="a"} | x = ip("1.1.1.1")`, `{job="a"} | x != ip("1.1.1.1")`} {
		if _, err := parseCheck(t, source, p); err != nil {
			t.Errorf("%q rejected: %v", source, err)
		}
	}
}
