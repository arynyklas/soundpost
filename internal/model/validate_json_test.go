// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// Expectation values for a corpus entry. Unknown entries are checked
// differentially only.
const (
	vUnknown = iota
	vReject
	vAccept
)

type validateCase struct {
	name string
	in   []byte
	want int
}

func vc(name, in string, ok bool) validateCase {
	w := vReject
	if ok {
		w = vAccept
	}
	return validateCase{name, []byte(in), w}
}

// handCases pin every rule of the accept set, one assertion per input. Both the
// reference and the scanner must agree with `ok`.
func handCases() []validateCase {
	var c []validateCase
	add := func(name, in string, ok bool) { c = append(c, vc(name, in, ok)) }
	// literals
	for _, s := range []string{"null", "true", "false", " null ", "\tnull\r\n"} {
		add("literal "+s, s, true)
	}
	for _, s := range []string{"", " ", "\n", "nul", "nulll", "tru", "True", "NULL", "truefalse", "fals", "nullnull", "n", "t", "f", "undefined", "nil"} {
		add(fmt.Sprintf("bad literal %q", s), s, false)
	}
	// numbers
	for _, s := range []string{"0", "-0", "1", "-1", "10", "1e5", "1E5", "1e+5", "1e-5", "1E+5", "-1.5e10", "0.5", "0e0", "0.0", "-0.0e-0", "1e999999", "123456789012345678901234567890", "1.000000000000000000001", "9", "-9", "0.1e1"} {
		add("number "+s, s, true)
	}
	for _, s := range []string{"01", "-01", "00", "1.", ".5", "-", "+1", "1e", "1e+", "1e-", "1.e5", "0x10", "1_0", "--1", "NaN", "Infinity", "-Infinity", "1 2", "1,2", "1e5.5", "1.5.5", "-.5", "- 1", "1a", "1E", "0.", "0.e1", "٣", "1\x00", "-a"} {
		add(fmt.Sprintf("bad number %q", s), s, false)
	}
	add("number in array", "[1,-0,1e5,0.5]", true)
	add("leading zero in array", "[01]", false)
	add("dangling dot in array", "[1.]", false)
	add("leading zero in object", `{"a":01}`, false)
	add("number then letter in array", "[1a]", false)
	add("number then brace in array", "[1}", false)
	// whitespace
	add("ws around scalar", " \t\r\n1 \t\r\n", true)
	add("ws in array", "[ 1 ,\n2\t,\r3 ]", true)
	add("ws in object", "{ \"a\" : 1 ,\n \"b\"\r:\t2 }", true)
	add("ws colon on next line", "{\"a\"\n:\r1}", true)
	add("ws empty array", "[ \n\t]", true)
	add("ws empty object", "{ \t\r\n}", true)
	for _, w := range []string{"\f", "\v", "\xc2\xa0", "\xef\xbb\xbf", "\x00", "\u2028", "\x1f", "\x7f"} {
		add(fmt.Sprintf("bad ws %q before", w), w+"1", false)
		add(fmt.Sprintf("bad ws %q after", w), "1"+w, false)
		add(fmt.Sprintf("bad ws %q inside array", w), "["+w+"1]", false)
	}
	// strings
	for _, s := range []string{`""`, `"a"`, `"\""`, `"\\"`, `"\/"`, `"\b\f\n\r\t"`, `"\u0041"`, `"\u00e9"`, `"\uFFFF"`, `"\u0000"`, `"\uffff"`, `"\ud7ff"`, `"\ue000"`, `"\ud83d\ude00"`, `"\uD83D\uDE00"`, `"\ud800\udc00"`, `"\udbff\udfff"`, `"\udbff\udc00"`, `"\ud800\udfff"`, `"é😀"`, `"\\u0041"`, `"\\\\u0041"`, `"a\\"`, `"\\ud800"`, `"\u0041\ud83d\ude00\u0042"`, "\"\x7f\"", `"a\ud83d\ude00"`, `"\ud83d\ude00a"`, `"\ud83d\ude00\ud83d\ude00"`, "\"\U0010ffff\"", "\"\ufffe\"", "\"\ufffd\""} {
		add("string "+s, s, true)
	}
	for _, s := range []string{`"\x"`, `"\u12"`, `"\u12G4"`, `"\u+123"`, `"\u 123"`, `"\u-123"`, `"\u0x41"`, `"\u00_1"`, `"\U0041"`, `"\a"`, `"\'"`, `"\0"`, `"\ "`, `"abc`, `"abc\"`, `"abc\`, `"\`, `"`, `'a'`, `"\u"`, `"\u1"`, `"\u123"`, `"\u123"x`, `abc`, `"a" "b"`, `"a"b`, `"a`, "\"\n\"", "\"\t\"", "\"\r\"", "\"\x00\"", "\"\x1f\"", "\"a\x01b\"", `"\ud83d"`, `"\ud83dx"`, `"\ud83d\u0041"`, `"\ud83d\ud83d"`, `"\ud83d\ude0"`, `"\ud83d\ude00\ude00"`, `"\ude00"`, `"\ude00\ud83d"`, `"\udc00"`, `"\udfff"`, `"\ud800"`, `"\udbff"`, `"\udbff\ue000"`, `"\udbff\udbff"`, `"\ud800\ud800"`, `"\ud83d\\ude00"`, `"\ud83d\n"`, `"a\ud83d"`, `"\ud83d`, `"\ud83d\ude0`, `"\ud83d\ude00`, `"\ud83d\u`, `"\ud83d\`, `"\ud83d\u00`, `"\ud83d\ud`, `"\ud83d\udc0g"`, `"\ud83d\udc"`, `"\ud83d\"`, `"\ud83d"\ude00"`} {
		add(fmt.Sprintf("bad string %q", s), s, false)
	}
	for b := 0; b < 0x20; b++ {
		add(fmt.Sprintf("raw control %#x in string", b), "\"a"+string(rune(b))+"b\"", false)
		add(fmt.Sprintf("raw control %#x in key", b), "{\"a"+string(rune(b))+"\":1}", false)
		add(fmt.Sprintf("raw control %#x after escape", b), "\"\\n"+string(rune(b))+"\"", false)
	}
	for _, e := range []string{"b", "f", "n", "r", "t", "/", `\`, `"`} {
		add("escape "+e, `"\`+e+`"`, true)
		add("escaped key "+e, `{"\`+e+`":1}`, true)
	}
	// invalid UTF-8, every class
	bad := map[string]string{
		"lone continuation 80":  "\x80",
		"lone continuation bf":  "\xbf",
		"overlong c0 80":        "\xc0\x80",
		"overlong c1 bf":        "\xc1\xbf",
		"overlong e0 80 80":     "\xe0\x80\x80",
		"overlong e0 9f bf":     "\xe0\x9f\xbf",
		"overlong f0 80 80 80":  "\xf0\x80\x80\x80",
		"overlong f0 8f bf bf":  "\xf0\x8f\xbf\xbf",
		"surrogate ed a0 80":    "\xed\xa0\x80",
		"surrogate ed bf bf":    "\xed\xbf\xbf",
		"above max f4 90 80 80": "\xf4\x90\x80\x80",
		"f5":                    "\xf5\x80\x80\x80",
		"f8":                    "\xf8\x88\x80\x80\x80",
		"fe":                    "\xfe",
		"ff":                    "\xff",
		"truncated 2 byte":      "\xc3",
		"truncated 3 byte":      "\xe2\x82",
		"truncated 4 byte":      "\xf0\x9f\x98",
		"bad continuation":      "\xc3\x28",
		"bad continuation 3":    "\xe2\x28\xa1",
		"bad continuation 4":    "\xf0\x9f\x28\x80",
	}
	for name, s := range bad {
		add("utf8 "+name+" in string", "\"a"+s+"b\"", false)
		add("utf8 "+name+" at string end", "\""+s+"\"", false)
		add("utf8 "+name+" before closing quote missing", "\"a"+s, false)
		add("utf8 "+name+" in key", "{\""+s+"\":1}", false)
		add("utf8 "+name+" after value", "1"+s, false)
		add("utf8 "+name+" before value", s+"1", false)
		add("utf8 "+name+" between tokens", "[1,"+s+"2]", false)
		add("utf8 "+name+" in array string", "[\"x"+s+"\"]", false)
	}
	for name, s := range map[string]string{"2 byte": "é", "3 byte": "€", "4 byte": "😀", "max": "\U0010ffff", "nonchar": "\ufffe", "bom inside string": "\ufeff", "ed 9f bf": "\ud7ff", "ee 80 80": "\ue000", "empty": ""} {
		add("utf8 valid "+name, "\""+s+"\"", true)
		add("utf8 valid key "+name, "{\""+s+"\":1}", true)
	}
	// arrays and objects
	for _, s := range []string{"[]", "{}", "[ ]", "{ }", "[1]", "[1,2]", "[[],[]]", `{"a":{}}`, `{"a":[]}`, "[{}]", `{"":1}`, `{"a":1,"b":2}`, `[{"a":1},{"a":2}]`, `[[1],[2,[3]]]`, `{"a":[1,{"b":null}]}`, `[true,false,null,"x",1,{},[]]`, `{"a":"a"}`, `{"a":1,"ab":2,"abc":3}`, `{"a":1,"A":2}`, `{"a":1,"a ":2}`, `{"\u0000":1,"":2}`, `{"a":1,"b":{"a":1},"c":[{"a":1}]}`} {
		add("structure "+s, s, true)
	}
	for _, s := range []string{"[,]", "[1,]", "[,1]", "[1 2]", "[1,,2]", "[", "]", "[1", "[1,", "[1}", "{]", "{", "}", "{\"a\"", `{"a":`, `{"a":1`, `{"a":1,`, `{"a":1,}`, "{,}", `{"a"}`, `{"a":}`, `{"a" 1}`, `{"a":1 "b":2}`, `{1:2}`, `{"a":1:2}`, `{:1}`, `{"a"::1}`, `{'a':1}`, `{"a":1}}`, "[1]]", "[1][2]", "{}{}", `{"a":1}x`, "[]1", "[]]", "[[]", `{"a":1,"b"}`, `{"a":1,"b":}`, `{"a":1,,"b":2}`, `{"a",1}`, `{"a":1,"b":2,}`, `[1,2,]`, "[1 ,]", `{null:1}`, `{true:1}`, `{[]:1}`, `{{}:1}`, `{"a":1,2}`, `{"a":[1,2}`, `[{"a":1]`, `[{"a":1],`, `{"a":1]`, `["a":1]`, "[:]", "[1:2]", `{"a" "b"}`, `{"a":"b" "c"}`, `[1,2}`, "[[1]", "[1]]]", "{\"a\":1}\x00", "[1]\u2028"} {
		add("bad structure "+s, s, false)
	}
	// duplicate keys, decoded before comparing
	for _, s := range []string{
		`{"a":1,"a":2}`, `{"a":1,"\u0061":2}`, `{"\u0061":1,"a":2}`, `{"\u0061":1,"\u0061":2}`, `{"\u0061":1,"\u0061":1}`,
		`{"é":1,"\u00e9":2}`, `{"\u00e9":1,"é":2}`, "{\"😀\":1,\"\\ud83d\\ude00\":2}", "{\"\\ud83d\\ude00\":1,\"😀\":2}", `{"\ud83d\ude00":1,"\ud83d\ude00":2}`,
		`{"a\nb":1,"a\u000ab":2}`, `{"a\u000ab":1,"a\nb":2}`, `{"\/":1,"/":2}`, `{"/":1,"\/":2}`, `{"\"":1,"\u0022":2}`, `{"\\":1,"\u005c":2}`, `{"\\":1,"\u005C":2}`,
		`{"\b":1,"\u0008":2}`, `{"\f":1,"\u000c":2}`, `{"\r":1,"\u000d":2}`, `{"\t":1,"\u0009":2}`, `{"\u0000":1,"\u0000":2}`, `{"":1,"":2}`,
		`{"a":1,"b":2,"a":3}`, `{"a":1,"b":2,"b":3}`, `{"ab":1,"a\u0062":2}`, `{"a\u0062c":1,"ab\u0063":2}`, `{"\u0061\u0062":1,"a\u0062":2}`,
		`{"x":{"a":1,"a":2}}`, `{"x":{"y":{"z":1,"w":2,"z":3}}}`, `{"x":[{"b":1,"b":2}]}`, `{"x":[1,[{"b":1,"\u0062":2}]]}`, `[{"a":1,"a":2}]`, `[{"a":1},{"a":2},{"b":1,"b":2}]`,
		`{"\u0061":{"\u0062":1},"a":2}`, `{"\u0061":{"\u0062":1,"\u0063":2},"\u0064":3,"\u0061":4}`, `{"a":{"\u0062":1,"\u0063":2},"b":3,"\u0062":4,"\u0063":5,"\u0064":6,"b":7}`,
		`{"\ud800\udc00":1,"\ud800\udc00":2}`, `{"\udbff\udfff":1,"\udbff\udfff":2}`, "{\"\U00010000\":1,\"\\ud800\\udc00\":2}", `{"\uD83D\uDE00":1,"\ud83d\ude00":2}`, `{"\u00E9":1,"\u00e9":2}`,
	} {
		add("duplicate "+s, s, false)
	}
	for _, s := range []string{
		`{"a":1,"A":2}`, `{"\u0061":1,"\u0062":2}`, `{"\u0061":1,"b":2}`, `{"é":1,"e":2}`, `{"\ud83d\ude00":1,"\ud83d\ude01":2}`, `{"\ud83d\ude00":1,"x":2}`,
		`{"a":{"a":1}}`, `{"a":[{"a":1}]}`, `{"a":1,"b":{"a":1,"b":1}}`, `{"a\n":1,"a":2}`, `{"\u0000":1,"":2}`, `{"\u0000":1,"\u0001":2}`, `{"/":1,"\\/":2}`, `{"a":"a","b":"a"}`,
		`{"\u0061":{"\u0062":1},"b":2}`, `{"\u0061":{"\u0062":1},"\u0062":2}`, `[{"\u0061":1},{"\u0061":2}]`, `{"a":1,"\u0061b":2}`, `{"\\u0061":1,"a":2}`, `{"\\u0061":1,"\\u0061x":2}`,
	} {
		add("distinct "+s, s, true)
	}
	return c
}

func nestDoc(kind byte, n int, scalar bool) string {
	s := ""
	if scalar {
		s = "1"
	}
	for lvl := n - 1; lvl >= 0; lvl-- {
		arr := kind == 'a' || (kind == 'm' && lvl%2 == 0)
		switch {
		case arr:
			s = "[" + s + "]"
		case s == "":
			s = "{}"
		default:
			s = `{"a":` + s + "}"
		}
	}
	return s
}

func bigKeys(n int, dupAt int, dupSpelling string) string {
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"k%d":%d`, i, i)
	}
	if dupAt >= 0 {
		fmt.Fprintf(&b, `,"%s":0`, strings.Replace(dupSpelling, "#", fmt.Sprint(dupAt), 1))
	}
	b.WriteByte('}')
	return b.String()
}

func validateCorpus() []validateCase {
	c := handCases()
	unknown := func(name string, in string) { c = append(c, validateCase{name, []byte(in), vUnknown}) }
	// depth boundary for arrays, objects and mixed, empty and non-empty innermost
	for _, kind := range []byte{'a', 'o', 'm'} {
		for n := 55; n <= 70; n++ {
			for _, scalar := range []bool{false, true} {
				limit := 65
				if scalar {
					limit = 64
				}
				want := vReject
				if n <= limit {
					want = vAccept
				}
				c = append(c, validateCase{fmt.Sprintf("depth %c n=%d scalar=%v", kind, n, scalar), []byte(nestDoc(kind, n, scalar)), want})
			}
		}
	}
	unknown("deep unterminated", strings.Repeat("[", 100000))
	unknown("deep terminated", strings.Repeat("[", 100000)+strings.Repeat("]", 100000))
	unknown("deep objects", strings.Repeat(`{"a":`, 5000)+"1"+strings.Repeat("}", 5000))
	unknown("wide array", "["+strings.Repeat("1,", 99999)+"1]")
	unknown("wide array of arrays", "["+strings.Repeat("[1],", 9999)+"[1]]")
	// trailing content after a valid document at the depth limit
	unknown("deep plus trailing", nestDoc('a', 64, false)+" x")
	unknown("deep plus second value", nestDoc('a', 64, false)+nestDoc('a', 1, false))
	// objects around the linear/hash threshold, with a duplicate at every position
	for _, n := range []int{1, 2, 15, 16, 17, 18, 31, 32, 33, 40} {
		unknown(fmt.Sprintf("keys n=%d distinct", n), bigKeys(n, -1, ""))
		for i := 0; i < n; i++ {
			unknown(fmt.Sprintf("keys n=%d dup %d", n, i), bigKeys(n, i, "k#"))
		}
		unknown(fmt.Sprintf("keys n=%d dup escaped", n), bigKeys(n, n-1, `\u006b#`))
	}
	for _, n := range []int{100, 300, 1000} {
		unknown(fmt.Sprintf("keys n=%d distinct", n), bigKeys(n, -1, ""))
		for _, i := range []int{0, 1, n / 3, n / 2, n - 2, n - 1} {
			unknown(fmt.Sprintf("keys n=%d dup %d", n, i), bigKeys(n, i, "k#"))
			unknown(fmt.Sprintf("keys n=%d dup escaped %d", n, i), bigKeys(n, i, `\u006b#`))
		}
	}
	// nested big objects: inner key sets reuse the outer names
	{
		inner := bigKeys(20, -1, "")
		var b strings.Builder
		b.WriteByte('{')
		for i := 0; i < 20; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `"k%d":%s`, i, inner)
		}
		b.WriteByte('}')
		unknown("nested big objects distinct", b.String())
		unknown("nested big objects dup in last inner", strings.TrimSuffix(b.String(), inner+"}")+bigKeys(20, 19, "k#")+"}")
		unknown("nested big objects dup outer after inner", strings.TrimSuffix(b.String(), "}")+`,"k0":1}`)
		unknown("nested big objects dup outer after inner escaped", strings.TrimSuffix(b.String(), "}")+`,"\u006b0":1}`)
	}
	// large strings
	mb4 := strings.Repeat("a", 4<<20)
	unknown("4MiB string", `"`+mb4+`"`)
	unknown("4MiB string value in object", `{"a":"`+mb4+`"}`)
	unknown("4MiB string key", `{"`+mb4+`":1}`)
	unknown("4MiB string with lone high at end", `"`+mb4+`\ud83d"`)
	unknown("4MiB string with pair at end", `"`+mb4+`\ud83d\ude00"`)
	unknown("4MiB string with control at end", `"`+mb4+"\x01\"")
	unknown("4MiB string invalid utf8 at end", `"`+mb4+"\xff\"")
	unknown("4MiB string unterminated", `"`+mb4)
	unknown("4MiB multibyte", `"`+strings.Repeat("é", 2<<20)+`"`)
	unknown("4MiB escapes", `"`+strings.Repeat(`\n\u00e9\ud83d\ude00`, 1<<18)+`"`)
	unknown("4MiB escaped key dup", `{"`+strings.Repeat(`\u0061`, 1<<19)+`":1,"`+strings.Repeat("a", 1<<19)+`":2}`)
	unknown("4MiB escaped key distinct", `{"`+strings.Repeat(`\u0061`, 1<<19)+`":1,"`+strings.Repeat("a", 1<<19)+`b":2}`)
	unknown("4MiB whitespace", strings.Repeat(" ", 4<<20)+"1")
	unknown("4MiB base64 value", `{"bytes":"`+base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\x00\xff\x10", 1<<20)))+`"}`)
	// 100000-key objects
	big := bigKeys(100000, -1, "")
	unknown("100000 keys distinct", big)
	unknown("100000 keys dup first at end", bigKeys(100000, 0, "k#"))
	unknown("100000 keys dup last at end", bigKeys(100000, 99999, "k#"))
	unknown("100000 keys dup escaped at end", bigKeys(100000, 77777, `\u006b#`))
	{
		var b strings.Builder
		b.WriteByte('{')
		for i := 0; i < 100000; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			if i%2 == 0 {
				fmt.Fprintf(&b, `"\u0075%d":1`, i)
			} else {
				fmt.Fprintf(&b, `"v%d":1`, i)
			}
		}
		b.WriteByte('}')
		unknown("100000 escaped-half keys distinct", b.String())
		unknown("100000 escaped-half raw dup of escaped", strings.TrimSuffix(b.String(), "}")+`,"u500":1}`)
		unknown("100000 escaped-half escaped dup of raw", strings.TrimSuffix(b.String(), "}")+`,"\u0076501":1}`)
	}
	// truncation and single-byte damage of valid documents
	docs := []string{
		`{"a":1,"b":[true,false,null,"x\u00e9\ud83d\ude00\n"],"c":{"d":-1.5e+10,"e":{}},"\u0066":[]}`,
		`[1,"a",{"k":"\ud83d\ude00"},[[]],-0,0.5,1E-2]`,
		`"\ud83d\ude00\u0041\\\"\/"`,
		`{"\u0061":1,"b":{"\u0062":2}} `,
		"  \t\r\n[ { } , [ ] ]\n",
		`-0.5e-10`,
		`{"é😀":"€"}`,
		`{"k0":1,"k1":2,"k2":3,"k3":4,"k4":5,"k5":6,"k6":7,"k7":8,"k8":9,"k9":10,"k10":11,"k11":12,"k12":13,"k13":14,"k14":15,"k15":16,"k16":17,"k17":18}`,
		"true", "false", "null",
	}
	repl := []string{`"`, `\`, `,`, `:`, `}`, `]`, `[`, `{`, `0`, `u`, `d`, ` `, "\x00", "\xff", "\n", "e", "-", "."}
	for di, d := range docs {
		for k := 0; k <= len(d); k++ {
			unknown(fmt.Sprintf("doc %d prefix %d", di, k), d[:k])
			unknown(fmt.Sprintf("doc %d suffix %d", di, k), d[k:])
			unknown(fmt.Sprintf("doc %d trailing %d", di, k), d+d[:k])
			if k < len(d) {
				unknown(fmt.Sprintf("doc %d delete %d", di, k), d[:k]+d[k+1:])
				for _, r := range repl {
					unknown(fmt.Sprintf("doc %d replace %d %q", di, k, r), d[:k]+r+d[k+1:])
					unknown(fmt.Sprintf("doc %d insert %d %q", di, k, r), d[:k]+r+d[k:])
				}
			}
		}
	}
	return c
}

func TestValidateJSONMatchesReference(t *testing.T) {
	corpus := validateCorpus()
	if len(corpus) < 200 {
		t.Fatalf("corpus has %d inputs, want at least 200", len(corpus))
	}
	accepted, rejected := 0, 0
	for _, tc := range corpus {
		ref := referenceValidateJSON(tc.in)
		got := ValidateJSON(tc.in)
		if (ref == nil) != (got == nil) {
			t.Errorf("%s: reference err=%v, ValidateJSON err=%v, input %.200q", tc.name, ref, got, tc.in)
			continue
		}
		if got != nil {
			if f, ok := got.(*Fault); !ok || f.Code != Invalid {
				t.Errorf("%s: error %v is not an Invalid fault", tc.name, got)
			}
			rejected++
		} else {
			accepted++
		}
		switch {
		case tc.want == vAccept && got != nil:
			t.Errorf("%s: want accept, rejected: %.200q", tc.name, tc.in)
		case tc.want == vReject && got == nil:
			t.Errorf("%s: want reject, accepted: %.200q", tc.name, tc.in)
		}
	}
	t.Logf("corpus: %d inputs, %d accepted, %d rejected", len(corpus), accepted, rejected)
	if accepted < 100 || rejected < 100 {
		t.Fatalf("corpus is lopsided: %d accepted, %d rejected", accepted, rejected)
	}
}

func TestValidateJSONHandCasesAreSpecifiedByReference(t *testing.T) {
	for _, tc := range handCases() {
		got := referenceValidateJSON(tc.in) == nil
		if got != (tc.want == vAccept) {
			t.Errorf("%s: reference accept=%v, case says %v: %.200q", tc.name, got, tc.want == vAccept, tc.in)
		}
	}
}

func TestValidateJSONDepthBoundary(t *testing.T) {
	for _, kind := range []byte{'a', 'o', 'm'} {
		for _, tc := range []struct {
			n      int
			scalar bool
			ok     bool
		}{{64, false, true}, {65, false, true}, {66, false, false}, {63, true, true}, {64, true, true}, {65, true, false}} {
			doc := []byte(nestDoc(kind, tc.n, tc.scalar))
			if got := ValidateJSON(doc) == nil; got != tc.ok {
				t.Errorf("kind %c n=%d scalar=%v: accept=%v, want %v", kind, tc.n, tc.scalar, got, tc.ok)
			}
			if got := referenceValidateJSON(doc) == nil; got != tc.ok {
				t.Errorf("reference kind %c n=%d scalar=%v: accept=%v, want %v", kind, tc.n, tc.scalar, got, tc.ok)
			}
		}
	}
}

func FuzzValidateJSONMatchesReference(f *testing.F) {
	for _, tc := range validateCorpus() {
		if len(tc.in) <= 4096 {
			f.Add(tc.in)
		}
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		ref := referenceValidateJSON(in)
		got := ValidateJSON(in)
		if (ref == nil) != (got == nil) {
			t.Fatalf("reference err=%v, ValidateJSON err=%v, input %q", ref, got, in)
		}
	})
}

type strictStruct struct {
	A int      `json:"a"`
	B string   `json:"b"`
	C []string `json:"c"`
}

type strictBytes struct {
	Data []byte `json:"data"`
	N    int    `json:"n"`
}

func strictTargets() []func() any {
	return []func() any{
		func() any { return new(map[string]any) },
		func() any { return new(strictStruct) },
		func() any { return new(strictBytes) },
	}
}

func strictInputs() []validateCase {
	c := validateCorpus()
	extra := []string{
		`{"a":1}`, `{"a":1} `, "{\"a\":1}\n", " \t\r\n{\"a\":1}\t", `{"a":1}x`, `{"a":1} {"a":1}`, `{"a":1}{}`, `{"a":1}1`, `{"a":1},`, `{"a":1}]`,
		`{"a":1,"b":"x","c":["y"]}`, `{"a":1,"unknown":2}`, `{"A":1}`, `{"a":"x"}`, `{"a":1.5}`, `{"a":null}`, `null`, `[]`, `"s"`, `1`, `{}`, ` {} `,
		`{"data":"AAEC","n":3}`, `{"data":"AAEC","data2":1}`, `{"data":"!!!"}`, `{"data":null}`, `{"data":""}`, `{"data":[1,2]}`, `{"data":"AAEC"}{"n":1}`,
		`{"a":1,"a":2}`, `{"a":1,"\u0061":2}`, `{"data":"\ud800"}`, `{"b":"\ud83d\ude00"}`, `{"b":"\u00e9"}`, "{\"b\":\"\xff\"}", `{"b":"x"} garbage`,
		`{"a":9223372036854775807}`, `{"a":9223372036854775808}`, `{"a":1e2}`, `{"a":-0}`,
	}
	for _, s := range extra {
		c = append(c, validateCase{"strict " + s, []byte(s), vUnknown})
	}
	return c
}

func TestStrictJSONMatchesReference(t *testing.T) {
	inputs := strictInputs()
	decoded := 0
	for _, tc := range inputs {
		if len(tc.in) > 1<<20 && !strings.HasPrefix(tc.name, "4MiB base64") {
			continue
		}
		for ti, mk := range strictTargets() {
			want, got := mk(), mk()
			wantErr := referenceStrictJSON(tc.in, want)
			gotErr := StrictJSON(tc.in, got)
			if (wantErr == nil) != (gotErr == nil) {
				t.Errorf("%s target %d: reference err=%v, StrictJSON err=%v, input %.200q", tc.name, ti, wantErr, gotErr, tc.in)
				continue
			}
			if gotErr != nil {
				if f, ok := gotErr.(*Fault); !ok || f.Code != Invalid {
					t.Errorf("%s target %d: error %v is not an Invalid fault", tc.name, ti, gotErr)
				}
				continue
			}
			decoded++
			if !reflect.DeepEqual(want, got) {
				t.Errorf("%s target %d: decoded values differ: %v vs %v", tc.name, ti, want, got)
			}
		}
	}
	if decoded < 50 {
		t.Fatalf("only %d successful decodes, corpus too weak", decoded)
	}
}

func FuzzStrictJSONMatchesReference(f *testing.F) {
	for _, tc := range strictInputs() {
		if len(tc.in) <= 4096 {
			f.Add(tc.in)
		}
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		for ti, mk := range strictTargets() {
			want, got := mk(), mk()
			wantErr := referenceStrictJSON(in, want)
			gotErr := StrictJSON(in, got)
			if (wantErr == nil) != (gotErr == nil) {
				t.Fatalf("target %d: reference err=%v, StrictJSON err=%v, input %q", ti, wantErr, gotErr, in)
			}
			if gotErr == nil && !reflect.DeepEqual(want, got) {
				t.Fatalf("target %d: decoded values differ: %v vs %v, input %q", ti, want, got, in)
			}
		}
	})
}

// validateAllocDoc builds a replicated-fragment-shaped document whose string
// value holds n bytes of base64 (plus a few escapes, which must not make
// validation copy the value either).
func validateAllocDoc(n int) []byte {
	raw := make([]byte, n)
	for i := range raw {
		raw[i] = byte(i * 31)
	}
	b64 := base64.StdEncoding.EncodeToString(raw)
	return []byte(`{"type":"artifact_fragment","artifact":{"id":"0123456789abcdef","index":3,"bytes":"` + b64 + `\n\u00e9\ud83d\ude00","tags":["a","b",{"k":1}]},"n":-1.5e3,"ok":true}`)
}

func totalAlloc(fn func()) uint64 {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	fn()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

func TestValidateJSONAllocationsAreBounded(t *testing.T) {
	small, large := validateAllocDoc(2<<10), validateAllocDoc(256<<10)
	if len(large) < 340_000 || len(large) > 360_000 || len(small) > 4_000 {
		t.Fatalf("unexpected document sizes %d and %d", len(small), len(large))
	}
	validate := ValidateJSON
	if validate(small) != nil || validate(large) != nil {
		t.Fatal("test documents must validate")
	}
	smallAllocs := testing.AllocsPerRun(20, func() { _ = validate(small) })
	largeAllocs := testing.AllocsPerRun(20, func() { _ = validate(large) })
	if largeAllocs != smallAllocs {
		t.Errorf("allocation count depends on string length: %v for %d bytes, %v for %d bytes", smallAllocs, len(small), largeAllocs, len(large))
	}
	const runs = 20
	smallBytes := totalAlloc(func() {
		for range runs {
			_ = validate(small)
		}
	}) / runs
	largeBytes := totalAlloc(func() {
		for range runs {
			_ = validate(large)
		}
	}) / runs
	t.Logf("allocs/op: %v (%d B doc), %v (%d B doc); bytes/op: %d, %d", smallAllocs, len(small), largeAllocs, len(large), smallBytes, largeBytes)
	if largeBytes > smallBytes+256 {
		t.Errorf("allocated bytes depend on string length: %d B/op for %d bytes, %d B/op for %d bytes", smallBytes, len(small), largeBytes, len(large))
	}
	if largeAllocs > 2 {
		t.Errorf("validating a well-formed document allocates %v times, want at most 2", largeAllocs)
	}
}

func BenchmarkValidateJSONFragment(b *testing.B) {
	doc := validateAllocDoc(256 << 10)
	b.SetBytes(int64(len(doc)))
	b.ReportAllocs()
	for range b.N {
		if ValidateJSON(doc) != nil {
			b.Fatal("invalid")
		}
	}
}

func BenchmarkReferenceValidateJSONFragment(b *testing.B) {
	doc := validateAllocDoc(256 << 10)
	b.SetBytes(int64(len(doc)))
	b.ReportAllocs()
	for range b.N {
		if referenceValidateJSON(doc) != nil {
			b.Fatal("invalid")
		}
	}
}
