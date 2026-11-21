// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	strconv "github.com/arynyklas/soundpost/third_party/format/go124/strconv"
	"math"
	"math/big"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/regexcompat"
	u15 "github.com/arynyklas/soundpost/third_party/regex/go124/unicode"
	"github.com/arynyklas/soundpost/third_party/templateprimitives/humanize"
	timezone "github.com/arynyklas/soundpost/third_party/timezone/go124"
)

// This is the individually enumerated pinned whitelist, not a Sprig FuncMap.
// s/i/f/t/a are concrete string/int/float64/time.Time/any parameters; * is variadic.
// Argument order is observable: pipelines append their value, including legacy aliases.
var templateSignatures = map[string]string{
	"Replace": "sssi", "ToLower": "s", "ToUpper": "s", "Trim": "ss", "TrimLeft": "ss", "TrimPrefix": "ss", "TrimRight": "ss", "TrimSpace": "s", "TrimSuffix": "ss",
	"__line__": "", "__timestamp__": "", "add": "a*", "addf": "a*", "alignLeft": "is", "alignRight": "is", "b64dec": "s", "b64enc": "s", "bytes": "s", "ceil": "a", "contains": "ss", "count": "ss", "date": "sa", "default": "aa*", "div": "aa", "divf": "aa*", "duration": "s", "duration_seconds": "s", "float64": "a", "floor": "a", "fromJson": "s", "hasPrefix": "ss", "hasSuffix": "ss", "indent": "is", "int": "a", "lower": "s", "max": "aa*", "maxf": "aa*", "min": "aa*", "minf": "aa*", "mod": "aa", "mul": "aa*", "mulf": "aa*", "nindent": "is", "now": "", "regexReplaceAll": "sss", "regexReplaceAllLiteral": "sss", "repeat": "is", "replace": "sss", "round": "aif*", "sub": "aa", "subf": "aa*", "substr": "iis", "title": "s", "toDate": "ss", "toDateInZone": "sss", "trim": "s", "trimAll": "ss", "trimPrefix": "ss", "trimSuffix": "ss", "trunc": "is", "unixEpoch": "t", "unixEpochMillis": "t", "unixEpochNanos": "t", "unixToTime": "s", "upper": "s", "urldecode": "s", "urlencode": "s",
}

func TemplateFunctions(p profile.Profile) []TemplateFunctionSpec {
	if p.ID != "logql-loki-3.5.2" || p.Commit != "257d2f62bf8a81b44dea6fe88968d1d28c8e01e7" {
		return nil
	}
	out := make([]TemplateFunctionSpec, 0, len(templateSignatures))
	for name, sig := range templateSignatures {
		var parameters []string
		for i, c := range strings.TrimSuffix(sig, "*") {
			kind := map[rune]string{'s': "string", 'i': "int", 'f': "float64", 't': "time.Time", 'a': "any"}[c]
			if strings.HasSuffix(sig, "*") && i == len(sig)-2 {
				kind = "..." + kind
			}
			parameters = append(parameters, kind)
		}
		result := "string"
		switch name {
		case "__timestamp__", "now", "toDate", "toDateInZone":
			result = "time.Time"
		case "unixToTime":
			result = "(time.Time,error)"
		case "add", "sub", "div", "mod", "mul", "min", "max":
			result = "int64"
		case "int":
			result = "int"
		case "addf", "subf", "mulf", "divf", "minf", "maxf", "ceil", "floor", "round", "float64":
			result = "float64"
		case "duration", "duration_seconds", "bytes":
			result = "(float64,error)"
		case "count":
			result = "(int,error)"
		case "default", "fromJson":
			result = "any"
		case "contains", "hasPrefix", "hasSuffix":
			result = "bool"
		case "regexReplaceAll", "regexReplaceAllLiteral", "urldecode":
			result = "(string,error)"
		}
		out = append(out, TemplateFunctionSpec{Name: name, Signature: name + "(" + strings.Join(parameters, ",") + ")->" + result})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
func templateArgs(signature string, args []any) error {
	variadic := strings.HasSuffix(signature, "*")
	if variadic {
		signature = strings.TrimSuffix(signature, "*")
	}
	minimum := len(signature)
	if variadic {
		minimum--
	}
	if len(args) < minimum || !variadic && len(args) != minimum {
		return templateBad
	}
	for i, v := range args {
		j := i
		if j >= len(signature) {
			j = len(signature) - 1
		}
		if j < 0 {
			return templateBad
		}
		if literal, ok := v.(templateLiteral); ok {
			n := literal.number
			switch signature[j] {
			case 'i':
				if !n.IsInt || int64(int(n.Int64)) != n.Int64 {
					return templateBad
				}
				v = int(n.Int64)
			case 'f':
				if !n.IsFloat {
					return templateBad
				}
				v = n.Float64
			case 'a':
				var e error
				v, e = templateDefault(v)
				if e != nil {
					return e
				}
			default:
				return templateBad
			}
			args[i] = v
		}
		switch signature[j] {
		case 's':
			if _, ok := v.(string); !ok {
				return templateBad
			}
		case 'i':
			if _, ok := v.(int); !ok {
				return templateBad
			}
		case 'f':
			if _, ok := v.(float64); !ok {
				return templateBad
			}
		case 't':
			if _, ok := v.(time.Time); !ok {
				return templateBad
			}
		}
	}
	return nil
}
func (s *templateState) stringWork(text string) error { return s.charge(int64(len(text))/64 + 1) }

// cutsetWork meters strings.Trim*: with a non-ASCII cutset of r runes every
// trimmed character is looked up in the cutset, so the cost is up to len(src)*r.
// Charged before the call, in the same units as stringWork.
func (s *templateState) cutsetWork(src, cutset string) error {
	runes := utf8.RuneCountInString(cutset)
	if runes <= 1 || len(cutset) == runes {
		return nil
	}
	return s.charge(int64(len(src))*int64(runes)/64 + 1)
}
func (s *templateState) invoke(name string, args []any) (any, error) {
	if e := s.charge(1); e != nil {
		return nil, e
	}
	sig, ok := templateSignatures[name]
	if !ok {
		return s.builtin(name, args)
	}
	if e := templateArgs(sig, args); e != nil {
		return nil, e
	}
	if e := s.reserve(256); e != nil {
		return nil, e
	}
	// Strings are scanned only after cancellation and proportional work admission.
	for _, a := range args {
		if text, ok := a.(string); ok {
			if e := s.stringWork(text); e != nil {
				return nil, e
			}
			if e := s.reserve(int64(len(text))*16 + 256); e != nil {
				return nil, e
			}
		}
	}
	str := func(i int) string { return args[i].(string) }
	integer := func(i int) int { return args[i].(int) }
	alloc := func(n int64) error { return s.reserve(n + 64) }
	switch name {
	case "__line__":
		return s.input.Line, nil
	case "__timestamp__":
		return time.Unix(0, int64(s.input.Timestamp)).In(s.template.runtime.Location), nil
	case "now":
		return s.template.runtime.Now(), nil
	case "upper", "ToUpper":
		if e := alloc(int64(len(str(0))) * 4); e != nil {
			return nil, e
		}
		return regexcompat.ToUpper(s.template.profile, str(0))
	case "lower", "ToLower":
		if e := alloc(int64(len(str(0))) * 4); e != nil {
			return nil, e
		}
		return regexcompat.ToLower(s.template.profile, str(0))
	case "title":
		if e := alloc(int64(len(str(0))) * 4); e != nil {
			return nil, e
		}
		previous := rune(' ')
		return strings.Map(func(r rune) rune {
			old := r
			if templateWordBoundary(previous) {
				r = u15.ToTitle(r)
			}
			previous = old
			return r
		}, str(0)), nil
	case "Trim":
		if e := s.cutsetWork(str(0), str(1)); e != nil {
			return nil, e
		}
		return strings.Trim(str(0), str(1)), nil
	case "TrimLeft":
		if e := s.cutsetWork(str(0), str(1)); e != nil {
			return nil, e
		}
		return strings.TrimLeft(str(0), str(1)), nil
	case "TrimRight":
		if e := s.cutsetWork(str(0), str(1)); e != nil {
			return nil, e
		}
		return strings.TrimRight(str(0), str(1)), nil
	case "TrimPrefix":
		return strings.TrimPrefix(str(0), str(1)), nil
	case "TrimSuffix":
		return strings.TrimSuffix(str(0), str(1)), nil
	case "trimAll":
		if e := s.cutsetWork(str(1), str(0)); e != nil {
			return nil, e
		}
		return strings.Trim(str(1), str(0)), nil
	case "trimPrefix":
		return strings.TrimPrefix(str(1), str(0)), nil
	case "trimSuffix":
		return strings.TrimSuffix(str(1), str(0)), nil
	case "trim", "TrimSpace":
		return strings.TrimFunc(str(0), u15.IsSpace), nil
	case "contains":
		return strings.Contains(str(1), str(0)), nil
	case "hasPrefix":
		return strings.HasPrefix(str(1), str(0)), nil
	case "hasSuffix":
		return strings.HasSuffix(str(1), str(0)), nil
	case "Replace", "replace":
		source, old, replacement, count := str(0), str(1), str(2), -1
		if name == "replace" {
			source, old, replacement = str(2), str(0), str(1)
		} else {
			count = integer(3)
		}
		occurrences := strings.Count(source, old)
		if count >= 0 && count < occurrences {
			occurrences = count
		}
		n := int64(len(source)) + int64(occurrences)*int64(len(replacement))
		if e := alloc(n); e != nil {
			return nil, e
		}
		return strings.Replace(source, old, replacement, count), nil
	case "repeat":
		n := integer(0)
		if n < 0 {
			return nil, templateBad
		}
		if n == 0 || str(1) == "" {
			return "", nil
		}
		if int64(n) > templateMaxBytes {
			return nil, &TemplateLimitError{Resource: "intermediate"}
		}
		bytes := int64(n) * int64(len(str(1)))
		if e := alloc(bytes); e != nil {
			return nil, e
		}
		if e := s.charge(int64(n)/64 + bytes/64 + 1); e != nil {
			return nil, e
		}
		return strings.Repeat(str(1), n), nil
	case "indent", "nindent":
		width := integer(0)
		if width < 0 {
			return nil, templateBad
		}
		if int64(width) > templateMaxBytes {
			return nil, &TemplateLimitError{Resource: "intermediate"}
		}
		lines := int64(strings.Count(str(1), "\n")) + 1
		n := int64(len(str(1))) + int64(width)*lines + 1
		if e := alloc(n*4 + int64(width)*2); e != nil {
			return nil, e
		}
		pad := strings.Repeat(" ", width)
		result := pad + strings.ReplaceAll(str(1), "\n", "\n"+pad)
		if name == "nindent" {
			result = "\n" + result
		}
		return result, nil
	case "trunc":
		n, source := integer(0), str(1)
		if n >= 0 {
			if n < len(source) {
				return source[:n], nil
			}
		} else if n >= -len(source) {
			return source[len(source)+n:], nil
		}
		return source, nil
	case "substr":
		start, end, source := integer(0), integer(1), str(2)
		if start < 0 {
			if end < 0 || end > len(source) {
				return nil, templateBad
			}
			return source[:end], nil
		}
		if end < 0 || end > len(source) {
			end = len(source)
		}
		if start > end || start > len(source) {
			return nil, templateBad
		}
		return source[start:end], nil
	case "alignLeft", "alignRight":
		width, source := integer(0), str(1)
		if width < 0 {
			return source, nil
		}
		if int64(width) > templateMaxBytes {
			return nil, &TemplateLimitError{Resource: "intermediate"}
		}
		count := utf8.RuneCountInString(source)
		if width >= count {
			if e := alloc(int64(len(source)) + int64(width-count)*2); e != nil {
				return nil, e
			}
			pad := strings.Repeat(" ", width-count)
			if name == "alignLeft" {
				return source + pad, nil
			}
			return pad + source, nil
		}
		if e := alloc(int64(len(source)) * 8); e != nil {
			return nil, e
		}
		runes := []rune(source)
		if name == "alignRight" {
			return string(runes[count-width:]), nil
		}
		return string(runes[:width]), nil
	case "b64enc":
		if e := alloc(int64(len(str(0)))*4 + 128); e != nil {
			return nil, e
		}
		return base64.StdEncoding.EncodeToString([]byte(str(0))), nil
	case "b64dec":
		if e := alloc(int64(len(str(0)))*3 + 128); e != nil {
			return nil, e
		}
		v, e := base64.StdEncoding.DecodeString(str(0))
		if e != nil {
			return e.Error(), nil
		}
		return string(v), nil
	case "urlencode":
		if e := alloc(int64(len(str(0))) * 6); e != nil {
			return nil, e
		}
		return url.QueryEscape(str(0)), nil
	case "urldecode":
		if e := alloc(int64(len(str(0))) * 2); e != nil {
			return nil, e
		}
		v, e := url.QueryUnescape(str(0))
		if e != nil {
			return nil, primitiveFailure(e)
		}
		return v, nil
	case "fromJson":
		// encoding/json accepts at most 10k nested containers. Its map/interface/token
		// amplification is conservatively admitted before the decoder allocates anything.
		if e := alloc(int64(len(str(0)))*128 + 4096); e != nil {
			return nil, e
		}
		var v any
		_ = json.Unmarshal([]byte(str(0)), &v)
		return v, nil
	case "duration", "duration_seconds":
		d, e := time.ParseDuration(str(0))
		if e != nil {
			return nil, primitiveFailure(e)
		}
		return d.Seconds(), nil
	case "bytes":
		if e := alloc(int64(len(str(0)))*4 + 1024); e != nil {
			return nil, e
		}
		v, e := templateParseBytes(str(0))
		if e != nil {
			return nil, primitiveFailure(e)
		}
		return v, nil
	case "int":
		return int(templateInt(args[0])), nil
	case "float64":
		return templateFloat(args[0]), nil
	case "add":
		var n int64
		for _, a := range args {
			n += templateInt(a)
		}
		return n, nil
	case "sub":
		return templateInt(args[0]) - templateInt(args[1]), nil
	case "div", "mod":
		a, b := templateInt(args[0]), templateInt(args[1])
		if b == 0 {
			return nil, templateBad
		}
		if name == "div" {
			return a / b, nil
		}
		return a % b, nil
	case "mul", "min", "max":
		n := templateInt(args[0])
		for _, a := range args[1:] {
			x := templateInt(a)
			if name == "mul" {
				n *= x
			} else if name == "max" && x > n || name == "min" && x < n {
				n = x
			}
		}
		return n, nil
	case "ceil":
		return math.Ceil(templateFloat(args[0])), nil
	case "floor":
		return math.Floor(templateFloat(args[0])), nil
	case "round":
		precision := integer(1)
		threshold := 0.5
		if len(args) > 2 {
			threshold = args[2].(float64)
		}
		factor := math.Pow10(precision)
		scaled := templateFloat(args[0]) * factor
		_, fraction := math.Modf(scaled)
		rounded := math.Floor(scaled)
		if fraction >= threshold {
			rounded = math.Ceil(scaled)
		}
		return rounded / factor, nil
	case "minf", "maxf":
		n := templateFloat(args[0])
		for _, a := range args[1:] {
			if name == "minf" {
				n = math.Min(n, templateFloat(a))
			} else {
				n = math.Max(n, templateFloat(a))
			}
		}
		return n, nil
	case "addf", "subf", "mulf", "divf":
		return s.decimal(name, args)
	case "default":
		if len(args) > 1 && templateTruth(args[1]) {
			return args[1], nil
		}
		return args[0], nil
	case "date":
		layout := str(0)
		var v time.Time
		switch x := args[1].(type) {
		case time.Time:
			v = x
		case int:
			v = time.Unix(int64(x), 0)
		case int64:
			v = time.Unix(x, 0)
		default:
			v = s.template.runtime.Now()
		}
		if e := alloc(int64(len(layout))*64 + 256); e != nil {
			return nil, e
		}
		return v.In(s.template.runtime.Location).Format(layout), nil
	case "toDate":
		if e := alloc(int64(len(str(0))+len(str(1)))*64 + 4096); e != nil {
			return nil, e
		}
		v, _ := time.ParseInLocation(str(0), str(1), s.template.runtime.Location)
		return v, nil
	case "toDateInZone":
		if e := alloc(int64(len(str(0))+len(str(1))+len(str(2)))*64 + 1048576); e != nil {
			return nil, e
		}
		loc := s.template.runtime.Location
		if str(1) != "Local" {
			var e error
			loc, e = timezone.LoadLocation(str(1))
			if e != nil {
				if errors.Is(e, timezone.ErrUnknown) {
					loc = time.UTC
				} else {
					return nil, e
				}
			}
		}
		v, _ := time.ParseInLocation(str(0), str(2), loc)
		return v, nil
	case "unixEpoch":
		return strconv.FormatInt(args[0].(time.Time).Unix(), 10), nil
	case "unixEpochMillis":
		return strconv.FormatInt(args[0].(time.Time).UnixMilli(), 10), nil
	case "unixEpochNanos":
		return strconv.FormatInt(args[0].(time.Time).UnixNano(), 10), nil
	case "unixToTime":
		text := str(0)
		n, e := strconv.ParseInt(text, 10, 64)
		if e != nil {
			return nil, unixPrimitiveFailure(text, e)
		}
		var nanos int64
		switch len(text) {
		case 5:
			n *= 86400
		case 10:
		case 13:
			nanos = n * int64(time.Millisecond)
			n = 0
		case 16:
			nanos = n * int64(time.Microsecond)
			n = 0
		case 19:
			nanos = n
			n = 0
		default:
			return nil, unixPrimitiveFailure(text, nil)
		}
		return time.Unix(n, nanos).In(s.template.runtime.Location), nil
	case "count", "regexReplaceAll", "regexReplaceAllLiteral":
		return s.regexFunction(name, args)
	}
	return nil, templateBad
}
func templateWordBoundary(r rune) bool {
	if r < 128 {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_')
	}
	if u15.IsLetter(r) || u15.IsDigit(r) {
		return false
	}
	return u15.IsSpace(r)
}
func templateInt(v any) int64 {
	switch x := v.(type) {
	case int:
		return int64(x)
	case int64:
		return x
	case uint8:
		return int64(x)
	case uint64:
		return int64(x)
	case float64:
		if math.IsNaN(x) || x >= 9223372036854775808.0 || x < -9223372036854775808.0 {
			return math.MinInt64
		}
		return int64(x)
	case bool:
		if x {
			return 1
		}
		return 0
	case string:
		// Coercion does not trim whitespace. The pinned decimal-zero suffix rule
		// also tolerates trailing dots until a zero is seen; keep its observable
		// acceptance independently of ordinary decimal number parsing.
		zero := strings.LastIndexByte(x, '0')
		if zero >= 0 && strings.Trim(x[zero+1:], ".") == "" {
			point := strings.LastIndexByte(x[:zero], '.')
			if point >= 0 && strings.Trim(x[point+1:zero], "0") == "" {
				x = x[:point]
			}
		}
		n, e := strconv.ParseInt(x, 0, 64)
		if e != nil {
			return 0
		}
		return n
	}
	return 0
}
func templateFloat(v any) float64 {
	switch x := v.(type) {
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case uint8:
		return float64(x)
	case uint64:
		return float64(x)
	case float64:
		return x
	case bool:
		if x {
			return 1
		}
	case string:
		n, e := strconv.ParseFloat(x, 64)
		if e != nil {
			return 0
		}
		return n
	}
	return 0
}

// Both byte filters and the template helper share the individually approved
// pinned MIT quantity primitive; each caller owns its admission/error projection.
func templateParseBytes(text string) (float64, error) {
	n, e := humanize.ParseBytes(text)
	return float64(n), e
}
func (s *templateState) decimal(name string, args []any) (any, error) {
	if e := s.reserve(int64(len(args))*8192 + 8192); e != nil {
		return nil, e
	}
	result := new(big.Rat)
	start := 0
	if name != "addf" {
		n := templateFloat(args[0])
		if math.IsInf(n, 0) || math.IsNaN(n) {
			return nil, templateBad
		}
		if _, ok := result.SetString(strconv.FormatFloat(n, 'f', -1, 64)); !ok {
			return nil, templateBad
		}
		start = 1
	}
	for _, a := range args[start:] {
		if e := s.charge(8); e != nil {
			return nil, e
		}
		n := templateFloat(a)
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return nil, templateBad
		}
		r, ok := new(big.Rat).SetString(strconv.FormatFloat(n, 'f', -1, 64))
		if !ok {
			return nil, templateBad
		}
		bits := int64(result.Num().BitLen() + result.Denom().BitLen() + r.Num().BitLen() + r.Denom().BitLen() + 128)
		// Admit big-number scratch and common-denominator storage before arithmetic.
		if e := s.reserve(bits*16 + 8192); e != nil {
			return nil, e
		}
		if bits > 8000000 {
			return nil, &TemplateLimitError{Resource: "work"}
		}
		if e := s.charge(bits*bits/4096 + 1); e != nil {
			return nil, e
		}
		switch name {
		case "addf":
			result.Add(result, r)
		case "subf":
			result.Sub(result, r)
		case "mulf":
			result.Mul(result, r)
		case "divf":
			if r.Sign() == 0 {
				return nil, templateBad
			}
			result.Quo(result, r)
			// The observable decimal primitive rounds every division to sixteen places,
			// half away from zero, rather than accumulating binary floating error.
			scale := big.NewInt(10000000000000000)
			num := new(big.Int).Mul(result.Num(), scale)
			q, rem := new(big.Int), new(big.Int)
			q.QuoRem(num, result.Denom(), rem)
			twice := new(big.Int).Lsh(new(big.Int).Abs(rem), 1)
			if twice.Cmp(result.Denom()) >= 0 {
				if num.Sign() < 0 {
					q.Sub(q, big.NewInt(1))
				} else {
					q.Add(q, big.NewInt(1))
				}
			}
			result.SetFrac(q, scale)
		}
		if e := s.charge(1); e != nil {
			return nil, e
		}
	}
	out, _ := result.Float64()
	return out, nil
}
func (s *templateState) regexFunction(name string, args []any) (any, error) {
	pattern, source := args[0].(string), args[1].(string)
	if e := s.reserve(int64(len(pattern)+1)*16000 + int64(len(source)+1)*64); e != nil {
		return nil, e
	}
	if s.regex == nil {
		p := s.template.profile
		if p.Identity == "" {
			p.Identity = "template"
		}
		if p.ConfigurationHash == "" {
			p.ConfigurationHash = "template"
		}
		var e error
		s.regex, e = regexcompat.NewScope(p, regexcompat.Limits{CacheEntries: 128, CachePatternBytes: 1 << 20, ProgramUnits: 1000000, PatternBytes: 16384, InputBytes: uint64(templateMaxBytes), Work: 100000000, Matches: 100000, OutputBytes: uint64(templateMaxBytes)})
		if e != nil {
			return nil, templateBad
		}
	}
	checked := templateCheckContext{Context: s.ctx, state: s}
	re, e := s.regex.Compile(checked, pattern, regexcompat.Search)
	if e != nil {
		return nil, s.regexError(e)
	}
	captures := int64(re.NumSubexp()+1) * 2
	if int64(len(source)+1) > templateMaxBytes/(captures*8+32) {
		return nil, &TemplateLimitError{Resource: "regex captures"}
	}
	if e := s.reserve(int64(len(source)+1) * (captures*8 + 32)); e != nil {
		return nil, e
	}
	matches, e := s.regex.FindAllStringSubmatchIndex(checked, re, source, -1)
	if e != nil {
		return nil, s.regexError(e)
	}
	if name == "count" {
		return len(matches), nil
	}
	replacement := args[2].(string)
	if name == "regexReplaceAllLiteral" {
		if e := s.reserve(int64(len(replacement))*2 + 64); e != nil {
			return nil, e
		}
		replacement = strings.ReplaceAll(replacement, "$", "$$")
	}
	per := int64(len(source)+1) * int64(len(replacement)+1)
	if per < 0 || per > templateMaxBytes || len(matches) > 0 && per > templateMaxBytes/int64(len(matches)) {
		return nil, &TemplateLimitError{Resource: "intermediate"}
	}
	if e := s.reserve(per*int64(len(matches)) + int64(len(source))); e != nil {
		return nil, e
	}
	out, e := s.regex.ReplaceAllString(checked, re, source, replacement)
	if e != nil {
		return nil, s.regexError(e)
	}
	return out, nil
}
func (s *templateState) regexError(e error) error {
	if s.fatal != nil {
		return s.fatal
	}
	if e == regexcompat.ErrBudget {
		return &TemplateLimitError{Resource: "regex", Cause: e}
	}
	if s.ctx.Err() != nil {
		return s.ctx.Err()
	}
	return primitiveFailure(e)
}
