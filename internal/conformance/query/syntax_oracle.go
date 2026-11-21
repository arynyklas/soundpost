// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

type SyntaxProbe struct {
	ID         string `json:"id"`
	Expression string `json:"expression"`
	Formatted  string `json:"formatted"`
}
type SyntaxObservation struct {
	ID                 string `json:"id"`
	Accepted           bool   `json:"accepted"`
	ValueType          string `json:"type,omitempty"`
	Formatted          string `json:"formatted,omitempty"`
	FormatPreservedAST bool   `json:"format_preserved_ast"`
	ErrorType          string `json:"error_type,omitempty"`
	ErrorCategory      string `json:"error_category,omitempty"`
	ErrorText          string `json:"error_text,omitempty"`
	StartByte          *int   `json:"start_byte,omitempty"`
	// HTTP exposes only the start in line:byte-column diagnostic text, never End.
	EndPositionExposed bool `json:"end_position_exposed"`
}
type parserEnvelope struct {
	Status    string          `json:"status"`
	Data      json.RawMessage `json:"data"`
	ErrorType string          `json:"errorType"`
	Error     string          `json:"error"`
}

func parserRequest(ctx context.Context, client *http.Client, base, endpoint, expression string) (parserEnvelope, error) {
	var result parserEnvelope
	body := url.Values{"query": {expression}}.Encode()
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, base+endpoint, strings.NewReader(body))
	if e != nil {
		return result, e
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, e := client.Do(req)
	if e != nil {
		return result, e
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if e != nil {
		return result, e
	}
	if len(raw) > 4<<20 {
		return result, fmt.Errorf("parser observation exceeds bound")
	}
	if e = json.Unmarshal(raw, &result); e != nil {
		return result, fmt.Errorf("invalid parser observation: %w", e)
	}
	if response.StatusCode == 400 || response.StatusCode == 422 {
		if result.Status != "error" || result.ErrorType != "bad_data" || result.Error == "" {
			return result, fmt.Errorf("unexpected parser rejection envelope")
		}
		return result, nil
	}
	if response.StatusCode != 200 || result.Status != "success" {
		return result, fmt.Errorf("parser transport unavailable: HTTP %d %s", response.StatusCode, raw)
	}
	return result, nil
}
func decodeReferenceAST(raw json.RawMessage) (map[string]any, error) {
	var ast map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if e := d.Decode(&ast); e != nil {
		return nil, e
	}
	return ast, nil
}

// referenceType reads public AST result metadata; it does not parse or evaluate
// source text. Both exact release endpoints expose these node discriminator names.
func referenceType(ast map[string]any) (string, error) {
	child := func(name string) (string, error) {
		v, ok := ast[name].(map[string]any)
		if !ok {
			return "", fmt.Errorf("missing reference AST child %s", name)
		}
		return referenceType(v)
	}
	switch ast["type"] {
	case "numberLiteral", "durationExpr":
		return "scalar", nil
	case "stringLiteral":
		return "string", nil
	case "vectorSelector", "aggregation":
		return "vector", nil
	case "matrixSelector", "subquery":
		return "matrix", nil
	case "parenExpr", "unaryExpr":
		return child("expr")
	case "call":
		f, ok := ast["func"].(map[string]any)
		if !ok {
			return "", fmt.Errorf("missing reference function metadata")
		}
		t, ok := f["returnType"].(string)
		if !ok {
			return "", fmt.Errorf("missing reference return type")
		}
		return t, nil
	case "binaryExpr":
		a, e := child("lhs")
		if e != nil {
			return "", e
		}
		b, e := child("rhs")
		if e != nil {
			return "", e
		}
		if a == "vector" || b == "vector" {
			return "vector", nil
		}
		return "scalar", nil
	default:
		return "", fmt.Errorf("unobserved reference AST node type %v", ast["type"])
	}
}

var referencePosition = regexp.MustCompile(`(?:^|\s)([0-9]+):([0-9]+): parse error:`)

func referenceStart(expression, message string) (*int, error) {
	m := referencePosition.FindStringSubmatch(message)
	if m == nil {
		return nil, nil
	}
	line, _ := strconv.Atoi(m[1])
	column, _ := strconv.Atoi(m[2])
	if line < 1 || column < 1 {
		return nil, fmt.Errorf("invalid reference position")
	}
	offset := 0
	for i := 1; i < line; i++ {
		n := strings.IndexByte(expression[offset:], '\n')
		if n < 0 {
			return nil, fmt.Errorf("reference line outside expression")
		}
		offset += n + 1
	}
	offset += column - 1
	if offset > len(expression) {
		return nil, fmt.Errorf("reference byte position outside expression")
	}
	return &offset, nil
}
func referenceErrorCategory(text string) string {
	// Source-derived distinctions for function/operand checking. The HTTP API
	// otherwise exposes one parse-error class and no private Go checkAST category.
	for _, phrase := range []string{"expected type ", "argument(s) in call to", "arguments in call to", "binary expression must contain", "vector matching only allowed", "aggregation expression", "function \""} {
		if strings.Contains(text, phrase) {
			return "type"
		}
	}
	return "syntax-or-type"
}
func normalizeReferenceTree(v any) any {
	switch t := v.(type) {
	case map[string]any:
		if t["type"] == "parenExpr" {
			return normalizeReferenceTree(t["expr"])
		}
		r := make(map[string]any, len(t))
		for k, v := range t {
			r[k] = normalizeReferenceTree(v)
		}
		return r
	case []any:
		r := make([]any, len(t))
		for i, v := range t {
			r[i] = normalizeReferenceTree(v)
		}
		return r
	default:
		return v
	}
}
func observeSyntax(ctx context.Context, client *http.Client, base string, probes []SyntaxProbe) ([]SyntaxObservation, error) {
	if len(probes) == 0 {
		return nil, fmt.Errorf("empty syntax batch")
	}
	out := make([]SyntaxObservation, 0, len(probes))
	seen := map[string]bool{}
	for _, probe := range probes {
		if probe.ID == "" || seen[probe.ID] {
			return nil, fmt.Errorf("duplicate or empty syntax case")
		}
		seen[probe.ID] = true
		observation := SyntaxObservation{ID: probe.ID}
		parsed, e := parserRequest(ctx, client, base, "/api/v1/parse_query", probe.Expression)
		if e != nil {
			return nil, e
		}
		if parsed.Status == "error" {
			observation.ErrorType = parsed.ErrorType
			observation.ErrorText = parsed.Error
			observation.ErrorCategory = referenceErrorCategory(parsed.Error)
			observation.StartByte, e = referenceStart(probe.Expression, parsed.Error)
			if e != nil {
				return nil, e
			}
			out = append(out, observation)
			continue
		}
		observation.Accepted = true
		tree, e := decodeReferenceAST(parsed.Data)
		if e != nil {
			return nil, e
		}
		observation.ValueType, e = referenceType(tree)
		if e != nil {
			return nil, e
		}
		formatted, e := parserRequest(ctx, client, base, "/api/v1/format_query", probe.Expression)
		if e != nil {
			return nil, e
		}
		if formatted.Status != "success" {
			return nil, fmt.Errorf("reference formatter rejected accepted expression")
		}
		if e = json.Unmarshal(formatted.Data, &observation.Formatted); e != nil {
			return nil, e
		}
		if probe.Formatted != "" {
			roundtrip, e := parserRequest(ctx, client, base, "/api/v1/parse_query", probe.Formatted)
			if e != nil {
				return nil, e
			}
			if roundtrip.Status == "success" {
				other, e := decodeReferenceAST(roundtrip.Data)
				if e != nil {
					return nil, e
				}
				observation.FormatPreservedAST = reflect.DeepEqual(normalizeReferenceTree(tree), normalizeReferenceTree(other))
			}
		}
		out = append(out, observation)
	}
	return out, nil
}
