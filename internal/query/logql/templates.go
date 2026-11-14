// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"encoding/json"
	"errors"
	fmt "github.com/arynyklas/soundpost/third_party/format/go124/fmt"
	strconv "github.com/arynyklas/soundpost/third_party/format/go124/strconv"
	"math"
	"sort"
	"strings"
	"text/template"
	"text/template/parse"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/regexcompat"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// TemplateRuntime deliberately contains no evaluator timestamp or ambient capabilities.
// Location is required; a nil clock selects the real wall clock, never query time.
type TemplateRuntime struct {
	Now      func() time.Time
	Location *time.Location
}
type TemplateInput struct {
	Line      string
	Timestamp model.UnixNano
	Labels    model.Labels
	Fields    []TypedField
}
type TemplateFunctionSpec struct {
	Name      string
	Signature string
}
type Template struct {
	root        *parse.Tree
	trees       map[string]*parse.Tree
	profile     profile.Profile
	runtime     TemplateRuntime
	sourceBytes int64
}

// Error() is safe diagnostic text. LanguageDetail() is separately projected only
// into authorized query result labels, never automatic logging or JSON fields.
type TemplateError struct {
	Phase          string
	languageDetail string
	semanticCode   string
}

func (e *TemplateError) Error() string       { return "LogQL template " + e.Phase + " failed" }
func (e *TemplateError) SafeMessage() string { return e.Error() }
func (e *TemplateError) GoString() string    { return e.Error() }

type TemplateLimitError struct {
	Resource string
	Cause    error
}

func (e *TemplateLimitError) Error() string {
	return "LogQL template " + e.Resource + " limit exceeded"
}
func (e *TemplateLimitError) Unwrap() error { return e.Cause }

var templateBad = &TemplateError{Phase: "execution"}
var templateBreak = errors.New("template range break")
var templateContinue = errors.New("template range continue")

const templateMaxBytes int64 = 16 << 20
const templateMaxWork int64 = 1000000
const templateMaxDepth = 128

func CompileTemplate(source string, p profile.Profile, runtime TemplateRuntime) (*Template, error) {
	return compileTemplateNamed(source, p, runtime, "line")
}
func compileLabelTemplate(source string, p profile.Profile, runtime TemplateRuntime) (*Template, error) {
	return compileTemplateNamed(source, p, runtime, "label")
}
func compileTemplateNamed(source string, p profile.Profile, runtime TemplateRuntime, rootName string) (*Template, error) {
	if p.ID != "logql-loki-3.5.2" || p.Commit != "257d2f62bf8a81b44dea6fe88968d1d28c8e01e7" || runtime.Location == nil {
		return nil, &TemplateError{Phase: "configuration"}
	}
	if len(source) > 256<<10 {
		return nil, &TemplateLimitError{Resource: "source"}
	}
	if runtime.Now == nil {
		runtime.Now = time.Now
	}
	names := template.FuncMap{}
	for _, s := range TemplateFunctions(p) {
		names[s.Name] = func(...any) (any, error) { return nil, templateBad }
	}
	// Only parsing is delegated. No Go template executor or reflective input binding runs.
	parsed, e := template.New(rootName).Funcs(names).Option("missingkey=zero").Parse(source)
	if e != nil {
		return nil, &TemplateError{Phase: "parse"}
	}
	trees := make(map[string]*parse.Tree)
	remaining := 100000
	for _, t := range parsed.Templates() {
		if e := templateValidate(t.Tree.Root, &remaining, 0); e != nil {
			return nil, e
		}
		trees[t.Name()] = t.Tree
	}
	return &Template{root: parsed.Tree, trees: trees, profile: profile.Profile{ID: p.ID, Commit: p.Commit, Identity: p.Identity, ConfigurationHash: p.ConfigurationHash}, runtime: runtime, sourceBytes: int64(len(source))}, nil
}

type templateBinding struct {
	name  string
	value any
}

// Root label-map misses are zero strings; decoded JSON-map misses are nil.
type templateRoot map[string]any
type templateLiteral struct{ number *parse.NumberNode }

func templateDefault(v any) (any, error) {
	literal, ok := v.(templateLiteral)
	if !ok {
		return v, nil
	}
	n := literal.number
	if n.IsComplex && strings.HasSuffix(n.Text, "i") {
		return n.Complex128, nil
	}
	if strings.ContainsAny(n.Text, ".eEpP") && n.IsFloat {
		return n.Float64, nil
	}
	if n.IsInt && int64(int(n.Int64)) == n.Int64 {
		return int(n.Int64), nil
	}
	if n.IsFloat && !n.IsUint {
		return n.Float64, nil
	}
	return nil, templateBad
}

type templateState struct {
	ctx            context.Context
	account        value.Account
	template       *Template
	input          TemplateInput
	reserved, work int64
	depth          int
	vars           []templateBinding
	output         strings.Builder
	regex          *regexcompat.Scope
	fatal          error
	node           parse.Node
	tree           *parse.Tree
}

// Regex VM cancellation checkpoints also enforce query-account authorization;
// the first failure is sticky and can never be demoted to a formatting error.
type templateCheckContext struct {
	context.Context
	state *templateState
}

func (c templateCheckContext) Err() error {
	if c.state.fatal != nil {
		return c.state.fatal
	}
	if e := c.Context.Err(); e != nil {
		c.state.fatal = e
		return e
	}
	if e := c.state.account.Check(c.Context); e != nil {
		c.state.fatal = e
		return e
	}
	return nil
}
func (t *Template) Execute(ctx context.Context, input TemplateInput, account value.Account) (result string, err error) {
	if t == nil || account == nil || ctx == nil {
		return "", &TemplateError{Phase: "configuration"}
	}
	s := &templateState{ctx: ctx, account: account, template: t, input: input, tree: t.root}
	defer func() {
		account.Release(s.reserved)
		if recover() != nil {
			result = ""
			err = errors.New("LogQL template internal execution failure")
		}
		if err != nil {
			result = ""
		}
	}()
	if err = s.charge(1); err != nil {
		return "", err
	}
	if err = s.reserve(int64(len(input.Labels)+len(input.Fields))*96 + 128); err != nil {
		return "", err
	}
	rootData, err := s.bindInput()
	if err != nil {
		return "", err
	}
	s.vars = []templateBinding{{"$", rootData}}
	if err = s.walk(t.root.Root, rootData); err != nil {
		if err == templateBad {
			err = errors.New("LogQL template internal value contract failure")
		}
		return "", err
	}
	if err = s.charge(1); err != nil {
		return "", err
	}
	return s.output.String(), nil
}
func (s *templateState) bindInput() (any, error) {
	if len(s.input.Fields) == 0 {
		labels := make(map[string]string, len(s.input.Labels))
		for _, l := range s.input.Labels {
			if e := s.charge(1); e != nil {
				return nil, e
			}
			labels[l.Name] = l.Value
		}
		return labels, nil
	}
	root := make(templateRoot, len(s.input.Labels)+len(s.input.Fields))
	// Typed scalars stay closed; current stage labels win name collisions.
	for _, f := range s.input.Fields {
		// The scalar is encoded first (bounded by its own size), then the
		// decoder buffers and the decoded value are reserved from that size
		// before the decoder runs.
		raw, e := f.Value.MarshalJSON()
		if e != nil {
			return nil, templateBad
		}
		if e = s.reserve(int64(len(raw))*8 + 1024); e != nil {
			return nil, e
		}
		var v any
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.UseNumber()
		if decoder.Decode(&v) != nil {
			return nil, templateBad
		}
		if n, ok := v.(json.Number); ok {
			v, e = strconv.ParseInt(string(n), 10, 64)
			if e != nil {
				return nil, templateBad
			}
		}
		root[f.Name] = v
	}
	for _, l := range s.input.Labels {
		if e := s.charge(1); e != nil {
			return nil, e
		}
		root[l.Name] = l.Value
	}
	stringsOnly := true
	for _, v := range root {
		if e := s.charge(1); e != nil {
			return nil, e
		}
		if _, ok := v.(string); !ok {
			stringsOnly = false
			break
		}
	}
	if !stringsOnly {
		return root, nil
	}
	if e := s.reserve(int64(len(root))*96 + 64); e != nil {
		return nil, e
	}
	labels := make(map[string]string, len(root))
	for k, v := range root {
		if e := s.charge(1); e != nil {
			return nil, e
		}
		labels[k] = v.(string)
	}
	return labels, nil
}
func (s *templateState) charge(n int64) error {
	if n < 0 || n > templateMaxWork-s.work {
		return &TemplateLimitError{Resource: "work"}
	}
	s.work += n
	if e := s.ctx.Err(); e != nil {
		return e
	}
	return s.account.Check(s.ctx)
}
func (s *templateState) reserve(n int64) error {
	if e := s.charge(n/64 + 1); e != nil {
		return e
	}
	if n < 0 || n > templateMaxBytes || n > math.MaxInt64-s.reserved {
		return &TemplateLimitError{Resource: "memory"}
	}
	if e := s.account.Reserve(n); e != nil {
		return &TemplateLimitError{Resource: "memory", Cause: e}
	}
	s.reserved += n
	return nil
}
func (s *templateState) outputString(text string) error {
	if int64(len(text)) > templateMaxBytes-int64(s.output.Len()) {
		return &TemplateLimitError{Resource: "output"}
	}
	// Builder growth may retain the previous backing array: reserve twice before writing.
	if e := s.reserve(int64(len(text))*2 + 64); e != nil {
		return e
	}
	s.output.WriteString(text)
	return nil
}
func (s *templateState) push(name string, v any) error {
	if e := s.reserve(48); e != nil {
		return e
	}
	s.vars = append(s.vars, templateBinding{name, v})
	return nil
}
func (s *templateState) assign(name string, v any) error {
	for i := len(s.vars) - 1; i >= 0; i-- {
		if s.vars[i].name == name {
			s.vars[i].value = v
			return nil
		}
	}
	return s.fail("undefined variable: %s", name)
}
func (s *templateState) variable(name string) (any, error) {
	for i := len(s.vars) - 1; i >= 0; i-- {
		if s.vars[i].name == name {
			return s.vars[i].value, nil
		}
	}
	return nil, s.fail("undefined variable: %s", name)
}
func (s *templateState) walk(list *parse.ListNode, dot any) error {
	if list == nil {
		return nil
	}
	s.depth++
	defer func() { s.depth-- }()
	if s.depth > templateMaxDepth {
		return &TemplateLimitError{Resource: "depth"}
	}
	for _, node := range list.Nodes {
		if e := s.charge(1); e != nil {
			return e
		}
		s.node = node
		switch n := node.(type) {
		case *parse.TextNode:
			if int64(len(n.Text)) > templateMaxBytes-int64(s.output.Len()) {
				return &TemplateLimitError{Resource: "output"}
			}
			if e := s.reserve(int64(len(n.Text))*2 + 64); e != nil {
				return e
			}
			s.output.Write(n.Text)
		case *parse.ActionNode:
			v, e := s.pipe(n.Pipe, dot, true)
			if e != nil {
				return e
			}
			if len(n.Pipe.Decl) == 0 {
				str, e := s.stringify(v)
				if e != nil {
					return e
				}
				if e = s.outputString(str); e != nil {
					return e
				}
			}
		case *parse.IfNode:
			mark := len(s.vars)
			v, e := s.pipe(n.Pipe, dot, true)
			if e != nil {
				return e
			}
			if templateTruth(v) {
				e = s.walk(n.List, dot)
			} else {
				e = s.walk(n.ElseList, dot)
			}
			s.vars = s.vars[:mark]
			if e != nil {
				return e
			}
		case *parse.WithNode:
			mark := len(s.vars)
			v, e := s.pipe(n.Pipe, dot, true)
			if e != nil {
				return e
			}
			if templateTruth(v) {
				e = s.walk(n.List, v)
			} else {
				e = s.walk(n.ElseList, dot)
			}
			s.vars = s.vars[:mark]
			if e != nil {
				return e
			}
		case *parse.RangeNode:
			if e := s.rangeNode(n, dot); e != nil {
				return e
			}
		case *parse.BreakNode:
			return templateBreak
		case *parse.ContinueNode:
			return templateContinue
		case *parse.TemplateNode:
			tree := s.template.trees[n.Name]
			if tree == nil {
				return s.fail("template %q not defined", n.Name)
			}
			v, e := s.pipe(n.Pipe, dot, false)
			if e != nil {
				return e
			}
			saved, oldTree := s.vars, s.tree
			if e = s.reserve(48); e != nil {
				return e
			}
			s.vars = []templateBinding{{"$", v}}
			s.tree = tree
			e = s.walk(tree.Root, v)
			s.tree = oldTree
			s.vars = saved
			if e != nil {
				return e
			}
		default:
			return templateBad
		}
	}
	return nil
}
func (s *templateState) rangeNode(n *parse.RangeNode, dot any) error {
	mark := len(s.vars)
	defer func() { s.vars = s.vars[:mark] }()
	v, e := s.pipe(n.Pipe, dot, false)
	if e != nil {
		return e
	}
	declarations := n.Pipe.Decl
	for _, d := range declarations {
		if n.Pipe.IsAssign {
			e = s.assign(d.Ident[0], v)
		} else {
			e = s.push(d.Ident[0], v)
		}
		if e != nil {
			return e
		}
	}
	iterMark := len(s.vars)
	count := 0
	iteration := func(k, v any) error {
		if e := s.charge(1); e != nil {
			return e
		}
		count++
		s.vars = s.vars[:iterMark]
		for i, d := range declarations {
			val := v
			if len(declarations) > 1 && i == 0 {
				val = k
			}
			if e := s.assign(d.Ident[0], val); e != nil {
				return e
			}
		}
		e := s.walk(n.List, v)
		if e == templateContinue {
			return nil
		}
		return e
	}
	if root, ok := v.(templateRoot); ok {
		v = map[string]any(root)
	}
	if len(declarations) > 1 {
		switch v.(type) {
		case int, int64, uint64, uint8, time.Month, time.Weekday, time.Duration:
			return s.fail("can't use %v to iterate over more than one variable", v)
		}
	}
	switch x := v.(type) {
	case nil:
	case int:
		for i := range x {
			e = iteration(i, i)
			if e == templateBreak {
				break
			}
			if e != nil {
				return e
			}
		}
	case int64:
		for i := range x {
			e = iteration(i, i)
			if e == templateBreak {
				break
			}
			if e != nil {
				return e
			}
		}
	case uint64:
		for i := range x {
			e = iteration(i, i)
			if e == templateBreak {
				break
			}
			if e != nil {
				return e
			}
		}
	case uint8:
		for i := range x {
			e = iteration(i, i)
			if e == templateBreak {
				break
			}
			if e != nil {
				return e
			}
		}
	case time.Month:
		for i := range x {
			e = iteration(i, i)
			if e == templateBreak {
				break
			}
			if e != nil {
				return e
			}
		}
	case time.Weekday:
		for i := range x {
			e = iteration(i, i)
			if e == templateBreak {
				break
			}
			if e != nil {
				return e
			}
		}
	case time.Duration:
		for i := range x {
			e = iteration(i, i)
			if e == templateBreak {
				break
			}
			if e != nil {
				return e
			}
		}
	case []any:
		for i, v := range x {
			e = iteration(i, v)
			if e == templateBreak {
				break
			}
			if e != nil {
				return e
			}
		}
	case []byte:
		for i, v := range x {
			e = iteration(i, v)
			if e == templateBreak {
				break
			}
			if e != nil {
				return e
			}
		}
	case map[string]any:
		if e = s.reserve(int64(len(x)) * 32); e != nil {
			return e
		}
		if e = s.sortWork(len(x)); e != nil {
			return e
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			if e = s.charge(1); e != nil {
				return e
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			e = iteration(k, x[k])
			if e == templateBreak {
				break
			}
			if e != nil {
				return e
			}
		}
	case map[string]string:
		if e = s.reserve(int64(len(x)) * 32); e != nil {
			return e
		}
		if e = s.sortWork(len(x)); e != nil {
			return e
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			if e = s.charge(1); e != nil {
				return e
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			e = iteration(k, x[k])
			if e == templateBreak {
				break
			}
			if e != nil {
				return e
			}
		}
	default:
		return s.fail("range can't iterate over %v", v)
	}
	if count == 0 {
		return s.walk(n.ElseList, dot)
	}
	return nil
}
func (s *templateState) pipe(p *parse.PipeNode, dot any, bind bool) (any, error) {
	if p == nil {
		return nil, nil
	}
	if e := s.charge(1); e != nil {
		return nil, e
	}
	var prior any
	have := false
	for _, cmd := range p.Cmds {
		v, e := s.command(cmd, dot, prior, have)
		if e != nil {
			return nil, e
		}
		prior = v
		have = true
	}
	if bind {
		for _, d := range p.Decl {
			var e error
			if p.IsAssign {
				e = s.assign(d.Ident[0], prior)
			} else {
				e = s.push(d.Ident[0], prior)
			}
			if e != nil {
				return nil, e
			}
		}
	}
	return prior, nil
}
func (s *templateState) command(cmd *parse.CommandNode, dot, prior any, have bool) (any, error) {
	if e := s.charge(1); e != nil {
		return nil, e
	}
	if len(cmd.Args) == 0 {
		return nil, templateBad
	}
	if id, ok := cmd.Args[0].(*parse.IdentifierNode); ok {
		s.node = id
		signature, ok := templateSignature(id.Ident)
		if !ok {
			return nil, s.fail("%q is not a defined function", id.Ident)
		}
		count := len(cmd.Args) - 1
		if have {
			count++
		}
		if e := s.arity(id.Ident, signature, count, len(cmd.Args)-1); e != nil {
			return nil, e
		}
		if id.Ident == "and" || id.Ident == "or" {
			var v any
			for _, a := range cmd.Args[1:] {
				var e error
				v, e = s.argument(a, dot, 'a')
				if e != nil {
					return nil, e
				}
				if templateTruth(v) == (id.Ident == "or") {
					return v, nil
				}
			}
			if have {
				v = prior
			}
			return v, nil
		}
		if e := s.reserve(int64(count)*24 + 64); e != nil {
			return nil, e
		}
		args := make([]any, 0, count)
		for i, a := range cmd.Args[1:] {
			v, e := s.argument(a, dot, templateParameter(signature, i))
			if e != nil {
				return nil, e
			}
			args = append(args, v)
		}
		if have {
			v, e := s.argumentValue(prior, templateParameter(signature, len(args)))
			if e != nil {
				return nil, e
			}
			args = append(args, v)
		}
		return s.callAt(id.Ident, args, cmd)
	}
	if len(cmd.Args) > 1 || have {
		return s.methodCommand(cmd.Args[0], dot, cmd.Args[1:], prior, have)
	}
	if _, nilCommand := cmd.Args[0].(*parse.NilNode); nilCommand {
		s.node = cmd.Args[0]
		return nil, s.fail("nil is not a command")
	}
	v, e := s.atom(cmd.Args[0], dot)
	if e != nil {
		return nil, e
	}
	v, e = templateDefault(v)
	if e != nil {
		return nil, s.fail("%s overflows int", cmd.Args[0])
	}
	return v, nil
}
func (s *templateState) atom(node parse.Node, dot any) (any, error) {
	if e := s.charge(1); e != nil {
		return nil, e
	}
	s.node = node
	switch n := node.(type) {
	case *parse.DotNode:
		return dot, nil
	case *parse.NilNode:
		return nil, nil
	case *parse.StringNode:
		return n.Text, nil
	case *parse.BoolNode:
		return n.True, nil
	case *parse.NumberNode:
		return templateLiteral{n}, nil
	case *parse.FieldNode:
		return s.fields(dot, n.Ident)
	case *parse.VariableNode:
		v, e := s.variable(n.Ident[0])
		if e != nil {
			return nil, e
		}
		return s.fields(v, n.Ident[1:])
	case *parse.ChainNode:
		v, e := s.atom(n.Node, dot)
		if e != nil {
			return nil, e
		}
		return s.fields(v, n.Field)
	case *parse.PipeNode:
		return s.pipe(n, dot, true)
	case *parse.IdentifierNode:
		return s.call(n.Ident, nil)
	}
	return nil, templateBad
}
func (s *templateState) fields(v any, names []string) (any, error) {
	value, _, e := s.fieldChain(v, names)
	return value, e
}

// A map's nil interface element is still a valid interface{} receiver within
// one field chain. A completed pipeline unwraps it into an invalid/nil value.
// Keeping that distinction local preserves both native missing-map errors and
// untyped nil/variable-boundary behavior without exposing a wrapper to helpers.
func (s *templateState) fieldChain(v any, names []string) (any, bool, error) {
	interfaceNil := false
	for _, name := range names {
		if e := s.charge(1); e != nil {
			return nil, false, e
		}
		if interfaceNil {
			return nil, false, s.fail("nil pointer evaluating interface {}.%s", name)
		}
		switch x := v.(type) {
		case templateRoot:
			var ok bool
			v, ok = x[name]
			if !ok {
				v = ""
			} else {
				interfaceNil = v == nil
			}
		case map[string]string:
			v = x[name]
		case map[string]any:
			v = x[name]
			interfaceNil = v == nil
		case time.Time, time.Duration, time.Month, time.Weekday, *time.Location:
			var e error
			v, e = s.invokeMethod(v, name, nil)
			if e != nil {
				return nil, false, e
			}
		case nil:
			v = nil
		default:
			return nil, false, s.fail("can't evaluate field %s in type %s", name, templateType(v))
		}
	}
	return v, interfaceNil, nil
}
func templateTruth(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return len(x) > 0
	case int:
		return x != 0
	case int64:
		return x != 0
	case uint64:
		return x != 0
	case uint8:
		return x != 0
	case time.Month:
		return x != 0
	case time.Weekday:
		return x != 0
	case time.Duration:
		return x != 0
	case float64:
		return x != 0
	case complex128:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	case map[string]string:
		return len(x) > 0
	case templateRoot:
		return len(x) > 0
	case []byte:
		return len(x) > 0
	}
	return true
}
func (s *templateState) valueSize(v any, depth int) (int64, error) {
	if e := s.charge(1); e != nil {
		return 0, e
	}
	if depth > templateMaxDepth {
		return 0, &TemplateLimitError{Resource: "depth"}
	}
	n := int64(128)
	if root, ok := v.(templateRoot); ok {
		v = map[string]any(root)
	}
	switch x := v.(type) {
	case string:
		n += int64(len(x)) * 8
	case []byte:
		n += int64(len(x)) * 8
	case time.Time:
		zone, _ := x.Zone()
		n += int64(len(zone)+len(x.Location().String())) * 8
	case *time.Location:
		n += int64(len(x.String())) * 8
	case []any:
		for _, v := range x {
			z, e := s.valueSize(v, depth+1)
			if e != nil {
				return 0, e
			}
			n += z
			if n > templateMaxBytes {
				return 0, &TemplateLimitError{Resource: "intermediate"}
			}
		}
	case map[string]any:
		if e := s.sortWork(len(x)); e != nil {
			return 0, e
		}
		for k, v := range x {
			z, e := s.valueSize(v, depth+1)
			if e != nil {
				return 0, e
			}
			n += int64(len(k))*8 + z
			if n > templateMaxBytes {
				return 0, &TemplateLimitError{Resource: "intermediate"}
			}
		}
	case map[string]string:
		if e := s.sortWork(len(x)); e != nil {
			return 0, e
		}
		for k, v := range x {
			if e := s.charge(1); e != nil {
				return 0, e
			}
			n += int64(len(k)+len(v))*8 + 128
			if n > templateMaxBytes {
				return 0, &TemplateLimitError{Resource: "intermediate"}
			}
		}
	}
	return n, nil
}
func (s *templateState) stringify(v any) (string, error) {
	n, e := s.valueSize(v, 0)
	if e != nil {
		return "", e
	}
	if e = s.reserve(n + 1024); e != nil {
		return "", e
	}
	if v == nil {
		return "<no value>", nil
	}
	return fmt.Sprint(v), nil
}
func (s *templateState) sortWork(n int) error {
	levels := int64(1)
	for k := n; k > 1; k /= 2 {
		levels++
	}
	return s.charge(int64(n)*levels + 1)
}
