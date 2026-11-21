// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"encoding/json"
	"slices"
	"testing"
)

// The registry of axes and values the builders implement is the one place Generate
// consults, so it must say exactly what the builders do: every value it lists
// changes the generated case (a listed value no builder branch implements would be
// counted as covered while generating the default), and the locked spec declares
// nothing outside it.
func TestEveryImplementedAxisValueChangesWhatIsGenerated(t *testing.T) {
	for language, axes := range builderAxes {
		base := map[string]string{}
		for axis, values := range axes {
			base[axis] = values[0]
		}
		for axis, values := range axes {
			seen := map[string]string{}
			for _, value := range values {
				c := map[string]string{}
				for k, v := range base {
					c[k] = v
				}
				c[axis] = value
				r := &splitmix{s: 7}
				var expr string
				var in []InputRecord
				if language == "promql" {
					expr, in = promExpression(c, r), promInput(c)
				} else {
					expr, in = logExpression(c, r), logInput(c)
				}
				raw, _ := json.Marshal(in)
				key := expr + "\x00" + string(raw)
				if prev, dup := seen[key]; dup {
					t.Errorf("%s: %s=%s is listed as implemented but generates what %s=%s generates", language, axis, value, axis, prev)
				}
				seen[key] = value
			}
		}
	}
}

func TestTheLockedSpecDeclaresOnlyWhatTheBuildersImplement(t *testing.T) {
	spec := realSpec(t)
	if err := spec.checkBuilders(); err != nil {
		t.Fatal(err)
	}
	for _, l := range spec.Languages {
		for _, a := range l.Axes {
			implemented := builderAxes[l.Language][a.ID]
			for _, v := range a.Values {
				if !slices.Contains(implemented, v) {
					t.Errorf("%s axis %s declares %s", l.Language, a.ID, v)
				}
			}
		}
	}
	// The builders read no axis the locked spec leaves undeclared.
	for _, l := range spec.Languages {
		if len(builderAxes[l.Language]) != len(l.Axes) {
			t.Errorf("%s: the builders implement %d axes, the spec declares %d", l.Language, len(builderAxes[l.Language]), len(l.Axes))
		}
	}
}
