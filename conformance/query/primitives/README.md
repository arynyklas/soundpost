# Pinned generic primitive differential probe

Copyright 2026 Aryn Yklas. Apache-2.0 first-party tooling and independently authored inputs; original downloaded generic Go/Grafana primitives retain BSD-3-Clause.

Development-only. No production package imports these source templates or references. The source files ending `.go.txt` are assembled in ignored private modules only when the probe is explicitly invoked. It neither imports upstream telemetry engines nor treats optimized selectors as equivalent to direct primitive compilation.

Run from the repository root with Python 3.10+ and the owned Go1.27.3 compiler:

```text
python -m unittest discover -s conformance/query/primitives -p "test_*.py"
python conformance/query/primitives/probe.py --own-go .tools/go/bin/go.exe --output .tools/primitive-probe/results.json
```

On Linux amd64 substitute `python3` and `.tools/linux/go/bin/go`. The first probe invocation acquires missing hash-pinned exact reference compiler/module archives; it does not mutate root dependencies, locks, source inventories or profiles. Downloads and build caches live in ignored `.tools/primitive-probe`; temporary generated modules and extracted compilers/sources are removed on normal completion/error.

`artifacts.json` pins actual Go1.23.4/Go1.24.5/Go1.26.10 reference compilers and the exact two Grafana regexp editions. `corpus.py` supplies independent inputs; `reference.go.txt` executes direct generic Compile separately from fork-syntax Perl|DotNL + Simplify + anchored-wrapper Compile. `own.go.txt` calls the corresponding owned regexcompat profile APIs. Reference observations, not inferred selector expectations, drive the comparison.

The JSON output includes all 315 paired case observations, exact runtime/source/request identities and explicit mismatches. Invalid bytes are base64 encoded. Compiler/source/coverage failure cannot yield equality. Exit **0** means observed semantic equality, **1** means actual differences and **2** means probe failure. An unexecuted probe is not a compatibility claim.

See [the integration report](../../../.superpowers/sdd/approved-product/regex-reference-report.md) for acquisition hashes, output identity details, handoff status and remaining acceptance boundaries. This tool does not qualify optimized selector prefix/suffix consumption, indexed normalization, query execution, cancellation or scoped resource limits.
