#!/usr/bin/env python3
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Records what the pinned reference observed in a configuration-phase run, so the
Go tests can replay those observations against the owned resolver without a
container runtime. Usage, from the repository root:

    go run ./cmd/soundpost-querycheck compare --phase configuration \\
      --cases conformance/query/cases/release-configuration.json --require-locked \\
      --runtime <docker> > report.json
    python3 conformance/query/author/record-configuration-observations.py report.json

Each recorded observation is bound to its input by the SHA-256 of
profile NUL features NUL document; a changed case row invalidates its recording.
"""
import hashlib, json, sys

Q = "conformance/query"
OUT = "internal/conformance/query/testdata/native-configuration-observations.json"


def digest(profile, features, config):
    return hashlib.sha256((profile + "\x00" + ",".join(features) + "\x00" + config).encode()).hexdigest()


report = json.load(open(sys.argv[1]))
assert report["failed"] == 0 and report["compared"] == len(report["cases"]), "record only a passing run"
cases = {}
for c in json.load(open(f"{Q}/cases/release-configuration.json"))["cases"]:
    cases[c["id"]] = c
rows, oracles = [], {}
for c in report["cases"]:
    oracle = c["oracle"]
    oracles[c["profile"]] = {k: oracle[k] for k in ("revision", "version", "image_sha256", "configuration_sha256")}
    authored = {s["name"]: s for s in cases[c["id"]]["scenarios"]}
    for s in c["scenarios"]:
        a = authored[s["name"]]
        rows.append({"profile": c["profile"], "case": c["id"], "scenario": s["name"],
                     "input_sha256": digest(c["profile"], a.get("features", []), a["config"]),
                     "reference": {k: v for k, v in s["reference"].items() if v not in (None, "", {})} | {"accepted": s["reference"]["accepted"]}})
rows.sort(key=lambda r: (r["profile"], r["case"], r["scenario"]))
doc = {"schema": "soundpost-recorded-prometheus-configuration-observations-v1",
       "copyright": "Copyright 2026 Aryn Yklas", "license": "Apache-2.0",
       "note": "Observed black-box from the unmodified upstream /bin/prometheus of each pinned image in its configuration-phase variant; inputs are authored, outputs are the reference's own.",
       "oracles": oracles, "observations": rows}
with open(OUT, "w", newline="\n") as f:
    json.dump(doc, f, indent=1, ensure_ascii=False, sort_keys=True)
    f.write("\n")
print("recorded", len(rows), "observations ->", OUT)
