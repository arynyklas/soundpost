#!/usr/bin/env python3
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Records the configuration-phase oracle variants (decision D29) in
conformance/query/source-lock.json and conformance/query/provenance.json.

Run from the repository root after building the two variant images:

    docker build --pull=false --provenance=false --sbom=false \\
      -f conformance/query/oracles/promql-prometheus-<v>-configuration.Dockerfile \\
      -t soundpost-oracle-promql-prometheus-<v>-configuration:current conformance/query/oracles
    python3 conformance/query/author/lock-configuration-oracle.py [docker]

It reads the image ids and layer lists from the local docker daemon, hashes the
Dockerfile, the added configuration file and the observation script, and checks
that every variant is the evaluation oracle's layers plus exactly one layer.
"""
import hashlib, json, subprocess, sys

Q = "conformance/query"
DOCKER = sys.argv[1] if len(sys.argv) > 1 else "docker"
SCRIPT = "internal/conformance/query/configuration_observe.sh"
PROFILES = {"promql-prometheus-3.1.0": "3.1.0", "promql-prometheus-3.13.5": "3.13.5"}


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def inspect(ref):
    out = subprocess.check_output([DOCKER, "image", "inspect", ref, "--format", "{{.Id}}\n{{json .RootFS.Layers}}\n{{.Os}}/{{.Architecture}}"], text=True).split("\n")
    return out[0], json.loads(out[1]), out[2]


lock_path = f"{Q}/source-lock.json"
lock = json.loads(open(lock_path, newline="").read())
records = {}
for p in lock["profiles"]:
    version = PROFILES.get(p["id"])
    if not version:
        continue
    base_id, base_layers, _ = inspect(p["artifact"]["path"])
    assert base_id == p["artifact"]["path"], (p["id"], base_id, p["artifact"]["path"])
    image = f"soundpost-oracle-promql-prometheus-{version}-configuration:current"
    image_id, layers, platform = inspect(image)
    assert layers[: len(base_layers)] == base_layers and len(layers) == len(base_layers) + 1, "variant must be the base layers plus one layer"
    rec = {
        "image": image,
        "image_id": image_id,
        "base_image_id": base_id,
        "architecture": platform,
        "base_layers": len(base_layers),
        "added_layer_diff_id": layers[-1],
        "dockerfile": f"oracles/promql-prometheus-{version}-configuration.Dockerfile",
        "dockerfile_sha256": sha(f"{Q}/oracles/promql-prometheus-{version}-configuration.Dockerfile"),
        "configuration_file": f"oracles/promql-prometheus-{version}-configuration.yaml",
        "configuration_file_sha256": sha(f"{Q}/oracles/promql-prometheus-{version}-configuration.yaml"),
        "installed_at": "/etc/prometheus/soundpost-configuration-phase.yaml",
        "observer_script": SCRIPT,
        "observer_script_sha256": sha(SCRIPT),
    }
    p["configuration_oracle"] = rec
    records[p["id"]] = rec
open(lock_path, "w", newline="").write(json.dumps(lock, indent=2, ensure_ascii=False) + "\n")

prov_path = f"{Q}/provenance.json"
section = {
    "decision": "D29 (2026-11-15): the configuration obligations stay in the language ledger and are observed with a separately pinned configuration-phase oracle variant built from the same pinned upstream release; black box, no source copying.",
    "method": "docker build --pull=false --provenance=false --sbom=false of the recorded Dockerfile: FROM the locked evaluation-oracle image id (local store, no registry pull) and one COPY of the recorded configuration file; no RUN, no entrypoint change. The harness starts the unmodified upstream /bin/prometheus of that image through `--entrypoint /bin/sh <observation script>` in the same isolation as the evaluation oracle (no network, read-only root, uid 65534, no capabilities) and reads only its exit/log and /api/v1/status/config.",
    "profiles": records,
}
text = open(prov_path, newline="").read()
marker = ',\n  "configuration_oracles":'
if marker in text:
    text = text[: text.index(marker)] + "\n}\n"
assert text.endswith("\n}\n"), "unexpected provenance.json tail"
body = json.dumps(section, indent=2, ensure_ascii=False).replace("\n", "\n  ")
text = text[: -len("\n}\n")] + marker + " " + body + "\n}\n"
open(prov_path, "w", newline="").write(text)
json.loads(text)
print(json.dumps(records, indent=2))
print("relock provenance.json: python3 conformance/query/author/relock.py provenance.json")
