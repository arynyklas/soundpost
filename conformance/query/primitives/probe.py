#!/usr/bin/env python3
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Development-only actual pinned primitive observations. Never imported by production.

Uses only Python's standard library. Downloads hash-pinned generic source and Go
compiler archives into ignored .tools; executes only when explicitly invoked.
Exit 0 = all observed semantics agree; 1 = actual differences; 2 = probe failure.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE))
from corpus import cases


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def acquire(url, path, expected):
    """Reject corrupt cached bytes; do not silently replace provenance failures."""
    path = Path(path)
    if path.exists():
        data = path.read_bytes()
    else:
        with urllib.request.urlopen(url, timeout=180) as response:
            data = response.read()
    if digest(data) != expected:
        raise ValueError("artifact SHA256 mismatch: " + str(path))
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
            temporary.write(data)
            name = temporary.name
        os.replace(name, path)
    return path


def archive_destination(root, name):
    namepath = PurePosixPath(name)
    if (namepath.is_absolute() or ".." in namepath.parts or ":" in name or "\\" in name):
        raise ValueError("unsafe archive entry: " + name)
    destination = Path(root).resolve().joinpath(*namepath.parts)
    if not destination.is_relative_to(Path(root).resolve()):
        raise ValueError("archive entry escapes extraction directory")
    return destination


def extract(archive, destination):
    """Extract verified archives to fresh private directories, rejecting links."""
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as source:
            for entry in source.infolist():
                target = archive_destination(destination, entry.filename)
                if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError("archive symlink rejected")
                if entry.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(source.read(entry))
                    if entry.external_attr >> 16:
                        target.chmod((entry.external_attr >> 16) & 0o777)
    else:
        with tarfile.open(archive, "r:gz") as source:
            for entry in source:
                target = archive_destination(destination, entry.name)
                if entry.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif entry.isfile():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with source.extractfile(entry) as content:
                        target.write_bytes(content.read())
                    target.chmod(entry.mode & 0o777)
                else:
                    raise ValueError("non-file archive member rejected: " + entry.name)


def index_results(expected, rows):
    result = {}
    for row in rows:
        key = row["id"]
        if key in result:
            raise ValueError("duplicate result: " + key)
        result[key] = row["observation"]
    if set(result) != set(expected) or len(expected) != len(set(expected)):
        raise ValueError("result case coverage differs from request")
    return result


def compare(expected, reference, own):
    ref = index_results(expected, reference)
    actual = index_results(expected, own)
    return [{"id": key, "reference": ref[key], "own": actual[key]}
            for key in expected if ref[key] != actual[key]]


def check_identity(actual, compiler, module, goos, goarch):
    wanted = {"compiler": compiler, "module": module, "unicode": "15.0.0", "goos": goos, "goarch": goarch}
    for key, value in wanted.items():
        if actual.get(key) != value:
            raise ValueError("reference identity mismatch for " + key + ": " + repr(actual))


def source_identity():
    paths = []
    for directory in ("internal/query/regexcompat", "internal/query/profile", "third_party/regex"):
        paths.extend(path for path in (ROOT / directory).rglob("*") if path.is_file())
    paths.extend([ROOT / "go.mod", ROOT / "go.sum"])
    inventory = {path.relative_to(ROOT).as_posix(): digest(path.read_bytes())
                 for path in sorted(paths) if path.exists()}
    return {"tree_sha256": digest(canonical(inventory)), "files": inventory}


def validate_original_sources(edition, goroot, module):
    """Bind executed archives to every original source hash in local provenance."""
    checked = {}
    for entry in edition["files"]:
        url = entry["source"]
        if "#" in url:
            path = module / url.split("#", 1)[1]
        elif "/src/" in url:
            path = goroot / "src" / url.split("/src/", 1)[1]
        else:
            raise ValueError("unsupported provenance URL: " + url)
        actual = digest(path.read_bytes())
        if actual != entry["source_sha256"]:
            raise ValueError("original source differs from primitive provenance: " + url)
        checked[url] = actual
    return checked


def run_worker(go, goroot, directory, adapter, request, cache):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "runner.go").write_bytes((HERE / "runner.go.txt").read_bytes())
    (directory / "adapter.go").write_bytes((HERE / adapter).read_bytes())
    env = os.environ.copy()
    env.update({"GOROOT": str(goroot), "GOTOOLCHAIN": "local", "GOWORK": "off", "GOENV": "off",
                "GOFLAGS": "", "GO111MODULE": "on", "GOPROXY": "off", "GOSUMDB": "off",
                "CGO_ENABLED": "0", "GOCACHE": str(cache / "build"),
                "GOMODCACHE": str(cache / "modules"), "GOPATH": str(cache / "gopath")})
    # Host or cross-compile environment must not silently select another target.
    for key in ("GOOS", "GOARCH", "GOEXPERIMENT", "GODEBUG"):
        env.pop(key, None)
    completed = subprocess.run([str(go), "run", "-mod=mod", "."], cwd=directory,
                               input=canonical(request), stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=env, timeout=300)
    if completed.returncode:
        raise RuntimeError("worker failed (" + str(go) + "):\n" + completed.stderr.decode("utf-8", "replace"))
    return json.loads(completed.stdout)


def write_report(path, result):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--own-go", required=True, type=Path, help="owned Go1.27.3 executable (never auto-downloads/updates root deps)")
    parser.add_argument("--output", type=Path, default=ROOT / ".tools/primitive-probe/results.json")
    args = parser.parse_args()
    goos = {"Windows": "windows", "Linux": "linux"}.get(platform.system())
    goarch = {"AMD64": "amd64", "x86_64": "amd64"}.get(platform.machine())
    if not goos or not goarch:
        parser.error("pinned archive inventory currently supports Windows/Linux amd64 only")
    own_go = args.own_go.resolve()
    artifact_bytes = (HERE / "artifacts.json").read_bytes()
    pins = json.loads(artifact_bytes)
    provenance_bytes = (ROOT / "third_party/regex/sources.json").read_bytes()
    editions = {e["edition"]: e for e in json.loads(provenance_bytes)["editions"]}
    corpus = cases()
    cache = ROOT / ".tools/primitive-probe"
    cache.mkdir(parents=True, exist_ok=True)
    result = {"schema": "soundpost-primitive-differential-v1", "status": "incomplete",
              "scope": "generic Compile and normalized anchored Perl|DotNL fork-syntax primitive; NOT optimized selectors",
              "artifact_manifest_sha256": digest(artifact_bytes), "sources_manifest_sha256": digest(provenance_bytes),
              "corpus_sha256": digest(canonical(corpus)), "case_count_per_profile": len(corpus), "cases": corpus,
              "probe_files": {p.name: digest(p.read_bytes()) for p in sorted(HERE.iterdir()) if p.is_file()},
              "owned_source": source_identity(), "profiles": []}
    try:
        with tempfile.TemporaryDirectory(prefix="run-", dir=cache) as work:
            work = Path(work)
            for pin in pins["profiles"]:
                edition = editions[pin["edition"]]
                if (edition["toolchain"], edition["regexp_module"], edition["module_zip_sha256"]) != (
                        pin["compiler"], pin["module"], pin["module_zip_sha256"]):
                    raise ValueError("probe artifact inventory and primitive provenance disagree")
                compiler_pin = pins["toolchains"][pin["compiler"]][goos + "-" + goarch]
                archive = acquire("https://go.dev/dl/" + compiler_pin["filename"],
                                  cache / "archives" / compiler_pin["filename"], compiler_pin["sha256"])
                toolchain = work / pin["edition"] / "toolchain"
                extract(archive, toolchain)
                goroot = toolchain / "go"
                go = goroot / "bin" / ("go.exe" if goos == "windows" else "go")
                module_archive = acquire("https://proxy.golang.org/github.com/grafana/regexp/@v/" + pin["module"] + ".zip",
                                         cache / "archives" / ("grafana-" + pin["module"] + ".zip"), pin["module_zip_sha256"])
                modules = work / pin["edition"] / "sources"
                extract(module_archive, modules)
                module = modules / ("github.com/grafana/regexp@" + pin["module"])
                original_sources = validate_original_sources(edition, goroot, module)
                request = {"profile": pin["id"], "commit": pin["commit"], "cases": corpus}
                refdir = work / pin["edition"] / "reference"
                refdir.mkdir(parents=True)
                (refdir / "go.mod").write_text("module primitive-reference\n\ngo 1.23.0\n\nrequire github.com/grafana/regexp " + pin["module"] + "\nreplace github.com/grafana/regexp => " + json.dumps(module.as_posix()) + "\n", encoding="utf-8")
                reference = run_worker(go, goroot, refdir, "reference.go.txt", request, cache / pin["compiler"])
                check_identity(reference["identity"], pin["compiler"], pin["module"], goos, goarch)
                owndir = work / pin["edition"] / "owned"
                owndir.mkdir(parents=True)
                (owndir / "go.mod").write_text("module github.com/arynyklas/soundpost/conformance/primitiveprobe\n\ngo 1.27.3\n\nrequire github.com/arynyklas/soundpost v0.0.0\nreplace github.com/arynyklas/soundpost => " + json.dumps(ROOT.as_posix()) + "\n", encoding="utf-8")
                own = run_worker(own_go, own_go.parent.parent, owndir, "own.go.txt", request, cache / "go1.27.3")
                if own["identity"].get("compiler") != "go1.27.3" or own["identity"].get("implementation") != "soundpost/regexcompat":
                    raise ValueError("owned worker compiler/adapter identity mismatch")
                for observed in (reference, own):
                    if observed["identity"].get("profile") != pin["id"] or observed["identity"].get("commit") != pin["commit"]:
                        raise ValueError("worker profile identity mismatch")
                mismatches = compare([c["id"] for c in corpus], reference["results"], own["results"])
                result["profiles"].append({"pin": pin, "compiler_archive": compiler_pin,
                    "compiler_executable_sha256": digest(go.read_bytes()), "owned_compiler_executable_sha256": digest(own_go.read_bytes()),
                    "request_sha256": digest(canonical(request)), "original_sources": original_sources,
                    "reference": reference, "own": own, "mismatches": mismatches})
                write_report(args.output, result)
        if source_identity() != result["owned_source"]:
            raise ValueError("owned source changed during differential run; rerun after integration settles")
        result["status"] = "different" if any(p["mismatches"] for p in result["profiles"]) else "equal"
        write_report(args.output, result)
        print(json.dumps({"status": result["status"], "report": str(args.output), "profiles": len(result["profiles"]),
                          "cases_per_profile": len(corpus), "mismatches": sum(len(p["mismatches"]) for p in result["profiles"])}))
        return 1 if result["status"] == "different" else 0
    except Exception as error:
        result["status"] = "probe-error"
        result["error"] = str(error)
        write_report(args.output, result)
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
