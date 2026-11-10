// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Real Vite build + real private source-map upload. Run with Windows Node from the repository root:
//   node examples/reference/web/build.mjs
// Environment: REFERENCE_ORG, REFERENCE_PROJECT, REFERENCE_SOURCE, REFERENCE_BUILD_ID (32 hex), REFERENCE_ENDPOINT
// (node origin), REFERENCE_ARTIFACT_TOKEN (private artifact-write credential; held in a closure, never printed) and
// REFERENCE_OUT_DIR (absolute output directory). Prints exactly one JSON line on success; the build FAILS (exit 1) if any
// JS asset did not get an upload receipt. Diagnostics are closed codes, never bodies or credentials.
import {readdirSync, readFileSync, rmSync} from "node:fs";
import {join} from "node:path";
import {build} from "vite";
import {referenceConfig} from "./vite.config.ts";

function fail(code) {
  process.stderr.write("reference_build_failed: " + code + "\n");
  process.exit(1);
}
function required(name) {
  const value = process.env[name];
  if (!value) fail("missing_" + name);
  return value;
}

const org = required("REFERENCE_ORG"), project = required("REFERENCE_PROJECT"), source = required("REFERENCE_SOURCE");
const buildId = required("REFERENCE_BUILD_ID"), endpoint = required("REFERENCE_ENDPOINT"), outDir = required("REFERENCE_OUT_DIR");
if (!/^[0-9a-f]{32}$/.test(buildId)) fail("invalid_build_id");
const token = required("REFERENCE_ARTIFACT_TOKEN");
delete process.env.REFERENCE_ARTIFACT_TOKEN;

const receipts = [];
try {
  await build(referenceConfig({org, project, source, buildId, endpoint, outDir, credential: () => token, onReceipt: receipt => receipts.push(receipt)}));
} catch (error) {
  const reason = [error, error?.cause].map(value => value && typeof value === "object" && value.name === "SoundpostArtifactError" ? String(value.message).slice(0, 120) : undefined).find(value => typeof value === "string");
  fail(reason ?? (error && typeof error === "object" && "code" in error && typeof error.code === "string" ? error.code : "build_error"));
}

function* files(dir, prefix = "") {
  for (const entry of readdirSync(join(dir, prefix), {withFileTypes: true})) {
    const name = prefix ? prefix + "/" + entry.name : entry.name;
    if (entry.isDirectory()) yield* files(dir, name);
    else yield name;
  }
}
const scripts = [...files(outDir)].filter(name => /\.js$/.test(name));
if (scripts.length === 0 || receipts.length !== scripts.length) fail("upload_receipt_missing");
for (const name of scripts) {
  const text = readFileSync(join(outDir, name), "utf8");
  if (text.includes("sourceMappingURL")) fail("source_map_reference_present");
  if (!receipts.some(receipt => receipt.path === name)) fail("upload_receipt_missing");
}
// The private maps are already uploaded; they must not stay in the directory the gateway serves.
for (const name of [...files(outDir)]) if (name.endsWith(".map")) rmSync(join(outDir, name));
const assets = receipts.map(receipt => ({
  file: receipt.path, debug_id: receipt.debug_id, generated_sha256: receipt.generated_sha256, map_sha256: receipt.map_sha256, artifact_id: receipt.id,
}));
process.stdout.write(JSON.stringify({build_id: buildId, assets, upload: "ok"}) + "\n");
