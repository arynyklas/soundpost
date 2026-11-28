// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// The web app's build stage of the compose estate (service `webbuild`): the same real Vite build and private source-map upload as
// build.mjs, driven by the source onboarding the `provision` service wrote, with its result staged for the gateway.
//   node examples/reference/web/stage.mjs
// Reads $REFERENCE_CFG/web-build.json ({org, project, source, build_id, endpoint, artifact_token}) and $REFERENCE_CFG/web.json (the page's
// own source configuration), runs build.mjs with that identity (the credential travels in the child's environment only), writes the
// build to $REFERENCE_WEB_ROOT/dist and the page configuration with the build's receipt (shipped asset path -> artifact id, which is how
// the browser SDK names the artifact in the frames of an error) to $REFERENCE_WEB_ROOT/config.json. Prints exactly one JSON line: the
// build's own result plus the size of every shipped file. Closed diagnostics only; no body or credential is printed.
import {spawn} from "node:child_process";
import {readdirSync, readFileSync, statSync, writeFileSync} from "node:fs";
import {join} from "node:path";
import {fileURLToPath} from "node:url";

function fail(code) {
  process.stderr.write("reference_stage_failed: " + code + "\n");
  process.exit(1);
}

const cfg = process.env.REFERENCE_CFG ?? "/cfg";
const root = process.env.REFERENCE_WEB_ROOT ?? "/web";
let spec, page;
try {
  spec = JSON.parse(readFileSync(join(cfg, "web-build.json"), "utf8"));
  page = JSON.parse(readFileSync(join(cfg, "web.json"), "utf8"));
} catch {
  fail("provisioning_unreadable");
}
for (const key of ["org", "project", "source", "build_id", "endpoint", "artifact_token"]) {
  if (typeof spec[key] !== "string" || spec[key] === "") fail("missing_" + key);
}
const dist = join(root, "dist");
const env = {
  ...process.env,
  REFERENCE_ORG: spec.org, REFERENCE_PROJECT: spec.project, REFERENCE_SOURCE: spec.source, REFERENCE_BUILD_ID: spec.build_id,
  REFERENCE_ENDPOINT: spec.endpoint, REFERENCE_ARTIFACT_TOKEN: spec.artifact_token, REFERENCE_OUT_DIR: dist,
};
const child = spawn(process.execPath, [fileURLToPath(new URL("./build.mjs", import.meta.url))], {env, stdio: ["ignore", "pipe", "inherit"]});
let out = "";
child.stdout.on("data", chunk => { out += chunk; });
const code = await new Promise(resolve => child.on("close", resolve));
if (code !== 0) fail("build_exit_" + code);
const line = out.trim().split("\n").filter(l => l.startsWith("{")).pop();
let result;
try {
  result = JSON.parse(line);
} catch {
  fail("build_output_undecodable");
}
const ids = {};
for (const asset of result.assets ?? []) ids[asset.file] = asset.artifact_id;
writeFileSync(join(root, "config.json"), JSON.stringify({...page, artifact_ids: ids}), {mode: 0o644});
const sizes = {};
for (const entry of readdirSync(join(dist, "assets"), {withFileTypes: true})) {
  if (entry.isFile()) sizes[entry.name] = statSync(join(dist, "assets", entry.name)).size;
}
process.stdout.write(JSON.stringify({...result, sizes}) + "\n");
