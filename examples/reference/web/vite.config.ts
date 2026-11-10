// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Build configuration for the reference order page. build.mjs supplies every identity and the private artifact-write
// credential; nothing here reads the environment, and the credential never reaches the bundle (the plugin seals it).
import {fileURLToPath} from "node:url";
import {soundpostVite} from "../../../packages/build/src/index.ts";
import type {ArtifactReceipt} from "../../../packages/build/src/index.ts";

export interface ReferenceBuild {
  readonly org: string;
  readonly project: string;
  readonly source: string;
  readonly buildId: string;
  /** Soundpost node origin that serves POST /api/v1/artifacts. */
  readonly endpoint: string;
  readonly credential: () => string;
  readonly outDir: string;
  readonly onReceipt: (receipt: ArtifactReceipt) => void;
}

const here = fileURLToPath(new URL(".", import.meta.url));
const packages = fileURLToPath(new URL("../../../packages/", import.meta.url));

export function referenceConfig(build: ReferenceBuild) {
  return {
    configFile: false,
    root: here,
    logLevel: "warn",
    define: {__REFERENCE_BUILD_ID__: JSON.stringify(build.buildId)},
    resolve: {
      alias: [
        {find: /^@soundpost\/browser$/, replacement: packages + "browser/src/index.ts"},
        {find: /^@soundpost\/core\/types$/, replacement: packages + "core/src/types.ts"},
        {find: /^@soundpost\/core$/, replacement: packages + "core/src/client.ts"},
      ],
    },
    plugins: [soundpostVite({
      org: build.org, project: build.project, source: build.source, build: build.buildId,
      upload: {endpoint: build.endpoint, credential: build.credential},
      onReceipt: build.onReceipt,
    })],
    build: {
      outDir: build.outDir,
      emptyOutDir: true,
      target: "es2022",
      minify: true,
      modulePreload: {polyfill: false},
    },
  };
}
