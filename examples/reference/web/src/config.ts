// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {Config} from "@soundpost/browser";

/** The public browser-source configuration the gateway serves at /config.json. Extra fields are ignored. */
export interface PublicConfig {
  readonly org: string;
  readonly project: string;
  readonly source: string;
  readonly credential: string;
  readonly build: string;
  readonly endpoint: string;
  readonly policy: Config["policy"];
  readonly trusted_keys: Readonly<Record<string, string>>;
  readonly resource: Config["resource"];
  readonly descriptor: NonNullable<Config["descriptor"]>;
}

function base64url(value: string): Uint8Array {
  const text = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(text, character => character.charCodeAt(0));
}

/** SDK configuration for a client with the registered aliases of the order page. */
export function sdkConfig(raw: PublicConfig, extra: Partial<Config> = {}): Config {
  const trustedKeys = Object.fromEntries(Object.entries(raw.trusted_keys).map(([id, value]) => [id, base64url(value)]));
  return {
    org: raw.org, project: raw.project, source: raw.source, credential: raw.credential, build: raw.build, endpoint: raw.endpoint,
    policy: raw.policy, trustedKeys, resource: raw.resource, descriptor: raw.descriptor,
    operations: ["ui.action", "http.call"], dependencies: ["gateway"], origins: ["gateway"],
    deploymentTraces: true, deploymentErrors: true, ...extra,
  };
}
