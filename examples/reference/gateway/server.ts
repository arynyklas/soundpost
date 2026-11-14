// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Reference gateway (Bun). Serves the built browser app and proxies POST /api/orders to the API.
// Request and response bodies are never read, logged or stored here; log lines carry method, path and status only.
import {readFileSync} from "node:fs";
import {isAbsolute, join, relative, resolve} from "node:path";
import {init} from "../../../packages/bun/src/index.ts";
import type {Client, Config} from "../../../packages/bun/src/index.ts";
import {installFetch} from "../../../packages/bun/src/fetch.ts";
import type {FetchLease} from "../../../packages/bun/src/fetch.ts";
import {installServe} from "../../../packages/bun/src/serve.ts";
import type {ServeLease} from "../../../packages/bun/src/serve.ts";
import {HttpsReceiptTransport} from "../../../packages/core/src/transport.ts";

const SCRIPT_RUNTIME = "1.3.14";
const flags = new Map<string, string>();
for (let index = 2; index < process.argv.length; index += 2) {
  const name = process.argv[index], value = process.argv[index + 1];
  if (name === undefined || !name.startsWith("--") || value === undefined) throw Error("usage: server.ts --listen HOST:PORT --cert PEM --key PEM [--config JSON] --ca PEM --api-url URL --web-dir DIR --web-config JSON");
  flags.set(name.slice(2), value);
}
function flag(name: string, required = true): string {
  const value = flags.get(name);
  if (value === undefined && required) throw Error("missing_flag_" + name);
  return value ?? "";
}
if (Bun.version !== SCRIPT_RUNTIME) throw Error("qualified_runtime_required");

const [host, portText] = flag("listen").split(/:(?=\d+$)/);
if (!host || !portText) throw Error("invalid_listen");
const ca = readFileSync(flag("ca"), "utf8");
const apiURL = new URL(flag("api-url"));
if (apiURL.protocol !== "https:" || apiURL.username || apiURL.password) throw Error("verified_https_api_required");
const webDir = resolve(flag("web-dir"));
const webConfig = readFileSync(flag("web-config"));
const configPath = flag("config", false);

interface RawConfig {
  org: string; project: string; source: string; credential: string; build: string; endpoint: string;
  policy: Config["policy"]; trusted_keys: Record<string, string>; resource: Config["resource"]; descriptor: NonNullable<Config["descriptor"]>;
}
// fetch with the private CA for one request; preconnect is part of the platform fetch type.
const tlsFetch: typeof fetch = Object.assign(
  (input: string | URL | Request, options?: BunFetchRequestInit) => fetch(input, {...options, tls: {ca}}),
  {preconnect: fetch.preconnect},
);
function sdkConfig(raw: RawConfig): Config {
  if (new URL(raw.endpoint).protocol !== "https:") throw Error("verified_https_ingest_required");
  const trustedKeys = Object.fromEntries(Object.entries(raw.trusted_keys).map(([id, value]) => [id, Uint8Array.from(Buffer.from(value, "base64url"))]));
  const config: Config = {
    org: raw.org, project: raw.project, source: raw.source, credential: raw.credential, build: raw.build, endpoint: raw.endpoint,
    policy: raw.policy, trustedKeys, resource: raw.resource, descriptor: raw.descriptor,
    operations: ["request", "http.call"], dependencies: ["api"], origins: ["api"],
    deploymentTraces: true, deploymentErrors: true,
  };
  return {...config, transport: new HttpsReceiptTransport(config, (url, options) => tlsFetch(url, options))};
}
const raw: RawConfig | undefined = configPath ? JSON.parse(readFileSync(configPath, "utf8")) : undefined;
// The page's connect-src must name the Soundpost node origin, taken from the same config the SDK uses.
const nodeOrigin = raw ? new URL(raw.endpoint).origin : undefined;
const csp = [
  "default-src 'none'", "script-src 'self'", "style-src 'self'", "img-src 'self'",
  "connect-src 'self'" + (nodeOrigin ? " " + nodeOrigin : ""),
  "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'",
].join("; ");

let client: Client | undefined;
let serve: ServeLease | undefined;
let outbound: FetchLease | undefined;
if (raw) {
  client = init(sdkConfig(raw));
  serve = installServe(client, {operation: "request"});
  outbound = installFetch(client, {operation: "http.call", origins: [{origin: apiURL.origin, dependency: "api"}], fetch: tlsFetch});
}

const log = (method: string, path: string, status: number): void => { console.error(method + " " + path + " " + status); };
const security = {"X-Content-Type-Options": "nosniff", "Content-Security-Policy": csp, "Referrer-Policy": "no-referrer"} as const;

async function proxyOrder(request: Request): Promise<Response> {
  const headers = new Headers(), contentType = request.headers.get("content-type");
  if (contentType) headers.set("content-type", contentType);
  const target = new URL("/orders", apiURL);
  try {
    // The body (capped at 64 KiB by the server) is forwarded byte for byte with a Content-Length; never inspected.
    const init = {method: "POST", headers, body: await request.arrayBuffer(), signal: request.signal};
    const response = await (outbound ? outbound.fetch(target, init) : fetch(target, {...init, tls: {ca}}));
    const out = new Headers(security), type = response.headers.get("content-type");
    if (type) out.set("content-type", type);
    out.set("cache-control", "no-store");
    return new Response(response.body, {status: response.status, headers: out});
  } catch {
    return new Response(null, {status: 502, headers: {...security, "cache-control": "no-store"}});
  }
}
const orders = serve ? serve.handler(request => proxyOrder(request)) : undefined;

async function route(request: Request, server: Bun.Server<undefined>): Promise<Response> {
  const url = new URL(request.url), method = request.method;
  if (url.pathname === "/healthz") return method === "GET" ? new Response("ok", {headers: {...security, "cache-control": "no-store"}}) : new Response(null, {status: 405, headers: {...security, Allow: "GET"}});
  if (url.pathname === "/config.json") {
    if (method !== "GET") return new Response(null, {status: 405, headers: {...security, Allow: "GET"}});
    return new Response(webConfig, {headers: {...security, "content-type": "application/json", "cache-control": "no-store"}});
  }
  if (url.pathname === "/api/orders") {
    if (method !== "POST") return new Response(null, {status: 405, headers: {...security, Allow: "POST"}});
    const response = orders ? await orders(request, server) : await proxyOrder(request);
    return response ?? new Response(null, {status: 502});
  }
  if (method !== "GET" && method !== "HEAD") return new Response(null, {status: 405, headers: {...security, Allow: "GET, HEAD"}});
  let name: string;
  try { name = decodeURIComponent(url.pathname); } catch { return new Response(null, {status: 400, headers: security}); }
  if (name.includes("\0") || name.includes("\\")) return new Response(null, {status: 400, headers: security});
  if (name.endsWith("/")) name += "index.html";
  const file = resolve(join(webDir, name));
  const inside = relative(webDir, file);
  if (inside === "" || inside.startsWith("..") || isAbsolute(inside) || file.endsWith(".map")) return new Response(null, {status: 404, headers: security});
  const body = Bun.file(file);
  if (!(await body.exists())) return new Response(null, {status: 404, headers: security});
  const headers = new Headers(security);
  headers.set("content-type", body.type);
  if (file.endsWith(".html")) { headers.set("Document-Policy", "js-profiling"); headers.set("cache-control", "no-store"); }
  return new Response(method === "HEAD" ? null : body, {headers});
}

const server = Bun.serve({
  hostname: host,
  port: Number(portText),
  tls: {cert: Bun.file(flag("cert")), key: Bun.file(flag("key"))},
  maxRequestBodySize: 65536,
  async fetch(request, server) {
    const response = await route(request, server);
    log(request.method, new URL(request.url).pathname, response.status);
    return response;
  },
  error() { return new Response(null, {status: 500}); },
});
console.log(JSON.stringify({listening: host + ":" + server.port, telemetry: client ? "enabled" : "disabled"}));

let closing = false;
async function close(): Promise<void> {
  if (closing) return;
  closing = true;
  await server.stop(true);
  serve?.close();
  outbound?.close();
  let failed = false;
  let report = {pending: 0, lost: 0, receipts: [] as readonly unknown[]};
  if (client) {
    try {
      report = await client.flush(10000);
      failed = report.pending !== 0 || report.lost !== 0;
    } finally {
      await client.close();
    }
  }
  console.log(JSON.stringify({flush: {pending: report.pending, lost: report.lost, receipts: report.receipts.length}, runtime: "bun", version: Bun.version}));
  process.exit(failed ? 1 : 0);
}
process.once("SIGINT", () => { void close(); });
process.once("SIGTERM", () => { void close(); });
