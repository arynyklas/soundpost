// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Order page. The Soundpost source configuration is fetched from the gateway (`/config.json`) at start; the only value
// baked into the bundle is the build ID, which must equal the configured build. The note text is sent to the order API
// as the product's own request body and is never given to the SDK, logged, stored or placed in a URL.
import {init, installFetch} from "@soundpost/browser";
import {sdkConfig} from "./config.ts";
import type {PublicConfig} from "./config.ts";
import {formatReceipt} from "./receipt.ts";
import type {Order} from "./receipt.ts";
import {profileFor, replayFor} from "./scenarios.ts";
import type {ProfileOutcome, ReplayOutcome} from "./scenarios.ts";
import "./style.css";

declare const __REFERENCE_BUILD_ID__: string;

interface Reference {
  readonly buildId: string;
  traceId: string;
  spanId: string;
  ready: boolean;
  flush(): Promise<{pending: number; lost: number; receipts: number}>;
  profile(durationMs: number): Promise<ProfileOutcome>;
  replay(): Promise<ReplayOutcome>;
}
declare global {
  interface Window {__reference?: Reference}
}

function element<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (!found) throw Error("missing_element_" + id);
  return found as T;
}

async function start(): Promise<void> {
  const result = element<HTMLDivElement>("result");
  const response = await fetch("/config.json", {cache: "no-store", credentials: "omit"});
  if (!response.ok) throw Error("config_unavailable");
  const raw = await response.json() as PublicConfig;
  if (raw.build !== __REFERENCE_BUILD_ID__) {
    result.textContent = "build mismatch: this page refuses to start";
    throw Error("build_mismatch");
  }
  const client = init(sdkConfig(raw));
  const gateway = installFetch(client, {operation: "http.call", origins: [{origin: location.origin, dependency: "gateway"}]});
  const reference: Reference = {
    buildId: __REFERENCE_BUILD_ID__, traceId: "", spanId: "", ready: false,
    async flush() {
      const report = await client.flush(10000);
      return {pending: report.pending, lost: report.lost, receipts: report.receipts.length};
    },
    profile: durationMs => profileFor(durationMs),
    replay: () => replayFor(raw),
  };

  const button = element<HTMLButtonElement>("place-order");
  const item = element<HTMLSelectElement>("item");
  const note = element<HTMLTextAreaElement>("note");
  async function placeOrder(): Promise<void> {
    const body = JSON.stringify({item: item.value, quantity: 2, note: note.value});
    result.textContent = "";
    await client.withSpan("ui.action", async () => {
      // A browser has no ambient async context: save the closed context now and pass it to the adapter explicitly.
      const context = client.traceContext();
      if (!context) throw Error("trace_context_missing");
      reference.traceId = context.traceId;
      reference.spanId = context.spanId;
      const reply = await gateway.fetch(location.origin + "/api/orders", {method: "POST", headers: {"content-type": "application/json"}, body}, context);
      if (!reply.ok) {
        result.textContent = "order failed (" + reply.status + ")";
        return;
      }
      const order = await reply.json() as Order;
      result.textContent = formatReceipt(order);
    });
  }
  button.addEventListener("click", () => {
    button.disabled = true;
    placeOrder().catch((error: unknown) => {
      // withSpan has already captured the error with the ui.action trace. Rethrow outside the promise chain so the
      // failure stays an ordinary uncaught page error, exactly as it would be without telemetry.
      result.textContent = "receipt unavailable";
      setTimeout(() => { throw error; });
    }).finally(() => { button.disabled = false; });
  });
  button.disabled = false;
  reference.ready = true;
  window.__reference = reference;
}

start().catch((error: unknown) => {
  setTimeout(() => { throw error; });
});
