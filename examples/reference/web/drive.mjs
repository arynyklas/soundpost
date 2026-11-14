// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Real-browser driver (Linux Node + Playwright + Chrome, headless). Trust for the private CA comes from the caller's
// NSS database (HOME); certificate errors are never ignored. Playwright is resolved through NODE_PATH, as for web/.
//   node examples/reference/web/drive.mjs --origin https://127.0.0.1:PORT --chrome PATH \
//        --scenario order|replay|profile [--item sku-100|sku-404] [--note-env REFERENCE_NOTE]
// Prints exactly one JSON line. The note comes from the named environment variable and is never printed; error
// messages are never printed (names and bundle positions only).
import {createHash} from "node:crypto";
import {createRequire} from "node:module";

const require = createRequire(import.meta.url);
const {chromium} = require("@playwright/test");
const CANARY = "CANARY_BODY_7f3a";

const args = new Map();
for (let index = 2; index < process.argv.length; index += 2) {
  const name = process.argv[index], value = process.argv[index + 1];
  if (!name?.startsWith("--") || value === undefined) throw Error("usage");
  args.set(name.slice(2), value);
}
const origin = new URL(args.get("origin") ?? "").origin;
const scenario = args.get("scenario");
if (!["order", "replay", "profile"].includes(scenario)) throw Error("invalid_scenario");
const item = args.get("item") ?? "sku-100";
if (!["sku-100", "sku-404"].includes(item)) throw Error("invalid_item");
const note = process.env[args.get("note-env") ?? "REFERENCE_NOTE"] ?? "";

const sha256 = bytes => createHash("sha256").update(bytes).digest("hex");
// Bundle positions only: `<origin>/<path>:<line>:<column>` at the end of a stack line.
function frames(stack) {
  const found = [];
  for (const line of String(stack ?? "").split("\n")) {
    const match = line.match(/(https?:\/\/[^\s()]+?):(\d+):(\d+)\)?\s*$/);
    if (!match) continue;
    const url = new URL(match[1]);
    if (url.origin !== origin) continue;
    found.push({path: url.pathname.replace(/^\//, ""), line: Number(match[2]), column: Number(match[3])});
  }
  return found;
}

const browser = await chromium.launch({executablePath: args.get("chrome"), headless: true});
const result = {};
try {
  const context = await browser.newContext();
  const page = await context.newPage();
  const pageErrors = [], ingest = [], orders = [];
  let consoleErrors = 0, documentPolicy = null;
  page.on("pageerror", error => pageErrors.push({name: error.name, frames: frames(error.stack)}));
  page.on("console", message => { if (message.type() === "error") consoleErrors++; });
  page.on("response", async response => {
    const url = new URL(response.url());
    if (url.pathname === "/" && url.origin === origin && documentPolicy === null) documentPolicy = response.headers()["document-policy"] ?? "";
    if (url.pathname.startsWith("/ingest/")) ingest.push({method: response.request().method(), path: url.pathname, status: response.status()});
    if (url.origin === origin && url.pathname === "/api/orders") {
      const body = await response.body().catch(() => null);
      if (body === null) return;
      const sent = response.request().postDataBuffer();
      orders.push({method: response.request().method(), path: url.pathname, status: response.status(), body_sha256: sha256(body), body_bytes: body.length,
        request_body_sha256: sent ? sha256(sent) : null, request_body_bytes: sent ? sent.length : 0});
    }
  });
  page.on("requestfailed", request => { if (new URL(request.url()).pathname.startsWith("/ingest/")) ingest.push({method: request.method(), path: new URL(request.url()).pathname, status: 0}); });

  await page.goto(origin + "/");
  await page.waitForFunction(() => Boolean(window.__reference?.ready), undefined, {timeout: 15000});
  Object.assign(result, {chrome: browser.version(), scenario});

  if (scenario === "order") {
    await page.selectOption("#item", item);
    await page.fill("#note", note);
    await page.click("#place-order");
    await page.waitForFunction(() => (document.getElementById("result")?.textContent ?? "") !== "", undefined, {timeout: 15000});
    if (item === "sku-404") {
      const deadline = Date.now() + 3000;
      while (pageErrors.length === 0 && Date.now() < deadline) await page.waitForTimeout(50);
    }
    const reference = await page.evaluate(() => {
      const value = window.__reference;
      return {build_id: value.buildId, trace_id: value.traceId, span_id: value.spanId};
    });
    const flush = await page.evaluate(() => window.__reference.flush());
    const canaryHit = await page.evaluate(canary => {
      const clone = document.documentElement.cloneNode(true);
      clone.querySelector("#note")?.remove();
      const stored = [...Object.values(localStorage), ...Object.values(sessionStorage)].join("\n");
      return (clone.outerHTML + clone.textContent + stored + location.href).includes(canary);
    }, CANARY);
    Object.assign(result, reference, {request: orders[0] ?? null, page_errors: pageErrors, flush, console_errors: consoleErrors, canary_in_dom: canaryHit, ingest});
  } else if (scenario === "profile") {
    const outcome = await page.evaluate(() => window.__reference.profile(300));
    Object.assign(result, {build_id: await page.evaluate(() => window.__reference.buildId), document_policy_header: documentPolicy, profile: outcome, page_errors: pageErrors, console_errors: consoleErrors, ingest});
  } else {
    // The recorder runs in the page while the driver types the canary note into the textarea, clicks it and writes the same
    // text into a text node: it must see structure only. 1.3 s lets the recorder's 1 s event flush deliver the interaction.
    await page.evaluate(() => window.__reference.startReplay());
    await page.fill("#note", note);
    await page.click("#note");
    await page.evaluate(text => { document.getElementById("result").textContent = text; }, note);
    await page.waitForTimeout(1300);
    const outcome = await page.evaluate(() => window.__reference.finishReplay());
    Object.assign(result, {build_id: await page.evaluate(() => window.__reference.buildId), replay: outcome, page_errors: pageErrors, console_errors: consoleErrors, ingest});
  }
} finally {
  await browser.close();
}
process.stdout.write(JSON.stringify(result) + "\n");
