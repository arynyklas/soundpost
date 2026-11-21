// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {spawn, type ChildProcess} from "node:child_process";
import {mkdtempSync, rmSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {BidiConnection} from "./bidi.ts";

/**
 * Preferences of the throwaway profile: nothing but the page under test may start a request (no favicon, update, telemetry, remote
 * settings or captive-portal traffic) so that "requests of this tab" is a complete count, and nothing prompts.
 */
export const QUIET_PROFILE: Readonly<Record<string, string | number | boolean>> = Object.freeze({
 "browser.chrome.site_icons": false, "browser.shell.checkDefaultBrowser": false, "browser.startup.page": 0, "browser.newtabpage.enabled": false,
 "browser.aboutwelcome.enabled": false, "datareporting.healthreport.uploadEnabled": false, "datareporting.policy.dataSubmissionEnabled": false,
 "toolkit.telemetry.enabled": false, "toolkit.telemetry.unified": false, "app.update.enabled": false, "app.update.auto": false,
 "app.normandy.enabled": false, "network.captive-portal-service.enabled": false, "network.connectivity-service.enabled": false,
 "browser.safebrowsing.malware.enabled": false, "browser.safebrowsing.phishing.enabled": false, "extensions.update.enabled": false,
 "network.prefetch-next": false, "network.dns.disablePrefetch": true, "network.http.speculative-parallel-limit": 0,
});

export interface FirefoxLaunch {
 readonly binary: string;
 /** Extra environment (for example LD_LIBRARY_PATH on a host without system GTK). */
 readonly env?: Readonly<Record<string, string>>;
 readonly prefs?: Readonly<Record<string, string | number | boolean>>;
}
export interface FirefoxProcess {
 readonly connection: BidiConnection;
 readonly version: string;
 stop(): Promise<void>;
}

const prefLine = ([name, value]: [string, string | number | boolean]): string => `user_pref(${JSON.stringify(name)}, ${typeof value === "string" ? JSON.stringify(value) : String(value)});`;

/** Starts a stock headless Firefox on a fresh profile and returns an open BiDi session (`session.new` already answered). */
export async function launchFirefox(options: FirefoxLaunch): Promise<FirefoxProcess> {
 const profile = mkdtempSync(join(tmpdir(), "soundpost-firefox-"));
 writeFileSync(join(profile, "user.js"), Object.entries({...QUIET_PROFILE, ...options.prefs}).map(prefLine).join("\n") + "\n");
 const child: ChildProcess = spawn(options.binary, ["--headless", "--no-remote", "--profile", profile, "--remote-debugging-port", "0", "about:blank"], {env: {...process.env, ...options.env, MOZ_HEADLESS: "1"}, stdio: ["ignore", "ignore", "pipe"]});
 const exited = new Promise<never>((_, reject) => { child.once("exit", code => reject(new Error(`firefox exited with ${code} before it listened`))); });
 exited.catch(() => undefined);
 const url = await Promise.race([
  new Promise<string>(resolve => {
   let text = "";
   child.stderr!.on("data", (chunk: Buffer) => {
    text += chunk.toString();
    const match = /WebDriver BiDi listening on (ws:\/\/[^\s]+)/.exec(text);
    if (match !== null) resolve(match[1]!);
   });
  }),
  exited,
  new Promise<never>((_, reject) => setTimeout(() => reject(new Error("firefox did not report a BiDi endpoint within 60 s")), 60000)),
 ]).catch(error => { child.kill(); rmSync(profile, {recursive: true, force: true}); throw error; });
 const connection = await BidiConnection.connect(`${url}/session`);
 const session = await connection.send<{capabilities: {browserVersion: string}}>("session.new", {capabilities: {}});
 return {
  connection, version: session.capabilities.browserVersion,
  async stop() {
   connection.close();
   const closed = new Promise<void>(resolve => child.once("exit", () => resolve()));
   child.kill();
   await Promise.race([closed, new Promise<void>(resolve => setTimeout(resolve, 10000))]);
   rmSync(profile, {recursive: true, force: true});
  },
 };
}
