// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

/** The only text value a replay node can carry. */
export type ReplayMask = "[masked]";
/** Inert tag enum of the server's closed schema (internal/replays nodeTags); every other element is the generic structural tag "masked". */
export type ReplayTag = "div" | "span" | "p" | "button" | "input" | "section" | "canvas" | "masked";
/** Closed structural node, exactly the server's model.MaskedNode: no geometry, style or content. IDs are canonical decimal strings of recorder-local counters (C04 uint64 form). */
export interface ReplayNode {
 readonly id: string;
 readonly parent: string;
 readonly tag: ReplayTag;
 /** "masked" marks an opaque subtree (frame, closed root, unsupported widget, overflow); never a source class name. */
 readonly class: "" | "masked";
 /** Constant mask for text and input nodes, "" for pure structure. Never a source value. */
 readonly text: "" | ReplayMask;
}
export type ReplayEventKind = "pointer" | "scroll" | "resize" | "mutation" | "checkpoint" | "gap";
export interface ReplayEvent { readonly at_ns: string; readonly kind: ReplayEventKind; readonly node: string; readonly x: number; readonly y: number }
export interface ReplayClock { readonly wall_ns: string; readonly mono_ns: string; readonly domain: { readonly host: string; readonly boot: string; readonly runtime: string }; readonly uncertainty_ns: string }
/**
 * Mirrors C04 ReplayChunk. A chunk is a checkpoint chunk when checkpoint_sequence === sequence;
 * continuation chunks of one snapshot repeat the first chunk's sequence. gap=true means history
 * before this chunk is not continuous.
 */
export interface ReplayChunk {
 readonly replay_id: string;
 readonly session_id: string;
 readonly recorder_version: string;
 readonly sequence: string;
 readonly previous_hash: string;
 readonly checkpoint_sequence: string;
 readonly checkpoint_hash: string;
 readonly clock: ReplayClock;
 readonly nodes: readonly ReplayNode[];
 readonly events: readonly ReplayEvent[];
 readonly loss: string;
 readonly gap: boolean;
 readonly capture_policy_revision: string;
}
export type EnqueueResult = "accepted" | "rejected";

/** Platform-owned reads, captured from prototypes so own-property getter traps never run. */
export interface DomAccessors {
 nodeType(node: object): number;
 firstChild(node: object): object | null;
 nextSibling(node: object): object | null;
 parentNode(node: object): object | null;
 localName(element: object): string;
 /** Open shadow root or null. Closed roots are invisible to page script and become opaque only when closedShadow reports them. */
 openShadowRoot(element: object): object | null;
 closedShadow?(element: object): boolean;
 editable(element: object): boolean;
 mutationTarget(record: object): object | null;
 eventTarget(event: object): object | null;
 clientX(event: object): number;
 clientY(event: object): number;
}
export interface MutationObserverLike { observe(target: object, options: object): void; disconnect(): void }
export interface ReplayEventTargetLike { addEventListener(type: string, listener: (event: object) => void, options: object): void; removeEventListener(type: string, listener: (event: object) => void, options: object): void }
export interface ReplayTimers { set(callback: () => void, ms: number): unknown; clear(handle: unknown): void }
export interface ReplayConfig {
 /** Project policy says replay is approved. */
 readonly projectPolicy: boolean;
 /** Deployment explicitly opted in. */
 readonly deploymentOptIn: boolean;
 readonly root: object;
 readonly replayId: string;
 readonly sessionId: string;
 readonly capturePolicyRevision: string;
 readonly domain: { readonly host: string; readonly boot: string; readonly runtime: string };
 readonly clock: () => { readonly wall_ns: string; readonly mono_ns: string; readonly uncertainty_ns: string };
 readonly dom?: DomAccessors;
 readonly observer?: new (callback: (records: readonly object[]) => void) => MutationObserverLike;
 readonly eventTarget?: ReplayEventTargetLike;
 readonly viewport?: () => { readonly w: number; readonly h: number; readonly x: number; readonly y: number };
 readonly timers?: ReplayTimers;
 /** Called after setConsent(false) so the owner can destroy its own pending replay chunks. */
 readonly onRevoked?: () => void;
}
export interface ReplayRecorder { setConsent(enabled: boolean): void; close(): void }
