// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import type { ActionKind, ActionPayload, ActionRequest, AncestryOrder, ExceptionChain, ExceptionEdge, Id, IssueEvidenceView, OccurrenceEvidence, RegressionExplanation, SafeFrame, SourceView } from '../api/types';

export const MAX_FRAMES = 64;
export const MAX_COMPARE = 16;
const ID = /^[0-9a-f]{32}$/;
const MAX_TEXT = 512;

/** What each symbolication outcome means to a reader. Every non-mapped outcome keeps the original sanitized frame; nothing here suggests a guess. */
const FRAME_REASON: Record<string, string> = {
 resolved: 'Mapped through the exact source map of this build.',
 identity_mismatch: 'Not mapped: the artifact is not part of this build, or its identity does not match the recorded debug and generated hashes.',
 artifact_unavailable: 'Not mapped: no source map is available for this artifact in your scope (absent, expired, deleted or not readable by you).',
 artifact_corrupt: 'Not mapped: the stored source map failed its integrity check.',
 invalid_map: 'Not mapped: the stored source map is not a valid map.',
 resource_limit: 'Not mapped: the source map exceeds the size limits of the sandboxed resolver.',
 deadline: 'Not mapped: the resolver ran out of time for this frame.',
 sandbox_unavailable: 'Not mapped: the sandbox that resolves source maps is not available on this server, so no map was read.',
 worker_failure: 'Not mapped: the sandboxed resolver failed on this frame.',
 unmapped: 'Not mapped: the frame has no line and column, or the source map has no mapping at that position.',
 source_context_denied: 'Mapped position unavailable: the source context was requested but the separate sources grant was not held.',
 frame_limit: 'Not mapped: more distinct frames were requested than one lookup resolves.',
 artifact_read_not_granted: 'Not mapped: your account holds telemetry access to this project but not the artifacts.read grant.',
 symbolicator_not_wired: 'Not mapped: this installation has no symbolication service wired.',
};
export function frameReasonWords(reason: string): string { return FRAME_REASON[reason] ?? 'Not mapped: the resolver gave a reason this page does not recognise.'; }

const SOURCE_REASON: Record<string, string> = {
 sources_not_requested: 'Source content was not requested; it is never fetched by default.',
 source_grant_required: 'Source content is withheld: reading source text needs the separate sources grant (artifacts.read, raw.read and a named source-reader entry), which this account does not hold for this artifact.',
 no_source_content: 'This source map carries no source content, so only the position is shown.',
 frame_not_mapped: 'No source context is shown because this frame was not mapped; that is not a statement about your grant.',
};
/** One plain sentence for the source state of a frame. State is always spelled out; never colour alone. */
export function sourceWords(source: SourceView): string {
 switch (source.state) {
  case 'present': return 'Source context is shown below because this account holds the separate sources grant.';
  case 'withheld': return SOURCE_REASON[source.reason ?? ''] ?? 'Source content is withheld.';
  case 'absent': return SOURCE_REASON[source.reason ?? ''] ?? 'No source content exists for this frame.';
 }
}

/** `file:line:column in function`, from the mapped identity or the original sanitized frame. */
export function positionText(file: string, line: number, column: number | null, fn: string): string {
 return `${file}:${line}${column === null ? '' : `:${column}`}${fn ? ` in ${fn}` : ''}`;
}

export type Parsed<T> = { ok: true; value: T } | { ok: false; error: string };

/** One frame per line: `<artifact id> <line> <column|-> <function name>`. The artifact must be an exact 32-hex ArtifactID: a path, URL or release label is never accepted as an identity. */
export function parseFrameLines(text: string): Parsed<SafeFrame[]> {
 const lines = text.split('\n').map((l) => l.trim()).filter((l) => l !== '');
 if (lines.length === 0) return { ok: false, error: 'Enter at least one frame.' };
 if (lines.length > MAX_FRAMES) return { ok: false, error: `Enter at most ${MAX_FRAMES} frames.` };
 const frames: SafeFrame[] = [];
 for (const [i, line] of lines.entries()) {
  const m = /^([^\s]+)\s+(\d{1,9})\s+(\d{1,9}|-)(?:\s+(.*))?$/.exec(line);
  const where = `Line ${i + 1}`;
  if (!m) return { ok: false, error: `${where}: expected "<artifact id> <line> <column or -> <function>".` };
  const [, artifact = '', lineNo = '', column = '', fn = ''] = m;
  if (!ID.test(artifact)) return { ok: false, error: `${where}: the artifact must be an artifact ID of 32 lowercase hexadecimal characters, not a path, URL or label.` };
  if (fn.length > MAX_TEXT || /\p{Cc}/u.test(fn)) return { ok: false, error: `${where}: the function name is too long or contains control characters.` };
  frames.push({ module_id: '', function: fn, artifact_id: artifact, line: Number(lineNo), column: column === '-' ? null : Number(column), in_app: true, async: false });
 }
 return { ok: true, value: frames };
}

/** Releases to compare against: distinct IDs separated by commas or spaces, at most 16. */
export function parseCompareIds(text: string): Parsed<Id[]> {
 const ids = text.split(/[\s,]+/).filter((s) => s !== '');
 if (ids.length > MAX_COMPARE) return { ok: false, error: `Compare at most ${MAX_COMPARE} releases.` };
 if (!ids.every((s) => ID.test(s)) || new Set(ids).size !== ids.length) return { ok: false, error: 'Each release ID must be 32 lowercase hexadecimal characters, listed once.' };
 return { ok: true, value: ids };
}

/** The relation of the viewed release to another, from immutable parent edges only. `unknown` is never turned into a verdict. */
export function orderWords(order: AncestryOrder): string {
 switch (order) {
  case 'same': return 'This is the same release.';
  case 'ancestor': return 'This release is an ancestor of it: it was built on top of this release.';
  case 'descendant': return 'This release is a descendant of it: this release was built on top of it.';
  case 'concurrent': return 'The two are concurrent: neither is an ancestor of the other.';
  case 'unknown': return 'Ancestry unknown: the registered parent edges do not connect them, so no order is claimed.';
 }
}

export function occurrenceAncestryWords(o: OccurrenceEvidence): string {
 return o.ancestry === 'known'
  ? `Release ancestry known (release ${o.release_id ?? ''}).`
  : 'Ancestry unknown: this occurrence carries no usable release ancestry, so no regression is claimed from it.';
}

export const ISSUE_ACTIONS: readonly ActionKind[] = ['resolve', 'ignore', 'unignore', 'reopen'];
export const ISSUE_ACTION_LABEL: Record<string, string> = { resolve: 'Resolve', ignore: 'Ignore', unignore: 'Stop ignoring', reopen: 'Reopen' };

/** The request for one issue action against the revision on screen. There is no actor, origin or timestamp field, and the browser holds no issue state of its own: the answer decides. The server requires a reason for every issue action (it is the audit record's reason), and only a resolve may name the releases that contain the fix. */
export function buildIssueAction(org: Id, project: Id, view: IssueEvidenceView, kind: ActionKind, reason: string, commandId: Id, fixedIn: string = ''): Parsed<ActionRequest> {
 const text = reason.trim();
 if (!ISSUE_ACTIONS.includes(kind)) return { ok: false, error: 'Choose one of the listed actions.' };
 if (!view.grouping) return { ok: false, error: 'The issue revision is not known, so no action can be prepared.' };
 if (text === '') return { ok: false, error: 'Give a reason: it is recorded with the action in the audit trail.' };
 if (new TextEncoder().encode(text).length > 512 || /\p{Cc}/u.test(text)) return { ok: false, error: 'The reason may be at most 512 bytes and must not contain control characters.' };
 const payload: ActionPayload = { reason: text };
 if (fixedIn.trim() !== '') {
  if (kind !== 'resolve') return { ok: false, error: 'Only a resolve names the releases that contain the fix.' };
  const parsed = parseCompareIds(fixedIn);
  if (!parsed.ok) return { ok: false, error: parsed.error.replace('Compare at most', 'Name at most') };
  payload.fixed_frontier = parsed.value;
 }
 return { ok: true, value: { org, command_id: commandId, expected_version: view.grouping.revision, project_id: project, target_id: view.issue, entity_kind: 'issue', kind, payload } };
}

/** The decision of one stored regression evaluation. The reason itself is the evaluator's stored sentence and is shown beside this verdict, never replaced by it. */
export function regressionDecisionWords(x: RegressionExplanation): string {
 return x.eligible ? 'Eligible: this occurrence qualifies as a recurrence of the resolved issue.' : 'Not eligible: this occurrence is not a recurrence of the resolved issue.';
}

/** Ancestry is part of the verdict: unknown ancestry is decided by the explicit resolution time boundary and says so, it is never presented as release ancestry. */
export function regressionAncestryWords(x: RegressionExplanation): string {
 return x.ancestry_known ? 'Release ancestry known.' : 'Ancestry unknown: decided by the explicit resolution time boundary, not by release ancestry.';
}

export function regressionPolicyWords(x: RegressionExplanation): string {
 const within = x.window_ns === '0' ? 'with no time window' : `within ${x.window_ns} ns of event time`;
 return `${x.qualifying} qualifying of ${x.threshold} needed, ${within}.`;
}

export function regressionOutcomeWords(x: RegressionExplanation): string {
 return x.reopened ? 'Reopened the issue.' : 'Did not reopen the issue.';
}

const MECHANISM_WORDS: Record<string, string> = {
 manual: 'Reported by the application itself (captured and sent by hand).',
 uncaught_exception: 'An exception nothing caught: it reached the top of the program.',
 unhandled_rejection: 'A promise rejection nothing handled.',
 thread_exception: 'An exception that ended a thread.',
 asyncio_exception: 'An exception the asynchronous event loop reported.',
};
export function mechanismWords(mechanism: string): string { return MECHANISM_WORDS[mechanism] ?? 'A mechanism this page does not recognise.'; }

/** The stored handled and fatal flags in words. They are two separate facts: a handled error can still be recorded as fatal and an unhandled one as not fatal. */
export function handledFatalWords(handled: boolean, fatal: boolean): string {
 return `${handled ? 'Handled' : 'Not handled'}, ${fatal ? 'fatal' : 'not fatal'}.`;
}

const CHAIN_REASON_WORDS: Record<string, string> = {
 cycle: 'the chain loops back on itself; the repeated error was not followed again',
 node_limit: 'the chain has more errors than a record keeps; the rest were not stored',
 frame_limit: 'the chain has more frames than a record keeps; the rest were not stored',
 group_limit: 'an error group has more members than a record keeps; the rest were not stored',
 unknown_throw: 'a thrown value was not an error object, so nothing about it was stored',
 project_root_unconfigured: 'the SDK had no project root configured, so frame paths were not made project-relative',
 frame_not_project_safe: 'a frame path could not be made project-relative safely and was left out',
 foreign_or_custom_error_class: 'an error class from another realm or a custom class was not recognised',
 safe_original_stack_unavailable: 'the original stack could not be read safely',
 stack_formatter_hooked: 'the runtime stack formatter was replaced by the application, so the stack was not parsed',
 stack_not_plain: 'the stack was not plain text',
 stack_unparsed: 'the stack text was not in a format the SDK parses',
 native_brand_unavailable: 'the native error brand could not be checked',
 cause_accessor: 'the cause was behind an accessor, which the SDK never runs',
 group_accessor: 'the group members were behind an accessor, which the SDK never runs',
 safe_group_boundary_unavailable: 'the boundary of an error group could not be established safely',
 unsafe_group_container: 'the group container was not a plain list, so its members were not read',
};
export function chainReasonWords(reason: string): string { return CHAIN_REASON_WORDS[reason] ?? 'a reason this page does not recognise'; }

/** One edge of the stored exception chain as a sentence: the stored kind and the two classes it joins, in the stored direction. Nothing is added about which error came first. */
export function chainEdgeWords(chain: ExceptionChain, edge: ExceptionEdge): string {
 const name = (i: number): string => `${chain.nodes[i]?.exception_class ?? '?'} (node ${i})`;
 const kind = edge.kind === 'group' ? `group member ${(edge.ordinal ?? 0) + 1}` : edge.kind;
 return `${name(edge.from)} to ${name(edge.to)}: ${kind}`;
}

export const EVIDENCE_REASON: Record<string, string> = {
 release_records_need_org_admin: 'Release records can only be read by an organization administrator. Your account can read telemetry for this project, but not the release registry.',
 issue_evidence_needs_org_admin: 'Persisted issue evidence can only be read by an organization administrator in this installation. Your account cannot read it.',
 issue_evidence_view_not_built: 'Persisted issue evidence is not available in this installation: no issue evidence reader is wired.',
 release_reader_not_wired: 'The release registry is not wired in this installation.',
 occurrence_payload_view_not_built: 'Occurrence payloads (exception chain, mechanism, handled or fatal, code) are not available: this installation has no reader of stored error records wired.',
 occurrence_needs_telemetry_read: 'The stored occurrence (exception chain, mechanism, handled or fatal, code, frames) is telemetry: reading it needs the telemetry.read grant on this project, which administration alone does not give.',
 occurrence_not_stored: 'This occurrence is no longer stored: its record expired or was erased. The evidence about it stays; its payload does not.',
 occurrence_read_partial: 'The stored occurrence could not be found, but some storage did not answer, so it is not known whether it still exists. Try again.',
 evidence_window_compacted: 'This issue has more evidence than one list holds: the oldest occurrences are folded into counts and are no longer listed here.',
 regression_explanation_view_not_built: 'No regression explanation is available: this installation has no reader of the stored explanations wired. A regression is never inferred from timestamps or release labels.',
 no_regression_evaluated: 'No regression has been evaluated: no occurrence has arrived after a resolution. That is not a statement that none can happen.',
 ancestry_unknown: 'Some release ancestry is unknown. Unknown ancestry is not a regression and is never guessed.',
 frames_unmapped: 'Some frames were not mapped; each lists its reason and keeps the original sanitized frame.',
 sandbox_unavailable: 'Symbolication is not available: the sandbox that resolves source maps could not start on this server, so no map was read. The original sanitized frames are kept.',
};
