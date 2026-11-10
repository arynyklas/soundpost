// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import type { ActionKind, ActionRequest, AncestryOrder, Id, IssueEvidenceView, OccurrenceEvidence, SafeFrame, SourceView } from '../api/types';

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
 unmapped: 'Not mapped: this frame has no line and column to look up.',
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

/** The request for one issue action against the revision on screen. There is no actor, origin or timestamp field, and the browser holds no issue state of its own: the answer decides. */
export function buildIssueAction(org: Id, project: Id, view: IssueEvidenceView, kind: ActionKind, reason: string, commandId: Id): Parsed<ActionRequest> {
 const text = reason.trim();
 if (!ISSUE_ACTIONS.includes(kind)) return { ok: false, error: 'Choose one of the listed actions.' };
 if (!view.grouping) return { ok: false, error: 'The issue revision is not known, so no action can be prepared.' };
 if (new TextEncoder().encode(text).length > 512 || /\p{Cc}/u.test(text)) return { ok: false, error: 'The reason may be at most 512 bytes and must not contain control characters.' };
 return { ok: true, value: { org, command_id: commandId, expected_version: view.grouping.revision, project_id: project, target_id: view.issue, entity_kind: 'issue', kind, payload: text ? { reason: text } : {} } };
}

export const EVIDENCE_REASON: Record<string, string> = {
 release_records_need_org_admin: 'Release records can only be read by an organization administrator. Your account can read telemetry for this project, but not the release registry.',
 issue_evidence_needs_org_admin: 'Persisted issue evidence can only be read by an organization administrator in this installation. Your account cannot read it.',
 issue_evidence_view_not_built: 'Persisted issue evidence is not available in this installation: no issue evidence reader is wired.',
 release_reader_not_wired: 'The release registry is not wired in this installation.',
 occurrence_payload_view_not_built: 'Occurrence payloads (exception chain, mechanism, handled or fatal, code) are not available: no view projects stored error records into an issue yet.',
 regression_explanation_view_not_built: 'No regression explanation is available: the stored explanations are not projected yet. A regression is never inferred from timestamps or release labels.',
 ancestry_unknown: 'Some release ancestry is unknown. Unknown ancestry is not a regression and is never guessed.',
 frames_unmapped: 'Some frames were not mapped; each lists its reason and keeps the original sanitized frame.',
};
