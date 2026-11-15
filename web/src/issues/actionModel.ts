// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// The state machine behind the issue actions panel, apart from React so every transition is a plain function: what a submit does
// (refuse locally, or send one request and wait), and what each kind of server answer or failure makes of the outcome, of the form
// and of the page's copy of the issue. The browser holds no issue state of its own: only a committed answer from the server changes
// what is shown as done, and the page then re-reads the stored issue.
import { ApiFault, OutcomeUnknown, VersionConflict, type ActionKind, type ActionRequest, type ActionResponse, type Id, type IssueActionView, type IssueEvidenceView } from '../api/types';
import { buildIssueAction } from '../evidence/model';

/** What the server has told us about the last action. A committed answer is the issue exactly as the lifecycle committed it, and `not_available` is shown as exactly that. */
export type IssueOutcome =
 | { kind: 'idle' }
 | { kind: 'invalid'; text: string }
 | { kind: 'pending' }
 | { kind: 'committed'; action: ActionKind; issue: IssueActionView }
 | { kind: 'not_available'; reason: string }
 | { kind: 'conflict'; detail: string; expected: string; current: string }
 | { kind: 'unknown'; request: ActionRequest }
 | { kind: 'refused'; status: number; detail: string; code: string; requestId: string };

/** The one sentence a conflict gets: a moved revision and a transition the workflow does not allow are different facts and are never merged. */
export function conflictWords(detail: string, expected: string, current: string): string {
 return detail === 'issue_state_conflict'
  ? `The issue is at revision ${current}, the revision you acted on, but its workflow state does not allow this action (for example: resolving an issue that is already resolved, or reopening one that is not resolved). Nothing was changed.`
  : `The issue is now at revision ${current}; you were acting on revision ${expected}. Nothing was changed. The page is reloading the issue so you can act on what is there now.`;
}

export interface SubmitInput {
 org: Id;
 project: Id;
 view: IssueEvidenceView;
 kind: ActionKind;
 reason: string;
 fixedIn: string;
 /** The outcome on screen now. */
 outcome: IssueOutcome;
 /** The page is re-reading the issue. */
 busy: boolean;
 commandId: Id;
}

/** `request` is the one request to send, or null when nothing is sent. A submit while one is pending or the page is re-reading does nothing at all; a form that cannot be a request says why and sends nothing; otherwise the outcome becomes pending. Only a resolve carries fix releases. */
export function submitIssueAction(input: SubmitInput): { outcome: IssueOutcome; request: ActionRequest | null } {
 if (input.outcome.kind === 'pending' || input.busy) return { outcome: input.outcome, request: null };
 const built = buildIssueAction(input.org, input.project, input.view, input.kind, input.reason, input.commandId, input.kind === 'resolve' ? input.fixedIn : '');
 if (!built.ok) return { outcome: { kind: 'invalid', text: built.error }, request: null };
 return { outcome: { kind: 'pending' }, request: built.value };
}

/** What came back for a sent request: the server's answer, or the way the call failed. */
export type Settled = { kind: 'answer'; response: ActionResponse } | { kind: 'failure'; error: unknown };

export interface Settlement {
 outcome: IssueOutcome;
 /** The reason and fix releases were used and are cleared. Kept otherwise, so a refusal never costs the person their text. */
 clearForm: boolean;
 /** The page re-reads the stored issue. */
 reload: boolean;
}

/** The outcome of one settled request. Committed needs the issue the server committed; a version or state conflict, which differ, reload the page to the current revision; an unknown outcome keeps the request for an identical resend; a refusal keeps the server's own code. Anything else is a plain unavailable refusal, never a success. */
export function settleIssueAction(request: ActionRequest, settled: Settled): Settlement {
 if (settled.kind === 'answer') {
  const response = settled.response;
  if (response.state === 'committed' && response.issue) return { outcome: { kind: 'committed', action: request.kind, issue: response.issue }, clearForm: true, reload: true };
  return { outcome: { kind: 'not_available', reason: response.reason ?? 'not_available' }, clearForm: false, reload: false };
 }
 const error = settled.error;
 if (error instanceof VersionConflict) return { outcome: { kind: 'conflict', detail: error.detail, expected: request.expected_version, current: error.currentVersion }, clearForm: false, reload: true };
 if (error instanceof OutcomeUnknown) return { outcome: { kind: 'unknown', request }, clearForm: false, reload: false };
 if (error instanceof ApiFault) return { outcome: { kind: 'refused', status: error.status, detail: error.detail, code: error.code, requestId: error.requestId }, clearForm: false, reload: false };
 return { outcome: { kind: 'refused', status: 0, detail: '', code: 'unavailable', requestId: '' }, clearForm: false, reload: false };
}
