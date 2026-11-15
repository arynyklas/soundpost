// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// The saved-view flow apart from React: what a save sends, what opening a view does to the form, what each server answer makes of
// the outcome, and the export document. A saved view is a query the person chose to keep: it is sent only by an explicit save, it
// is owned by one project, and opening it never switches a profile or a project selection behind the person's back.
import { ApiFault, OutcomeUnknown, type Id, type SavedView, type SavedViewDeleteRequest, type SavedViewSaveRequest } from '../api/types';
import type { ViewContext } from '../app/context';
import { selection, type Built, type QueryForm } from './form';
import { featuresOf, profileById, type ProfileInfo } from './profiles';

export const MAX_NAME_BYTES = 120;
export const MAX_SAVED_EXPRESSION_BYTES = 16384;
/** The server keeps at most this many saved views per project and refuses another, never dropping an older one. */
export const MAX_VIEWS_PER_PROJECT = 100;

export interface SaveInput {
 name: string;
 /** The project that owns the view: one of the form's projects. */
 project: Id;
 commandId: Id;
 /** Present when the form was opened from a saved view and is saved over it, at the revision that was read. */
 update?: { id: Id; revision: string };
}

/** The request of one explicit save, or every reason the form cannot be saved. The text is sent exactly as typed. A query over a restricted source is never saved: its readers hold raw.read, a grant a project saved view cannot carry. */
export function buildSaveRequest(context: ViewContext, form: QueryForm, registry: readonly ProfileInfo[], input: SaveInput): Built<SavedViewSaveRequest> {
 const { problems, featureSet } = selection(context, form, registry);
 const name = input.name.trim();
 const nameBytes = new TextEncoder().encode(name).length;
 if (name === '') problems.push('Give the view a name.');
 else if (nameBytes > MAX_NAME_BYTES || /\p{Cc}/u.test(name)) problems.push(`The name may be at most ${MAX_NAME_BYTES} bytes and must not contain control characters.`);
 if (new TextEncoder().encode(form.expression).length > MAX_SAVED_EXPRESSION_BYTES) problems.push(`A saved query may be at most ${MAX_SAVED_EXPRESSION_BYTES} bytes.`);
 if (form.source !== '') problems.push('A query over a restricted source is not saved.');
 if (!form.projects.includes(input.project)) problems.push('The owning project must be one of the selected projects.');
 if (form.mode === 'range' && !/^[1-9][0-9]{0,9}$/.test(form.stepSeconds)) problems.push('The step must be a whole number of seconds, at least 1.');
 if (form.language === 'logql' && form.logLimit !== '' && !/^[1-9][0-9]{0,19}$/.test(form.logLimit)) problems.push('The log page size must be a whole number of at least 1.');
 if (problems.length > 0) return { ok: false, problems };
 const request: SavedViewSaveRequest = {
  org: context.org, project: input.project, operation: 'save', command_id: input.commandId, name,
  language: form.language, profile: form.profileId, feature_set: featureSet, expression: form.expression,
  projects: [...form.projects], mode: form.mode, allow_partial: form.allowPartial,
  ...(form.mode === 'range' ? { step_seconds: form.stepSeconds } : {}),
  ...(form.language === 'logql' ? { ...(form.logLimit !== '' ? { log_limit: form.logLimit } : {}), log_order: form.logOrder } : {}),
  ...(input.update !== undefined ? { id: input.update.id, expected_revision: input.update.revision } : {}),
 };
 return { ok: true, request };
}

export function buildDeleteRequest(context: ViewContext, view: SavedView, commandId: Id): SavedViewDeleteRequest {
 return { org: context.org, project: view.project, operation: 'delete', command_id: commandId, id: view.id, expected_revision: view.revision };
}

/** What opening a saved view does to the form, or why it cannot be opened. The form takes exactly what was saved. A profile or feature set the server no longer registers, or a project outside the selected scope, is a refusal that says so: nothing is switched to another profile and no project is silently dropped. */
export function openView(context: ViewContext, view: SavedView, registry: readonly ProfileInfo[]): { ok: true; patch: Partial<QueryForm> } | { ok: false; reason: string } {
 const profile = profileById(registry, view.profile);
 if (profile === undefined) return { ok: false, reason: `The profile ${view.profile} is not registered by this server any more, so this view cannot be opened. It is not switched to another profile.` };
 if (profile.language !== view.language) return { ok: false, reason: 'This view names a profile of the other language, so it cannot be opened.' };
 const features = featuresOf(profile, view.feature_set);
 if (features === null) return { ok: false, reason: `The feature set of this view is not registered by ${profile.id} any more, so it cannot be opened. It is not switched to another feature set.` };
 const outside = view.projects.filter((p) => !context.projects.includes(p));
 if (outside.length > 0) return { ok: false, reason: `This view runs over ${outside.length === 1 ? 'a project' : 'projects'} outside the selected scope (${outside.join(', ')}). Add ${outside.length === 1 ? 'it' : 'them'} to the scope to open it; the view is not narrowed for you.` };
 return {
  ok: true,
  patch: {
   language: view.language, profileId: view.profile, features, expression: view.expression, mode: view.mode,
   stepSeconds: view.step_seconds ?? '15', projects: context.projects.filter((p) => view.projects.includes(p)), allowPartial: view.allow_partial,
   logLimit: view.log_limit ?? '', logOrder: view.log_order ?? 'backward', source: '',
  },
 };
}

/** What the page says of the last save or delete. Only a committed answer is shown as done; a refusal keeps the person's text. */
export type SavedOutcome =
 | { kind: 'idle' }
 | { kind: 'invalid'; problems: string[] }
 | { kind: 'pending' }
 | { kind: 'saved'; view: SavedView; updated: boolean }
 | { kind: 'deleted'; id: Id; name: string }
 | { kind: 'conflict'; what: 'save' | 'delete' }
 | { kind: 'unknown'; what: 'save' | 'delete' }
 | { kind: 'refused'; status: number; code: string; requestId: string };

export type SavedSettled = { kind: 'saved'; view: SavedView; updated: boolean } | { kind: 'deleted'; id: Id; name: string } | { kind: 'failure'; what: 'save' | 'delete'; error: unknown };

export interface SavedSettlement {
 outcome: SavedOutcome;
 /** The project's list is read again from the server. */
 reload: boolean;
 /** The name field is cleared (it was used by a committed save). */
 clearName: boolean;
}

/** A 409 is a lost race, never a merge: the revision moved or the project is full, and the list is re-read so the person sees what is there now. A transport failure is an unknown outcome the same command ID may repeat. Anything else keeps the server's own code. */
export function settleSaved(settled: SavedSettled): SavedSettlement {
 if (settled.kind === 'saved') return { outcome: { kind: 'saved', view: settled.view, updated: settled.updated }, reload: true, clearName: true };
 if (settled.kind === 'deleted') return { outcome: { kind: 'deleted', id: settled.id, name: settled.name }, reload: true, clearName: false };
 const error = settled.error;
 if (error instanceof OutcomeUnknown) return { outcome: { kind: 'unknown', what: settled.what }, reload: false, clearName: false };
 if (error instanceof ApiFault) {
  if (error.status === 409) return { outcome: { kind: 'conflict', what: settled.what }, reload: true, clearName: false };
  return { outcome: { kind: 'refused', status: error.status, code: error.code, requestId: error.requestId }, reload: false, clearName: false };
 }
 return { outcome: { kind: 'refused', status: 0, code: 'unavailable', requestId: '' }, reload: false, clearName: false };
}

/** The words for a refusal: a 404 is deliberately the same for a missing project, a missing view and a missing grant. */
export function refusalWords(status: number): string {
 if (status === 401) return 'Your session has ended. Sign in again; nothing was saved or deleted.';
 if (status === 404) return 'This view or project was not found or is not available to this account. Nothing was changed.';
 if (status === 429) return 'This project already holds the most saved views it may. Delete one first; nothing was saved.';
 if (status === 413) return 'The view is too large. Nothing was saved.';
 return 'The server refused this. Nothing was changed.';
}

/** The text of an export: the views exactly as the server holds them for the project, nothing added by the browser. */
export function exportDocument(org: Id, project: Id, views: readonly SavedView[]): string {
 return JSON.stringify({ format: 'soundpost.saved-views', version: 1, org, project, views }, null, 2);
}
