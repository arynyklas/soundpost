// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Turns what the Explore form says into the exact C06 request, or into every reason it cannot be one. Nothing is defaulted
// behind the person's back: the profile and the registered feature set that are sent are the ones selected, the expression is
// sent exactly as typed, sizes and times are exact decimal strings, and partial results are requested only when opted into.
import type { LiveTicketRequest, QueryLanguage, QueryRequest } from '../api/types';
import { isId, validWindow, type ViewContext } from '../app/context';
import { featureSetId, profileById, profilesFor } from './profiles';

export interface QueryForm {
 language: QueryLanguage;
 profileId: string;
 /** The registered features that are enabled; their set is looked up in the profile, never guessed. */
 features: string[];
 expression: string;
 mode: 'instant' | 'range';
 /** Nanoseconds since the epoch, canonical decimal. */
 instantTime: string;
 /** A whole number of seconds. */
 stepSeconds: string;
 projects: string[];
 allowPartial: boolean;
 /** The most samples or log entries the query may return before it is refused (decimal). */
 maxReturned: string;
 /** LogQL log queries only; '' sends none, so an over-budget result is a typed quota error. */
 logLimit: string;
 logOrder: 'backward' | 'forward';
 /** A named restricted source for a raw.read query; '' for ordinary telemetry. */
 source: string;
}
export type Built<T> = { ok: true; request: T } | { ok: false; problems: string[] };
/** The server decodes at most this many bytes of a request body. */
export const MAX_BODY_BYTES = 65536;

const INT64_MAX = 9223372036854775807n;
const UINT64_MAX = 18446744073709551615n;
const wholeNs = (v: string): boolean => /^(0|[1-9][0-9]{0,18})$/.test(v) && BigInt(v) <= INT64_MAX;
const positive = (v: string, max: bigint): boolean => /^[1-9][0-9]{0,19}$/.test(v) && BigInt(v) <= max;

export function defaultForm(context: ViewContext, language: QueryLanguage): QueryForm {
 return {
  language, profileId: profilesFor(language)[0]?.id ?? '', features: [], expression: '', mode: language === 'logql' ? 'range' : 'instant', instantTime: context.end, stepSeconds: '15',
  projects: context.projects, allowPartial: false, maxReturned: '10000', logLimit: '1000', logOrder: 'backward', source: '',
 };
}

/** The shared selection checks: profile, registered feature set, projects, expression and restricted source. */
function selection(context: ViewContext, form: QueryForm): { problems: string[]; featureSet: string } {
 const problems: string[] = [];
 let featureSet = '';
 if (form.expression.trim() === '') problems.push('Enter a query expression.');
 const profile = profileById(form.profileId);
 if (profile === undefined) problems.push('Choose a pinned profile.');
 else if (profile.language !== form.language) problems.push('The profile does not belong to the selected language.');
 else {
  const id = featureSetId(profile, form.features);
  if (id === null) problems.push('This profile registers no feature set with exactly these features.');
  else featureSet = id;
 }
 if (form.projects.length === 0) problems.push('Select at least one project.');
 else if (form.projects.some((p) => !context.projects.includes(p)) || new Set(form.projects).size !== form.projects.length) problems.push('Every project must be one of the projects in the selected scope.');
 if (form.source !== '') {
  if (!isId(form.source)) problems.push('The restricted source ID must be 32 lowercase hexadecimal characters.');
  else if (form.language !== 'logql') problems.push('A restricted source can only be read with LogQL.');
  else if (form.projects.length !== 1) problems.push('A restricted source is read for exactly one project.');
 }
 return { problems, featureSet };
}

const tooLarge = (body: unknown): string | null => (new TextEncoder().encode(JSON.stringify(body)).length > MAX_BODY_BYTES ? `The request is larger than the ${MAX_BODY_BYTES}-byte limit.` : null);

export function buildQueryRequest(context: ViewContext, form: QueryForm): Built<QueryRequest> {
 const { problems, featureSet } = selection(context, form);
 let evaluation: QueryRequest['evaluation'] = { instant: true, time: '0', start: '0', end: '0', step: '0' };
 if (form.mode === 'instant') {
  if (!wholeNs(form.instantTime)) problems.push('The evaluation time must be whole nanoseconds.');
  else evaluation = { instant: true, time: form.instantTime, start: '0', end: '0', step: '0' };
 } else if (!/^[1-9][0-9]{0,9}$/.test(form.stepSeconds)) problems.push('The step must be a whole number of seconds, at least 1.');
 else if (!validWindow(context.start, context.end)) problems.push('The selected window is not a valid half-open range.');
 else evaluation = { instant: false, time: '0', start: context.start, end: context.end, step: String(BigInt(form.stepSeconds) * 1_000_000_000n) };
 const budgetOk = positive(form.maxReturned, UINT64_MAX);
 if (!budgetOk) problems.push('The result budget must be a whole number of at least 1.');
 let logLimit = '';
 if (form.language === 'logql' && form.logLimit !== '') {
  if (!positive(form.logLimit, UINT64_MAX)) problems.push('The log page size must be a whole number of at least 1.');
  else if (budgetOk && BigInt(form.logLimit) > BigInt(form.maxReturned)) problems.push('The log page size cannot exceed the result budget.');
  else logLimit = form.logLimit;
 }
 if (problems.length > 0) return { ok: false, problems };
 const request: QueryRequest = {
  org: context.org, language: form.language, profile: form.profileId, expression: form.expression, feature_set: featureSet, evaluation, projects: [...form.projects],
  budget: { timeout_ns: '0', memory_bytes: '0', max_returned: form.maxReturned }, allow_partial: form.allowPartial,
  ...(form.source !== '' ? { permission: 'raw.read' as const, source: form.source } : {}),
  ...(form.language === 'logql' ? { ...(logLimit !== '' ? { log_limit: logLimit } : {}), log_order: form.logOrder } : {}),
 };
 const large = tooLarge(request);
 return large === null ? { ok: true, request } : { ok: false, problems: [large] };
}

/** The stored selector of a live stream: a LogQL log query over the selected projects. The stream's own limits are the server's defaults. */
export function buildLiveRequest(context: ViewContext, form: QueryForm): Built<LiveTicketRequest> {
 const { problems, featureSet } = selection(context, form);
 if (form.language !== 'logql') problems.push('Only a LogQL log query can be streamed live.');
 if (problems.length > 0) return { ok: false, problems };
 const request: LiveTicketRequest = {
  org: context.org, projects: [...form.projects], profile: form.profileId, feature_set: featureSet, expression: form.expression,
  budget: { timeout_ns: '0', memory_bytes: '0', max_returned: '0' },
  ...(form.source !== '' ? { permission: 'raw.read' as const, source: form.source } : {}),
 };
 const large = tooLarge(request);
 return large === null ? { ok: true, request } : { ok: false, problems: [large] };
}
