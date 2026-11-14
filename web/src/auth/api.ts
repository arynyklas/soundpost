// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
export type Id = string;
export interface Session { csrf: string; user: Id; expires: string }
export class RequestFailure extends Error {
 constructor(public status: number, public requestId: string, route: string) {
  let message = 'The request was not accepted. Check your entries and try again.';
  if (status === 401) {
   switch (route) {
    case 'login': message = 'Sign-in could not be verified. Check your credentials.'; break;
    case 'reauthenticate': message = 'Reauthentication could not be verified. Check your credentials.'; break;
    case 'bootstrap': message = 'Initialization could not be verified. Check the one-use token.'; break;
    case 'oidc/start': message = 'Single sign-on could not be started. Check the organization and provider details.'; break;
    default: message = 'Your session has ended. Sign in again.';
   }
  } else if (status === 403 || status === 404) message = 'Access is not available for this account or selection.';
  else if (status === 503) message = 'The authority is unavailable. No change was confirmed.';
  super(message);
 }
}
export async function request<T>(route: string, body?: unknown, csrf?: string, signal?: AbortSignal): Promise<T> {
 const response = await fetch(`/api/v1/${route}`, { method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(csrf ? { 'X-CSRF-Token': csrf } : {}) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }), ...(signal ? {signal} : {}) });
 if (!response.ok) throw new RequestFailure(response.status, response.headers.get('X-Request-ID') ?? '', route);
 return await response.json() as T;
}
