// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { isId, sectionOf } from './context';

/** D33: the server also serves the console shell for GET on a path-shaped link /<section>[/<entity>]?org=..&projects=..
 * (IDs only), and the console, still hash-routed, rewrites that path to the equivalent hash route before it renders and
 * without a reload. Nothing here reads data; every read is the console's own authenticated API call. Returns the hash
 * route of the link, or null when the address is not a console path. */
const ENTITY_PARAM: Readonly<Record<string, 'incident' | 'target' | 'service' | undefined>> = {
 incidents: 'incident', issues: 'target', releases: 'target', traces: 'target', replays: 'target', profiles: 'target', jobs: 'target', services: 'service',
};
/** The only query parameters a path link may carry: scope and window, the same ones the hash route has. */
const SCOPE_PARAMS = ['org', 'env', 'start', 'end', 'tz'] as const;

export function hashForPath(pathname: string, search: string): string | null {
 if (pathname.includes('\\') || !pathname.startsWith('/')) return null;
 const [section = '', entity, ...rest] = pathname.slice(1).split('/');
 if (rest.length > 0 || sectionOf(section) === undefined) return null;
 const entityParam = ENTITY_PARAM[section];
 if (entity !== undefined && (entityParam === undefined || entity === '')) return null;
 const query = new URLSearchParams(search);
 const out = new URLSearchParams({ view: section });
 let project = '';
 for (const name of SCOPE_PARAMS) { const v = query.get(name); if (v !== null) out.set(name, v); }
 // The entity is a bare ID or a `project:id` pair; the pair also names the project when the link carries none.
 let ref = entity ?? '';
 if (entityParam === 'target' || entityParam === 'incident') {
  const [first = '', second] = ref.split(':');
  if (second === undefined && ref !== '' && isId(first)) { const only = (query.get('projects') ?? '').split(',').filter((p) => p !== ''); if (only.length === 1) ref = `${only[0]}:${first}`; }
  project = ref.includes(':') ? ref.split(':')[0] ?? '' : '';
 }
 out.set('projects', query.get('projects') ?? project);
 if (ref !== '') out.set(entityParam ?? 'target', ref);
 return `#${out}`;
}

/** Rewrites a path-shaped link in the address bar to its hash route. An address that already carries a hash keeps it (the
 * hash is the router); the path and its query are dropped so no stale address survives. */
export function rewriteConsolePath(loc: Pick<Location, 'pathname' | 'search' | 'hash'>, replace: (url: string) => void): boolean {
 const hash = hashForPath(loc.pathname, loc.search);
 if (hash === null) return false;
 replace(`/${loc.hash !== '' ? loc.hash : hash}`);
 return true;
}
