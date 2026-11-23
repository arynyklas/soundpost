// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { Id } from '../api/types';
import { MAX_PROJECTS, isId, validTimezone, windowEndingAt, type ViewContext } from '../app/context';
import { Dialog } from '../ui/primitives';
import { projectLabel, useShell } from './ShellContext';

/** Organizations the account can name (administrators only; everyone else enters IDs). */
export interface KnownOrg { id: Id; name: string }

/** Validation of the "enter identifiers" form; the message is the sentence the person sees. */
export function validateScopeForm(f: { org: string; projects: string; environment: string; timezone: string }): { ok: true; org: Id; projects: Id[]; environment: string; timezone: string } | { ok: false; message: string } {
 const org = f.org.trim();
 const list = f.projects.split(/[\s,]+/).filter((p) => p !== '');
 if (!isId(org)) return { ok: false, message: 'Organization ID must be 32 lowercase hexadecimal characters.' };
 if (list.length === 0 || list.length > MAX_PROJECTS || !list.every(isId) || new Set(list).size !== list.length) return { ok: false, message: `Enter 1 to ${MAX_PROJECTS} distinct project IDs, each 32 lowercase hexadecimal characters.` };
 if (!validTimezone(f.timezone.trim())) return { ok: false, message: 'Time zone must be a valid IANA name such as UTC or Europe/Berlin.' };
 if (f.environment.trim() !== '' && !isId(f.environment.trim())) return { ok: false, message: 'Environment ID must be empty (all environments) or 32 lowercase hexadecimal characters.' };
 return { ok: true, org, projects: list, environment: f.environment.trim(), timezone: f.timezone.trim() };
}

/** The organization and project picker. Names come from the directory route when it is served; the identifier form always works. */
export function ScopePicker(props: { open: boolean; onClose: () => void; orgs: readonly KnownOrg[] }): React.JSX.Element | null {
 const shell = useShell();
 const current = shell.context;
 const names = shell.names;
 const [org, setOrg] = React.useState(current?.org ?? '');
 const [projects, setProjects] = React.useState(current?.projects.join(', ') ?? '');
 const [environment, setEnvironment] = React.useState(current?.environment ?? '');
 const [timezone, setTimezone] = React.useState(current?.timezone ?? Intl.DateTimeFormat().resolvedOptions().timeZone);
 const [minutes, setMinutes] = React.useState(current?.span ?? 60);
 const [error, setError] = React.useState('');
 const picked = projects.split(/[\s,]+/).filter((p) => p !== '');
 const named = names.state === 'ready' && names.forOrg === org && names.projects.size > 0;
 const submit = (event: React.FormEvent<HTMLFormElement>): void => {
  event.preventDefault();
  const v = validateScopeForm({ org, projects, environment, timezone });
  if (!v.ok) { setError(v.message); return; }
  setError('');
  shell.applyScope({ org: v.org, projects: v.projects, environment: v.environment, timezone: v.timezone, ...windowEndingAt(Date.now(), minutes), span: minutes });
  props.onClose();
 };
 const toggle = (id: Id): void => {
  const next = picked.includes(id) ? picked.filter((p) => p !== id) : picked.length < MAX_PROJECTS ? [...picked, id] : picked;
  setProjects(next.join(', '));
 };
 return (
  <Dialog open={props.open} onClose={props.onClose} title="Organization and projects" testId="scope-picker">
   <form onSubmit={submit} aria-label="Select scope" className="modal-body">
    <p className="small t2">Applies to every page. Selecting a scope is navigation, not access: every read is authorized by the server for your own account, and anything you may not read is shown as not found.</p>
    {props.orgs.length > 0 && (
     <label>Known organizations
      <select value={props.orgs.some((o) => o.id === org) ? org : ''} onChange={(e) => { if (e.target.value !== '') { setOrg(e.target.value); setProjects(''); } }}>
       <option value="">Enter an organization ID below</option>
       {props.orgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
      </select>
     </label>
    )}
    <label>Organization ID <input value={org} onChange={(e) => setOrg(e.target.value)} autoComplete="off" spellCheck={false} data-autofocus="" /></label>
    {named && (
     <fieldset>
      <legend>Projects <span className="t3 small">{picked.length} of {names.projects.size} selected · at most {MAX_PROJECTS} at once</span></legend>
      {[...names.projects.keys()].map((id) => <label key={id} className="option"><input type="checkbox" checked={picked.includes(id)} onChange={() => toggle(id)} disabled={!picked.includes(id) && picked.length >= MAX_PROJECTS} /><span className="grow">{projectLabel(names, id)}</span></label>)}
      <div className="row small"><button type="button" className="btn-ghost btn-sm" onClick={() => setProjects([...names.projects.keys()].slice(0, MAX_PROJECTS).join(', '))}>Select all</button><button type="button" className="btn-ghost btn-sm" onClick={() => setProjects('')}>Clear</button></div>
     </fieldset>
    )}
    <label>Project IDs (comma separated) <input value={projects} onChange={(e) => setProjects(e.target.value)} autoComplete="off" spellCheck={false} /></label>
    <label>Environment ID (optional) <input value={environment} onChange={(e) => setEnvironment(e.target.value)} autoComplete="off" spellCheck={false} /></label>
    <label>Time zone <input value={timezone} onChange={(e) => setTimezone(e.target.value)} autoComplete="off" spellCheck={false} /></label>
    <label>Window
     <select value={minutes} onChange={(e) => setMinutes(Number(e.target.value))}>
      {[[15, 'Last 15 minutes'], [60, 'Last hour'], [360, 'Last 6 hours'], [1440, 'Last 24 hours'], [10080, 'Last 7 days'], [43200, 'Last 30 days']].map(([m, l]) => <option key={m} value={m}>{l}</option>)}
     </select>
    </label>
    {error && <p role="alert" className="error">{error}</p>}
    <p className="xsmall t3">Each project is evaluated on its own; lists show the project on every row.</p>
    <div className="row"><button type="button" className="ml-auto" onClick={props.onClose}>Cancel</button><button type="submit" className="btn-primary">Apply scope</button></div>
   </form>
  </Dialog>
 );
}

/** A label of the current scope for the sidebar button: the organization and how many projects. */
export function scopeSummary(context: ViewContext | null, orgName: string | undefined, projectCount: number | undefined): { title: string; detail: string; mark: string } {
 if (!context) return { title: 'No scope selected', detail: 'Pick an organization', mark: '?' };
 const title = orgName ?? `org ${context.org.slice(0, 4)}…${context.org.slice(-4)}`;
 const detail = projectCount !== undefined ? `${context.projects.length} of ${projectCount} projects` : `${context.projects.length} project${context.projects.length === 1 ? '' : 's'}`;
 return { title, detail, mark: (orgName ?? context.org).slice(0, 2).toUpperCase() };
}
