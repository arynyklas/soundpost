// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { Id } from '../api/types';
import { isId, type IncidentRef, type ViewContext } from './context';
import { projectLabel, useShell } from '../shell/ShellContext';

/** "Open by ID": a compact form every list screen keeps, so a person who holds an identifier (from a notification, a ticket or the command line)
 * can open the entity without browsing. The form names and labels are part of the e2e contract: `Open an incident`, `Open a trace`, `Open a service`... */
export function OpenByRef(props: { context: ViewContext; noun: 'incident' | 'issue' | 'release' | 'trace' | 'replay' | 'profile' | 'job'; current: IncidentRef | null; open: (ref: IncidentRef) => void }): React.JSX.Element {
 const shell = useShell();
 const [project, setProject] = React.useState(props.current?.project ?? props.context.projects[0] ?? '');
 const [value, setValue] = React.useState(props.current?.id ?? '');
 const [error, setError] = React.useState('');
 const Noun = props.noun.charAt(0).toUpperCase() + props.noun.slice(1);
 const article = `${props.noun === 'issue' ? 'an' : props.noun === 'incident' ? 'an' : 'a'} ${props.noun}`;
 return (
  <form aria-label={`Open ${article}`} className="open-by-id" onSubmit={(e) => { e.preventDefault(); if (!isId(value.trim())) return setError(`${Noun} ID must be 32 lowercase hexadecimal characters.`); setError(''); props.open({ project, id: value.trim() }); }}>
   <label>Project <select value={project} onChange={(e) => setProject(e.target.value)}>{props.context.projects.map((p) => <option key={p} value={p}>{projectLabel(shell.names, p)}</option>)}</select></label>
   <label>{Noun} ID <input value={value} onChange={(e) => setValue(e.target.value)} autoComplete="off" spellCheck={false} /></label>
   <button type="submit">Open {props.noun}</button>
   {error && <p role="alert" className="error">{error}</p>}
  </form>
 );
}

export function OpenService(props: { service: Id; open: (id: Id) => void }): React.JSX.Element {
 const [value, setValue] = React.useState(props.service);
 const [error, setError] = React.useState('');
 return (
  <form aria-label="Open a service" className="open-by-id" onSubmit={(e) => { e.preventDefault(); if (!isId(value.trim())) return setError('Service ID must be 32 lowercase hexadecimal characters.'); setError(''); props.open(value.trim()); }}>
   <label>Service ID <input value={value} onChange={(e) => setValue(e.target.value)} autoComplete="off" spellCheck={false} /></label>
   <button type="submit">Open service</button>
   {error && <p role="alert" className="error">{error}</p>}
  </form>
 );
}
