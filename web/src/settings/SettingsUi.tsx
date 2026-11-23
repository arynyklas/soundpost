// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { Id } from '../api/types';
import { projectLabel, useShell } from '../shell/ShellContext';
import { Card, cx } from '../ui/primitives';
import { SETTINGS_PAGES, type SettingsPage } from './pages';

/** A card of a settings screen: its heading names it (a region name is unique on a page, so a title says which one). */
export function Panel(props: { title: string; actions?: React.ReactNode; footer?: React.ReactNode; children: React.ReactNode }): React.JSX.Element {
 const id = React.useId();
 return <Card title={props.title} titleId={id} actions={props.actions} footer={props.footer}>{props.children}</Card>;
}

/** The pages of Settings as a row of links (the address carries the page), shown on every page of it. */
export function SettingsNav(props: { current: SettingsPage }): React.JSX.Element {
 const shell = useShell();
 return (
  <nav className="set-nav" aria-label="Settings pages">
   <ul>
    {SETTINGS_PAGES.map((p) => <li key={p.id}><a href={shell.href('settings', { page: p.id })} aria-current={p.id === props.current ? 'page' : undefined} data-settings-tab={p.id}>{p.nav}</a></li>)}
   </ul>
  </nav>
 );
}

/** A table that always renders (an empty one says so in its own row) inside a focusable, labelled scroll region. Below 820px its rows stack: the same cells, once. */
export function PlainTable(props: { label: string; caption?: string; columns: readonly string[]; rows: readonly (readonly React.ReactNode[])[]; empty: string; tableAttrs?: Record<string, string>; rowAttrs?: (index: number) => Record<string, string> }): React.JSX.Element {
 return (
  <div className="table-region" tabIndex={0} role="region" aria-label={props.label}>
   <table className="table stack" aria-label={props.label} {...props.tableAttrs}>
    <caption className="sr-only">{props.caption ?? props.label}</caption>
    <thead><tr>{props.columns.map((c) => <th key={c} scope="col">{c}</th>)}</tr></thead>
    <tbody>
     {props.rows.length === 0 && <tr><td colSpan={props.columns.length}>{props.empty}</td></tr>}
     {props.rows.map((cells, i) => <tr key={i} {...props.rowAttrs?.(i)}>{cells.map((cell, j) => <td key={j} data-label={props.columns[j]}>{cell}</td>)}</tr>)}
    </tbody>
   </table>
  </div>
 );
}

/** The project a screen works on when several are in scope: one select, named by display name when the directory has one. */
export function ProjectSelect(props: { projects: readonly Id[]; value: Id; onChange: (project: Id) => void }): React.JSX.Element | null {
 const { names } = useShell();
 if (props.projects.length < 2) return null;
 return (
  <label className="set-project">
   <span>Project</span>
   <select value={props.value} onChange={(e) => props.onChange(e.target.value)}>
    {props.projects.map((p) => <option key={p} value={p}>{projectLabel(names, p)}</option>)}
   </select>
  </label>
 );
}

/** The project chosen on a screen that works on one: the first of the scope until another is picked, and never one that left the scope. */
export function useChosenProject(projects: readonly Id[]): [Id | undefined, (project: Id) => void] {
 const [picked, setPicked] = React.useState<Id | ''>('');
 const chosen = picked !== '' && projects.includes(picked) ? picked : projects[0];
 return [chosen, setPicked];
}

/** A key/value list of facts, in the console's props layout. */
export function Facts(props: { items: readonly [string, React.ReactNode][]; className?: string }): React.JSX.Element {
 return <dl className={cx('props', props.className)}>{props.items.map(([k, v]) => <React.Fragment key={k}><dt>{k}</dt><dd>{v}</dd></React.Fragment>)}</dl>;
}
