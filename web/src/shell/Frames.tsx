// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { formatNs } from '../app/context';
import { EmptyState } from '../ui/primitives';
import { ScopeControls } from './ScopeControls';
import { useShell } from './ShellContext';

/** The sticky page header. A list screen gives a `title` (the page's only h1); an entity screen gives a breadcrumb and puts its h1 in <Hero>. */
export function PageHead(props: { title?: string; sub?: string; crumb?: React.ReactNode; actions?: React.ReactNode; noScope?: boolean }): React.JSX.Element {
 return (
  <header className="page-head">
   {props.title && <h1 tabIndex={-1}>{props.title}</h1>}
   {props.sub && <span className="sub">{props.sub}</span>}
   {props.crumb && <nav className="crumb" aria-label="Breadcrumb">{props.crumb}</nav>}
   {props.actions}
   {!props.noScope && <ScopeControls />}
  </header>
 );
}

/** The identity block of an entity screen: its h1, its facts, its actions and its lineage. */
export function Hero(props: { children: React.ReactNode }): React.JSX.Element { return <div className="hero">{props.children}</div>; }
export function Content(props: { children: React.ReactNode; className?: string }): React.JSX.Element { return <div className={props.className ? `content ${props.className}` : 'content'}>{props.children}</div>; }

/** Forms used now and then on an entity page (map frames, compare, open another), folded under one summary so the evidence comes first. Native details: keyboard and touch open it. */
export function Tools(props: { label?: string; children: React.ReactNode }): React.JSX.Element {
 return <details className="tools"><summary>{props.label ?? 'Tools'}</summary><div className="tools-body col g16">{props.children}</div></details>;
}

/** One line that says what a section means, with the full rule under "How this is decided". The full text stays in the DOM. */
export function Explain(props: { line: React.ReactNode; children: React.ReactNode; testId?: string }): React.JSX.Element {
 return <div className="explain" data-testid={props.testId}><p className="small t2">{props.line}</p><details><summary>How this is decided</summary><p className="small t2">{props.children}</p></details></div>;
}

/** Shown by every scoped screen until an organization and projects are chosen: nothing is read before then. */
export function NeedScope(props: { title: string }): React.JSX.Element {
 const shell = useShell();
 return (
  <>
   <PageHead title={props.title} noScope />
   <Content>
    <div className="card">
     <EmptyState icon="globe" title="Choose an organization and projects" action={<button type="button" className="btn-primary" onClick={shell.openScope}>Choose scope</button>}>
      Select an organization and projects to begin. Nothing is shown until a scope is chosen. Choosing a scope is navigation, not access: every read is authorized by the server for your own account.
     </EmptyState>
    </div>
   </Content>
  </>
 );
}

/** The scope in identifiers, for support and for specs: the organization, the projects, the environment and the exact window. Collapsed under one muted line; the header controls already show the scope in words. */
export function ScopeDetails(): React.JSX.Element | null {
 const { context: c } = useShell();
 if (!c) return null;
 return (
  <details className="scope-details">
   <summary>Scope identifiers</summary>
   <dl className="scope-bar" aria-label="Current scope">
    <dt>Organization</dt><dd data-testid="visible-org"><code>{c.org}</code></dd>
    <dt>Projects</dt><dd data-testid="visible-projects"><code>{c.projects.join(', ')}</code></dd>
    <dt>Environment</dt><dd data-testid="visible-environment">{c.environment === '' ? 'All environments' : <code>{c.environment}</code>}{c.environment !== '' && ' (the server narrows the Services view to it; sections that cannot be narrowed say so)'}</dd>
    <dt>Time zone</dt><dd>{c.timezone}</dd>
    <dt>Window</dt><dd>{formatNs(c.start, c.timezone)} to {formatNs(c.end, c.timezone)} (end excluded)</dd>
   </dl>
  </details>
 );
}
