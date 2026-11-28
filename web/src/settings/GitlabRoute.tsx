// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { gitlabSettingsDisconnect, gitlabSettingsRead, gitlabSettingsSave, gitlabSettingsTest, type GitlabMapping, type GitlabSettings, type GitlabTest, type GitlabWritten } from '../api/gitlab';
import { stateOfFault } from '../api/client';
import { unwrapWrite } from '../api/consoleWrite';
import type { Id, LoadState } from '../api/types';
import { scopeKey, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { Content, PageHead } from '../shell/Frames';
import { projectLabel, useShell } from '../shell/ShellContext';
import { Icon } from '../ui/Icon';
import { Callout, DataTable, Dialog, NotAvailable, Pill } from '../ui/primitives';
import { describeAdminFailure } from './admin';
import { AuditedForm } from './AuditedForm';
import { BOUNDARY, buildConnection, connectionWords, createFromWords, draftsOf, emptyMapping, expiryWords, type ConnectionDraft, type MappingDraft } from './gitlabModel';
import { Facts, Panel } from './SettingsUi';

type Loaded = LoadState<GitlabSettings> | { kind: 'not_built' };

function useSettings(context: ViewContext): { load: Loaded; reload: () => void } {
 const key = `${scopeKey(context)}|${context.generation}`;
 const [held, setHeld] = React.useState<{ key: string; load: Loaded }>({ key: '', load: { kind: 'loading' } });
 const [tick, setTick] = React.useState(0);
 React.useEffect(() => {
  const ctl = new AbortController();
  gitlabSettingsRead(context.org, ctl.signal).then(
   (r) => { if (!ctl.signal.aborted) setHeld({ key, load: r.kind === 'ok' ? { kind: 'ready', data: r.data } : r.kind === 'not_built' ? { kind: 'not_built' } : stateOfFault(r.fault) }); },
   (e: unknown) => { if (!ctl.signal.aborted && !(e instanceof DOMException && e.name === 'AbortError')) setHeld({ key, load: stateOfFault(e) }); },
  );
  return () => ctl.abort();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key, tick]);
 return { load: held.key === key ? held.load : { kind: 'loading' }, reload: () => setTick((n) => n + 1) };
}

interface Manage { epoch: string; projects: [Id, string][]; reload: () => void }

function MappingEditor(props: { drafts: MappingDraft[]; projects: [Id, string][]; onChange: (next: MappingDraft[]) => void }): React.JSX.Element {
 const set = (i: number, patch: Partial<MappingDraft>): void => props.onChange(props.drafts.map((d, j) => (j === i ? { ...d, ...patch } : d)));
 return (
  <fieldset className="set-perm-set">
   <legend>Project mappings</legend>
   <div className="col g12">
    {props.drafts.length === 0 && <p className="small t2">No project is mapped: the “Create GitLab issue” button is hidden everywhere. Copy still works.</p>}
    {props.drafts.map((d, i) => (
     <div key={i} className="set-mapping" role="group" aria-label={`Mapping ${i + 1}`}>
      <div className="set-grid">
       <label>Mapping {i + 1}: Soundpost project <select value={d.project} onChange={(e) => set(i, { project: e.target.value })}><option value="">Choose a project</option>{props.projects.map(([pid, name]) => <option key={pid} value={pid}>{name} ({pid.slice(0, 8)}…)</option>)}</select></label>
       <label>Mapping {i + 1}: GitLab project (group/project) <input className="mono" value={d.gitlabProject} onChange={(e) => set(i, { gitlabProject: e.target.value })} autoComplete="off" spellCheck={false} /></label>
      </div>
      <div className="row wrap g12">
       <label className="check"><input type="checkbox" checked={d.incident} onChange={(e) => set(i, { incident: e.target.checked })} /> Mapping {i + 1}: create from incidents</label>
       <label className="check"><input type="checkbox" checked={d.issue} onChange={(e) => set(i, { issue: e.target.checked })} /> Mapping {i + 1}: create from error issues</label>
      </div>
      <label>Mapping {i + 1}: default labels (comma separated) <input value={d.labels} onChange={(e) => set(i, { labels: e.target.value })} autoComplete="off" spellCheck={false} /></label>
      <button type="button" className="btn btn-sm btn-ghost" onClick={() => props.onChange(props.drafts.filter((_, j) => j !== i))}><Icon name="trash" size="xs" />Remove mapping {i + 1}</button>
     </div>
    ))}
    <div><button type="button" className="btn btn-sm" onClick={() => props.onChange([...props.drafts, emptyMapping('')])}><Icon name="plus" size="xs" />Map a project</button></div>
   </div>
  </fieldset>
 );
}

function ConnectionForm(props: { org: Id; settings: GitlabSettings; manage: Manage }): React.JSX.Element {
 const s = props.settings;
 const [draft, setDraft] = React.useState<ConnectionDraft>(() => ({ baseUrl: s.baseHost ? `https://${s.baseHost}` : '', token: '', mappings: draftsOf(s) }));
 return (
  <AuditedForm<GitlabWritten>
   name="gitlab-connection" label="Change the GitLab connection" submitLabel={s.connected ? 'Save connection' : 'Connect'} describe={describeAdminFailure} onStale={props.manage.reload} saved={() => 'Saved. The server committed this connection. The token is sealed and is not shown again.'}
   onCommitted={() => { setDraft((d) => ({ ...d, token: '' })); props.manage.reload(); }}
   check={() => { const built = buildConnection(draft, s.token.hasToken); return built.ok ? null : built.error; }}
   fingerprint={() => JSON.stringify([draft, props.manage.epoch])}
   run={async (commandId, reason, signal) => {
    const built = buildConnection(draft, s.token.hasToken);
    if (!built.ok) throw new Error(built.error);
    return unwrapWrite(await gitlabSettingsSave({ org: props.org, commandId, expectedEpoch: props.manage.epoch, reason, baseUrl: built.value.baseUrl, ...(built.value.token !== undefined ? { token: built.value.token } : {}), mappings: built.value.mappings }, signal));
   }}>
   <label>GitLab address (https){s.baseHost ? ` — now ${s.baseHost}; only its host is shown here, so check the address` : ''} <input value={draft.baseUrl} onChange={(e) => setDraft({ ...draft, baseUrl: e.target.value })} autoComplete="off" spellCheck={false} data-autofocus /></label>
   <label>Access token (write-only; sealed on save and never shown again{s.token.hasToken ? '; leave empty to keep the sealed one' : ''}) <input type="password" value={draft.token} onChange={(e) => setDraft({ ...draft, token: e.target.value })} autoComplete="new-password" spellCheck={false} /></label>
   <MappingEditor drafts={draft.mappings} projects={props.manage.projects} onChange={(mappings) => setDraft({ ...draft, mappings })} />
  </AuditedForm>
 );
}

function DisconnectForm(props: { org: Id; manage: Manage }): React.JSX.Element {
 return (
  <AuditedForm<GitlabWritten>
   name="gitlab-disconnect" label="Disconnect GitLab" submitLabel="Disconnect" describe={describeAdminFailure} onStale={props.manage.reload} saved={() => 'Disconnected. The server committed this change.'} onCommitted={props.manage.reload}
   check={() => null} fingerprint={() => props.manage.epoch}
   run={async (commandId, reason, signal) => unwrapWrite(await gitlabSettingsDisconnect({ org: props.org, commandId, expectedEpoch: props.manage.epoch, reason }, signal))}>
   <p className="small t2">After disconnecting no issue can be created. The links already stored on incidents and issues stay.</p>
  </AuditedForm>
 );
}

type TestState = { kind: 'idle' } | { kind: 'running' } | { kind: 'done'; result: GitlabTest } | { kind: 'not_built' } | { kind: 'failed' };

/** GitLab settings: the one-way connection (POST /api/v1/gitlab/settings). Soundpost creates a GitLab issue from an incident or an error issue and keeps the link; nothing is synced, read back or
 * auto-resolved and no suspect commits are used. The token is write-only. Reading is for any organization member; saving, disconnecting and the project mappings are for organization administrators. */
export function GitlabRoute(props: { context: ViewContext }): React.JSX.Element {
 const c = props.context;
 const shell = useShell();
 const { load, reload } = useSettings(c);
 const names = shell.names;
 const [editing, setEditing] = React.useState(false);
 const [disconnecting, setDisconnecting] = React.useState(false);
 const [test, setTest] = React.useState<TestState>({ kind: 'idle' });
 const settings = load.kind === 'ready' ? load.data : undefined;
 const manage: Manage | undefined = settings?.canEdit === true && settings.epoch !== undefined
  ? { epoch: settings.epoch, projects: [...names.projects.entries()].sort((a, b) => a[1].localeCompare(b[1])), reload }
  : undefined;
 const words = settings ? connectionWords(settings) : undefined;
 const runTest = (): void => {
  setTest({ kind: 'running' });
  gitlabSettingsTest(c.org, new AbortController().signal).then(
   (r) => setTest(r.kind === 'ok' ? { kind: 'done', result: r.data } : r.kind === 'not_built' ? { kind: 'not_built' } : { kind: 'failed' }),
   () => setTest({ kind: 'failed' }),
  );
 };
 const mapped = new Map<Id, GitlabMapping>(settings ? settings.mappings.map((m): [Id, GitlabMapping] => [m.projectId, m]) : []);
 const rows = settings ? [...new Set([...c.projects, ...settings.mappings.map((m) => m.projectId)])] : [];
 const expiry = settings?.token.hasToken ? expiryWords(settings.token.expiresAt, Date.now()) : undefined;
 return (
  <>
   <PageHead crumb={<><a href={shell.href('settings')}>Settings</a><span aria-hidden="true">›</span></>} title="GitLab" sub="create issues from incidents and errors"
    actions={settings?.connected && settings.canEdit === true ? <button type="button" className="btn ml-auto" onClick={runTest} disabled={test.kind === 'running'}><Icon name="refresh" size="s" />Test connection</button> : undefined} />
   <Content>
    {load.kind === 'not_built' && <NotAvailable title="GitLab settings are not available yet">This installation does not serve the GitLab connection yet. Nothing is shown in its place; copying a link or a description from an incident or an issue does not need it.</NotAvailable>}
    {load.kind !== 'ready' && load.kind !== 'not_built' && <StatusPanel state={load} />}
    {settings && words && (
     <div className="grid-side">
      <div className="col g16">
       <Panel title="Connection" actions={<Pill tone={words.tone} {...(words.tone === 'ok' ? { icon: 'check' as const } : {})} testId="gitlab-state">{words.label}</Pill>}>
        <div className="col g12">
         <p className="small t2">{words.text}</p>
         <Facts items={[
          ['Instance', settings.baseHost ? <code>{settings.baseHost}</code> : 'not set'],
          ['Credential', settings.token.hasToken ? 'An access token is stored encrypted. It is never shown again.' : 'No token is stored.'],
          ['Scopes', settings.token.scopes === undefined ? 'Not reported' : settings.token.scopes.length === 0 ? 'none' : <span className="set-perms">{settings.token.scopes.map((x) => <code key={x}>{x}</code>)}</span>],
          ...(expiry ? [['Expires', <span key="e" className="row wrap"><Pill tone={expiry.tone === 'unk' ? 'unk' : expiry.tone}>{expiry.label}</Pill><span className="small t2">{expiry.text}</span></span>] as [string, React.ReactNode]] : []),
          ['Network', 'Redirects are never followed. A private address works only when an administrator allowed its prefix.'],
         ]} />
         {test.kind === 'running' && <p role="status" className="small t2">Asking GitLab…</p>}
         {test.kind === 'not_built' && <p role="status" data-state="unsupported" className="small t2">The connection test is not available yet in this installation.</p>}
         {test.kind === 'failed' && <p role="alert" className="error">The test was not confirmed. Nothing is known about the token from it.</p>}
         {test.kind === 'done' && (
          <Callout tone={test.result.ok ? 'ok' : 'crit'} role="status" testId="gitlab-test">
           {test.result.ok ? <>GitLab accepted the token. Scopes: {test.result.scopes.join(', ') || 'none reported'}.{test.result.expiresAt ? ` Expires ${test.result.expiresAt.slice(0, 10)}.` : ''}</> : <>GitLab did not accept the token{test.result.code ? <> (<code>{test.result.code}</code>)</> : ''}. Creating issues is refused until it is replaced.</>}
          </Callout>
         )}
         {manage
          ? <div className="row wrap"><button type="button" className="btn btn-sm" onClick={() => setEditing(true)}>{settings.connected ? 'Change connection or token' : 'Connect GitLab'}</button>{settings.connected && <button type="button" className="btn btn-sm btn-ghost" onClick={() => setDisconnecting(true)}>Disconnect</button>}</div>
          : <p className="xsmall t3">Only organization administrators change the connection.</p>}
        </div>
       </Panel>
       <Panel title="Project mapping">
        <div className="col g12">
         {rows.length === 0
          ? <p role="status" data-state="empty" className="set-empty">No project is in scope and none is mapped.</p>
          : <DataTable label="Soundpost projects mapped to GitLab projects" rows={rows} rowKey={(p) => p} rowAttrs={(p) => ({ 'data-gitlab-project': p, 'data-gitlab-mapped': String(mapped.has(p)) })} columns={[
           { key: 'project', header: 'Soundpost project', cell: (p) => <b>{projectLabel(shell.names, p)}</b> },
           { key: 'gitlab', header: 'GitLab project', cell: (p) => { const m = mapped.get(p); return m ? <code>{m.gitlabProject}</code> : <span className="t3">not mapped</span>; } },
           { key: 'from', header: 'Create issues from', cell: (p) => { const m = mapped.get(p); return m ? createFromWords(m.createFrom) : <span className="small t3">The “Create GitLab issue” button is hidden on this project. Copy still works.</span>; } },
           { key: 'labels', header: 'Default labels', cell: (p) => { const m = mapped.get(p); return m && m.labels.length > 0 ? <span className="set-perms">{m.labels.map((l) => <code key={l}>{l}</code>)}</span> : m ? <span className="t3">none</span> : null; } },
          ]} />}
        </div>
       </Panel>
      </div>
      <aside className="col g16" aria-label="How the connection works">
       <Panel title="What crosses the boundary">
        <ul className="consequences">
         {BOUNDARY.map((b) => <li key={b.head}><Icon name={b.icon} size="s" /><span><b>{b.head}:</b> {b.text}</span></li>)}
        </ul>
       </Panel>
      </aside>
     </div>
    )}
   </Content>
   {settings && manage && (
    <>
     <Dialog open={editing} onClose={() => setEditing(false)} title={settings.connected ? 'Change the GitLab connection' : 'Connect GitLab'} tall>
      <div className="modal-body"><ConnectionForm org={c.org} settings={settings} manage={manage} /></div>
     </Dialog>
     <Dialog open={disconnecting} onClose={() => setDisconnecting(false)} title="Disconnect GitLab">
      <div className="modal-body"><DisconnectForm org={c.org} manage={manage} /></div>
     </Dialog>
    </>
   )}
  </>
 );
}
