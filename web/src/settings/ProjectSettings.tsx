// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { capabilities, isAbort, stateOfFault } from '../api/client';
import type { Id, LoadState, VisibleSource } from '../api/types';
import { scopeKey, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { RestorePanel } from '../auth/RestorePanel';
import { SessionContext } from '../auth/ElevationDialog';
import { projectLabel, useShell } from '../shell/ShellContext';
import { DataTable, EmptyState, Pill } from '../ui/primitives';
import { RetentionPanel } from './PolicySettings';
import { Panel } from './SettingsUi';

function SourcesPanel(props: { context: ViewContext; project: Id; name: string }): React.JSX.Element {
 const c = props.context;
 const key = `${scopeKey(c)}|${props.project}|${c.generation}`;
 const [held, setHeld] = React.useState<{ key: string; load: LoadState<VisibleSource[]> }>({ key: '', load: { kind: 'loading' } });
 React.useEffect(() => {
  const ctl = new AbortController();
  capabilities(c.org, props.project, ctl.signal).then(
   (r) => { if (!ctl.signal.aborted) setHeld({ key, load: r.sources.length ? { kind: 'ready', data: r.sources } : { kind: 'empty', data: [] } }); },
   (e: unknown) => { if (!ctl.signal.aborted && !isAbort(e)) setHeld({ key, load: stateOfFault(e) }); },
  );
  return () => ctl.abort();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key]);
 const load: LoadState<VisibleSource[]> = held.key === key ? held.load : { kind: 'loading' };
 return (
  <Panel title={`Sources of ${props.name}`}>
   <div className="col g12">
    <p className="small t2">Source capabilities this account may read. A project with no readable source is empty, not unhealthy.</p>
    {load.kind === 'ready'
     ? <DataTable label={`Readable sources of ${props.name}`} rows={load.data} rowKey={(s) => s.id} columns={[
      { key: 'id', header: 'Source', cell: (s) => <code>{s.id}</code> },
      { key: 'class', header: 'Class', cell: (s) => s.class },
      { key: 'kinds', header: 'Kinds', cell: (s) => s.kinds.join(', ') },
      { key: 'replay', header: 'Replay', cell: (s) => <Pill tone={s.replay ? 'ok' : 'line'}>{s.replay ? 'replay' : 'no replay'}</Pill> },
     ]} />
     : load.kind === 'empty' ? <EmptyState icon="plug" title="No readable source">Nothing is ingested for this project through a source this account may read.</EmptyState>
      : <StatusPanel state={load} />}
   </div>
  </Panel>
 );
}

/** The project page of Settings: for each project in scope, the sources this account may read and the retention of each signal (C11 /api/v1/policies, under the account's own policy.write
 * grant or organization administration), and, after a restore, the inactive sources and senders of this organization with their audited reauthorization. */
export function ProjectPage(props: { context: ViewContext }): React.JSX.Element {
 const c = props.context;
 const { names } = useShell();
 const session = React.useContext(SessionContext);
 const restored = session?.session.restore?.pending ?? 0;
 return (
  <div data-settings-page="project" className="col g16">
   {restored > 0 && session && (
    <Panel title="Restored access">
     <div className="set-restore">
      <RestorePanel csrf={session.session.csrf} pending={restored} label="Restored sources and senders" title="Restored: inactive sources and senders" only={(item) => item.kind === 'source' || (item.kind === 'integration' && (item.key ?? '').startsWith('destination:') && item.org === c.org)}
       intro="This installation was restored from a backup. Its sources and notification senders are disabled: a source's credential is revoked and a sender's endpoint secret is sealed away, so nothing is ingested or sent through them until an instance administrator reauthorizes each one here, with fresh authentication and an audit record. Reauthorizing a source issues a new credential, shown once." />
     </div>
    </Panel>
   )}
   {c.projects.map((project) => {
    const name = projectLabel(names, project);
    return (
     <div key={project} data-project={project} className="col g16">
      <SourcesPanel context={c} project={project} name={name} />
      <RetentionPanel context={c} project={project} name={name} />
     </div>
    );
   })}
  </div>
 );
}
