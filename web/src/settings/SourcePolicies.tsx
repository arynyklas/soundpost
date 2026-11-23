// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { isAbort } from '../api/client';
import type { Id } from '../api/types';
import type { ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { memberName, projectLabel, useShell } from '../shell/ShellContext';
import { Icon } from '../ui/Icon';
import { DataTable, Dialog, Pill } from '../ui/primitives';
import { buildSourcePolicySetting, changeSourcePolicy, getSourceFence, nextSourcePolicy, type AdminSetting, type AdminSourceView, type SourceFenceView } from './admin';
import { AdminForm, useAdminRead } from './AdminForm';
import { Panel } from './SettingsUi';

const POLL_MS = 1500;

/** Follows one source policy operation until it leaves fencing. While it fences the source is closed to ingest, so this is shown as in
 * progress, never as done; a failed read of its progress says so and does not guess a phase. */
function FenceStatus(props: { org: Id; operation: Id; done: () => void }): React.JSX.Element {
 const [fence, setFence] = React.useState<SourceFenceView | null>(null);
 const [failed, setFailed] = React.useState(false);
 const done = React.useRef(props.done);
 React.useEffect(() => { done.current = props.done; });
 React.useEffect(() => {
  const ctl = new AbortController();
  let timer = 0;
  const poll = (): void => {
   getSourceFence(props.org, props.operation, ctl.signal).then(
    (f) => { if (ctl.signal.aborted) return; setFence(f); setFailed(false); if (f.phase === 'fencing') timer = window.setTimeout(poll, POLL_MS); else done.current(); },
    (e: unknown) => { if (!ctl.signal.aborted && !isAbort(e)) { setFailed(true); timer = window.setTimeout(poll, POLL_MS * 2); } },
   );
  };
  poll();
  return () => { ctl.abort(); clearTimeout(timer); };
 }, [props.org, props.operation]);
 const fencing = fence?.phase === 'fencing';
 return (
  <p role="status" className="set-note" data-fence={props.operation} data-fence-phase={fence?.phase ?? 'unknown'}>
   <Pill tone={fence === null ? 'unk' : fencing ? 'high' : 'ok'}>{fence === null ? 'Reading' : fencing ? 'Fencing' : fence.phase}</Pill>{' '}
   Source policy operation <code>{props.operation}</code>: {fence === null ? (failed ? 'its progress could not be read yet.' : 'reading its progress.') : fencing ? 'fencing. The source is closed to ingest while the new policy takes effect; this is not complete.' : `${fence.phase}. The source is open again under the new policy.`}
  </p>
 );
}

function stateWords(s: AdminSourceView): string {
 if (s.retired) return 'retired';
 if (s.revoked) return 'revoked';
 if (s.closing) return 'closing (a policy change is taking effect)';
 return 'active';
}

function PolicyToggles(props: { org: Id; epoch: string; source: AdminSourceView; reload: () => void; started: (operation: Id) => void }): React.JSX.Element {
 const s = props.source;
 const [enabled, setEnabled] = React.useState(s.policy.enabled);
 const [replay, setReplay] = React.useState(s.policy.replay);
 return (
  <AdminForm name={`source-policy-${s.id}`} label={`Change the admitted policy of source ${s.id}`} org={props.org} epoch={props.epoch} submitLabel="Save admitted policy" onStale={props.reload}
   onCommitted={(done) => { if (done.operation) props.started(done.operation); props.reload(); }}
   build={() => (enabled === s.policy.enabled && replay === s.policy.replay ? { ok: false, error: 'Nothing to save: change enablement or replay.' } : { ok: true, value: { kind: 'source.policy', payload: { source: s.id, policy: nextSourcePolicy(s, { enabled, replay }) } } })}
   send={async (sent, signal) => {
    const fence = await changeSourcePolicy({ command_id: sent.commandId, source: s.id, expected_revision: s.policy.revision, policy: nextSourcePolicy(s, { enabled, replay }), reason: sent.reason }, signal);
    return { phase: fence.phase, operation: fence.operation };
   }}>
   <label className="check"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} data-autofocus /> Policy enabled: the source may ingest</label>
   <label className="check"><input type="checkbox" checked={replay} onChange={(e) => setReplay(e.target.checked)} /> Session replay enabled</label>
  </AdminForm>
 );
}

function ChangePolicy(props: { org: Id; epoch: string; source: AdminSourceView; reload: () => void; started: (operation: Id) => void }): React.JSX.Element | null {
 const [open, setOpen] = React.useState(false);
 const s = props.source;
 if (s.revoked || s.retired || s.closing) return <span className="small t3">Not changeable now</span>;
 return (
  <>
   <button type="button" className="btn btn-sm" aria-label={`Change the admitted policy of source ${s.id}`} onClick={() => setOpen(true)}><Icon name="edit" size="xs" />Change</button>
   <Dialog open={open} onClose={() => setOpen(false)} title="Change the admitted policy">
    <div className="modal-body">
     <p className="small t2">The policy change takes effect through a fence: the source is closed to ingest until it completes, and that is shown as it happens.</p>
     <PolicyToggles {...props} />
    </div>
   </Dialog>
  </>
 );
}

function SettingForm(props: { org: Id; epoch: string; projects: [Id, string][]; sources: AdminSourceView[]; reload: () => void; started: (operation: Id) => void }): React.JSX.Element {
 const [source, setSource] = React.useState('');
 const [project, setProject] = React.useState('');
 const [origins, setOrigins] = React.useState('');
 const [restricted, setRestricted] = React.useState(false);
 const [readers, setReaders] = React.useState('');
 const [enabled, setEnabled] = React.useState(true);
 const chosen = project !== '' ? project : props.projects[0]?.[0] ?? '';
 return (
  <AdminForm name="source_policy" label="Set the access policy of a source" org={props.org} epoch={props.epoch} submitLabel="Save access policy" onStale={props.reload}
   onCommitted={(done) => { if (done.operation) props.started(done.operation); props.reload(); }}
   build={() => {
    if (!/^[0-9a-f]{32}$/.test(source.trim())) return { ok: false, error: 'A source ID is 32 lowercase hexadecimal characters.' };
    const built = buildSourcePolicySetting(chosen, origins, restricted, readers, enabled);
    return built.ok ? { ok: true, value: { kind: 'source_policy', payload: { id: source.trim(), config: built.value } } } : built;
   }}>
   <div className="set-grid">
    <label>Source ID <input value={source} onChange={(e) => setSource(e.target.value)} list="known-sources" autoComplete="off" spellCheck={false} /></label>
    <datalist id="known-sources">{props.sources.map((s) => <option key={s.id} value={s.id} />)}</datalist>
    <label>Project <select value={chosen} onChange={(e) => setProject(e.target.value)}>{props.projects.map(([pid, name]) => <option key={pid} value={pid}>{name} ({pid})</option>)}</select></label>
   </div>
   <label>Browser origins that may use it (https, one per line or comma separated) <textarea className="mono" value={origins} onChange={(e) => setOrigins(e.target.value)} rows={2} spellCheck={false} /></label>
   <label className="check"><input type="checkbox" checked={restricted} onChange={(e) => setRestricted(e.target.checked)} /> Restricted: only the named readers may read what it delivers</label>
   <label>Readers (user IDs) <input value={readers} onChange={(e) => setReaders(e.target.value)} autoComplete="off" spellCheck={false} /></label>
   <label className="check"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled</label>
  </AdminForm>
 );
}

function admitted(s: AdminSourceView): string {
 const p = s.policy;
 return `admitted policy revision ${p.revision}, class ${p.class}, kinds ${p.kinds.join(', ') || 'none'}; ${p.enabled ? 'policy enabled' : 'policy disabled'}; replay ${p.replay ? 'enabled' : 'not enabled'}; log templates ${p.templates.length === 0 ? 'none' : p.templates.map((t) => `${t.id} (revision ${t.revision})`).join(', ')}${s.browser ? `; browser origins ${s.origins.join(', ') || 'none'}` : ''}.`;
}

/** Source policies: which sources exist, their admitted policy (kinds, log templates, replay), and who may use and read them. A policy
 * change takes effect through a fence: the source is closed to ingest until it completes, and that phase is shown as it happens. */
export function SourcePolicies(props: { context: ViewContext }): React.JSX.Element {
 const c = props.context;
 const { names } = useShell();
 const sources = useAdminRead(c, 'source');
 const settings = useAdminRead(c, 'source_policy');
 const org = useAdminRead(c, 'organization');
 const [operations, setOperations] = React.useState<Id[]>([]);
 const started = (operation: Id): void => setOperations((ops) => (ops.includes(operation) ? ops : [...ops, operation]));
 const reloadAll = (): void => { sources.reload(); settings.reload(); org.reload(); };
 const list = sources.load.kind === 'ready' ? sources.load.data.sources : undefined;
 const rules = settings.load.kind === 'ready' ? settings.load.data : undefined;
 const orgView = org.load.kind === 'ready' ? org.load.data.org : undefined;
 const projects: [Id, string][] = orgView ? Object.entries(orgView.projects).sort((a, b) => a[1].localeCompare(b[1])) : [];
 return (
  <div data-settings-page="source-policies" className="col g16">
   {sources.load.kind !== 'ready' && <StatusPanel state={sources.load} />}
   {operations.map((op) => <FenceStatus key={op} org={c.org} operation={op} done={reloadAll} />)}
   {list && (
    <div data-section="sources">
     <Panel title="Sources">
      <div className="col g12">
       {list.length === 0
        ? <p role="status" data-state="empty" className="set-empty">This organization has no source.</p>
        : <DataTable label="Sources of the organization and their admitted policy" rows={list} rowKey={(s) => s.id} rowAttrs={(s) => ({ 'data-source': s.id, 'data-source-state': stateWords(s).split(' ')[0] })} columns={[
         { key: 'id', header: 'Source', cell: (s) => <div className="cell-title"><code>{s.id}</code><span className="s">Project {projectLabel(names, s.project)} <code>{s.project}</code></span></div> },
         { key: 'state', header: 'State', cell: (s) => <Pill tone={stateWords(s) === 'active' ? 'ok' : 'high'}>{stateWords(s)}</Pill> },
         { key: 'policy', header: 'Admitted policy', cell: (s) => <span className="small">{admitted(s)}</span> },
         { key: 'act', header: <span className="sr-only">Change</span>, label: 'Change', cell: (s) => <ChangePolicy org={c.org} epoch={sources.load.kind === 'ready' ? sources.load.data.epoch : ''} source={s} reload={reloadAll} started={started} /> },
        ]} />}
      </div>
     </Panel>
    </div>
   )}
   {rules && (
    <div data-section="source-access">
     <Panel title="Access policies">
      <div className="col g12">
       <p className="small t2">The access policy of a source names its project, the browser origins that may use it, whether it is restricted to named readers, and whether it is enabled. Changing it for a live source fences that source.</p>
       {rules.settings.length === 0
        ? <p role="status" data-state="empty" className="set-empty">No access policy is set.</p>
        : <DataTable label="Access policy of each source" rows={rules.settings} rowKey={(s) => s.key} rowAttrs={(s) => ({ 'data-source-access': s.key.slice('source_policy:'.length) })} columns={[
         { key: 'id', header: 'Source', cell: (s: AdminSetting) => <code>{s.key.slice('source_policy:'.length)}</code> },
         { key: 'project', header: 'Project', cell: (s) => <code>{String(s.config.project_id ?? '')}</code> },
         { key: 'state', header: 'State', cell: (s) => <Pill tone={s.config.enabled === true ? 'ok' : 'line'}>{s.config.enabled === true ? 'enabled' : 'disabled'}</Pill> },
         { key: 'readers', header: 'Readers', cell: (s) => { const n = Array.isArray(s.config.readers) ? s.config.readers.length : 0; const ids = Array.isArray(s.config.readers) ? s.config.readers.filter((r): r is string => typeof r === 'string') : []; return s.config.restricted === true ? `restricted to ${n} named reader${n === 1 ? '' : 's'}${ids.length > 0 ? `: ${ids.map((r) => memberName(names, r) ?? `${r.slice(0, 8)}…`).join(', ')}` : ''}` : 'not restricted'; } },
         { key: 'origins', header: 'Browser origins', cell: (s) => { const o = Array.isArray(s.config.origins) ? s.config.origins.filter((x): x is string => typeof x === 'string') : []; return o.length === 0 ? 'none' : o.join(', '); } },
        ]} />}
       <h3 className="set-sub">Set an access policy</h3>
       <SettingForm org={c.org} epoch={rules.epoch} projects={projects} sources={list ?? []} reload={reloadAll} started={started} />
      </div>
     </Panel>
    </div>
   )}
  </div>
 );
}
