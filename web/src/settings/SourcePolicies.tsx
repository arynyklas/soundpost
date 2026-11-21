// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { isAbort } from '../api/client';
import type { Id } from '../api/types';
import type { ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { buildSourcePolicySetting, changeSourcePolicy, getSourceFence, nextSourcePolicy, type AdminSetting, type AdminSourceView, type SourceFenceView } from './admin';
import { AdminForm, useAdminRead } from './AdminForm';

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
 return (
  <p role="status" data-fence={props.operation} data-fence-phase={fence?.phase ?? 'unknown'}>
   Source policy operation <code>{props.operation}</code>: {fence === null ? (failed ? 'its progress could not be read yet.' : 'reading its progress.') : fence.phase === 'fencing' ? 'fencing. The source is closed to ingest while the new policy takes effect; this is not complete.' : `${fence.phase}. The source is open again under the new policy.`}
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
   <label><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Policy enabled: the source may ingest</label>
   <label><input type="checkbox" checked={replay} onChange={(e) => setReplay(e.target.checked)} /> Session replay enabled</label>
  </AdminForm>
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
   <label>Source ID <input value={source} onChange={(e) => setSource(e.target.value)} list="known-sources" autoComplete="off" spellCheck={false} /></label>
   <datalist id="known-sources">{props.sources.map((s) => <option key={s.id} value={s.id} />)}</datalist>
   <label>Project <select value={chosen} onChange={(e) => setProject(e.target.value)}>{props.projects.map(([pid, name]) => <option key={pid} value={pid}>{name} ({pid})</option>)}</select></label>
   <label>Browser origins that may use it (https, one per line or comma separated) <textarea value={origins} onChange={(e) => setOrigins(e.target.value)} rows={2} spellCheck={false} /></label>
   <label><input type="checkbox" checked={restricted} onChange={(e) => setRestricted(e.target.checked)} /> Restricted: only the named readers may read what it delivers</label>
   <label>Readers (user IDs) <input value={readers} onChange={(e) => setReaders(e.target.value)} autoComplete="off" spellCheck={false} /></label>
   <label><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled</label>
  </AdminForm>
 );
}

/** Source policies: which sources exist, their admitted policy (kinds, log templates, replay), and who may use and read them. A policy
 * change takes effect through a fence: the source is closed to ingest until it completes, and that phase is shown as it happens. */
export function SourcePolicies(props: { context: ViewContext }): React.JSX.Element {
 const c = props.context;
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
  <div data-settings-page="source-policies">
   <h3>Source policies of organization <code>{c.org}</code></h3>
   {sources.load.kind !== 'ready' && <StatusPanel state={sources.load} />}
   {operations.map((op) => <FenceStatus key={op} org={c.org} operation={op} done={reloadAll} />)}
   {list && (
    <section aria-labelledby="sources-list" data-section="sources">
     <h4 id="sources-list">Sources</h4>
     {list.length === 0 ? <p role="status" data-state="empty">This organization has no source.</p> : (
      <ul>{list.map((s) => (
       <li key={s.id} data-source={s.id} data-source-state={stateWords(s).split(' ')[0]}>
        <code>{s.id}</code> — project <code>{s.project}</code>; {stateWords(s)}; admitted policy revision {s.policy.revision}, class {s.policy.class}, kinds {s.policy.kinds.join(', ') || 'none'}; {s.policy.enabled ? 'policy enabled' : 'policy disabled'}; replay {s.policy.replay ? 'enabled' : 'not enabled'};
        {' '}log templates {s.policy.templates.length === 0 ? 'none' : s.policy.templates.map((t) => `${t.id} (revision ${t.revision})`).join(', ')}{s.browser ? `; browser origins ${s.origins.join(', ') || 'none'}` : ''}.
        {!s.revoked && !s.retired && !s.closing && <PolicyToggles org={c.org} epoch={sources.load.kind === 'ready' ? sources.load.data.epoch : ''} source={s} reload={reloadAll} started={started} />}
       </li>
      ))}</ul>
     )}
    </section>
   )}
   {rules && (
    <section aria-labelledby="source-access" data-section="source-access">
     <h4 id="source-access">Access policies</h4>
     <p>The access policy of a source names its project, the browser origins that may use it, whether it is restricted to named readers, and whether it is enabled. Changing it for a live source fences that source.</p>
     {rules.settings.length === 0 ? <p role="status" data-state="empty">No access policy is set.</p> : (
      <ul>{rules.settings.map((s: AdminSetting) => {
       const cfg = s.config;
       const origins = Array.isArray(cfg.origins) ? cfg.origins.filter((o): o is string => typeof o === 'string') : [];
       const readers = Array.isArray(cfg.readers) ? cfg.readers.length : 0;
       return <li key={s.key} data-source-access={s.key.slice('source_policy:'.length)}><code>{s.key.slice('source_policy:'.length)}</code> — project <code>{String(cfg.project_id ?? '')}</code>; {cfg.enabled === true ? 'enabled' : 'disabled'}; {cfg.restricted === true ? `restricted to ${readers} named reader${readers === 1 ? '' : 's'}` : 'not restricted'}; origins {origins.join(', ') || 'none'}.</li>;
      })}</ul>
     )}
     <SettingForm org={c.org} epoch={rules.epoch} projects={projects} sources={list ?? []} reload={reloadAll} started={started} />
    </section>
   )}
  </div>
 );
}
