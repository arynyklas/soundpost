// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { Id } from '../api/types';
import { StatusPanel } from '../app/StatusPanel';
import { newCommandId } from '../incidents/model';
import type { ViewContext } from '../app/context';
import { memberName, useShell, type Names } from '../shell/ShellContext';
import { Icon } from '../ui/Icon';
import { DataTable, Dialog, Pill } from '../ui/primitives';
import { PERMISSIONS, buildTeam, type AdminOrg, type TeamConfig } from './admin';
import { AdminForm, useAdminRead } from './AdminForm';
import { Panel } from './SettingsUi';

const NEW = 'new';

function TeamForm(props: { org: AdminOrg; epoch: string; reload: () => void; teamId: Id | typeof NEW; config: TeamConfig | undefined }): React.JSX.Element {
 const projects = Object.entries(props.org.projects).sort((a, b) => a[1].localeCompare(b[1]));
 const [members, setMembers] = React.useState(props.config?.members.join(', ') ?? '');
 const [chosen, setChosen] = React.useState<Id[]>(props.config?.projects ?? []);
 const [permissions, setPermissions] = React.useState<string[]>(props.config?.permissions ?? []);
 const [enabled, setEnabled] = React.useState(props.config?.enabled ?? true);
 const [fresh, setFresh] = React.useState<Id>(() => newCommandId());
 const id = props.teamId === NEW ? fresh : props.teamId;
 const flip = (list: string[], v: string): string[] => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);
 return (
  <AdminForm name={`team-${props.teamId === NEW ? 'new' : props.teamId}`} label={props.teamId === NEW ? 'Create a team' : `Change team ${props.teamId}`} org={props.org.id} epoch={props.epoch} submitLabel={props.teamId === NEW ? 'Create team' : 'Save team'} onStale={props.reload}
   onCommitted={() => { if (props.teamId === NEW) { setMembers(''); setChosen([]); setPermissions([]); setEnabled(true); setFresh(newCommandId()); } props.reload(); }}
   build={() => { const built = buildTeam(members, chosen, permissions, enabled); return built.ok ? { ok: true, value: { kind: 'team', payload: { id, config: built.value } } } : built; }}>
   <label>Members (user IDs, comma separated) <input value={members} onChange={(e) => setMembers(e.target.value)} autoComplete="off" spellCheck={false} /></label>
   <fieldset className="set-perm-set">
    <legend>Projects of this team</legend>
    {projects.length === 0 ? <p data-state="empty" className="set-empty">This organization has no project yet.</p> : <div className="set-checks">{projects.map(([pid, name]) => <label className="check" key={pid}><input type="checkbox" checked={chosen.includes(pid)} onChange={() => setChosen(flip(chosen, pid))} /> {name} <code>{pid}</code></label>)}</div>}
   </fieldset>
   <fieldset className="set-perm-set">
    <legend>Permissions on those projects</legend>
    <div className="set-checks">{PERMISSIONS.map((p) => <label className="check" key={p.id}><input type="checkbox" checked={permissions.includes(p.id)} onChange={() => setPermissions(flip(permissions, p.id))} /> {p.label} <code>{p.id}</code></label>)}</div>
   </fieldset>
   <label className="check"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Team enabled</label>
  </AdminForm>
 );
}

function ChangeTeam(props: { org: AdminOrg; epoch: string; reload: () => void; teamId: Id; config: TeamConfig }): React.JSX.Element {
 const [open, setOpen] = React.useState(false);
 return (
  <>
   <button type="button" className="btn btn-sm" aria-label={`Change team ${props.teamId}`} onClick={() => setOpen(true)}><Icon name="edit" size="xs" />Change</button>
   <Dialog open={open} onClose={() => setOpen(false)} title="Change team" tall>
    <div className="modal-body"><TeamForm {...props} /></div>
   </Dialog>
  </>
 );
}

function who(ids: readonly Id[], names: Names): string {
 const shown = ids.slice(0, 3).map((u) => memberName(names, u) ?? `${u.slice(0, 8)}…`);
 return `${ids.length} member${ids.length === 1 ? '' : 's'}${shown.length > 0 ? `: ${shown.join(', ')}${ids.length > shown.length ? ` and ${ids.length - shown.length} more` : ''}` : ''}`;
}

/** Teams: a set of members holding the same permissions on the same projects. A team grants only what it names, only to members of this
 * organization, and a disabled team grants nothing. A team is replaced as a whole; a stale save is refused and nothing is changed. */
export function TeamSettings(props: { context: ViewContext }): React.JSX.Element {
 const { load, reload } = useAdminRead(props.context, 'organization');
 const { names } = useShell();
 const data = load.kind === 'ready' ? load.data : undefined;
 const org = data?.org;
 const teams = org ? Object.entries(org.teams).sort((a, b) => a[0].localeCompare(b[0])) : [];
 const shown: Names = names.forOrg === props.context.org ? names : { ...names, members: new Map() };
 return (
  <div data-settings-page="teams" className="col g16">
   {load.kind !== 'ready' && <StatusPanel state={load} />}
   {data && org && (
    <>
     <p className="small t2" data-testid="admin-revision" data-epoch={data.epoch}>Read at organization policy epoch {data.epoch}. A team grants only what it names, only to members of this organization; a disabled team grants nothing.</p>
     <div data-section="teams">
      <Panel title="Teams of the organization">
       <div className="col g12">
        {teams.length === 0
         ? <p role="status" data-state="empty" className="set-empty">This organization has no team.</p>
         : <DataTable label="Teams, their members, projects and permissions" rows={teams} rowKey={([tid]) => tid} rowAttrs={([tid, t]) => ({ 'data-team': tid, 'data-team-state': t.enabled ? 'enabled' : 'disabled' })} columns={[
          { key: 'id', header: 'Team', cell: ([tid]) => <code>{tid}</code> },
          { key: 'state', header: 'State', cell: ([, t]) => <Pill tone={t.enabled ? 'ok' : 'line'} icon={t.enabled ? 'check' : 'pause'}>{t.enabled ? 'enabled' : 'disabled'}</Pill> },
          { key: 'members', header: 'Members', cell: ([, t]) => who(t.members, shown) },
          { key: 'projects', header: 'Projects', cell: ([, t]) => t.projects.map((p) => org.projects[p] ?? p).join(', ') || 'none' },
          { key: 'perms', header: 'Permissions', cell: ([, t]) => <span className="set-perms">{t.permissions.length === 0 ? 'none' : t.permissions.map((p) => <code key={p}>{p}</code>)}</span> },
          { key: 'act', header: <span className="sr-only">Change</span>, label: 'Change', cell: ([tid, t]) => <ChangeTeam org={org} epoch={data.epoch} reload={reload} teamId={tid} config={t} /> },
         ]} />}
        <h3 className="set-sub">Create a team</h3>
        <TeamForm org={org} epoch={data.epoch} reload={reload} teamId={NEW} config={undefined} />
       </div>
      </Panel>
     </div>
    </>
   )}
  </div>
 );
}
