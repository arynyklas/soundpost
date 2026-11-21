// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { Id } from '../api/types';
import { StatusPanel } from '../app/StatusPanel';
import { newCommandId } from '../incidents/model';
import type { ViewContext } from '../app/context';
import { PERMISSIONS, buildTeam, type AdminOrg, type TeamConfig } from './admin';
import { AdminForm, useAdminRead } from './AdminForm';

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
   <fieldset>
    <legend>Projects of this team</legend>
    {projects.length === 0 ? <p data-state="empty">This organization has no project yet.</p> : projects.map(([pid, name]) => <label key={pid}><input type="checkbox" checked={chosen.includes(pid)} onChange={() => setChosen(flip(chosen, pid))} /> {name} <code>{pid}</code></label>)}
   </fieldset>
   <fieldset>
    <legend>Permissions on those projects</legend>
    {PERMISSIONS.map((p) => <label key={p.id}><input type="checkbox" checked={permissions.includes(p.id)} onChange={() => setPermissions(flip(permissions, p.id))} /> {p.label} <code>{p.id}</code></label>)}
   </fieldset>
   <label><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Team enabled</label>
  </AdminForm>
 );
}

/** Teams: a set of members holding the same permissions on the same projects. A team grants only what it names, only to members of this
 * organization, and a disabled team grants nothing. A team is replaced as a whole; a stale save is refused and nothing is changed. */
export function TeamSettings(props: { context: ViewContext }): React.JSX.Element {
 const { load, reload } = useAdminRead(props.context, 'organization');
 const data = load.kind === 'ready' ? load.data : undefined;
 const org = data?.org;
 const teams = org ? Object.entries(org.teams).sort((a, b) => a[0].localeCompare(b[0])) : [];
 return (
  <div data-settings-page="teams">
   <h3>Teams of organization <code>{props.context.org}</code></h3>
   {load.kind !== 'ready' && <StatusPanel state={load} />}
   {data && org && (
    <>
     <p data-testid="admin-revision" data-epoch={data.epoch}>Read at organization policy epoch {data.epoch}.</p>
     <section aria-labelledby="teams-list" data-section="teams">
      <h4 id="teams-list">Teams</h4>
      {teams.length === 0 ? <p role="status" data-state="empty">This organization has no team.</p> : (
       <ul>{teams.map(([tid, team]) => (
        <li key={tid} data-team={tid} data-team-state={team.enabled ? 'enabled' : 'disabled'}>
         <code>{tid}</code> — {team.enabled ? 'enabled' : 'disabled'}; {team.members.length} member{team.members.length === 1 ? '' : 's'}; projects {team.projects.map((p) => org.projects[p] ?? p).join(', ') || 'none'}; permissions {team.permissions.join(', ') || 'none'}.
         <TeamForm org={org} epoch={data.epoch} reload={reload} teamId={tid} config={team} />
        </li>
       ))}</ul>
      )}
      <TeamForm org={org} epoch={data.epoch} reload={reload} teamId={NEW} config={undefined} />
     </section>
    </>
   )}
  </div>
 );
}
