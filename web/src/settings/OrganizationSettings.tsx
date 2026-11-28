// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { setMemberName } from '../api/console';
import type { Id } from '../api/types';
import type { ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { newCommandId } from '../incidents/model';
import { memberName, useShell, type Names } from '../shell/ShellContext';
import { DataTable, Person, Pill } from '../ui/primitives';
import { PERMISSIONS, validDisplayName, type AdminOrg } from './admin';
import { AdminForm, useAdminRead } from './AdminForm';
import { Panel } from './SettingsUi';

const ID = /^[0-9a-f]{32}$/;

interface Reload { epoch: string; reload: () => void }
type Built = { ok: true; user: string } | { ok: false; error: string };
const person = (user: string): Built => (ID.test(user.trim()) ? { ok: true, user: user.trim() } : { ok: false, error: 'A user ID is 32 lowercase hexadecimal characters.' });

function ProjectsSection(props: { org: AdminOrg; ctl: Reload; names: Names }): React.JSX.Element {
 const [name, setName] = React.useState('');
 const [id, setId] = React.useState<Id>(() => newCommandId());
 const projects = Object.entries(props.org.projects).sort((a, b) => a[1].localeCompare(b[1]) || a[0].localeCompare(b[0]));
 return (
  <div data-section="org-projects">
   <Panel title="Projects">
    <div className="col g12">
     {projects.length === 0
      ? <p role="status" data-state="empty" className="set-empty">This organization has no project.</p>
      : <DataTable label="Projects of the organization" rows={projects} rowKey={([pid]) => pid} rowAttrs={([pid]) => ({ 'data-org-project': pid })} columns={[
       { key: 'name', header: 'Project', cell: ([, pname]) => <b>{pname}</b> },
       { key: 'id', header: 'Project ID', cell: ([pid]) => <code>{pid}</code> },
      ]} />}
     <h3 className="set-sub">Create a project</h3>
     <AdminForm name="create_project" label="Create a project" org={props.org.id} epoch={props.ctl.epoch} submitLabel="Create project" onStale={props.ctl.reload} onCommitted={() => { setName(''); setId(newCommandId()); props.ctl.reload(); }}
      build={() => (name.trim() === '' || name.length > 128 ? { ok: false, error: 'A project needs a name of 1 to 128 characters.' } : { ok: true, value: { kind: 'create_project', payload: { id, name: name.trim() } } })}>
      <label>Project name <input value={name} onChange={(e) => setName(e.target.value)} maxLength={128} autoComplete="off" /></label>
     </AdminForm>
    </div>
   </Panel>
  </div>
 );
}

/** Sets or clears a display name over POST /api/v1/directory/names. A name is shown from the moment the server answered ok; a route this installation does not serve says so. */
function NameForm(props: { org: Id; members: Id[]; names: Names; onSet: (user: Id, name: string) => void }): React.JSX.Element {
 const [user, setUser] = React.useState('');
 const [name, setName] = React.useState('');
 const [command, setCommand] = React.useState<Id>(() => newCommandId());
 const [note, setNote] = React.useState<{ tone: 'ok' | 'error'; text: string } | null>(null);
 const [busy, setBusy] = React.useState(false);
 const chosen = user !== '' && props.members.includes(user) ? user : props.members[0] ?? '';
 if (props.names.state === 'not_built') return <p role="status" data-state="unsupported" className="set-empty">Display names are not available yet: this installation does not serve its directory.</p>;
 if (!props.names.canSetNames) return <p className="small t2">Display names are set by organization administrators{props.names.state === 'ready' ? '.' : ' once the directory has loaded.'}</p>;
 const submit = (e: React.FormEvent<HTMLFormElement>): void => {
  e.preventDefault();
  if (busy) return;
  if (chosen === '') { setNote({ tone: 'error', text: 'This organization has no member to name.' }); return; }
  if (!validDisplayName(name.trim())) { setNote({ tone: 'error', text: 'A display name is at most 80 bytes of text without control characters. Leave it empty to clear the name.' }); return; }
  setBusy(true);
  void setMemberName({ org: props.org, commandId: command, user: chosen, displayName: name.trim() }, new AbortController().signal).then((r) => {
   setBusy(false);
   if (r.kind === 'ok' && r.data.state === (name.trim() === '' ? 'cleared' : 'set')) { setCommand(newCommandId()); props.onSet(chosen, name.trim()); setName(''); setNote({ tone: 'ok', text: r.data.state === 'cleared' ? 'The display name was cleared.' : 'The display name was saved.' }); }
   else if (r.kind === 'ok') setNote({ tone: 'error', text: 'The server answered with a state this request did not ask for. Nothing is shown as saved.' });
   else if (r.kind === 'not_built') setNote({ tone: 'error', text: 'Display names are not available yet: this installation does not serve them. Nothing was changed.' });
   else setNote({ tone: 'error', text: `The name was not confirmed${r.fault.status === 403 || r.fault.status === 404 ? ': this account may not change it' : ''}. Nothing is shown as saved; sending again is the same command.` });
  });
 };
 return (
  <form aria-label="Set a display name" data-write="member-name" className="set-form" onSubmit={submit}>
   <div className="set-fields set-grid">
    <label>Member <select value={chosen} onChange={(e) => setUser(e.target.value)}>{props.members.map((m) => <option key={m} value={m}>{memberName(props.names, m) ?? m}</option>)}</select></label>
    <label>Display name (empty clears it) <input value={name} onChange={(e) => setName(e.target.value)} maxLength={80} autoComplete="off" /></label>
   </div>
   <div className="row wrap set-actions"><button type="submit" className="btn" disabled={busy}>{busy ? 'Saving…' : 'Save display name'}</button></div>
   {note?.tone === 'ok' && <p role="status" className="set-note set-note-ok">{note.text}</p>}
   {note?.tone === 'error' && <p role="alert" className="error">{note.text}</p>}
  </form>
 );
}

function MembersSection(props: { org: AdminOrg; ctl: Reload; names: Names }): React.JSX.Element {
 const [override, setOverride] = React.useState<ReadonlyMap<Id, string>>(new Map());
 const [member, setMember] = React.useState({ user: '', enabled: true });
 const members = Object.entries(props.org.members).sort((a, b) => a[0].localeCompare(b[0]));
 const named = (id: Id): string | undefined => { const o = override.get(id); return o !== undefined ? (o === '' ? undefined : o) : memberName(props.names, id); };
 return (
  <div data-section="org-people">
   <Panel title="Members">
    <div className="col g12">
     <p className="small t2">A member can hold project grants. Accounts are created by an instance administrator; this page only enrolls them here.</p>
     {members.length === 0
      ? <p role="status" data-state="empty" className="set-empty">No members.</p>
      : <DataTable label="Members of the organization" rows={members} rowKey={([u]) => u} rowAttrs={([u, on]) => ({ 'data-member': u, 'data-member-state': on ? 'enabled' : 'disabled' })} columns={[
       { key: 'who', header: 'Member', cell: ([u]) => <Person id={u} name={named(u)} /> },
       { key: 'id', header: 'User ID', cell: ([u]) => <code>{u}</code> },
       { key: 'state', header: 'State', cell: ([, on]) => <Pill tone={on ? 'ok' : 'line'} icon={on ? 'check' : 'pause'}>{on ? 'enabled' : 'disabled'}</Pill> },
      ]} />}
     <h3 className="set-sub">Enroll or remove a member</h3>
     <AdminForm name="membership" label="Change a membership" org={props.org.id} epoch={props.ctl.epoch} submitLabel="Save membership" onStale={props.ctl.reload} onCommitted={() => { setMember({ user: '', enabled: true }); props.ctl.reload(); }}
      build={() => { const p = person(member.user); return p.ok ? { ok: true, value: { kind: 'membership', payload: { user_id: p.user, enabled: member.enabled } } } : p; }}>
      <label>User ID <input value={member.user} onChange={(e) => setMember({ ...member, user: e.target.value })} autoComplete="off" spellCheck={false} /></label>
      <label className="check"><input type="checkbox" checked={member.enabled} onChange={(e) => setMember({ ...member, enabled: e.target.checked })} /> Member of this organization</label>
     </AdminForm>
     <h3 className="set-sub">Display names</h3>
     <NameForm org={props.org.id} members={members.map(([u]) => u)} names={props.names} onSet={(u, n) => setOverride(new Map(override).set(u, n))} />
    </div>
   </Panel>
  </div>
 );
}

function AdminsSection(props: { org: AdminOrg; ctl: Reload; names: Names }): React.JSX.Element {
 const [admin, setAdmin] = React.useState({ user: '', enabled: true });
 const admins = Object.entries(props.org.admins).filter(([, on]) => on).map(([u]) => u).sort();
 return (
  <div data-section="org-admins">
   <Panel title="Administrators">
    <div className="col g12">
     <p className="small t2">An administrator administers this organization: members, grants, teams, sources, destinations, rules and single sign-on.</p>
     {admins.length === 0
      ? <p role="status" data-state="empty" className="set-empty">No administrators.</p>
      : <DataTable label="Administrators of the organization" rows={admins} rowKey={(u) => u} rowAttrs={(u) => ({ 'data-admin': u })} columns={[
       { key: 'who', header: 'Administrator', cell: (u) => <Person id={u} name={memberName(props.names, u)} /> },
       { key: 'id', header: 'User ID', cell: (u) => <code>{u}</code> },
       { key: 'state', header: 'State', cell: () => <Pill tone="acc">administrator</Pill> },
      ]} />}
     <h3 className="set-sub">Make or remove an administrator</h3>
     <AdminForm name="org_admin" label="Change an administrator" org={props.org.id} epoch={props.ctl.epoch} submitLabel="Save administrator" onStale={props.ctl.reload} onCommitted={() => { setAdmin({ user: '', enabled: true }); props.ctl.reload(); }}
      build={() => { const p = person(admin.user); return p.ok ? { ok: true, value: { kind: 'org_admin', payload: { user_id: p.user, enabled: admin.enabled } } } : p; }}>
      <label>User ID <input value={admin.user} onChange={(e) => setAdmin({ ...admin, user: e.target.value })} autoComplete="off" spellCheck={false} /></label>
      <label className="check"><input type="checkbox" checked={admin.enabled} onChange={(e) => setAdmin({ ...admin, enabled: e.target.checked })} /> Administrator of this organization</label>
     </AdminForm>
    </div>
   </Panel>
  </div>
 );
}

function GrantsSection(props: { org: AdminOrg; ctl: Reload; names: Names }): React.JSX.Element {
 const projects = Object.entries(props.org.projects).sort((a, b) => a[1].localeCompare(b[1]));
 const [draft, setDraft] = React.useState<{ user: string; project: string; permissions: string[]; enabled: boolean }>({ user: '', project: '', permissions: [], enabled: true });
 const grants = Object.entries(props.org.grants).sort((a, b) => a[0].localeCompare(b[0]));
 const project = draft.project !== '' ? draft.project : projects[0]?.[0] ?? '';
 const toggle = (id: string): void => setDraft((d) => ({ ...d, permissions: d.permissions.includes(id) ? d.permissions.filter((p) => p !== id) : [...d.permissions, id] }));
 return (
  <div data-section="org-grants">
   <Panel title="Project grants">
    <div className="col g12">
     <p className="small t2">A grant gives one member permissions on one project, and only there. Revoking removes every permission on that project at once.</p>
     {grants.length === 0
      ? <p role="status" data-state="empty" className="set-empty">No project grant is set.</p>
      : <DataTable label="Grants by member and project" rows={grants} rowKey={([k]) => k} rowAttrs={([k]) => ({ 'data-grant': k })} columns={[
       { key: 'user', header: 'Member', cell: ([k]) => { const user = k.split(':')[0] ?? ''; return <Person id={user} name={memberName(props.names, user)} />; } },
       { key: 'project', header: 'Project', cell: ([k]) => { const pid = k.split(':')[1] ?? ''; return <span>{props.org.projects[pid] ?? 'unknown project'} <code>{pid}</code></span>; } },
       { key: 'perms', header: 'Permissions', cell: ([, perms]) => <span className="set-perms">{perms.map((p) => <code key={p}>{p}</code>)}</span> },
      ]} />}
     <h3 className="set-sub">Set or revoke a grant</h3>
     <AdminForm name="grant" label="Set or revoke a project grant" org={props.org.id} epoch={props.ctl.epoch} submitLabel="Save grant" onStale={props.ctl.reload} onCommitted={() => { setDraft({ user: '', project: '', permissions: [], enabled: true }); props.ctl.reload(); }}
      build={() => {
       if (!ID.test(draft.user.trim())) return { ok: false, error: 'A user ID is 32 lowercase hexadecimal characters.' };
       if (!ID.test(project)) return { ok: false, error: 'Create a project first.' };
       if (draft.enabled && draft.permissions.length === 0) return { ok: false, error: 'Choose at least one permission, or revoke the grant.' };
       return { ok: true, value: { kind: 'grant', payload: { user_id: draft.user.trim(), project_id: project, enabled: draft.enabled, permissions: PERMISSIONS.filter((p) => draft.permissions.includes(p.id)).map((p) => p.id) } } };
      }}>
      <div className="set-grid">
       <label>User ID <input value={draft.user} onChange={(e) => setDraft({ ...draft, user: e.target.value })} autoComplete="off" spellCheck={false} /></label>
       <label>Project <select value={project} onChange={(e) => setDraft({ ...draft, project: e.target.value })}>{projects.map(([pid, name]) => <option key={pid} value={pid}>{name} ({pid})</option>)}</select></label>
      </div>
      <fieldset className="set-perm-set">
       <legend>Permissions</legend>
       <div className="set-checks">{PERMISSIONS.map((p) => <label className="check" key={p.id}><input type="checkbox" checked={draft.permissions.includes(p.id)} onChange={() => toggle(p.id)} /> {p.label} <code>{p.id}</code></label>)}</div>
      </fieldset>
      <label className="check"><input type="checkbox" checked={draft.enabled} onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })} /> Grant (clear to revoke)</label>
     </AdminForm>
    </div>
   </Panel>
  </div>
 );
}

/** The organization: its projects, members, administrators and project grants. Every change is an audited admin command; only this organization's administrators can read or change any of it,
 * and anyone else sees it as not found. Members show their display name when the directory has one, else the short ID, and an administrator sets names here. */
export function OrganizationSettings(props: { context: ViewContext }): React.JSX.Element {
 const org = useAdminRead(props.context, 'organization');
 const { names } = useShell();
 const data = org.load.kind === 'ready' ? org.load.data : undefined;
 const ctl: Reload | undefined = data ? { epoch: data.epoch, reload: org.reload } : undefined;
 const shownNames: Names = names.forOrg === props.context.org ? names : { ...names, canSetNames: false };
 return (
  <div data-settings-page="organization" className="col g16">
   {org.load.kind !== 'ready' && <StatusPanel state={org.load} />}
   {data?.org && ctl && (
    <>
     <p className="small t2" data-testid="admin-revision" data-epoch={data.epoch}>Organization <b>{data.org.name}</b> <code>{props.context.org}</code>. Read at organization policy epoch {data.epoch}. A change to this organization since is refused and nothing is changed.</p>
     <ProjectsSection org={data.org} ctl={ctl} names={shownNames} />
     <MembersSection org={data.org} ctl={ctl} names={shownNames} />
     <AdminsSection org={data.org} ctl={ctl} names={shownNames} />
     <GrantsSection org={data.org} ctl={ctl} names={shownNames} />
    </>
   )}
  </div>
 );
}
