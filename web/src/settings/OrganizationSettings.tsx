// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { Id, LoadState } from '../api/types';
import { formatNs, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { newCommandId } from '../incidents/model';
import { PERMISSIONS, type AdminAudit, type AdminOrg, type AdminRead } from './admin';
import { AdminForm, useAdminRead } from './AdminForm';

const ID = /^[0-9a-f]{32}$/;
const word = (on: boolean): string => (on ? 'enabled' : 'disabled');

interface Reload { epoch: string; reload: () => void }

function ProjectsSection(props: { org: AdminOrg; ctl: Reload }): React.JSX.Element {
 const [name, setName] = React.useState('');
 const [id, setId] = React.useState<Id>(() => newCommandId());
 const projects = Object.entries(props.org.projects).sort((a, b) => a[1].localeCompare(b[1]) || a[0].localeCompare(b[0]));
 return (
  <section aria-labelledby="org-projects" data-section="org-projects">
   <h4 id="org-projects">Projects</h4>
   {projects.length === 0 ? <p role="status" data-state="empty">This organization has no project.</p> : <ul>{projects.map(([pid, pname]) => <li key={pid} data-org-project={pid}>{pname} <code>{pid}</code></li>)}</ul>}
   <AdminForm name="create_project" label="Create a project" org={props.org.id} epoch={props.ctl.epoch} submitLabel="Create project" onStale={props.ctl.reload} onCommitted={() => { setName(''); setId(newCommandId()); props.ctl.reload(); }}
    build={() => (name.trim() === '' || name.length > 128 ? { ok: false, error: 'A project needs a name of 1 to 128 characters.' } : { ok: true, value: { kind: 'create_project', payload: { id, name: name.trim() } } })}>
    <label>Project name <input value={name} onChange={(e) => setName(e.target.value)} maxLength={128} autoComplete="off" /></label>
   </AdminForm>
  </section>
 );
}

function PeopleSection(props: { org: AdminOrg; ctl: Reload }): React.JSX.Element {
 const members = Object.entries(props.org.members).sort((a, b) => a[0].localeCompare(b[0]));
 const admins = Object.entries(props.org.admins).filter(([, on]) => on).map(([u]) => u).sort();
 const [member, setMember] = React.useState({ user: '', enabled: true });
 const [admin, setAdmin] = React.useState({ user: '', enabled: true });
 const person = (user: string): Built => (ID.test(user.trim()) ? { ok: true, user: user.trim() } : { ok: false, error: 'A user ID is 32 lowercase hexadecimal characters.' });
 return (
  <section aria-labelledby="org-people" data-section="org-people">
   <h4 id="org-people">Members and administrators</h4>
   <p>A member can hold project grants; an administrator administers this organization. Accounts are created by an instance administrator; this page only enrolls them here.</p>
   <ul aria-label="Members">{members.length === 0 ? <li data-state="empty">No members.</li> : members.map(([u, on]) => <li key={u} data-member={u} data-member-state={word(on)}><code>{u}</code> — {word(on)}</li>)}</ul>
   <ul aria-label="Administrators">{admins.length === 0 ? <li data-state="empty">No administrators.</li> : admins.map((u) => <li key={u} data-admin={u}><code>{u}</code> — administrator</li>)}</ul>
   <AdminForm name="membership" label="Change a membership" org={props.org.id} epoch={props.ctl.epoch} submitLabel="Save membership" onStale={props.ctl.reload} onCommitted={() => { setMember({ user: '', enabled: true }); props.ctl.reload(); }}
    build={() => { const p = person(member.user); return p.ok ? { ok: true, value: { kind: 'membership', payload: { user_id: p.user, enabled: member.enabled } } } : p; }}>
    <label>User ID <input value={member.user} onChange={(e) => setMember({ ...member, user: e.target.value })} autoComplete="off" spellCheck={false} /></label>
    <label><input type="checkbox" checked={member.enabled} onChange={(e) => setMember({ ...member, enabled: e.target.checked })} /> Member of this organization</label>
   </AdminForm>
   <AdminForm name="org_admin" label="Change an administrator" org={props.org.id} epoch={props.ctl.epoch} submitLabel="Save administrator" onStale={props.ctl.reload} onCommitted={() => { setAdmin({ user: '', enabled: true }); props.ctl.reload(); }}
    build={() => { const p = person(admin.user); return p.ok ? { ok: true, value: { kind: 'org_admin', payload: { user_id: p.user, enabled: admin.enabled } } } : p; }}>
    <label>User ID <input value={admin.user} onChange={(e) => setAdmin({ ...admin, user: e.target.value })} autoComplete="off" spellCheck={false} /></label>
    <label><input type="checkbox" checked={admin.enabled} onChange={(e) => setAdmin({ ...admin, enabled: e.target.checked })} /> Administrator of this organization</label>
   </AdminForm>
  </section>
 );
}
type Built = { ok: true; user: string } | { ok: false; error: string };

function GrantsSection(props: { org: AdminOrg; ctl: Reload }): React.JSX.Element {
 const projects = Object.entries(props.org.projects).sort((a, b) => a[1].localeCompare(b[1]));
 const [draft, setDraft] = React.useState<{ user: string; project: string; permissions: string[]; enabled: boolean }>({ user: '', project: '', permissions: [], enabled: true });
 const grants = Object.entries(props.org.grants).sort((a, b) => a[0].localeCompare(b[0]));
 const project = draft.project !== '' ? draft.project : projects[0]?.[0] ?? '';
 const toggle = (id: string): void => setDraft((d) => ({ ...d, permissions: d.permissions.includes(id) ? d.permissions.filter((p) => p !== id) : [...d.permissions, id] }));
 return (
  <section aria-labelledby="org-grants" data-section="org-grants">
   <h4 id="org-grants">Project grants</h4>
   <p>A grant gives one member permissions on one project, and only there. Revoking removes every permission on that project at once.</p>
   {grants.length === 0 ? <p role="status" data-state="empty">No project grant is set.</p> : (
    <table aria-label="Project grants">
     <thead><tr><th scope="col">User</th><th scope="col">Project</th><th scope="col">Permissions</th></tr></thead>
     <tbody>{grants.map(([key, perms]) => { const [user = '', pid = ''] = key.split(':'); return <tr key={key} data-grant={key}><td><code>{user}</code></td><td>{props.org.projects[pid] ?? 'unknown project'} <code>{pid}</code></td><td>{perms.join(', ')}</td></tr>; })}</tbody>
    </table>
   )}
   <AdminForm name="grant" label="Set or revoke a project grant" org={props.org.id} epoch={props.ctl.epoch} submitLabel="Save grant" onStale={props.ctl.reload} onCommitted={() => { setDraft({ user: '', project: '', permissions: [], enabled: true }); props.ctl.reload(); }}
    build={() => {
     if (!ID.test(draft.user.trim())) return { ok: false, error: 'A user ID is 32 lowercase hexadecimal characters.' };
     if (!ID.test(project)) return { ok: false, error: 'Create a project first.' };
     if (draft.enabled && draft.permissions.length === 0) return { ok: false, error: 'Choose at least one permission, or revoke the grant.' };
     return { ok: true, value: { kind: 'grant', payload: { user_id: draft.user.trim(), project_id: project, enabled: draft.enabled, permissions: PERMISSIONS.filter((p) => draft.permissions.includes(p.id)).map((p) => p.id) } } };
    }}>
    <label>User ID <input value={draft.user} onChange={(e) => setDraft({ ...draft, user: e.target.value })} autoComplete="off" spellCheck={false} /></label>
    <label>Project <select value={project} onChange={(e) => setDraft({ ...draft, project: e.target.value })}>{projects.map(([pid, name]) => <option key={pid} value={pid}>{name} ({pid})</option>)}</select></label>
    <fieldset>
     <legend>Permissions</legend>
     {PERMISSIONS.map((p) => <label key={p.id}><input type="checkbox" checked={draft.permissions.includes(p.id)} onChange={() => toggle(p.id)} /> {p.label} <code>{p.id}</code></label>)}
    </fieldset>
    <label><input type="checkbox" checked={draft.enabled} onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })} /> Grant (clear to revoke)</label>
   </AdminForm>
  </section>
 );
}

function AuditSection(props: { audits: AdminAudit[]; timezone: string }): React.JSX.Element {
 const recent = [...props.audits].reverse().slice(0, 25);
 return (
  <section aria-labelledby="org-audit" data-section="org-audit">
   <h4 id="org-audit">Audit trail</h4>
   {recent.length === 0 ? <p role="status" data-state="empty">No audited change yet.</p> : (
    <ol aria-label="Recent audited changes">{recent.map((a) => <li key={a.id} data-audit-action={a.action}>{formatNs(a.timeNs, props.timezone)} — <strong>{a.action.replace(/_/g, ' ')}</strong> by <code>{a.principal}</code>{a.allowed ? '' : ' (refused)'}: {a.reason}</li>)}</ol>
   )}
  </section>
 );
}

/** The organization: its projects, members, administrators and project grants, with the audit trail of what changed them. Every change is
 * an audited admin command; only this organization's administrators can read or change any of it, and anyone else sees it as not found. */
export function OrganizationSettings(props: { context: ViewContext }): React.JSX.Element {
 const org = useAdminRead(props.context, 'organization');
 const audit = useAdminRead(props.context, 'audit');
 const data: AdminRead | undefined = org.load.kind === 'ready' ? org.load.data : undefined;
 const trail: LoadState<AdminRead> = audit.load;
 const ctl: Reload | undefined = data ? { epoch: data.epoch, reload: () => { org.reload(); audit.reload(); } } : undefined;
 return (
  <div data-settings-page="organization">
   <h3>Organization <code>{props.context.org}</code>{data?.org ? ` — ${data.org.name}` : ''}</h3>
   {org.load.kind !== 'ready' && <StatusPanel state={org.load} />}
   {data?.org && ctl && (
    <>
     <p data-testid="admin-revision" data-epoch={data.epoch}>Read at organization policy epoch {data.epoch}. A change to this organization since is refused and nothing is changed.</p>
     <ProjectsSection org={data.org} ctl={ctl} />
     <PeopleSection org={data.org} ctl={ctl} />
     <GrantsSection org={data.org} ctl={ctl} />
    </>
   )}
   {trail.kind === 'ready' && <AuditSection audits={trail.data.audits} timezone={props.context.timezone} />}
  </div>
 );
}
