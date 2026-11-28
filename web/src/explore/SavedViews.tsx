// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { deleteSavedView, isAbort, listSavedViews, saveSavedView, stateOfFault } from '../api/client';
import type { Id, LoadState, SavedView } from '../api/types';
import { encodeHash, formatNs, scopeKey, type ViewContext } from '../app/context';
import { Callout, Card } from '../ui/primitives';
import { StatusPanel } from '../app/StatusPanel';
import { newCommandId } from '../incidents/model';
import type { QueryForm } from './form';
import type { ProfileInfo } from './profiles';
import { MAX_NAME_BYTES, MAX_VIEWS_PER_PROJECT, buildDeleteRequest, buildSaveRequest, commandForAttempt, exportDocument, heldAfter, openView, refusalWords, settleSaved, type HeldCommand, type SavedOutcome } from './savedModel';

type Lists = Record<Id, LoadState<SavedView[]>>;
interface Editing { id: Id; revision: string; name: string }

function download(project: Id, text: string): void {
 const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
 const link = document.createElement('a');
 link.href = url;
 link.download = `soundpost-saved-views-${project}.json`;
 document.body.append(link);
 link.click();
 link.remove();
 URL.revokeObjectURL(url);
}

/**
 * Saved views, owned by a project. Saving is an explicit action: the query text is sent to the server only when the person presses
 * Save, it is then readable by everyone who holds telemetry.read on the owning project, and it is never put in this browser's
 * storage, a URL or a cookie. Opening a view fills the form with exactly what was saved; a profile that is no longer registered, or
 * a project outside the selected scope, is refused with the reason, never switched or narrowed. The transitions are in savedModel.ts.
 */
export function SavedViews(props: { context: ViewContext; registry: readonly ProfileInfo[]; form: QueryForm; onOpen: (patch: Partial<QueryForm>) => void }): React.JSX.Element {
 const { context, registry, form } = props;
 const scope = `${scopeKey(context)}|${context.generation}`;
 const [lists, setLists] = React.useState<Lists>({});
 const [name, setName] = React.useState('');
 const [owner, setOwner] = React.useState<Id>('');
 const [editing, setEditing] = React.useState<Editing | null>(null);
 const [confirming, setConfirming] = React.useState<Id | null>(null);
 const [opened, setOpened] = React.useState<{ id: Id; text: string } | null>(null);
 const [outcome, setOutcome] = React.useState<SavedOutcome>({ kind: 'idle' });
 const live = React.useRef<AbortController | null>(null);
 const held = React.useRef<HeldCommand | null>(null);
 const heldScope = React.useRef(scope);
 heldScope.current = scope;
 const ownerProject = form.projects.includes(owner) ? owner : form.projects[0] ?? '';

 const read = React.useCallback((project: Id, signal: AbortSignal): void => {
  listSavedViews(context.org, project, signal).then(
   (views) => { if (!signal.aborted) setLists((l) => ({ ...l, [project]: views.length === 0 ? { kind: 'empty', data: views } : { kind: 'ready', data: views } })); },
   (error: unknown) => { if (!signal.aborted && !isAbort(error)) setLists((l) => ({ ...l, [project]: stateOfFault(error) })); },
  );
 }, [context.org]);
 React.useEffect(() => {
  const controller = new AbortController();
  setLists(Object.fromEntries(context.projects.map((p): [Id, LoadState<SavedView[]>] => [p, { kind: 'loading' }])));
  for (const p of context.projects) read(p, controller.signal);
  return () => { controller.abort(); live.current?.abort(); held.current = null; };
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [scope]);

 const reload = (project: Id): void => { const c = new AbortController(); live.current?.abort(); live.current = c; read(project, c.signal); };
 const send = async (what: 'save' | 'delete', attempt: { held: HeldCommand }, run: () => Promise<{ kind: 'saved'; view: SavedView; updated: boolean } | { kind: 'deleted'; id: Id; name: string }>, project: Id): Promise<void> => {
  setOutcome({ kind: 'pending' });
  const settled = await run().catch((error: unknown) => ({ kind: 'failure' as const, what, error }));
  if (heldScope.current !== scope) return;
  const s = settleSaved(settled);
  // An unknown outcome is repeated under the same command ID (the server answers it with the first result); every decided outcome releases it.
  held.current = heldAfter(s, attempt);
  setOutcome(s.outcome);
  if (s.clearName) setName('');
  if (settled.kind === 'saved') setEditing({ id: settled.view.id, revision: settled.view.revision, name: settled.view.name });
  if (settled.kind === 'deleted') setEditing((e) => (e !== null && e.id === settled.id ? null : e));
  if (s.reload) reload(project);
 };
 const save = (asUpdate: boolean): void => {
  if (outcome.kind === 'pending') return;
  const built = buildSaveRequest(context, form, registry, { name: asUpdate && editing !== null && name.trim() === '' ? editing.name : name, project: ownerProject, commandId: newCommandId(), ...(asUpdate && editing !== null ? { update: { id: editing.id, revision: editing.revision } } : {}) });
  if (!built.ok) { setOutcome({ kind: 'invalid', problems: built.problems }); return; }
  const attempt = commandForAttempt(held.current, built.request, newCommandId);
  const request = attempt.request;
  void send('save', attempt, async () => ({ kind: 'saved', view: await saveSavedView(request, new AbortController().signal), updated: request.id !== undefined }), request.project);
 };
 const remove = (view: SavedView): void => {
  setConfirming(null);
  const attempt = commandForAttempt(held.current, buildDeleteRequest(context, view, newCommandId()), newCommandId);
  const request = attempt.request;
  void send('delete', attempt, async () => { await deleteSavedView(request, new AbortController().signal); return { kind: 'deleted', id: view.id, name: view.name }; }, view.project);
 };
 const open = (view: SavedView): void => {
  const result = openView(context, view, registry);
  if (!result.ok) { setOpened({ id: view.id, text: result.reason }); return; }
  setOpened(null);
  setOutcome({ kind: 'idle' });
  setEditing({ id: view.id, revision: view.revision, name: view.name });
  setName(view.name);
  setOwner(view.project);
  props.onOpen(result.patch);
 };
 const pending = outcome.kind === 'pending';
 return (
  <div data-section="saved-views">
   <Card title="Saved views" titleId="saved-heading" bodyClass="col g12">
    <p className="small t2">Saving is an explicit action. The query text is stored on the server under the project you choose and can then be read by every account that holds telemetry.read on that project; until you press Save it stays in this page&rsquo;s memory only, and nothing is ever kept in this browser&rsquo;s storage. A project keeps at most {MAX_VIEWS_PER_PROJECT} saved views.</p>
    <form aria-label="Save this query as a view" onSubmit={(e) => { e.preventDefault(); save(false); }} aria-busy={pending}>
     <fieldset disabled={pending} className="exp-fs">
      <legend>Save the query in the form above</legend>
      <div className="exp-fields">
       <label>Name (at most {MAX_NAME_BYTES} bytes) <input name="view-name" value={name} onChange={(e) => setName(e.target.value)} autoComplete="off" /></label>
       <label>Owning project <select name="view-owner" value={ownerProject} onChange={(e) => setOwner(e.target.value)}>{form.projects.map((p) => <option key={p} value={p}>{p}</option>)}</select></label>
       <button type="submit" className="btn btn-primary">Save as a new view</button>
       {editing !== null && <button type="button" className="btn" onClick={() => save(true)} data-testid="saved-update">Update &ldquo;{editing.name}&rdquo;</button>}
      </div>
     </fieldset>
    </form>
    <div data-outcome={outcome.kind} aria-live="polite" className="col g4">
     {outcome.kind === 'pending' && <p role="status"><strong>Waiting for the server.</strong> Nothing has been saved yet.</p>}
     {outcome.kind === 'invalid' && <ul role="alert" className="error" data-testid="saved-problems">{outcome.problems.map((p) => <li key={p}>{p}</li>)}</ul>}
     {outcome.kind === 'saved' && <Callout tone="ok" role="status" testId="saved-committed"><strong>{outcome.updated ? 'Updated' : 'Saved'}.</strong> &ldquo;{outcome.view.name}&rdquo; is now stored under project <code>{outcome.view.project}</code> at revision {outcome.view.revision}.</Callout>}
     {outcome.kind === 'deleted' && <Callout tone="ok" role="status" testId="saved-deleted"><strong>Deleted.</strong> &ldquo;{outcome.name}&rdquo; is gone from the server.</Callout>}
     {outcome.kind === 'conflict' && <p role="alert" className="error" data-testid="saved-conflict"><strong>Not applied.</strong> The view changed or was removed since you read it, or the project is full. Nothing was {outcome.what === 'save' ? 'saved' : 'deleted'}; the list below was read again.</p>}
     {outcome.kind === 'unknown' && <p role="alert" className="error" data-testid="saved-unknown"><strong>Outcome unknown.</strong> The connection failed after the request was sent, so the {outcome.what} may or may not have happened. The list below was read again; check it. Pressing the same button again repeats the same request under the same command, so it cannot be applied twice.</p>}
     {outcome.kind === 'refused' && <p role="alert" className="error" data-testid="saved-refused"><strong>Not applied.</strong> {refusalWords(outcome.status)} Code <code>{outcome.code}</code>.{outcome.requestId && <> Request <code>{outcome.requestId}</code>.</>}</p>}
     {opened !== null && <p role="alert" className="error" data-testid="saved-open-refused"><strong>Not opened.</strong> {opened.text}</p>}
    </div>
    {context.projects.map((project) => {
     const state = lists[project] ?? { kind: 'loading' as const };
     const views = 'data' in state ? state.data : [];
     return (
      <section key={project} className="exp-saved-project col g12" aria-label={`Saved views of project ${project}`} data-project={project} data-state={state.kind}>
       <h3>Project <code>{project}</code></h3>
       <StatusPanel state={state} />
       {state.kind === 'empty' && <p data-testid="saved-none">No saved view is stored for this project.</p>}
       {views.length > 0 && (
        <>
         <div className="table-region" tabIndex={0} role="region" aria-label={`Saved views table of project ${project}`}>
          <table className="table">
           <caption className="sr-only">Saved views of this project, as the server holds them</caption>
           <thead><tr><th scope="col">Name</th><th scope="col">Query</th><th scope="col">Runs over</th><th scope="col">Updated</th><th scope="col">Revision</th><th scope="col">Actions</th></tr></thead>
           <tbody>
            {views.map((v) => (
             <tr key={v.id} data-view={v.id} data-name={v.name}>
              <th scope="row">{v.name}</th>
              <td><code>{v.language}</code> / <code>{v.profile}</code>; {v.mode}{v.mode === 'range' && v.step_seconds !== undefined ? `, step ${v.step_seconds} s` : ''}<pre className="exp-expr">{v.expression}</pre></td>
              <td>{v.projects.length} project{v.projects.length === 1 ? '' : 's'}</td>
              <td>{formatNs(v.updated_ns, context.timezone)}</td>
              <td>{v.revision}</td>
              <td>
               <div className="row wrap g4">
                {v.language === form.language
                 ? <button type="button" className="btn btn-sm" onClick={() => open(v)} aria-label={`Open view ${v.name}`}>Open</button>
                 : <a className="btn btn-sm" href={encodeHash(context, v.language === 'logql' ? 'logs' : 'metrics')}>Opens on {v.language === 'logql' ? 'Logs' : 'Metrics'}</a>}
                {confirming === v.id
                 ? <><button type="button" className="btn btn-sm btn-danger" onClick={() => remove(v)} disabled={pending}>Confirm delete of {v.name}</button><button type="button" className="btn btn-sm" onClick={() => setConfirming(null)}>Keep it</button></>
                 : <button type="button" className="btn btn-sm" onClick={() => setConfirming(v.id)} disabled={pending} aria-label={`Delete view ${v.name}`}>Delete</button>}
               </div>
              </td>
             </tr>
            ))}
           </tbody>
          </table>
         </div>
         <div><button type="button" className="btn btn-sm" onClick={() => download(project, exportDocument(context.org, project, views))} data-testid="saved-export">Export these views as JSON</button></div>
        </>
       )}
      </section>
     );
    })}
   </Card>
  </div>
 );
}
