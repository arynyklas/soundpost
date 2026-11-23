// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { act, isAbort } from '../api/client';
import { ApiFault, OutcomeUnknown, VersionConflict, type ActionRequest, type IncidentView } from '../api/types';
import { Icon } from '../ui/Icon';
import { MAX_NOTE_BYTES, buildRequest, emptyDraft, faultText, newCommandId } from './model';
import { notServed } from './pageModel';

type State =
 | { kind: 'idle' }
 | { kind: 'invalid'; text: string }
 | { kind: 'pending' }
 | { kind: 'committed'; revision: string }
 | { kind: 'conflict'; expected: string; current: string }
 | { kind: 'unknown'; request: ActionRequest }
 | { kind: 'refused'; status: number; detail: string; code: string };

/** Whether this installation has answered that it does not serve notes. It is a property of the installation, so it holds for every incident until the page reloads. */
let notServedHere = false;
export const NOTES_UNAVAILABLE = 'Notes are not available yet: this installation does not accept timeline notes. Nothing is saved.';

export function noteBytes(text: string): number { return new TextEncoder().encode(text.trim()).length; }

/** The timeline notes composer: append-only text (1 to 2000 bytes) that a person adds to the incident, also after it is resolved. A note is a version-checked action like
 * every other: if someone else changes the incident first nothing is applied and the text is kept. When the server does not serve notes the composer is disabled and says so. */
export function NoteComposer(props: { view: IncidentView; reloading: boolean; onCommitted: (view: IncidentView) => void; onReload: () => void; /** Test seam: start as not served. */ unavailable?: boolean }): React.JSX.Element {
 const { view } = props;
 const [text, setText] = React.useState('');
 const [state, setState] = React.useState<State>({ kind: 'idle' });
 const [unavailable, setUnavailable] = React.useState(notServedHere || props.unavailable === true);
 const live = React.useRef<AbortController | null>(null);
 const status = React.useRef<HTMLDivElement>(null);
 React.useEffect(() => () => live.current?.abort(), []);
 React.useEffect(() => { if (state.kind !== 'idle') status.current?.focus(); }, [state.kind]);

 const send = async (request: ActionRequest): Promise<void> => {
  live.current?.abort();
  const controller = new AbortController();
  live.current = controller;
  setState({ kind: 'pending' });
  try {
   const response = await act(request, controller.signal);
   if (controller.signal.aborted) return;
   if (response.state === 'not_available' || !response.incident) { notServedHere = true; setUnavailable(true); setState({ kind: 'idle' }); return; }
   setText('');
   setState({ kind: 'committed', revision: response.incident.version });
   props.onCommitted(response.incident);
  } catch (error) {
   if (isAbort(error) || controller.signal.aborted) return;
   if (error instanceof VersionConflict) setState({ kind: 'conflict', expected: request.expected_version, current: error.currentVersion });
   else if (error instanceof OutcomeUnknown) setState({ kind: 'unknown', request });
   else if (error instanceof ApiFault && notServed(error.status, error.detail)) { notServedHere = true; setUnavailable(true); setState({ kind: 'idle' }); }
   else if (error instanceof ApiFault) setState({ kind: 'refused', status: error.status, detail: error.detail, code: error.code });
   else setState({ kind: 'refused', status: 0, detail: '', code: 'unavailable' });
  }
 };
 const submit = (e: React.FormEvent): void => {
  e.preventDefault();
  if (state.kind === 'pending' || unavailable) return;
  const built = buildRequest(view, { ...emptyDraft('note'), note: text }, newCommandId(), Date.now());
  if (!built.ok) { setState({ kind: 'invalid', text: built.error }); return; }
  void send(built.request);
 };

 const pending = state.kind === 'pending';
 const bytes = noteBytes(text);
 return (
  <form className="inc-composer" aria-label="Add a timeline note" onSubmit={submit} aria-busy={pending} data-testid="note-composer">
   <div className="row top g12">
    <label className="grow inc-composer-field"><span className="sr-only">Add a note to the timeline</span>
     <textarea name="note" rows={2} value={text} onChange={(e) => setText(e.target.value)} placeholder="Add a note: what you tried, what you see…" disabled={unavailable || pending} aria-describedby="note-help" />
    </label>
    <button type="submit" disabled={unavailable || pending || text.trim() === ''}><Icon name="note" size="s" />{pending ? 'Posting…' : 'Post note'}</button>
   </div>
   <p id="note-help" className="xsmall t3">{unavailable ? NOTES_UNAVAILABLE : <>Notes are append-only plain text and stay in Soundpost. <span className={bytes > MAX_NOTE_BYTES ? 'tone-crit' : undefined}>{bytes} of {MAX_NOTE_BYTES} bytes.</span> They are never sent to GitLab or in notifications.</>}</p>
   <div ref={status} tabIndex={-1} data-note-outcome={state.kind}>
    {state.kind === 'pending' && <p role="status"><strong>Pending.</strong> Waiting for the server. The note is not on the timeline yet.</p>}
    {state.kind === 'invalid' && <p role="alert" className="error"><strong>Not sent.</strong> {state.text}</p>}
    {state.kind === 'committed' && <p role="status"><strong>Posted.</strong> The server acknowledged revision {state.revision}.</p>}
    {state.kind === 'refused' && <p role="alert" className="error"><strong>Not saved.</strong> {faultText(state.detail, state.status)}{state.code && <> Code <code>{state.code}</code>.</>} Your text is kept.</p>}
    {state.kind === 'unknown' && (
     <div role="alert" className="error">
      <p><strong>Outcome unknown.</strong> The connection failed after the note was sent, so it may or may not be on the timeline. Resending the same request is safe: the server returns the original result instead of adding it twice.</p>
      <button type="button" onClick={() => { void send(state.request); }}>Resend the same request</button>
     </div>
    )}
    {state.kind === 'conflict' && (state.expected !== view.version
     ? <p role="alert" className="error"><strong>Reloaded.</strong> The incident is now at revision {view.version}; your note expected revision {state.expected} and was not saved. Post it again. Your text is kept.</p>
     : (
      <div role="alert" className="error">
       <p><strong>Conflict: not saved.</strong> Another action committed first and the incident is at revision {state.current}. Your note was not saved and nothing was retried. Your text is kept.</p>
       <button type="button" onClick={props.onReload} disabled={props.reloading}>Reload the current incident</button>
      </div>
     ))}
   </div>
  </form>
 );
}
