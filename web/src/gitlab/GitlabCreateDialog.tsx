// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { isAbort } from '../api/client';
import { gitlabCreate, gitlabLinkFrom, gitlabPreview, gitlabRecheck, type GitlabAnswer, type GitlabEntityKind, type GitlabLinkView, type GitlabPreview } from '../api/gitlab';
import type { ApiFault, Id } from '../api/types';
import { newCommandId } from '../incidents/model';
import { Icon } from '../ui/Icon';
import { Callout, Dialog } from '../ui/primitives';
import { answerWords, labelsText, parseLabels, previewUnavailableWords, previousWords, safeHref } from './model';

type Loaded =
 | { kind: 'loading' }
 | { kind: 'ready'; preview: GitlabPreview }
 | { kind: 'unavailable'; reason: string }
 | { kind: 'not_built' }
 | { kind: 'fault'; fault: ApiFault };
type Choice = 'create' | 'link';

/** A GitLab issue as a link when its address is a web address, else as plain text. */
export function GitlabLink(props: { link: GitlabLinkView }): React.JSX.Element {
 const text = `${props.link.gitlab_project}#${props.link.iid}`;
 const href = safeHref(props.link.url);
 return href ? <a href={href} target="_blank" rel="noopener noreferrer">{text}<span className="sr-only"> (opens GitLab in a new tab)</span></a> : <span>{text}</span>;
}

/** The one-way "Create GitLab issue": it shows what would be sent, creates one issue through the organization's GitLab connection and stores only the link.
 * One GitLab issue per record, ever: a stored link is shown and never duplicated. When the outcome is unknown nothing is retried blindly: the next step is
 * a lookup by the Soundpost marker. Nothing is read back from GitLab and nothing is synchronised. */
export function GitlabCreateDialog(props: { entity: GitlabEntityKind; org: Id; project: Id; id: Id; /** What the dialog is about, e.g. the incident title. */ subject: string; open: boolean; onClose: () => void; onLinked?: (link: GitlabLinkView) => void }): React.JSX.Element | null {
 const { entity, org, project, id, open } = props;
 const noun = entity === 'incident' ? 'incident' : 'error issue';
 const [loaded, setLoaded] = React.useState<Loaded>({ kind: 'loading' });
 const [title, setTitle] = React.useState('');
 const [labels, setLabels] = React.useState('');
 const [choice, setChoice] = React.useState<Choice>('create');
 const [answer, setAnswer] = React.useState<GitlabAnswer | null>(null);
 const [pending, setPending] = React.useState<'create' | 'recheck' | 'link' | null>(null);
 const live = React.useRef<AbortController | null>(null);
 const outcome = React.useRef<HTMLDivElement>(null);
 const onLinked = React.useRef(props.onLinked);
 onLinked.current = props.onLinked;

 React.useEffect(() => {
  if (!open) return;
  const controller = new AbortController();
  live.current = controller;
  setLoaded({ kind: 'loading' }); setAnswer(null); setPending(null); setChoice('create');
  gitlabPreview({ org, project, entity: { kind: entity, id } }, controller.signal).then(
   (r) => {
    if (controller.signal.aborted) return;
    if (r.kind === 'not_built') setLoaded({ kind: 'not_built' });
    else if (r.kind === 'fault') setLoaded({ kind: 'fault', fault: r.fault });
    else if (r.data.state === 'not_available') setLoaded({ kind: 'unavailable', reason: r.data.reason });
    else { setLoaded({ kind: 'ready', preview: r.data.preview }); setTitle(r.data.preview.title); setLabels(labelsText(r.data.preview.labels)); }
   },
   (error: unknown) => { if (!isAbort(error) && !controller.signal.aborted) setLoaded({ kind: 'not_built' }); },
  );
  return () => controller.abort();
 }, [open, org, project, entity, id]);
 React.useEffect(() => { if (answer) outcome.current?.focus(); }, [answer]);
 React.useEffect(() => () => live.current?.abort(), []);

 const settle = (a: GitlabAnswer): void => {
  setAnswer(a);
  setPending(null);
  if (a.state === 'linked') onLinked.current?.(a.link);
 };
 const start = async (kind: 'create' | 'recheck' | 'link', send: (signal: AbortSignal) => Promise<GitlabAnswer>): Promise<void> => {
  if (pending) return;
  live.current?.abort();
  const controller = new AbortController();
  live.current = controller;
  setPending(kind);
  setAnswer(null);
  try {
   const a = await send(controller.signal);
   if (!controller.signal.aborted) settle(a);
  } catch (error) {
   if (!isAbort(error)) setPending(null);
  }
 };

 const ready = loaded.kind === 'ready' ? loaded.preview : undefined;
 const entityRef = { kind: entity, id } as const;
 const create = (): Promise<void> => start('create', (signal) => gitlabCreate({ org, project, entity: entityRef, commandId: newCommandId(), title: title.trim(), labels: parseLabels(labels) }, signal));
 const recheck = (): Promise<void> => start('recheck', (signal) => gitlabRecheck({ org, project, entity: entityRef }, signal));
 const linkFrom = (): Promise<void> => (ready?.existingOn ? start('link', (signal) => gitlabLinkFrom({ org, project, entity: entityRef, from: ready.existingOn! }, signal)) : Promise.resolve());

 const ownLink = ready?.existing && (!ready.existingOn || (ready.existingOn.kind === entity && ready.existingOn.id === id)) ? ready.existing : undefined;
 const otherLink = ready?.existing && ready.existingOn && !ownLink ? ready.existing : undefined;
 const linked = answer?.state === 'linked' ? answer.link : undefined;
 const previous = ready?.previous;
 const needsLookup = answer?.state === 'unknown' || answer?.state === 'in_progress' || (answer === null && (previous?.state === 'unknown' || previous?.state === 'creating'));
 const words = answer ? answerWords(answer, entity) : undefined;
 const busy = pending !== null;
 const mode: Choice = otherLink ? choice : 'create';

 const submit = (e: React.FormEvent): void => {
  e.preventDefault();
  if (!ready || ownLink || linked || needsLookup || busy) return;
  if (mode === 'link') void linkFrom(); else if (ready.gitlabProject !== null && title.trim() !== '') void create();
 };

 return (
  <Dialog open={open} onClose={props.onClose} title="Create GitLab issue" tall testId="gitlab-create">
   <form className="modal-body" aria-label="Create a GitLab issue" onSubmit={submit} aria-busy={busy}>
    <p className="t2 gl-subject">For {noun} <strong>{props.subject}</strong></p>
    {loaded.kind === 'loading' && <div className="status status-loading" role="status" data-state="loading"><strong>Loading</strong> <span>Reading what would be sent to GitLab.</span></div>}
    {loaded.kind === 'not_built' && <Callout tone="unk" role="status" testId="gitlab-not-built"><span><strong>GitLab issue creation is not available yet.</strong> This installation does not serve it. Nothing was created.</span></Callout>}
    {loaded.kind === 'unavailable' && <Callout tone="unk" role="status" testId="gitlab-unavailable">{previewUnavailableWords(loaded.reason)}</Callout>}
    {loaded.kind === 'fault' && <Callout tone="crit" role="alert">{answerWords({ state: 'fault', fault: loaded.fault }, entity).text} Nothing was created.</Callout>}
    {ready && (
     <>
      {ownLink && <Callout tone="ok" role="status" testId="gitlab-existing">This {noun} already has the GitLab issue <GitlabLink link={ownLink} />. A second issue is never created for it.</Callout>}
      {previous && !ownLink && !linked && <Callout tone={previous.state === 'refused' ? 'high' : 'unk'} role="status" testId="gitlab-previous">{previousWords(previous)}</Callout>}
      {otherLink && !linked && (
       <fieldset className="col g4 small">
        <legend className="bold">The linked error issue already has GitLab issue <GitlabLink link={otherLink} /></legend>
        <label className="check"><input type="radio" name="gitlab-mode" value="create" checked={mode === 'create'} onChange={() => setChoice('create')} disabled={busy} />Create a new GitLab issue for this {noun}</label>
        <label className="check"><input type="radio" name="gitlab-mode" value="link" checked={mode === 'link'} onChange={() => setChoice('link')} disabled={busy} />Link {otherLink.gitlab_project}#{otherLink.iid} instead</label>
       </fieldset>
      )}
      {!ownLink && !linked && mode === 'create' && (
       <>
        {ready.gitlabProject === null
         ? <Callout tone="warn" role="status" testId="gitlab-unmapped">This Soundpost project is not mapped to a GitLab project, so no issue can be created. An organization admin maps it in the GitLab settings.</Callout>
         : <p className="small">GitLab project <code>{ready.gitlabProject}</code> (mapped to this Soundpost project)</p>}
        <label>Title<input name="title" value={title} onChange={(e) => setTitle(e.target.value)} maxLength={255} autoComplete="off" disabled={busy || needsLookup || ready.gitlabProject === null} data-autofocus /></label>
        <div className="col g4"><span className="small bold" id="gl-desc-label">Description that will be sent</span>
         <pre className="snippet gl-description" tabIndex={0} role="region" aria-labelledby="gl-desc-label" data-testid="gitlab-description">{ready.description}</pre></div>
        <label>Labels <span>Comma separated.</span><input name="labels" value={labels} onChange={(e) => setLabels(e.target.value)} autoComplete="off" disabled={busy || needsLookup || ready.gitlabProject === null} /></label>
       </>
      )}
      {!ownLink && !linked && (
       <div className="col g4"><span className="small bold">What this does</span>
        <ul className="consequences">
         <li><Icon name="git" size="s" /><span>{mode === 'link' ? <>Stores the existing GitLab issue as this {noun}’s link. Nothing is created in GitLab.</> : <>Creates <strong>one</strong> issue in {ready.gitlabProject ?? 'the mapped GitLab project'} through the organization’s GitLab connection and stores its link on this {noun}.</>}</span></li>
         <li><Icon name="lock" size="s" /><span>The description holds identifiers and links only. Log lines, stack values, user data and timeline notes stay in Soundpost.</span></li>
         <li><Icon name="bell" size="s" /><span>Soundpost keeps only the link. It does not read the GitLab issue back: closing it in GitLab does <strong>not</strong> resolve anything here.</span></li>
        </ul>
       </div>
      )}
     </>
    )}
    {words && (
     <div ref={outcome} tabIndex={-1} data-gitlab-outcome={answer?.state} role={words.tone === 'crit' || words.tone === 'unk' ? 'alert' : 'status'}>
      <Callout tone={words.tone}><span><strong>{words.title}.</strong> {words.text}{words.code && <> Code <code>{words.code}</code>.</>}{linked && <> <GitlabLink link={linked} /></>}</span></Callout>
     </div>
    )}
    <div className="row wrap">
     <span className="xsmall t3 grow">Clicking again never opens a second issue. If GitLab’s answer is lost, the outcome is shown as unknown and Soundpost looks for the issue before it tries again.</span>
     <button type="button" onClick={props.onClose}>{linked || ownLink ? 'Close' : 'Cancel'}</button>
     {needsLookup && <button type="button" className="btn-primary" onClick={() => { void recheck(); }} disabled={busy}>{pending === 'recheck' ? 'Checking…' : 'Check whether it was created'}</button>}
     {ready && !ownLink && !linked && !needsLookup && (
      <button type="submit" className="btn-primary" disabled={busy || (mode === 'create' && (ready.gitlabProject === null || title.trim() === ''))}>
       {busy ? 'Waiting for GitLab…' : mode === 'link' ? 'Link existing issue' : 'Create issue'}
      </button>
     )}
    </div>
   </form>
  </Dialog>
 );
}
