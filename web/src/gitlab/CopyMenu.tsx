// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { getMarkdown, type MarkdownFormat } from '../api/console';
import type { GitlabEntityKind } from '../api/gitlab';
import { isAbort } from '../api/client';
import { ApiFault, type Id } from '../api/types';
import { Icon } from '../ui/Icon';
import { copyItemsFor, copyOutcomeOf, copyWords, type CopyOutcome } from './model';
import { useMenu } from './useMenu';

interface Shown { words: string; /** Shown only when the browser refused the clipboard, so the text can still be copied by hand. */ markdown?: string }
const NOTE_MS = 9000;

/** Copy menu: the link, the task description or (incidents) the timeline as Markdown. The text is built by the server (public origin, identifiers, links, notes
 * the caller may read) and put on the clipboard; what happened is said in words, and a missing public origin or a route this installation does not serve yet is
 * never shown as a copy that worked. */
export function CopyMenu(props: { entity: GitlabEntityKind; org: Id; project: Id; id: Id }): React.JSX.Element {
 const { entity, org, project, id } = props;
 const { open, setOpen, wrap, trigger } = useMenu();
 const [busy, setBusy] = React.useState(false);
 const [shown, setShown] = React.useState<Shown | null>(null);
 const live = React.useRef<AbortController | null>(null);
 const timer = React.useRef<number | undefined>(undefined);
 React.useEffect(() => () => { live.current?.abort(); window.clearTimeout(timer.current); }, []);

 const show = (value: Shown): void => {
  setShown(value);
  window.clearTimeout(timer.current);
  timer.current = window.setTimeout(() => setShown(null), NOTE_MS);
 };
 const run = async (format: MarkdownFormat): Promise<void> => {
  setOpen(false);
  trigger.current?.focus();
  live.current?.abort();
  const controller = new AbortController();
  live.current = controller;
  setBusy(true);
  setShown(null);
  let outcome: CopyOutcome;
  try {
   outcome = copyOutcomeOf(format, await getMarkdown(entity, { org, project, id, format }, controller.signal));
  } catch (error) {
   if (isAbort(error) || controller.signal.aborted) return;
   outcome = { kind: 'fault', fault: new ApiFault(0, 'network', '', '') };
  }
  if (controller.signal.aborted) return;
  setBusy(false);
  if (outcome.kind !== 'copied') { show({ words: copyWords(outcome, true) }); return; }
  let clipboard = false;
  try { await navigator.clipboard.writeText(outcome.markdown); clipboard = true; } catch { clipboard = false; }
  show({ words: copyWords(outcome, clipboard), ...(clipboard ? {} : { markdown: outcome.markdown }) });
 };

 return (
  <div className="menu-wrap gl-copy" ref={wrap} data-testid="copy-menu">
   <button ref={trigger} type="button" className="btn" aria-haspopup="menu" aria-expanded={open} aria-busy={busy} onClick={() => setOpen(!open)} title="Copy the link, a task description or the timeline as Markdown">
    <Icon name="copy" size="s" />Copy<Icon name="caret" size="xs" />
   </button>
   {open && (
    <div className="menu" role="menu" aria-label="Copy as Markdown">
     {copyItemsFor(entity).map((item) => <button key={item.format} type="button" role="menuitem" onClick={() => { void run(item.format); }}>{item.label}</button>)}
    </div>
   )}
   {shown && (
    <div className="gl-copy-note" role="status">
     <p>{shown.words}</p>
     {shown.markdown !== undefined && <label>Markdown<textarea readOnly rows={5} value={shown.markdown} onFocus={(e) => e.currentTarget.select()} /></label>}
    </div>
   )}
  </div>
 );
}
