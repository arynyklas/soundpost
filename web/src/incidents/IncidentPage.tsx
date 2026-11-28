// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { getIncident, isAbort, stateOfFault } from '../api/client';
import { getRelated, type RelatedProposal } from '../api/console';
import { externalLinkOf, type GitlabLinkView } from '../api/gitlab';
import type { ApiFault, Id, IncidentView, LoadState, WindowView } from '../api/types';
import { formatNs, latestOnly, scopeKey, type Latest, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { SessionContext } from '../auth/ElevationDialog';
import { CopyMenu, GitlabCreateDialog, GitlabLink } from '../gitlab';
import { clockText } from '../shell/ScopeControls';
import { Content, Hero, PageHead } from '../shell/Frames';
import { memberName, projectLabel, useShell } from '../shell/ShellContext';
import { Icon } from '../ui/Icon';
import { Callout, Card, CopyButton, Lineage, Pill, SeverityIcon, cx, shortId } from '../ui/primitives';
import { ActionBar } from './ActionBar';
import { ActionDialog, PageOutcome, type Member } from './ActionDialogs';
import { NoteComposer } from './NoteComposer';
import { NotificationsCard } from './NotificationsCard';
import { TimelineCard } from './TimelineCard';
import { agoWords, incidentTitle } from './listModel';
import { msUntilExpiry, rateText, responseWords, sourceWords } from './model';
import { evidenceLinks, lineageItems, responseState } from './pageModel';
import { buildTimeline, openedAt } from './timelineModel';
import { useIncidentActions } from './useIncidentActions';

interface Loaded { state: LoadState<IncidentView>; view: IncidentView | undefined; reload: () => void; reloading: boolean; refreshFault: ApiFault | null; adopt: (view: IncidentView) => void }

/** Loads one incident for the scope. Data is keyed to the scope it was requested for; a reload keeps what is on screen (and the open dialog's draft) until the server
 * answers, and a reload that finds the incident no longer readable clears it instead of keeping stale content. */
function useIncident(context: ViewContext, project: Id, id: Id): Loaded {
 const key = `${scopeKey(context)}|${project}|${id}|${context.generation}`;
 const [held, setHeld] = React.useState<{ key: string; state: LoadState<IncidentView> }>({ key: '', state: { kind: 'loading' } });
 const [reloading, setReloading] = React.useState(false);
 const [refreshFault, setRefreshFault] = React.useState<ApiFault | null>(null);
 const latest = React.useRef<Latest>(latestOnly());
 const load = (initial: boolean): void => {
  const read = latest.current.begin();
  if (initial) { setHeld({ key, state: { kind: 'loading' } }); setRefreshFault(null); } else setReloading(true);
  getIncident(context.org, project, id, read.signal).then(
   (view) => { if (read.current()) { setHeld({ key, state: { kind: 'ready', data: view } }); setReloading(false); setRefreshFault(null); } },
   (error: unknown) => {
    if (!read.current() || isAbort(error)) return;
    const failed = stateOfFault(error);
    setReloading(false);
    if (initial || failed.kind === 'unauthorized') setHeld({ key, state: failed });
    else if (failed.kind === 'error') setRefreshFault(failed.fault);
    else setHeld({ key, state: failed });
   },
  );
 };
 React.useEffect(() => {
  load(true);
  return () => latest.current.stop();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key]);
 const state: LoadState<IncidentView> = held.key === key ? held.state : { kind: 'loading' };
 const view = state.kind === 'ready' ? state.data : undefined;
 return {
  state, view, reloading, refreshFault,
  reload: () => load(false),
  adopt: (next) => { latest.current.stop(); setReloading(false); setRefreshFault(null); setHeld({ key, state: { kind: 'ready', data: next } }); },
 };
}

type Related = { kind: 'loading' } | { kind: 'not_built' } | { kind: 'fault' } | { kind: 'ready'; items: RelatedProposal[] };
/** Related-incident proposals are display only: structured shared links, never time or text similarity. */
function useRelated(org: Id, project: Id, id: Id): Related {
 const key = `${org}|${project}|${id}`;
 const [held, setHeld] = React.useState<{ key: string; state: Related }>({ key: '', state: { kind: 'loading' } });
 React.useEffect(() => {
  const controller = new AbortController();
  getRelated(org, project, id, controller.signal).then(
   (r) => { if (!controller.signal.aborted) setHeld({ key, state: r.kind === 'ok' ? { kind: 'ready', items: r.data } : r.kind === 'not_built' ? { kind: 'not_built' } : { kind: 'fault' } }); },
   (error: unknown) => { if (!isAbort(error) && !controller.signal.aborted) setHeld({ key, state: { kind: 'fault' } }); },
  );
  return () => controller.abort();
 }, [key, org, project, id]);
 return held.key === key ? held.state : { kind: 'loading' };
}

function windowWords(w: WindowView, tz: string): string {
 const state = w.ended !== undefined ? `ended ${formatNs(w.ended, tz)}` : w.active ? 'active' : 'expired';
 return `${state}; from ${formatNs(w.from, tz)} until ${formatNs(w.until, tz)}`;
}
const capital = (s: string): string => s.charAt(0).toUpperCase() + s.slice(1);

function RelatedCard(props: { state: Related; context: ViewContext; href: (project: Id, id: Id) => string }): React.JSX.Element {
 const { state } = props;
 return (
  <Card title="Related · proposed" titleId="inc-related-h" actions={<span className="xsmall t3">shared evidence only</span>} testId="related-card">
   <div className="col g12">
    {state.kind === 'loading' && <p className="t2" role="status" data-state="loading">Looking for incidents that share a service, release or error issue.</p>}
    {state.kind === 'not_built' && <p className="t2" role="status" data-state="unsupported">Related-incident proposals are not available yet in this installation. Nothing is shown in their place.</p>}
    {state.kind === 'fault' && <p className="t2" role="status" data-state="error">Related incidents could not be read. They are not reported as absent.</p>}
    {state.kind === 'ready' && state.items.length === 0 && <p className="t2">No other incident shares a service, release or error issue with this one. Time alone never relates incidents.</p>}
    {state.kind === 'ready' && state.items.map((p) => (
     <div key={`${p.project_id}:${p.incident_id}`} className="col g4">
      <div className="row small">
       {p.severity === 'critical' || p.severity === 'major' || p.severity === 'minor' ? <SeverityIcon severity={p.severity} /> : null}
       {props.context.projects.includes(p.project_id) ? <a className="bold grow" href={props.href(p.project_id, p.incident_id)}>Incident {shortId(p.incident_id)}</a> : <span className="bold grow" title={p.incident_id}>Incident {shortId(p.incident_id)}</span>}
       <Pill tone={p.status === 'open' ? 'high' : 'ok'}>{p.status === 'open' ? 'Open' : 'Resolved'}</Pill>
      </div>
      <span className="xsmall t2">Shares {p.shared.map((s) => `the ${s.kind === 'issue' ? 'error issue' : s.kind} ${shortId(s.id)}`).join(', ') || 'linked records'}.{!props.context.projects.includes(p.project_id) && ' It is in a project outside the selected scope.'}</span>
     </div>
    ))}
    {state.kind === 'ready' && state.items.length > 0 && <p className="xsmall t3">Nothing is merged: each incident keeps its owner, timeline and resolve.</p>}
   </div>
  </Card>
 );
}

function IncidentBody(props: { view: IncidentView; incident: Loaded; context: ViewContext }): React.JSX.Element {
 const { view, incident, context } = props;
 const shell = useShell();
 const session = React.useContext(SessionContext);
 const { names } = shell;
 const tz = context.timezone;
 const nameOf = (id: string): string | undefined => memberName(names, id);
 const actions = useIncidentActions(view, incident.adopt, incident.reload, incident.reloading);
 const related = useRelated(view.org, view.project_id, view.incident_id);
 const [gitlabOpen, setGitlabOpen] = React.useState(false);
 const [linkedHere, setLinkedHere] = React.useState<GitlabLinkView | undefined>(undefined);
 const gitlab = externalLinkOf(view.timeline) ?? linkedHere;
 const members: Member[] = React.useMemo(() => [...names.members].map(([id, name]) => ({ id, name })), [names.members]);

 const now = Date.now();
 const title = incidentTitle(view);
 const items = buildTimeline(view, (ns) => formatNs(ns, tz));
 const opened = openedAt(view);
 const state = responseState(view, view.ack ? nameOf(view.ack.actor) ?? shortId(view.ack.actor) : undefined);
 const lineage = lineageItems(view, (section, o) => shell.href(section, o), view.ack ? nameOf(view.ack.actor) ?? shortId(view.ack.actor) : undefined);
 const evidence = evidenceLinks(view, context, now);
 const lastChange = items.find((i) => i.lane !== 'notification');
 const issues = view.links.filter((l) => l.kind === 'issue');
 const releases = view.links.filter((l) => l.kind === 'release');
 const sourceTone = view.condition.state === 'firing' ? 'crit' : view.condition.state === 'recovered' ? 'ok' : 'unk';
 const ownerName = view.owner ? nameOf(view.owner) : undefined;
 const url = `${window.location.origin}${window.location.pathname}${shell.href('incidents', { incident: { project: view.project_id, id: view.incident_id } })}`;

 return (
  <>
   <PageHead crumb={<><a href={shell.href('incidents')}>Incidents</a><Icon name="right" size="xs" /><span className="mono" title={view.incident_id}>{shortId(view.incident_id)}</span><CopyButton text={url} label="Copy incident link" /></>} />
   <Hero>
    <div className="row top g12 wrap">
     <SeverityIcon severity={view.severity} />
     <div className="col g4 grow inc-title-block">
      <h1 tabIndex={-1} className="inc-title">{title}</h1>
      <div className="row wrap small t2 inc-facts">
       <Pill tone={state.tone}>{capital(state.label)}</Pill>
       <span>{projectLabel(names, view.project_id)}</span>
       <span aria-hidden="true">·</span><span>{view.severity}</span>
       {opened !== undefined && <><span aria-hidden="true">·</span><span>opened {clockText(opened, tz, true)} ({agoWords(opened, now)})</span></>}
       {view.status === 'resolved' && view.resolved_at && <><span aria-hidden="true">·</span><span>resolved {clockText(view.resolved_at, tz, true)}</span></>}
       {gitlab && <><span aria-hidden="true">·</span><span className="row g4"><Icon name="git" size="xs" />GitLab issue <GitlabLink link={gitlab} /></span></>}
       <span aria-hidden="true">·</span>
       <span aria-live="polite" data-testid="revision">Revision <strong>{view.version}</strong>{incident.reloading ? ' (reloading…)' : ''}</span>
       <button type="button" className="btn btn-ghost btn-sm" onClick={incident.reload} disabled={incident.reloading}><Icon name="refresh" size="xs" />Reload incident</button>
      </div>
     </div>
     <ActionBar actions={actions} onGitlab={() => setGitlabOpen(true)} copy={<CopyMenu entity="incident" org={view.org} project={view.project_id} id={view.incident_id} />} />
    </div>
    <Lineage items={lineage} />
   </Hero>
   <Content>
    <div className="col g16" data-entity>
     {incident.refreshFault && <Callout tone="crit" role="alert">The latest reload failed (code <code>{incident.refreshFault.code}</code>). The incident below is the last answer the server gave, not necessarily current.</Callout>}
     {view.status === 'resolved' && view.source_firing && (
      <Callout tone="high" role="alert" testId="unresolved-source"><span><strong>Resolved by a person, but the alert source is still firing.</strong> The incident response was closed at {view.resolved_at ? formatNs(view.resolved_at, tz) : 'an unrecorded time'}; the source last reported firing at {formatNs(view.condition.observed_at, tz)}. Resolving does not recover the source.</span></Callout>
     )}
     {view.status === 'open' && view.ack && view.source_firing && (
      <Callout tone="info" role="status" testId="ack-source-firing"><span><strong>Acknowledged, and the source is still firing.</strong> An acknowledgement pauses reminders only; it does not change the alert condition.</span></Callout>
     )}
     {view.status === 'resolved' && <Callout tone="info"><span>This incident is resolved. A resolved incident accepts no further human actions except notes on its timeline. A worse impact or a new episode proposes a new linked incident.</span></Callout>}
     <PageOutcome actions={actions} />

     <div className="grid-3">
      <Card title="What changed" titleId="inc-what-h" testId="what-changed">
       <div className="col g12" data-section="issue-workflow">
        <p className="bold">{lastChange ? `${lastChange.actor !== undefined ? `${nameOf(lastChange.actor) ?? (lastChange.system ? 'System' : shortId(lastChange.actor))} ` : ''}${lastChange.text}` : 'No change is recorded yet.'}</p>
        {lastChange && <p className="small t2">{clockText(lastChange.at, tz, true)} · revision {lastChange.version ?? view.version}</p>}
        {issues.length === 0 ? <p className="small t2">No error issue is linked to this incident.</p> : <ul className="small">{issues.map((l) => <li key={l.id}>Linked error issue <a href={shell.href('issues', { target: { project: view.project_id, id: l.id } })}><code>{shortId(l.id)}</code></a> (its workflow state is shown on its own page)</li>)}</ul>}
        {releases.length > 0 && <ul className="small">{releases.map((l) => <li key={l.id}>Linked release <a href={shell.href('releases', { target: { project: view.project_id, id: l.id } })}><code>{shortId(l.id)}</code></a></li>)}</ul>}
       </div>
      </Card>
      <Card title="Impact now" titleId="inc-impact-h" testId="impact-now">
       <div className="col g12" data-section="alert-condition">
        <div className="row wrap"><Pill tone={sourceTone} testId="source-badge" icon={view.condition.state === 'firing' ? 'fire' : view.condition.state === 'recovered' ? 'check' : 'question'}>{sourceWords(view)}</Pill></div>
        <p className="bold">Impact severity {view.severity}, impact revision {view.impact_revision}</p>
        <p className="small t2" data-testid="rate">{rateText(view, (ns) => formatNs(ns, tz))}</p>
       </div>
      </Card>
      <Card title="Response" titleId="inc-response-h" testId="response">
       <div className="col g12" data-section="incident-response">
        <div className="row wrap"><Pill tone={view.status === 'open' ? 'high' : 'ok'} testId="status-badge">Incident: {view.status === 'open' ? 'open' : 'resolved by a person'}</Pill></div>
        <ul data-testid="response-words" className="inc-words">{responseWords(view).map((w) => <li key={w}>{view.owner && w === `Owner ${view.owner}` ? `Owner ${ownerName ?? view.owner}` : w}</li>)}</ul>
        {view.ack && <p className="small">Acknowledged by {nameOf(view.ack.actor) ?? <code>{view.ack.actor}</code>} at {formatNs(view.ack.at, tz)}; it covers impact revision {view.ack.impact_revision}{view.ack.current ? '' : ' only, and the impact is now revision ' + view.impact_revision}.</p>}
        {view.snooze && <p className="small" data-testid="snooze">Snooze by {nameOf(view.snooze.actor) ?? <code>{view.snooze.actor}</code>}, {windowWords(view.snooze, tz)}. Reason: {view.snooze.reason}</p>}
        {view.maintenance && <p className="small" data-testid="maintenance">Maintenance by {nameOf(view.maintenance.actor) ?? <code>{view.maintenance.actor}</code>}, {windowWords(view.maintenance, tz)}. Reason: {view.maintenance.reason}</p>}
       </div>
      </Card>
     </div>

     <div className="grid-side">
      <TimelineCard items={items} tz={tz} nameOf={nameOf} composer={<NoteComposer view={view} reloading={incident.reloading} onCommitted={incident.adopt} onReload={incident.reload} />} />
      <aside className="col g16" aria-label="Evidence, related incidents and notifications">
       <Card title="Evidence" titleId="inc-evidence-h" actions={<span className="xsmall t3">{clockText(evidence.window.start, tz, true)} to {evidence.window.open ? 'now' : clockText(evidence.window.end, tz, true)}</span>} testId="evidence-card" bodyClass={false}>
        <ul className="feed tight">
         {evidence.links.map((l) => <li key={l.key}><Icon name={l.icon} size="s" className="t3" /><a className="grow" href={l.href}>{l.label}{l.detail && <> <code>{l.detail}</code></>}</a></li>)}
        </ul>
        <p className="xsmall t3 inc-pad">The links open the screens for this project in the incident window. Their counts are shown there.</p>
       </Card>
       <RelatedCard state={related} context={context} href={(project, id) => shell.href('incidents', { incident: { project, id } })} />
       <NotificationsCard view={view} tz={tz} routesHref={shell.href('routing')} />
       <section className="card"><div className="card-body">
        <details className="more" data-testid="identifiers">
         <summary><Icon name="caret" size="xs" />Details and identifiers</summary>
         <dl className="props">
          <dt>Incident</dt><dd className="mono">{view.incident_id}</dd>
          <dt>Project</dt><dd className="mono">{view.project_id}</dd>
          <dt>Revision</dt><dd>{view.version}</dd>
          <dt>Condition</dt><dd className="mono">{view.condition.id}</dd>
          <dt>Episode</dt><dd className="mono">{view.episode_id}</dd>
          <dt>Impact revision</dt><dd>{view.impact_revision}{view.ack ? ` (acknowledged at ${view.ack.impact_revision})` : ''}</dd>
          <dt>Observed impacts</dt><dd>{view.observed_impacts}</dd>
          <dt>Last activity</dt><dd>{formatNs(view.last_activity, tz)}</dd>
          {view.previous && <><dt>Follows incident</dt><dd className="mono"><a href={shell.href('incidents', { incident: { project: view.project_id, id: view.previous } })}>{view.previous}</a></dd></>}
         </dl>
        </details>
       </div></section>
      </aside>
     </div>
    </div>
   </Content>
   <ActionDialog actions={actions} members={members} me={session?.session.user} />
   <GitlabCreateDialog entity="incident" org={view.org} project={view.project_id} id={view.incident_id} subject={title} open={gitlabOpen} onClose={() => setGitlabOpen(false)} onLinked={setLinkedHere} />
  </>
 );
}

/** The incident workspace. Three concerns stay separate in their own cards, badges and words: the alert condition (what the source reports), what changed (linked records) and
 * the incident response (what people decided). Nothing shows a committed status before the server answered. */
export function IncidentPage(props: { id: Id; project: Id; context: ViewContext }): React.JSX.Element {
 const { context, id, project } = props;
 const shell = useShell();
 const incident = useIncident(context, project, id);
 const { view } = incident;
 const expired = React.useRef(new Set<string>());
 React.useEffect(() => {
  if (!view) return;
  const ms = msUntilExpiry(view, Date.now());
  const windows = [view.snooze, view.maintenance].filter((w): w is WindowView => w?.active === true);
  const first = windows.sort((a, b) => Number(BigInt(a.until) - BigInt(b.until)))[0];
  if (ms === null || !first || ms > 2_000_000_000 || expired.current.has(first.until)) return;
  // A window that ended is refreshed from the server exactly once per window, even if the clocks disagree.
  const timer = setTimeout(() => { expired.current.add(first.until); incident.reload(); }, ms + 750);
  return () => clearTimeout(timer);
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [view?.version, view?.snooze?.until, view?.maintenance?.until, view?.snooze?.active, view?.maintenance?.active]);
 if (view) return <IncidentBody key={`${project}:${id}`} view={view} incident={incident} context={context} />;
 return (
  <>
   <PageHead crumb={<><a href={shell.href('incidents')}>Incidents</a><Icon name="right" size="xs" /><span className="mono" title={id}>{shortId(id)}</span></>} />
   <Hero><h1 tabIndex={-1} className={cx('inc-title')}>{incident.state.kind === 'unauthorized' && incident.state.status !== 401 ? 'Incident not found' : incident.state.kind === 'error' ? 'This incident could not be loaded' : incident.state.kind === 'loading' ? 'Loading incident' : `Incident ${shortId(id)}`}</h1></Hero>
   <Content>
    <div data-entity><StatusPanel state={incident.state} /></div>
    {incident.state.kind === 'unauthorized' && incident.state.status !== 401 && <p><a href={shell.href('incidents')}>Back to Incidents</a></p>}
   </Content>
  </>
 );
}
