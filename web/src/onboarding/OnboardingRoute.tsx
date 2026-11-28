// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { capabilities, investigate, stateOfView } from '../api/client';
import type { InvestigationView, LoadState, VisibleSource } from '../api/types';
import { StatusPanel } from '../app/StatusPanel';
import { requestFor, type ViewContext } from '../app/context';
import { useScoped } from '../app/loadState';
import { Content, PageHead } from '../shell/Frames';
import { projectLabel, useShell } from '../shell/ShellContext';
import { Icon } from '../ui/Icon';
import { Card, Pill, shortId } from '../ui/primitives';

interface Step { n: number; title: string; done: boolean; current: boolean; body: React.ReactNode; action?: React.ReactNode; status?: React.ReactNode }

function StepList(props: { steps: readonly Step[] }): React.JSX.Element {
 return (
  <ol className="steps">
   {props.steps.map((s) => (
    <li key={s.n} data-step={s.n} data-done={s.done ? 'yes' : 'no'}>
     <span className={s.done ? 'no no-ok' : s.current ? 'no no-cur' : 'no'}>{s.done ? <Icon name="check" size="xs" /> : s.n}</span>
     <div className="col g4"><b>{s.title}</b>{s.body}</div>
     <div>{s.status}{s.action}</div>
    </li>
   ))}
  </ol>
 );
}

interface Seen { sources: VisibleSource[]; view: InvestigationView }

/** Add a data source: a checklist that states what the installation can show about one project. It never claims a source was created or that data arrived when
 * nothing says so, and it names no SDK call (every SDK is configured from the source's own signed policy). */
export function OnboardingRoute(props: { context: ViewContext }): React.JSX.Element {
 const { context } = props;
 const shell = useShell();
 const [project, setProject] = React.useState(context.projects[0] ?? '');
 const chosen = context.projects.includes(project) ? project : (context.projects[0] ?? '');
 const state = useScoped<Seen>(context, `onboarding|${chosen}`, async (signal) => {
  const [caps, view] = await Promise.all([capabilities(context.org, chosen, signal), investigate({ ...requestFor(context, 'service'), projects: [chosen] }, signal)]);
  const seen: Seen = { sources: caps.sources, view };
  const viewState = stateOfView(view);
  return viewState.kind === 'unsupported' ? ({ kind: 'unsupported', reason: viewState.reason, data: seen } as LoadState<Seen>) : { kind: 'ready', data: seen };
 });
 const seen = 'data' in state ? state.data : undefined;
 const sources = seen?.sources ?? [];
 const metricNames = seen?.view.metric_names.length ?? 0;
 const services = seen?.view.services?.length ?? 0;
 const haveSource = sources.length > 0;
 const haveData = metricNames > 0 || services > 0;
 const steps: Step[] = [
  {
   n: 1, title: 'Create a source and its key', done: haveSource, current: !haveSource,
   body: haveSource
    ? <><span className="small t2">{sources.length} readable source{sources.length === 1 ? '' : 's'} in this project.</span><ul className="small">{sources.map((s) => <li key={s.id}><code title={s.id}>{shortId(s.id)}</code> · class {s.class} · {s.kinds.join(', ')}{s.replay ? ' · replay' : ''}</li>)}</ul></>
    : <span className="small t2">This account can read no source of {projectLabel(shell.names, chosen)} yet. An organization administrator creates a source and its key in Settings. The key is shown once, when the source is created: keep it in your secret store.</span>,
   status: haveSource ? <Pill tone="ok" icon="check">Done</Pill> : undefined,
   action: <a className="btn btn-sm" href={shell.href('settings', { page: 'sources' })}>Open source settings</a>,
  },
  {
   n: 2, title: 'Configure the SDK and send one event', done: false, current: haveSource && !haveData,
   body: <span className="small t2">Install the SDK for your runtime and configure it with the source's descriptor, key and signed policy; the SDK package README describes the configuration. Nothing here can tell that this was done: step 3 shows what arrived.</span>,
  },
  {
   n: 3, title: 'Verify ingestion', done: haveData, current: false,
   body: !seen
    ? <StatusPanel state={state} />
    : haveData
     ? <span className="small t2 row"><span className="dot dot-ok" aria-hidden="true" />Data was seen in this window: {metricNames} metric name{metricNames === 1 ? '' : 's'}{services > 0 ? `, ${services} service${services === 1 ? '' : 's'}` : ''}.</span>
     : <span className="small t2 row"><span className="dot dot-unk" aria-hidden="true" />No data was seen in this window. Health stays unknown until the first record arrives; this is not a healthy state.</span>,
   status: haveData ? <Pill tone="ok" icon="check">Data seen</Pill> : <Pill tone="unk" icon="question">Waiting</Pill>,
  },
  {
   n: 4, title: 'Add an alert rule', done: false, current: haveData,
   body: <span className="small t2">An alert rule decides what raises an incident. Until one covers a service, its health is not assessed.</span>,
   action: <a className="btn btn-sm" href={shell.href('rules')}>Open alert rules</a>,
  },
 ];
 return (
  <>
   <PageHead title="Add data source" sub={`Project ${projectLabel(shell.names, chosen)}`} />
   <Content>
    {context.projects.length > 1 && (
     <label className="small">Project
      <select value={chosen} onChange={(e) => setProject(e.target.value)}>{context.projects.map((p) => <option key={p} value={p}>{projectLabel(shell.names, p)}</option>)}</select>
     </label>
    )}
    <Card title="Steps" titleId="onb-steps" bodyClass={false}><StepList steps={steps} /></Card>
   </Content>
  </>
 );
}
