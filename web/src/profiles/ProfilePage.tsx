// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { getProfile } from '../api/client';
import type { Id } from '../api/types';
import { formatNs, scopeKey, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { EvidenceSections } from '../evidence/Sections';
import { dataOf, useEvidence } from '../evidence/useEvidence';
import { Content, Hero } from '../shell/Frames';
import { Card, CopyButton, Pill, shortId, type Tone } from '../ui/primitives';
import { capabilityRows, correlationOf, coverageRows, headerFacts, linkLines, lossFacts, sampleCoverageLines, sampling, stateWords, unitRows } from './model';
import { ProfileTable } from './ProfileTable';
import { ProfileTimeline } from './ProfileTimeline';
import type { ProfileResponse, ProfileView } from './types';

const STATE_PILL: Record<ProfileResponse['state'], { tone: Tone; word: string }> = {
 ready: { tone: 'ok', word: 'Ready' }, empty: { tone: 'unk', word: 'No observations' }, incomplete: { tone: 'high', word: 'Partial' }, stale: { tone: 'high', word: 'Stale' }, not_available: { tone: 'unk', word: 'Not available' },
};

/** One profile under the caller's own scope and its separate profiles.read grant: how it was collected, what each capability says, what was measured (kept in separate readings), what was lost, and the frames and timeline. The server reads only what this account may read inside the selected window; an unavailable method is stated as such and is never shown as zero. */
export function ProfilePage(props: { id: Id; project: Id; context: ViewContext }): React.JSX.Element {
 const { context, project, id } = props;
 const key = `${scopeKey(context)}|${project}|${id}|${context.generation}`;
 const evidence = useEvidence<ProfileResponse>(key, (signal) => getProfile(context.org, project, id, { start: context.start, end: context.end }, signal));
 const response = dataOf(evidence.state);
 const pill = response === undefined ? undefined : STATE_PILL[response.state];
 return (
  <>
   <Hero>
    <div className="col g4">
     <h1 tabIndex={-1}>Profile <code title={id}>{shortId(id)}</code></h1>
     {pill !== undefined && <div className="row wrap g4"><Pill tone={pill.tone}>{pill.word}</Pill></div>}
     <div className="row small t3"><span>Profile ID <code>{id}</code></span><CopyButton text={id} label="Copy profile ID" /></div>
    </div>
   </Hero>
   <Content>
    <p className="small t2">Observations are read from {formatNs(context.start, context.timezone)} to {formatNs(context.end, context.timezone)} ({context.timezone}). Observations outside this window or outside your access are not shown, and their absence is not proof that nothing happened.</p>
    <StatusPanel state={evidence.state} />
    {response && <EvidenceSections sections={response.sections} />}
    {response && <ProfileDetails response={response} />}
   </Content>
  </>
 );
}

/** The body of a profile response, free of loading: the state in words and, when the server returned a view, every part of it. */
export function ProfileDetails(props: { response: ProfileResponse }): React.JSX.Element {
 const { response } = props;
 return (
  <>
   <p className="small t2" data-testid="profile-state" data-state={response.state}>{stateWords(response)}</p>
   {response.view !== undefined && <ProfileFacts view={response.view} />}
  </>
 );
}

function ProfileFacts(props: { view: ProfileView }): React.JSX.Element {
 const { view } = props;
 const facts = React.useMemo(() => headerFacts(view), [view]);
 const units = React.useMemo(() => unitRows(view), [view]);
 const rate = React.useMemo(() => sampling(view), [view]);
 const caps = React.useMemo(() => capabilityRows(view), [view]);
 const coverage = React.useMemo(() => coverageRows(view), [view]);
 const sampleCoverage = React.useMemo(() => sampleCoverageLines(view), [view]);
 const loss = React.useMemo(() => lossFacts(view), [view]);
 const links = React.useMemo(() => linkLines(view), [view]);
 const correlation = React.useMemo(() => correlationOf(view), [view]);
 return (
  <>
   <Card title="How this profile was collected" titleId="pp-facts-heading" testId="profile-facts">
    <dl className="props exp-facts">
     {facts.map((f) => <React.Fragment key={f.label}><dt>{f.label}</dt><dd data-testid={f.testId}>{f.value}</dd></React.Fragment>)}
    </dl>
   </Card>

   <Card title="What was measured, kept separate" titleId="pp-units-heading" testId="profile-units" bodyClass="col g12">
    <p className="small t2">These five readings are different quantities. They are never added together and none is presented as one CPU duration. A reading that was not measured says so; it is never zero.</p>
    <ProfileTable label="Five separate readings of this profile" caption="Five separate readings of this profile">
     <thead><tr><th scope="col">Reading</th><th scope="col">Value</th><th scope="col">What it is</th></tr></thead>
     <tbody>
      {units.map((u) => (
       <tr key={u.id} data-testid={`unit-${u.id}`} data-state={u.state}>
        <th scope="row">{u.label}</th>
        <td>{u.text}</td>
        <td>{u.meaning}</td>
       </tr>
      ))}
     </tbody>
    </ProfileTable>
    <dl className="props" data-testid="profile-sampling">
     <dt>Requested sampling</dt><dd data-testid="sampling-requested">{rate.requested}</dd>
     <dt>Achieved sampling</dt><dd data-testid="sampling-achieved">{rate.achieved}</dd>
    </dl>
    <p className="small t3">Requested is what the collector was asked to do. Achieved is shown only when the profile reports it; otherwise it reads not reported, and no interval is invented.</p>
   </Card>

   <Card title="Capabilities" titleId="pp-caps-heading" bodyClass="col g12">
    {caps.length === 0 ? <p data-testid="profile-capabilities">No capability record was reported for this profile, so what the collector could do is not known.</p> : (
     <ProfileTable label="Capabilities reported for this profile" testId="profile-capabilities" caption="What each collection method reported it could do. The status is a word, not a colour. A method that is not supported collected nothing.">
      <thead><tr><th scope="col">Engine or runtime</th><th scope="col">System</th><th scope="col">Method</th><th scope="col">Status</th><th scope="col">Reason</th><th scope="col">Expiry</th><th scope="col">In this view</th></tr></thead>
      <tbody>
       {caps.map((c) => (
        <tr key={c.key} data-testid="capability-row" data-status={c.status} data-method={c.method}>
         <th scope="row">{c.engine}</th>
         <td>{c.platform}</td>
         <td>{c.method}</td>
         <td><strong>{c.statusWord}</strong></td>
         <td>{c.reason}</td>
         <td>{c.expires}</td>
         <td>{c.observations}</td>
        </tr>
       ))}
      </tbody>
     </ProfileTable>
    )}
   </Card>

   <Card title="Coverage" titleId="pp-cov-heading" testId="profile-coverage" bodyClass="col g12">
    {coverage.length === 0 ? <p>No coverage was reported.</p> : (
     <ProfileTable label="Coverage reported for this profile" caption="What each capability says it covered. Anything not complete is missing from the profile and is not estimated.">
      <thead><tr><th scope="col">Capability</th><th scope="col">Frames</th><th scope="col">Threads</th><th scope="col">Workers</th><th scope="col">Tasks</th></tr></thead>
      <tbody>
       {coverage.map((c) => (
        <tr key={c.key}><th scope="row">{c.label}</th><td>{c.frames}</td><td>{c.threads}</td><td>{c.workers}</td><td>{c.tasks}</td></tr>
       ))}
      </tbody>
     </ProfileTable>
    )}
    {sampleCoverage.length > 0 && <ul>{sampleCoverage.map((l) => <li key={l}>{l}</li>)}</ul>}
   </Card>

   <Card title="Loss" titleId="pp-loss-heading" testId="profile-loss" bodyClass="col g12">
    <ul>{loss.lines.map((l) => <li key={l}>{l}</li>)}</ul>
    {loss.reports.length > 0 && (
     <ProfileTable label="Loss reports from the collector" caption="Loss reports from the collector">
      <thead><tr><th scope="col">Signal</th><th scope="col">Reason</th><th scope="col">Records lost</th><th scope="col">Period</th><th scope="col">Queue</th></tr></thead>
      <tbody>
       {loss.reports.map((r) => <tr key={r.key}><th scope="row">{r.signal}</th><td>{r.reason}</td><td>{r.count}</td><td>{r.span}</td><td>{r.queue}</td></tr>)}
      </tbody>
     </ProfileTable>
    )}
   </Card>

   <Card title="Links" titleId="pp-links-heading" testId="profile-links" bodyClass="col g12">
    {links.length === 0 ? <p>No link was reported for this profile.</p> : <ul>{links.map((l) => <li key={l.key}>{l.text}</li>)}</ul>}
    <p className="small t3">Links are shown as text. Whether this account may open the target is checked where the target is opened, not here.</p>
   </Card>

   <ProfileTimeline view={view} correlation={correlation} />
  </>
 );
}
