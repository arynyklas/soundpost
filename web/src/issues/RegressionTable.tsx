// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { Id, RegressionExplanation, ReleaseRegression } from '../api/types';
import { encodeHash, formatNs, type ViewContext } from '../app/context';
import { regressionAncestryWords, regressionDecisionWords, regressionOutcomeWords, regressionPolicyWords } from '../evidence/model';

/** The stored regression evaluations of an issue (oldest first), or of the issues that ran in one release. Every cell is what the lifecycle recorded when the occurrence arrived: the verdict, the evaluator's own stored reason as text, the fix frontier it compared against, the policy it applied and whether it reopened the issue. Nothing is derived here from timestamps, release labels or the order of rows. */
export function RegressionTable(props: { context: ViewContext; project: Id; rows: (RegressionExplanation | ReleaseRegression)[]; caption: string; byRelease: boolean }): React.JSX.Element {
 const { context, project, rows } = props;
 const link = (section: 'issues' | 'releases', id: Id): React.JSX.Element => <a href={encodeHash(context, section, '', null, { project, id })}><code>{id}</code></a>;
 return (
  <table className="data-table" data-testid="regression-list">
   <caption>{props.caption}</caption>
   <thead>
    <tr>
     {props.byRelease && <th scope="col">Issue</th>}
     <th scope="col">Occurrence</th>
     <th scope="col">Event time</th>
     {!props.byRelease && <th scope="col">Release it ran in</th>}
     <th scope="col">Verdict</th>
     <th scope="col">Why (as stored)</th>
     <th scope="col">Fix frontier compared with</th>
     <th scope="col">Policy</th>
     <th scope="col">Outcome</th>
    </tr>
   </thead>
   <tbody>
    {rows.map((x) => (
     <tr key={`${'issue' in x ? x.issue : ''}:${x.occurrence}`} data-occurrence={x.occurrence} data-eligible={x.eligible ? 'yes' : 'no'} data-ancestry={x.ancestry_known ? 'known' : 'unknown'} data-reopened={x.reopened ? 'yes' : 'no'}>
      {props.byRelease && <td>{'issue' in x ? link('issues', x.issue) : null}</td>}
      <td><code>{x.occurrence}</code></td>
      <td>{formatNs(x.event_time_ns, context.timezone)}</td>
      {!props.byRelease && <td>{x.evidence_release === undefined ? 'The occurrence names no release.' : link('releases', x.evidence_release)}</td>}
      <td data-testid="regression-verdict">{regressionDecisionWords(x)} {regressionAncestryWords(x)}</td>
      <td data-testid="regression-reason">{x.reason}</td>
      <td>{x.frontier.length === 0 ? 'No fix frontier was recorded.' : x.frontier.map((f) => <span key={f}>{link('releases', f)} </span>)}</td>
      <td>{regressionPolicyWords(x)}</td>
      <td data-testid="regression-outcome">{regressionOutcomeWords(x)}</td>
     </tr>
    ))}
   </tbody>
  </table>
 );
}
