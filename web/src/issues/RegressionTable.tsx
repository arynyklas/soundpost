// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { Id, RegressionExplanation, ReleaseRegression } from '../api/types';
import { encodeHash, formatNs, type ViewContext } from '../app/context';
import { regressionAncestryWords, regressionDecisionWords, regressionOutcomeWords, regressionPolicyWords } from '../evidence/model';
import { DataTable, IdCode, type Column } from '../ui/primitives';

type Row = RegressionExplanation | ReleaseRegression;

/** The stored regression evaluations of an issue (oldest first), or of the issues that ran in one release. Every cell is what the lifecycle recorded when the occurrence arrived: the verdict, the evaluator's own stored reason as text, the fix frontier it compared against, the policy it applied and whether it reopened the issue. Nothing is derived here from timestamps, release labels or the order of rows. */
export function RegressionTable(props: { context: ViewContext; project: Id; rows: Row[]; caption: string; byRelease: boolean }): React.JSX.Element {
 const { context, project, rows } = props;
 const link = (section: 'issues' | 'releases', id: Id): React.JSX.Element => <a href={encodeHash(context, section, '', null, { project, id })}><IdCode value={id} /></a>;
 const columns: Column<Row>[] = [
  ...(props.byRelease ? [{ key: 'issue', header: 'Issue', cell: (x: Row) => ('issue' in x ? link('issues', x.issue) : null) }] : []),
  { key: 'occurrence', header: 'Occurrence', rowHeader: !props.byRelease, cell: (x) => <IdCode value={x.occurrence} /> },
  { key: 'time', header: 'Event time', cell: (x) => <span className="small">{formatNs(x.event_time_ns, context.timezone)}</span> },
  ...(!props.byRelease ? [{ key: 'release', header: 'Release it ran in', cell: (x: Row) => (x.evidence_release === undefined ? 'The occurrence names no release.' : link('releases', x.evidence_release)) }] : []),
  { key: 'verdict', header: 'Verdict', cell: (x) => <span data-testid="regression-verdict">{regressionDecisionWords(x)} {regressionAncestryWords(x)}</span> },
  { key: 'why', header: 'Why (as stored)', cell: (x) => <span data-testid="regression-reason">{x.reason}</span> },
  { key: 'frontier', header: 'Fix frontier compared with', cell: (x) => (x.frontier.length === 0 ? 'No fix frontier was recorded.' : <span className="row wrap g4">{x.frontier.map((f) => <span key={f}>{link('releases', f)}</span>)}</span>) },
  { key: 'policy', header: 'Policy', cell: (x) => <span className="small">{regressionPolicyWords(x)}</span> },
  { key: 'outcome', header: 'Outcome', cell: (x) => <span data-testid="regression-outcome">{regressionOutcomeWords(x)}</span> },
 ];
 return (
  <DataTable
   label={props.caption} testId="regression-list" rows={rows} columns={columns} tight
   rowKey={(x) => `${'issue' in x ? x.issue : ''}:${x.occurrence}`}
   rowAttrs={(x) => ({ 'data-occurrence': x.occurrence, 'data-eligible': x.eligible ? 'yes' : 'no', 'data-ancestry': x.ancestry_known ? 'known' : 'unknown', 'data-reopened': x.reopened ? 'yes' : 'no' })}
  />
 );
}
