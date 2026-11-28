// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { isAbort, stateOfFault } from '../api/client';
import type { Id, LoadState } from '../api/types';
import { formatNs, scopeKey, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { listRules, type RuleList, type RuleView } from '../settings/rules';
import { ProjectSelect, useChosenProject } from '../settings/SettingsUi';
import { Content, PageHead } from '../shell/Frames';
import { useShell } from '../shell/ShellContext';
import { Icon } from '../ui/Icon';
import { Callout, DataTable, Dialog, EmptyState, FilterChips, Pill, type Column } from '../ui/primitives';
import { ReplayForm, RetireForm, RuleForm, type RuleFormProps } from './RuleForms';

type Filter = 'all' | 'active' | 'retired';

/** One project's rule catalogue (POST /api/v1/rules), keyed to the scope it was asked for; `reload` reads again and keeps the answer on screen meanwhile. */
function useRules(context: ViewContext, project: Id | undefined): { load: LoadState<RuleList>; reload: () => void } {
 const key = `${scopeKey(context)}|${project ?? ''}|${context.generation}`;
 const [held, setHeld] = React.useState<{ key: string; load: LoadState<RuleList> }>({ key: '', load: { kind: 'loading' } });
 const [tick, setTick] = React.useState(0);
 React.useEffect(() => {
  if (project === undefined) return;
  const ctl = new AbortController();
  listRules(context.org, project, ctl.signal).then(
   (view) => { if (!ctl.signal.aborted) setHeld({ key, load: { kind: 'ready', data: view } }); },
   (e: unknown) => { if (!ctl.signal.aborted && !isAbort(e)) setHeld({ key, load: stateOfFault(e) }); },
  );
  return () => ctl.abort();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key, tick]);
 return { load: held.key === key ? held.load : { kind: 'loading' }, reload: () => setTick((n) => n + 1) };
}

function ChangeRule(props: RuleFormProps & { rule: RuleView }): React.JSX.Element {
 const [open, setOpen] = React.useState(false);
 return (
  <>
   <button type="button" className="btn btn-sm" aria-expanded={open} aria-label={`Change rule ${props.rule.rule_id}`} onClick={() => setOpen(true)}><Icon name="edit" size="xs" />Change</button>
   <Dialog open={open} onClose={() => setOpen(false)} title={`Rule ${props.rule.rule_id}`} tall>
    <div className="modal-body">
     <RuleForm {...props} existing={props.rule} />
     {props.rule.retired ? <Callout tone="info" role="status" testId="rule-retired">This rule is retired: it is no longer evaluated and its history stays. Saving a new version above brings it back.</Callout> : <RetireForm {...props} rule={props.rule} />}
     {props.rule.rule.kind === 'alert' && <ReplayForm {...props} rule={props.rule} />}
    </div>
   </Dialog>
  </>
 );
}

/** Alert rules: the rules the node's background workers evaluate, per project. Readers of the project see them; organization administrators save, retire and declare replays, each as an audited
 * command. The list has what the rules contract returns (kind, expression, interval, severity or written metric, version, state): there is no last-evaluation state and no incident link in it, so none is drawn. */
export function RulesRoute(props: { context: ViewContext }): React.JSX.Element {
 const c = props.context;
 const shell = useShell();
 const [project, pick] = useChosenProject(c.projects);
 const { load, reload } = useRules(c, project);
 const [filter, setFilter] = React.useState<Filter>('all');
 const [creating, setCreating] = React.useState(false);
 const [flash, setFlash] = React.useState('');
 const list = load.kind === 'ready' ? load.data : undefined;
 React.useEffect(() => { setFlash(''); setFilter('all'); }, [project]);
 const form: RuleFormProps | undefined = list && project ? { org: c.org, project, list, onChanged: reload, onStale: reload } : undefined;
 const rules = list ? list.rules.filter((r) => filter === 'all' || (filter === 'retired') === r.retired) : [];
 const columns: Column<RuleView>[] = [
  { key: 'rule', header: 'Rule', cell: (r) => (
   <div className="cell-title"><span className="a"><code title={r.rule.expression} className="set-expr">{r.rule.expression}</code></span><span className="s"><code>{r.rule_id}</code></span></div>
  ) },
  { key: 'kind', header: 'Kind', cell: (r) => <Pill tone={r.rule.kind === 'alert' ? 'high' : 'info'}>{r.rule.kind === 'alert' ? 'Alert' : 'Recording'}</Pill> },
  { key: 'does', header: 'When it fires or what it writes', label: 'Does', cell: (r) => (r.rule.kind === 'alert' ? `Severity ${r.rule.severity ?? 'not set'}` : `Writes ${r.rule.record_name ?? 'not set'}`) },
  { key: 'every', header: 'Every', cell: (r) => `${r.rule.interval_seconds} s` },
  { key: 'state', header: 'State', cell: (r) => <Pill tone={r.retired ? 'line' : 'ok'} icon={r.retired ? 'pause' : 'check'}>{r.retired ? 'Retired' : 'Active'}</Pill> },
  { key: 'version', header: 'Version', cell: (r) => <span className="num" title={`Updated ${formatNs(r.updated_ns, c.timezone)}`}>{r.version}</span> },
  ...(list?.can_author ? [{ key: 'act', header: <span className="sr-only">Change</span>, label: 'Change', cell: (r: RuleView) => (form ? <ChangeRule {...form} rule={r} /> : null) } as Column<RuleView>] : []),
 ];
 const count = (f: Filter): number => (list ? list.rules.filter((r) => f === 'all' || (f === 'retired') === r.retired).length : 0);
 return (
  <>
   <PageHead crumb={<><a href={shell.href('incidents')}>Incidents</a><span aria-hidden="true">›</span></>} title="Alert rules" sub="what raises an incident"
    actions={list?.can_author ? <button type="button" className="btn btn-primary ml-auto" onClick={() => setCreating(true)}><Icon name="plus" size="s" />New rule</button> : undefined} />
   <Content>
    {project === undefined ? <div className="card"><EmptyState icon="globe" title="Select a project">Rules belong to a project. Choose a scope with at least one project.</EmptyState></div> : (
     <>
      <div className="row wrap g12">
       <ProjectSelect projects={c.projects} value={project} onChange={pick} />
       {list && <FilterChips label="Filter rules by state" value={filter} onChange={setFilter} options={[{ value: 'all', label: 'All', count: count('all') }, { value: 'active', label: 'Active', count: count('active') }, { value: 'retired', label: 'Retired', count: count('retired') }]} />}
      </div>
      <Callout tone="info" icon="rule">An alert rule is evaluated by the node&apos;s background workers on its own fixed grid: it opens a condition for each series that stays present and notifies the organization&apos;s destinations. A recording rule writes its result back as a metric. A saved rule is checked first: an expression that does not parse or does not give an instant vector is refused and nothing is saved.</Callout>
      {flash !== '' && <p role="status" className="set-note set-note-ok" data-write-result="committed">{flash}</p>}
      {load.kind !== 'ready' && <StatusPanel state={load} />}
      {list && (
       <section className="card" aria-label={`Rules of the selected project, ${filter === 'all' ? 'all' : filter}`}>
        {list.rules.length === 0
         ? <EmptyState icon="rule" title="No rule is defined" testId="rules-empty">Nothing is evaluated for this project.{list.can_author ? '' : ' Only organization administrators create rules.'}</EmptyState>
         : rules.length === 0
          ? <EmptyState icon="rule" title={`No ${filter} rule`}>Choose another filter to see the other rules.</EmptyState>
          : <DataTable label="Alert and recording rules" rows={rules} rowKey={(r) => r.rule_id} columns={columns} rowAttrs={(r) => ({ 'data-rule': r.rule_id, 'data-rule-state': r.retired ? 'retired' : 'active', 'data-rule-version': r.version, 'data-rule-revision': r.revision })} />}
        <div className="card-foot">{list.rules.length} rule{list.rules.length === 1 ? '' : 's'}{list.can_author ? '' : '. Only organization administrators change rules.'}</div>
       </section>
      )}
     </>
    )}
   </Content>
   {form && list?.can_author && (
    <Dialog open={creating} onClose={() => setCreating(false)} title="New rule" tall>
     <div className="modal-body">
      <RuleForm {...form} key="new" onChanged={() => { reload(); setCreating(false); setFlash('Done. The server committed the new rule.'); }} />
     </div>
    </Dialog>
   )}
  </>
 );
}
