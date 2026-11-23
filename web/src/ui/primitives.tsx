// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { Icon, type IconName } from './Icon';

/** Join class names, skipping falsy parts. */
export function cx(...parts: (string | false | null | undefined)[]): string { return parts.filter(Boolean).join(' '); }

export type Tone = 'crit' | 'high' | 'warn' | 'ok' | 'info' | 'acc' | 'unk' | 'line' | 'neutral';

/** A state badge. The text always says the state; the tint and icon only reinforce it. */
export function Pill(props: { tone?: Tone; icon?: IconName; children: React.ReactNode; title?: string; className?: string; testId?: string; state?: string }): React.JSX.Element {
 const tone = props.tone ?? 'neutral';
 return <span className={cx('pill', tone !== 'neutral' && `pill-${tone}`, props.className)} title={props.title} data-testid={props.testId} data-state={props.state}>{props.icon && <Icon name={props.icon} size="xs" />}{props.children}</span>;
}

export type Severity = 'critical' | 'major' | 'minor';
/** Severity glyph with its word kept for assistive technology. */
export function SeverityIcon(props: { severity: Severity }): React.JSX.Element {
 const s = props.severity;
 const tone = s === 'critical' ? 'crit' : s === 'major' ? 'high' : 'low';
 return <span className={`sev sev-${tone}`} title={`${s[0]!.toUpperCase()}${s.slice(1)} severity`}><Icon name={s === 'critical' ? 'fire' : s === 'major' ? 'warn' : 'info'} size="xs" /><span className="sr-only">{s}</span></span>;
}

/** A person. Display names are not available to every reader, so a bare account ID is shown shortened and never invented as a name. */
export function Person(props: { id?: string | undefined; name?: string | undefined; unassigned?: string }): React.JSX.Element {
 if (!props.id && !props.name) return <span className="row t3"><span className="avatar avatar-none"><Icon name="user" size="xs" /></span>{props.unassigned ?? 'Unassigned'}</span>;
 const label = props.name ?? shortId(props.id ?? '');
 const initials = props.name ? props.name.split(/\s+/).map((w) => w[0] ?? '').join('').slice(0, 2).toUpperCase() : (props.id ?? '').slice(0, 2).toUpperCase();
 const tone = (props.id ?? props.name ?? '').charCodeAt(0) % 5;
 return <span className="row"><span className={cx('avatar', tone > 0 && `avatar-${tone + 1}`)} aria-hidden="true">{initials}</span><span className="ellipsis" title={props.id}>{label}</span></span>;
}

/** The first 8 hex characters of an ID, for places where a full 32-character ID would crowd the line. The full ID stays in the title. */
export function shortId(id: string): string { return id.length > 12 ? `${id.slice(0, 8)}…` : id; }

export function Card(props: { title?: React.ReactNode; titleId?: string; actions?: React.ReactNode; footer?: React.ReactNode; urgent?: boolean; children?: React.ReactNode; className?: string; bodyClass?: string | false; headingLevel?: 2 | 3; testId?: string; ariaLabel?: string }): React.JSX.Element {
 const H = props.headingLevel === 3 ? 'h3' : 'h2';
 return (
  <section className={cx('card', props.urgent && 'card-urgent', props.className)} aria-labelledby={props.title && props.titleId ? props.titleId : undefined} aria-label={!props.title ? props.ariaLabel : undefined} data-testid={props.testId}>
   {(props.title || props.actions) && <div className="card-head">{props.title && <H id={props.titleId}>{props.title}</H>}{props.actions && <span className="ml-auto row">{props.actions}</span>}</div>}
   {props.bodyClass === false ? props.children : <div className={cx('card-body', props.bodyClass)}>{props.children}</div>}
   {props.footer && <div className="card-foot">{props.footer}</div>}
  </section>
 );
}

export function Callout(props: { tone?: 'warn' | 'crit' | 'info' | 'high' | 'ok' | 'unk'; icon?: IconName; children: React.ReactNode; role?: 'status' | 'alert'; testId?: string; className?: string }): React.JSX.Element {
 const tone = props.tone ?? 'warn';
 const icon: IconName = props.icon ?? (tone === 'crit' ? 'fire' : tone === 'info' ? 'info' : tone === 'ok' ? 'check' : tone === 'unk' ? 'question' : 'warn');
 return <div className={cx('callout', tone !== 'warn' && `callout-${tone}`, props.className)} role={props.role} data-testid={props.testId}><Icon name={icon} size="s" /><span>{props.children}</span></div>;
}

export interface Column<T> {
 key: string;
 header: React.ReactNode;
 /** The label a narrow (stacked) layout shows above the value; defaults to the header when that is a string. */
 label?: string;
 cell: (row: T, index: number) => React.ReactNode;
 align?: 'right';
 /** The first column of a row is its row header unless this is false. */
 rowHeader?: boolean;
 /** Hidden below 1300px (a secondary, redundant glance such as a sparkline); never used for the only copy of a fact. */
 xlOnly?: boolean;
}
/** A data table inside a focusable, labelled scroll region. Below 820px the rows stack into a list: the same cells, never duplicated. */
export function DataTable<T>(props: { label: string; rows: readonly T[]; rowKey: (row: T) => string; columns: readonly Column<T>[]; rowClass?: (row: T) => string | undefined; rowAttrs?: (row: T) => Record<string, string | undefined>; tight?: boolean; stack?: boolean; testId?: string; caption?: string }): React.JSX.Element {
 const stack = props.stack !== false;
 return (
  <div className="table-region" tabIndex={0} role="region" aria-label={props.label} data-testid={props.testId}>
   <table className={cx('table', props.tight && 'tight', stack && 'stack')} role="table">
    <caption className="sr-only">{props.caption ?? props.label}</caption>
    <thead role="rowgroup"><tr role="row">{props.columns.map((c) => <th key={c.key} scope="col" role="columnheader" className={cx(c.align === 'right' && 'right', c.xlOnly && 'xl-only') || undefined}>{c.header}</th>)}</tr></thead>
    <tbody role="rowgroup">
     {props.rows.map((row, i) => (
      <tr key={props.rowKey(row)} role="row" className={props.rowClass?.(row)} {...props.rowAttrs?.(row)}>
       {props.columns.map((c, j) => {
        const label = c.label ?? (typeof c.header === 'string' ? c.header : undefined);
        const content = c.cell(row, i);
        return j === 0 && c.rowHeader !== false
         ? <th key={c.key} scope="row" role="rowheader" className={cx(c.xlOnly && 'xl-only') || undefined}>{content}</th>
         : <td key={c.key} role="cell" data-label={label} className={cx(c.align === 'right' && 'right', c.xlOnly && 'xl-only') || undefined}>{content}</td>;
       })}
      </tr>
     ))}
    </tbody>
   </table>
  </div>
 );
}

/** A section's honest "this part does not exist yet" state. Never faked data, never zero. */
export function NotAvailable(props: { title: string; children?: React.ReactNode; testId?: string; icon?: IconName }): React.JSX.Element {
 return (
  <div className="empty" role="status" data-state="unsupported" data-testid={props.testId}>
   <Icon name={props.icon ?? 'info'} />
   <h2>{props.title}</h2>
   <p>{props.children ?? 'This installation does not provide it yet. Nothing is shown in its place.'}</p>
  </div>
 );
}

export function EmptyState(props: { title: string; children?: React.ReactNode; icon?: IconName; action?: React.ReactNode; testId?: string }): React.JSX.Element {
 return (
  <div className="empty" role="status" data-state="empty" data-testid={props.testId}>
   {props.icon && <Icon name={props.icon} />}
   <h2>{props.title}</h2>
   {props.children && <p>{props.children}</p>}
   {props.action}
  </div>
 );
}

export interface LineageItem { kind: string; name: string; state?: string; tone?: 'crit' | 'high' | 'warn' | 'ok' | 'info' | 'acc' | 'unk'; icon: IconName; href?: string; current?: boolean; unavailable?: boolean }
/** One row of chips, in the same order on every page: Rule → Incident → Issue → Release → Service. A link that is not available is shown as such, not dropped. */
export function Lineage(props: { items: readonly LineageItem[]; label?: string }): React.JSX.Element {
 return (
  <ol className="lineage" aria-label={props.label ?? 'Related records: rule, incident, issue, release, service'} data-testid="lineage">
   {props.items.map((item, i) => {
    const inner = (
     <>
      <Icon name={item.icon} size="s" />
      <span className="lk">{item.kind}</span>
      <b>{item.name}</b>
      {item.state && <>{item.tone && <span className={`dot dot-${item.tone}`} aria-hidden="true" />}<span className="ls">{item.state}</span></>}
     </>
    );
    return (
     <li key={`${item.kind}:${item.name}`}>
      {i > 0 && <span className="lin-arrow" aria-hidden="true"><Icon name="right" size="xs" /></span>}
      {item.href && !item.current && !item.unavailable
       ? <a className="lin-chip" href={item.href}>{inner}</a>
       : <span className={cx('lin-chip', item.unavailable && 'is-unavailable')} aria-current={item.current ? 'true' : undefined}>{inner}</span>}
     </li>
    );
   })}
  </ol>
 );
}

/** Modal dialog on the native <dialog>: focus is trapped, Escape closes, the page behind is inert and focus returns to the opener. */
export function Dialog(props: { open: boolean; onClose: () => void; title: string; children: React.ReactNode; tall?: boolean; className?: string; testId?: string }): React.JSX.Element | null {
 const ref = React.useRef<HTMLDialogElement>(null);
 const titleId = React.useId();
 const { open, onClose } = props;
 React.useLayoutEffect(() => {
  const el = ref.current;
  if (!open || !el) return;
  if (!el.open) el.showModal();
  const first = el.querySelector<HTMLElement>('[data-autofocus]');
  first?.focus();
  return () => { if (el.open) el.close(); };
 }, [open]);
 if (!open) return null;
 return (
  <dialog ref={ref} className={cx('modal', props.tall && 'modal-tall', props.className)} aria-labelledby={titleId} data-testid={props.testId}
   onCancel={(e) => { e.preventDefault(); onClose(); }}
   onClick={(e) => { if (e.target === ref.current) onClose(); }}>
   <div className="modal-head"><h2 id={titleId}>{props.title}</h2><button type="button" className="btn btn-ghost btn-icon ml-auto" aria-label="Close" onClick={onClose}><Icon name="x" size="s" /></button></div>
   {props.children}
  </dialog>
 );
}

/** A segmented toggle group (one pressed at a time). */
export function Segmented<T extends string>(props: { label: string; value: T; options: readonly { value: T; label: string; count?: number }[]; onChange: (v: T) => void }): React.JSX.Element {
 return (
  <div className="seg" role="group" aria-label={props.label}>
   {props.options.map((o) => <button key={o.value} type="button" className="seg-item" aria-pressed={o.value === props.value} onClick={() => props.onChange(o.value)}>{o.label}{o.count !== undefined && <span className="count">{o.count}</span>}</button>)}
  </div>
 );
}

export function FilterChips<T extends string>(props: { label: string; value: T; options: readonly { value: T; label: string; count?: number }[]; onChange: (v: T) => void }): React.JSX.Element {
 return (
  <div className="chips" role="group" aria-label={props.label}>
   {props.options.map((o) => <button key={o.value} type="button" className="chip" aria-pressed={o.value === props.value} onClick={() => props.onChange(o.value)}>{o.label}{o.count !== undefined && <span className="count">{o.count}</span>}</button>)}
  </div>
 );
}

/** Copies text to the clipboard and says so in words. */
export function CopyButton(props: { text: string; label: string; className?: string }): React.JSX.Element {
 const [done, setDone] = React.useState<'idle' | 'copied' | 'failed'>('idle');
 const copy = (): void => {
  const write = navigator.clipboard?.writeText(props.text);
  if (!write) { setDone('failed'); return; }
  write.then(() => setDone('copied'), () => setDone('failed'));
  window.setTimeout(() => setDone('idle'), 2500);
 };
 return <><button type="button" className={cx('btn btn-ghost btn-icon btn-sm', props.className)} aria-label={props.label} onClick={copy}><Icon name={done === 'copied' ? 'check' : 'copy'} size="xs" /></button>{done !== 'idle' && <span className="sr-only" role="status">{done === 'copied' ? 'Copied' : 'Copy was not allowed by the browser'}</span>}</>;
}

/** An identifier shown short (about its first 12 characters, monospace) so a table or a fact list stays readable. The full value stays in the DOM and in the tooltip, and with `copy` a copy button (named `copy`) puts it on the clipboard. */
export function IdCode(props: { value: string; copy?: string }): React.JSX.Element {
 return <span className="idcode"><code className="id" title={props.value}>{props.value}</code>{props.copy !== undefined && <CopyButton text={props.value} label={props.copy} />}</span>;
}
