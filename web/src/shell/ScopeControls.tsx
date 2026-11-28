// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { isId, windowEndingAt, type ViewContext } from '../app/context';
import { Icon } from '../ui/Icon';
import { useShell } from './ShellContext';

export const WINDOW_PRESETS: readonly { minutes: number; label: string }[] = [
 { minutes: 15, label: 'Last 15 minutes' }, { minutes: 60, label: 'Last 1 hour' }, { minutes: 360, label: 'Last 6 hours' }, { minutes: 1440, label: 'Last 24 hours' }, { minutes: 10080, label: 'Last 7 days' }, { minutes: 43200, label: 'Last 30 days' },
];

/** Short clock text of a nanosecond instant in a time zone: "14:00", or "Nov 20 15:00" when the window spans more than a day. */
export function clockText(ns: string, timezone: string, withDate: boolean): string {
 const date = new Date(Number(BigInt(ns) / 1_000_000n));
 return new Intl.DateTimeFormat('en-GB', { timeZone: timezone, ...(withDate ? { month: 'short', day: '2-digit' } : {}), hour: '2-digit', minute: '2-digit', hour12: false }).format(date);
}
function zoneName(ns: string, timezone: string): string {
 const parts = new Intl.DateTimeFormat('en-GB', { timeZone: timezone, timeZoneName: 'short' }).formatToParts(new Date(Number(BigInt(ns) / 1_000_000n)));
 return parts.find((p) => p.type === 'timeZoneName')?.value ?? timezone;
}
/** "Last 1 hour" for a relative window, else the exact span; the range text always follows. */
export function windowLabel(c: ViewContext): { title: string; range: string } {
 const preset = c.span !== undefined ? WINDOW_PRESETS.find((p) => p.minutes === c.span) : undefined;
 const spanMs = Number((BigInt(c.end) - BigInt(c.start)) / 1_000_000n);
 const withDate = spanMs > 20 * 3600_000;
 const range = `${clockText(c.start, c.timezone, withDate)} – ${clockText(c.end, c.timezone, withDate)} ${zoneName(c.end, c.timezone)}`;
 return { title: preset?.label ?? 'Custom window', range };
}

/** Closes a popover on Escape or a press outside it; returns focus to its button on Escape. */
function usePopover(): { open: boolean; setOpen: (v: boolean) => void; wrap: React.RefObject<HTMLDivElement | null> } {
 const [open, setOpen] = React.useState(false);
 const wrap = React.useRef<HTMLDivElement>(null);
 React.useEffect(() => {
  if (!open) return;
  const down = (e: PointerEvent): void => { if (wrap.current && !wrap.current.contains(e.target as Node)) setOpen(false); };
  const key = (e: KeyboardEvent): void => { if (e.key === 'Escape') { setOpen(false); wrap.current?.querySelector<HTMLElement>('button')?.focus(); } };
  document.addEventListener('pointerdown', down);
  document.addEventListener('keydown', key);
  return () => { document.removeEventListener('pointerdown', down); document.removeEventListener('keydown', key); };
 }, [open]);
 return { open, setOpen, wrap };
}

function EnvironmentMenu(props: { context: ViewContext }): React.JSX.Element {
 const shell = useShell();
 const pop = usePopover();
 const [value, setValue] = React.useState(props.context.environment);
 const [error, setError] = React.useState('');
 const apply = (environment: string): void => { pop.setOpen(false); shell.applyScope({ ...props.context, environment }); };
 return (
  <div className="menu-wrap" ref={pop.wrap}>
   <button type="button" aria-haspopup="true" aria-expanded={pop.open} onClick={() => pop.setOpen(!pop.open)}>
    <Icon name="globe" size="s" /><span className="k">Env</span> {props.context.environment === '' ? 'All environments' : props.context.environment.slice(0, 8)}<Icon name="caret" size="xs" />
   </button>
   {pop.open && (
    <div className="menu" role="group" aria-label="Environment">
     <button type="button" aria-pressed={props.context.environment === ''} onClick={() => apply('')}>All environments</button>
     <form className="col g4" aria-label="Choose an environment by ID" onSubmit={(e) => { e.preventDefault(); const v = value.trim(); if (v !== '' && !isId(v)) { setError('Environment ID must be 32 lowercase hexadecimal characters.'); return; } apply(v); }}>
      <label className="small">Environment ID<input value={value} onChange={(e) => setValue(e.target.value)} autoComplete="off" spellCheck={false} /></label>
      {error && <p role="alert" className="error small">{error}</p>}
      <button type="submit" className="btn-primary">Apply environment</button>
     </form>
     <p className="menu-note">Only the Services view can be narrowed to one environment; other screens say so.</p>
    </div>
   )}
  </div>
 );
}

function WindowMenu(props: { context: ViewContext }): React.JSX.Element {
 const shell = useShell();
 const pop = usePopover();
 const label = windowLabel(props.context);
 const choose = (minutes: number): void => { pop.setOpen(false); shell.applyScope({ ...props.context, ...windowEndingAt(Date.now(), minutes), span: minutes }); };
 return (
  <div className="menu-wrap" ref={pop.wrap}>
   <button type="button" aria-haspopup="true" aria-expanded={pop.open} onClick={() => pop.setOpen(!pop.open)}>
    <Icon name="clock" size="s" />{label.title}<span className="k">· {label.range}</span><Icon name="caret" size="xs" />
   </button>
   {pop.open && (
    <div className="menu" role="group" aria-label="Time window">
     {WINDOW_PRESETS.map((p) => <button key={p.minutes} type="button" aria-pressed={props.context.span === p.minutes} onClick={() => choose(p.minutes)}>{p.label}</button>)}
     <p className="menu-note">Windows end now and are at most 31 days for list screens.</p>
    </div>
   )}
  </div>
 );
}

/** Environment, time window and Refresh: they sit in every page header. Without a scope only a prompt is shown. */
export function ScopeControls(): React.JSX.Element | null {
 const shell = useShell();
 const c = shell.context;
 if (!c) return null;
 return (
  <div className="scope-controls">
   <div className="scope-group"><EnvironmentMenu context={c} /><WindowMenu context={c} /></div>
   <button type="button" className="btn-icon" aria-label="Refresh" onClick={shell.refresh}><Icon name="refresh" size="s" /></button>
  </div>
 );
}
