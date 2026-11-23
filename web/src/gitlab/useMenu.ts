// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';

/** A button-and-menu popover: it focuses the first item when it opens, moves with the arrow keys, and closes on Escape (focus returns to the button) or a press outside. */
export function useMenu(): { open: boolean; setOpen: (open: boolean) => void; wrap: React.RefObject<HTMLDivElement | null>; trigger: React.RefObject<HTMLButtonElement | null> } {
 const [open, setOpen] = React.useState(false);
 const wrap = React.useRef<HTMLDivElement>(null);
 const trigger = React.useRef<HTMLButtonElement>(null);
 React.useEffect(() => {
  if (!open) return;
  wrap.current?.querySelector<HTMLElement>('[role=menuitem]')?.focus();
  const onDown = (e: MouseEvent): void => { if (!wrap.current?.contains(e.target as Node)) setOpen(false); };
  const onKey = (e: KeyboardEvent): void => {
   if (e.key === 'Escape') { setOpen(false); trigger.current?.focus(); return; }
   if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
   const items = Array.from(wrap.current?.querySelectorAll<HTMLElement>('[role=menuitem]') ?? []);
   if (items.length === 0) return;
   e.preventDefault();
   const at = items.indexOf(document.activeElement as HTMLElement);
   items[(at + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length]?.focus();
  };
  document.addEventListener('mousedown', onDown);
  document.addEventListener('keydown', onKey);
  return () => { document.removeEventListener('mousedown', onDown); document.removeEventListener('keydown', onKey); };
 }, [open]);
 return { open, setOpen, wrap, trigger };
}
