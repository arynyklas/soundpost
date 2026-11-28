// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';

export type Theme = 'dark' | 'light';
export const THEME_KEY = 'soundpost.theme';

export function isTheme(value: unknown): value is Theme { return value === 'dark' || value === 'light'; }

/** Dark is the default. The browser's colour-scheme preference is consulted only when the person has not chosen a theme yet. */
export function resolveTheme(stored: string | null, prefersLight: boolean): Theme {
 if (isTheme(stored)) return stored;
 return prefersLight ? 'light' : 'dark';
}

function readStored(): string | null {
 try { return window.localStorage.getItem(THEME_KEY); } catch { return null; }
}

export function applyTheme(theme: Theme): void {
 document.documentElement.setAttribute('data-theme', theme);
}

/** Applies the theme before the first render so the page never flashes the other theme. */
export function initTheme(): Theme {
 const prefersLight = typeof window.matchMedia === 'function' && window.matchMedia('(prefers-color-scheme: light)').matches;
 const theme = resolveTheme(readStored(), prefersLight);
 applyTheme(theme);
 return theme;
}

/** The current theme and a setter that applies and persists the choice (an explicit choice is stored; the preference fallback is not). */
export function useTheme(): [Theme, (next: Theme) => void] {
 const [theme, set] = React.useState<Theme>(() => (document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark'));
 const choose = React.useCallback((next: Theme): void => {
  applyTheme(next);
  try { window.localStorage.setItem(THEME_KEY, next); } catch { /* a browser that refuses storage still switches for this page */ }
  set(next);
 }, []);
 return [theme, choose];
}
