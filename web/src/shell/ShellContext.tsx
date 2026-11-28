// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { bareHash, encodeHash, type IncidentRef, type Navigation, type SectionId, type ViewContext } from '../app/context';
import type { Id } from '../api/types';

/** Display names of projects and members, from the directory route when this installation serves it. A missing name is never invented: callers fall back to the short ID. */
export interface Names {
 /** 'loading' until the first answer; 'not_built' when the directory route is not served; 'ready' otherwise. */
 state: 'loading' | 'ready' | 'not_built' | 'unavailable';
 /** The organization these names were read for. */
 forOrg?: Id;
 /** The organization's own name, when the directory states it. */
 orgName?: string;
 projects: ReadonlyMap<Id, string>;
 members: ReadonlyMap<Id, string>;
 canSetNames: boolean;
}
export const NO_NAMES: Names = { state: 'loading', projects: new Map(), members: new Map(), canSetNames: false };

export interface LinkOptions { service?: Id; incident?: IncidentRef | null; target?: IncidentRef | null; page?: string }
export interface ShellCounts { incidents?: number | undefined }

export interface ShellApi {
 nav: Navigation;
 context: ViewContext | null;
 section: SectionId;
 /** The address of a screen inside the current scope (or of the bare screen when no scope is chosen). */
 href: (section: SectionId, options?: LinkOptions) => string;
 go: (section: SectionId, options?: LinkOptions) => void;
 /** Reads the current screen again; a relative window ("last hour") slides to now first. */
 refresh: () => void;
 applyScope: (next: Omit<ViewContext, 'generation'>) => void;
 openScope: () => void;
 openSearch: () => void;
 names: Names;
 /** Pages publish small figures the sidebar shows (open incidents). */
 counts: ShellCounts;
 setCounts: (next: ShellCounts) => void;
}

const Ctx = React.createContext<ShellApi | null>(null);
export const ShellProvider = Ctx.Provider;
export function useShell(): ShellApi {
 const v = React.useContext(Ctx);
 if (!v) throw new Error('useShell outside the console shell');
 return v;
}

export function linkFor(context: ViewContext | null, section: SectionId, o: LinkOptions = {}): string {
 return context ? encodeHash(context, section, o.service ?? '', o.incident ?? null, o.target ?? null, o.page ?? '') : bareHash(section);
}

/** The name of a project for display: its directory name, else the short ID. */
export function projectLabel(names: Names, id: Id): string { return names.projects.get(id) ?? `project ${id.slice(0, 4)}…${id.slice(-4)}`; }
/** The name of a member for display, or undefined when none is known (callers show Person with the short ID). */
export function memberName(names: Names, id: Id | undefined): string | undefined { return id === undefined ? undefined : names.members.get(id); }
