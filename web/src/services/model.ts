// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// The service screens apart from React. Health comes only from stored incidents and conditions; a service whose health is not stated is `Not assessed`
// and one whose health could not be read is `Unknown`: neither is ever shown as healthy. RED figures the server cannot state are words, never 0.
import type { RedPoint, RedView } from '../api/console';
import type { HealthStatus, InvestigationView, ServiceHealth, ViewState, VisibleService } from '../api/types';
import type { Gap, Sample } from '../ui/chart/model';
import type { Tone } from '../ui/primitives';

/** What the page can say about a service's health. `reading` is only the moment before the answer arrives. */
export type ServiceHealthWord = HealthStatus | 'not_assessed' | 'unknown' | 'reading';

export interface HealthPillSpec { text: string; tone: Tone; icon: 'x' | 'warn' | 'check' | 'question' | 'clock' }
export function healthPill(word: ServiceHealthWord): HealthPillSpec {
 switch (word) {
  case 'failing': return { text: 'Failing', tone: 'crit', icon: 'x' };
  case 'degraded': return { text: 'Degraded', tone: 'high', icon: 'warn' };
  case 'healthy': return { text: 'Healthy', tone: 'ok', icon: 'check' };
  case 'unknown': return { text: 'Unknown', tone: 'unk', icon: 'question' };
  case 'not_assessed': return { text: 'Not assessed', tone: 'unk', icon: 'question' };
  case 'reading': return { text: 'Reading health', tone: 'unk', icon: 'clock' };
 }
}

/** Why a service has the health it has, in one line, from the stored incidents and conditions only. */
export function healthReason(word: ServiceHealthWord, health: ServiceHealth | undefined): string {
 switch (word) {
  case 'failing': {
   const n = health?.incidents.length ?? 0;
   const critical = health?.incidents.filter((i) => i.severity === 'critical').length ?? 0;
   return `${n} open incident${n === 1 ? '' : 's'}${critical > 0 ? `, ${critical} critical` : ''}${health?.truncated ? ' (more exist)' : ''}`;
  }
  case 'degraded': return `${health?.conditions.length ?? 0} active condition${health?.conditions.length === 1 ? '' : 's'} name${health?.conditions.length === 1 ? 's' : ''} it, no open incident`;
  case 'healthy': return 'no open incident is linked and no active condition names it';
  case 'unknown': return 'the health of this service could not be read';
  case 'not_assessed': return 'the installation does not state a health for it';
  case 'reading': return 'reading stored incidents and conditions';
 }
}

export const HEALTH_FILTERS: readonly { value: ServiceHealthWord | 'all'; label: string }[] = [
 { value: 'all', label: 'All' }, { value: 'failing', label: 'Failing' }, { value: 'degraded', label: 'Degraded' }, { value: 'healthy', label: 'Healthy' }, { value: 'unknown', label: 'Unknown' }, { value: 'not_assessed', label: 'Not assessed' },
];

/** The health a probe answered: the stated health, `not_assessed` when the view states none, `unknown` when the read failed. */
export function wordOfProbe(probe: { kind: 'view'; view: InvestigationView } | { kind: 'failed' }): ServiceHealthWord {
 if (probe.kind === 'failed') return 'unknown';
 return probe.view.health ? probe.view.health.status : 'not_assessed';
}

export interface ServiceRowModel { service: VisibleService; word: ServiceHealthWord; health: ServiceHealth | undefined; red: RedView | 'reading' | 'not_built' | 'failed' | 'not_read' }
const RANK: Record<ServiceHealthWord, number> = { failing: 0, degraded: 1, unknown: 2, not_assessed: 3, reading: 4, healthy: 5 };
/** The worst first, then by project and ID so the order is the same on every read. */
export function orderServices(rows: readonly ServiceRowModel[]): ServiceRowModel[] {
 return [...rows].sort((a, b) => RANK[a.word] - RANK[b.word] || a.service.project_id.localeCompare(b.service.project_id) || a.service.id.localeCompare(b.service.id));
}
export function filterServices(rows: readonly ServiceRowModel[], health: ServiceHealthWord | 'all', text: string): ServiceRowModel[] {
 const t = text.trim().toLowerCase();
 return rows.filter((r) => (health === 'all' || r.word === health) && (t === '' || r.service.id.includes(t) || r.service.project_id.includes(t) || r.service.environments.some((e) => e.includes(t))));
}
export function countsByHealth(rows: readonly ServiceRowModel[]): Record<ServiceHealthWord | 'all', number> {
 const out: Record<ServiceHealthWord | 'all', number> = { all: rows.length, failing: 0, degraded: 0, healthy: 0, unknown: 0, not_assessed: 0, reading: 0 };
 for (const r of rows) out[r.word]++;
 return out;
}

/** How many services get their health and RED figures read for the list; the rest are said not to be read. */
export const SERVICE_PROBE_LIMIT = 12;

// ---- RED ----
const nsToMs = (ns: string): number => Number(BigInt(ns) / 1_000_000n);
/** Server points (nanosecond instants, `null` for a bucket with no samples) as chart samples in epoch milliseconds. A bucket with no samples stays `null`, never 0. */
export function samplesOf(points: readonly RedPoint[]): Sample[] { return points.map((p) => ({ t: nsToMs(p.t), v: p.v })); }
export function gapsOf(gaps: readonly { start: string; end: string }[]): Gap[] { return gaps.map((g) => ({ from: nsToMs(g.start), to: nsToMs(g.end), text: 'no samples' })); }

/** A duration in milliseconds, in the unit a person reads: `612 ms`, `2.61 s`. */
export function durationMs(ms: number | null): string {
 if (ms === null) return 'not available';
 return ms >= 1000 ? `${(ms / 1000).toFixed(ms >= 10_000 ? 1 : 2)} s` : `${Math.round(ms)} ms`;
}
/** An error ratio (0..1) as a percentage. */
export function percent(ratio: number | null): string {
 if (ratio === null) return 'not available';
 const p = ratio * 100;
 return `${p >= 10 ? p.toFixed(0) : p.toFixed(p >= 1 ? 1 : 2)}%`;
}
export function perSecond(rate: number | null): string {
 if (rate === null) return 'not available';
 return `${rate >= 100 ? Math.round(rate) : rate.toFixed(rate >= 10 ? 1 : 2)}/s`;
}

const RED_REASONS: Readonly<Record<string, string>> = {
 no_samples: 'No span of this service was read in this window, so there are no samples. That is not zero traffic.',
 scan_capped: 'The quantiles come from the scanned spans only: the scan limit was reached, so they are partial.',
 shards_missing: 'Some data did not answer, so these figures are partial. Missing data is not zero.',
 no_finished_spans: 'Spans of this service were read but none had finished, so there is no duration. That is not zero latency.',
 spans_sampled: 'A stored span carries a sample probability below 1, so the counts are those of the stored spans, not the requests that were made.',
 list_source_not_wired: 'This installation does not read stored spans for this view, so no figure is shown.',
 separate_grant_required: 'This needs a grant your account does not hold on this project.',
};
export function redReasonText(reason: string | undefined): string {
 if (reason === undefined) return '';
 return RED_REASONS[reason] ?? 'The server reports a reason this page does not recognise; the figures shown are as it stated them.';
}

const PART_WORD: Readonly<Record<ViewState, string>> = { ready: 'Ready', empty: 'No samples', incomplete: 'Partial', stale: 'Stale', not_available: 'Not available' };
/** One RED part's state in words. */
export function partWord(state: ViewState): string { return PART_WORD[state]; }

/** The three charts' window in epoch milliseconds, from the scope's nanosecond window. */
export function windowMs(window: { start: string; end: string }): { start: number; end: number } { return { start: nsToMs(window.start), end: nsToMs(window.end) }; }

/** The words of the RED figures of one listed service for a table cell; every state that is not a figure is a word. */
export function redCell(red: ServiceRowModel['red'], pick: 'p99' | 'errors' | 'rate'): { text: string; figure: boolean } {
 if (red === 'reading') return { text: 'reading', figure: false };
 if (red === 'not_built') return { text: 'not available', figure: false };
 if (red === 'failed') return { text: 'not readable', figure: false };
 if (red === 'not_read') return { text: 'not read here', figure: false };
 const part = pick === 'p99' ? red.duration : pick === 'errors' ? red.errors : red.rate;
 if (part.state === 'empty') return { text: 'no samples', figure: false };
 if (part.state === 'not_available') return { text: 'not available', figure: false };
 const text = pick === 'p99' ? durationMs(red.duration.p99Ms) : pick === 'errors' ? percent(red.errors.ratio) : perSecond(red.rate.perSecond);
 return { text, figure: text !== 'not available' };
}

/** The ids of a service's declared dependencies across the projects that admit it, once each and sorted. */
export function dependencyNames(entries: readonly Pick<VisibleService, 'dependencies'>[]): string[] { return [...new Set(entries.flatMap((e) => e.dependencies))].sort(); }
