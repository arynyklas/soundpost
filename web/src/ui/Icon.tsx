// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';

/** The console's own icon set: 24x24 stroke glyphs in the common outline style, authored for this product (no third-party icon package and no
 * third-party path data, so there is no notice to carry). Only the icons the console uses are defined here. Icons are decorative: every use is
 * next to words or inside a control that has its own accessible name, so the svg is hidden from assistive technology. */
const PATHS = {
 home: '<path d="M4 11.5 12 5l8 6.5V20h-5.5v-5h-5v5H4z"/>',
 bell: '<path d="M6 10a6 6 0 0 1 12 0v4l1.5 2.5h-15L6 14z"/><path d="M10 19.5a2 2 0 0 0 4 0"/>',
 rule: '<path d="M4 6h10M4 12h16M4 18h7"/><circle cx="17" cy="6" r="2.5"/><circle cx="14" cy="18" r="2.5"/>',
 search: '<circle cx="11" cy="11" r="6.5"/><path d="m20 20-4.2-4.2"/>',
 clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
 gear: '<circle cx="12" cy="12" r="3"/><path d="M12 2.5v3M12 18.5v3M2.5 12h3M18.5 12h3M5.3 5.3l2.1 2.1M16.6 16.6l2.1 2.1M5.3 18.7l2.1-2.1M16.6 7.4l2.1-2.1"/>',
 bug: '<rect x="7" y="6.5" width="10" height="13" rx="5"/><path d="M12 10v9.5M3.5 12.5H7M17 12.5h3.5M4.5 7l3 2M19.5 7l-3 2M4.5 18l3-2M19.5 18l-3-2"/>',
 tag: '<path d="M3.5 3.5h7.5l9.5 9.5-7.5 7.5-9.5-9.5z"/><circle cx="8" cy="8" r="1.2"/>',
 trace: '<path d="M3.5 5h9M6.5 9.5h11M9.5 14h6M9.5 18.5h11"/>',
 logs: '<path d="M4 5h16M4 9.5h16M4 14h10M4 18.5h13"/>',
 chart: '<path d="M3.5 20h17"/><path d="m4.5 16 4.5-5.5 4 3 6-8"/>',
 flame: '<path d="M3 20h18M4 16h13M6 12h9M8 8h5"/>',
 replay: '<rect x="3" y="4.5" width="18" height="12" rx="2"/><path d="m10 8 4.5 2.5L10 13z"/><path d="M8 20h8"/>',
 box: '<rect x="3.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.5"/><path d="M10.5 7h6.5v6.5"/>',
 job: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/><path d="M12 1.5v2"/>',
 fire: '<path d="M12 3c.8 3.6 5 5.2 5 10.2A5 5 0 0 1 12 18a5 5 0 0 1-5-4.8c0-2.3 1.2-3.7 2.3-4.6.1 1.7 1 2.6 1.9 2.9C11 9 11.3 5.8 12 3z"/>',
 check: '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
 x: '<path d="m6 6 12 12M18 6 6 18"/>',
 question: '<circle cx="12" cy="12" r="8.5" stroke-dasharray="3 2.5"/><path d="M9.7 9.7a2.4 2.4 0 1 1 3.2 2.2c-.6.3-.9.8-.9 1.4M12 16.3h.01"/>',
 warn: '<path d="M12 3.5 21 19.5H3z"/><path d="M12 10v4M12 17h.01"/>',
 info: '<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5.5M12 7.8h.01"/>',
 lock: '<rect x="5" y="10.5" width="14" height="10" rx="2"/><path d="M8.5 10.5V8a3.5 3.5 0 0 1 7 0v2.5"/>',
 user: '<circle cx="12" cy="8.5" r="3.5"/><path d="M5 20a7 7 0 0 1 14 0"/>',
 users: '<circle cx="9" cy="8.5" r="3"/><path d="M3 19.5a6 6 0 0 1 12 0M16 5.8a3 3 0 0 1 0 5.4M18 14a6 6 0 0 1 3 5.5"/>',
 snooze: '<path d="M6 10a6 6 0 0 1 9.5-4.8M18 10v4l1.5 2.5h-15L6 14v-4"/><path d="M10 19.5a2 2 0 0 0 4 0M15 2.5h4l-4 4.5h4"/>',
 wrench: '<path d="M15 3.5a4.5 4.5 0 0 0-4.3 5.9L3.5 16.6l3.9 3.9 7.2-7.2A4.5 4.5 0 0 0 20.5 9l-3 3-3-1-1-3 3-3a4.6 4.6 0 0 0-1.5-.5z"/>',
 link: '<path d="M10 14a3.5 3.5 0 0 0 5 0l3-3a3.5 3.5 0 0 0-5-5l-1 1M14 10a3.5 3.5 0 0 0-5 0l-3 3a3.5 3.5 0 0 0 5 5l1-1"/>',
 dots: '<circle cx="5.5" cy="12" r="1.4" fill="currentColor"/><circle cx="12" cy="12" r="1.4" fill="currentColor"/><circle cx="18.5" cy="12" r="1.4" fill="currentColor"/>',
 caret: '<path d="m7 10 5 5 5-5"/>',
 right: '<path d="m10 7 5 5-5 5"/>',
 arrow: '<path d="M5 12h14M13 6l6 6-6 6"/>',
 refresh: '<path d="M19.5 12A7.5 7.5 0 1 1 17 6.4M19.5 3.5V7.5h-4"/>',
 copy: '<rect x="8.5" y="8.5" width="11" height="11" rx="2"/><path d="M5 15.5V5h10.5"/>',
 filter: '<path d="M4 5h16l-6.2 7.5v5.5l-3.6 1.5v-7z"/>',
 play: '<path d="M7 5v14l11.5-7z" fill="currentColor"/>',
 pause: '<path d="M8 5v14M16 5v14"/>',
 plus: '<path d="M12 5v14M5 12h14"/>',
 panel: '<rect x="3.5" y="4.5" width="17" height="15" rx="2"/><path d="M14.5 4.5v15"/>',
 db: '<ellipse cx="12" cy="6" rx="7" ry="2.5"/><path d="M5 6v12c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5V6M5 12c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5"/>',
 globe: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.5 2.6 2.5 14.4 0 17M12 3.5c-2.5 2.6-2.5 14.4 0 17"/>',
 layers: '<path d="m12 3 9 5-9 5-9-5z"/><path d="m3 13 9 5 9-5"/>',
 plug: '<path d="M9 3v5M15 3v5M6.5 8h11v3a5.5 5.5 0 0 1-11 0zM12 16.5V21"/>',
 send: '<path d="m4 12 16-8-6 16-2.5-6.5z"/>',
 pulse: '<path d="M3 12h4l2.5-6 4 12 2.5-6H21"/>',
 git: '<circle cx="6" cy="5" r="2"/><circle cx="6" cy="19" r="2"/><circle cx="18" cy="7" r="2"/><path d="M6 7v10M18 9a7 7 0 0 1-7 7H6"/>',
 commit: '<circle cx="12" cy="12" r="3.5"/><path d="M3 12h5.5M15.5 12H21"/>',
 note: '<path d="M4 5h16v11H9l-5 4z"/>',
 route: '<circle cx="6" cy="19" r="2.5"/><circle cx="18" cy="5" r="2.5"/><path d="M8.5 19H16a3.5 3.5 0 0 0 0-7H8a3.5 3.5 0 0 1 0-7h7.5"/>',
 doc: '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4M9 12h6M9 16h6"/>',
 dash: '<rect x="3.5" y="3.5" width="7" height="9" rx="1"/><rect x="13.5" y="3.5" width="7" height="5" rx="1"/><rect x="13.5" y="11.5" width="7" height="9" rx="1"/><rect x="3.5" y="15.5" width="7" height="5" rx="1"/>',
 move: '<path d="M4 8h16M16 4l4 4-4 4M20 16H4M8 12l-4 4 4 4"/>',
 sun: '<circle cx="12" cy="12" r="4"/><path d="M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6 7 7M17 17l1.4 1.4M5.6 18.4 7 17M17 7l1.4-1.4"/>',
 moon: '<path d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5z"/>',
 logout: '<path d="M9 4H5v16h4M16 8l4 4-4 4M20 12H9"/>',
 external: '<path d="M14 4h6v6M20 4l-9 9M18 14v6H4V6h6"/>',
 menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
 shield: '<path d="M12 3.5 5 6v5.5c0 4.2 2.9 7.3 7 9 4.1-1.7 7-4.8 7-9V6z"/>',
 key: '<circle cx="8" cy="15" r="3.5"/><path d="m10.5 12.5 8-8M15.5 7.5 18 10M13 10l2 2"/>',
 calendar: '<rect x="4" y="5.5" width="16" height="14.5" rx="2"/><path d="M4 10h16M8.5 3.5v4M15.5 3.5v4"/>',
 edit: '<path d="M4 20h4L19 9l-4-4L4 16z"/><path d="m13.5 6.5 4 4"/>',
 trash: '<path d="M4.5 7h15M9.5 7V4.5h5V7M6.5 7l1 13h9l1-13M10 11v6M14 11v6"/>',
 mail: '<rect x="3.5" y="5.5" width="17" height="13" rx="2"/><path d="m4 7 8 6 8-6"/>',
} as const;

export type IconName = keyof typeof PATHS;
export const ICON_NAMES = Object.keys(PATHS) as IconName[];
export type IconSize = 'm' | 's' | 'xs';
const SIZE_CLASS: Record<IconSize, string> = { m: 'icon', s: 'icon icon-s', xs: 'icon icon-xs' };

export function Icon(props: { name: IconName; size?: IconSize; className?: string }): React.JSX.Element {
 const cls = `${SIZE_CLASS[props.size ?? 'm']}${props.className ? ` ${props.className}` : ''}`;
 return <svg className={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false" dangerouslySetInnerHTML={{ __html: PATHS[props.name] }} />;
}
