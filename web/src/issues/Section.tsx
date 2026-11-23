// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';

/** One card of an entity page: a labelled section with its own h2 and a `data-section` hook for the e2e contract. */
export function Section(props: { id: string; section: string; title: React.ReactNode; actions?: React.ReactNode; children: React.ReactNode; bodyClass?: string }): React.JSX.Element {
 return (
  <section className="card" aria-labelledby={props.id} data-section={props.section}>
   <div className="card-head"><h2 id={props.id}>{props.title}</h2>{props.actions && <span className="ml-auto row">{props.actions}</span>}</div>
   <div className={props.bodyClass ? `card-body ${props.bodyClass}` : 'card-body'}>{props.children}</div>
  </section>
 );
}
