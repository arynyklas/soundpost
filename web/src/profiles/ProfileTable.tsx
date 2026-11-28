// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';

/** A table in a labelled, focusable scroll region with a visible caption that says what its cells mean. */
export function ProfileTable(props: { label: string; caption: React.ReactNode; testId?: string; children: React.ReactNode }): React.JSX.Element {
 return (
  <div className="table-region" tabIndex={0} role="region" aria-label={props.label}>
   <table className="table tight profile-table" data-testid={props.testId}>
    <caption className="exp-caption">{props.caption}</caption>
    {props.children}
   </table>
  </div>
 );
}
