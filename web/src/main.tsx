// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import {createRoot} from 'react-dom/client';
import {SessionBoundary} from './auth/SessionBoundary';
import './style.css';
const root=document.getElementById('root');
if(!root)throw new Error('Application root missing');
createRoot(root).render(<React.StrictMode><a className="skip" href="#main">Skip to content</a><SessionBoundary><section className="panel"><h2>Investigation surfaces</h2><p>No telemetry view is connected on this access page. No queue, project count or health status is inferred from organization membership.</p></section></SessionBoundary></React.StrictMode>);
