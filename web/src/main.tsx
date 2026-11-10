// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import {createRoot} from 'react-dom/client';
import {SessionBoundary} from './auth/SessionBoundary';
import {App} from './app/App';
import './style.css';
const root=document.getElementById('root');
if(!root)throw new Error('Application root missing');
createRoot(root).render(<React.StrictMode><a className="skip" href="#main">Skip to content</a><SessionBoundary><App/></SessionBoundary></React.StrictMode>);
