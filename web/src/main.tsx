// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import {createRoot} from 'react-dom/client';
import {SessionBoundary} from './auth/SessionBoundary';
import {App} from './app/App';
import {rewriteConsolePath} from './app/route';
import {initTheme} from './ui/theme';
import './styles/index.css';
const root=document.getElementById('root');
if(!root)throw new Error('Application root missing');
// The theme (dark by default, the saved choice, else the browser's preference) is applied before the first render so the page never flashes the other one.
initTheme();
// D33: a path-shaped console link (served the same public shell by the server) becomes its hash route before the first render, without a reload.
rewriteConsolePath(window.location,(url)=>history.replaceState(null,'',url));
// The address hash IS the router (scope, window, view), so the skip link must never navigate to "#main": it moves focus instead.
const skip=(event:React.MouseEvent<HTMLAnchorElement>):void=>{event.preventDefault();const main=document.getElementById('main');if(main){main.setAttribute('tabindex','-1');main.focus();}};
createRoot(root).render(<React.StrictMode><a className="skip" href="#main" onClick={skip}>Skip to content</a><SessionBoundary><App/></SessionBoundary></React.StrictMode>);
