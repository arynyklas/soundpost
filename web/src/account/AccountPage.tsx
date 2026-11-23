// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { ElevationControls, SessionContext } from '../auth/ElevationDialog';
import { RestorePanel } from '../auth/RestorePanel';
import { Content, PageHead } from '../shell/Frames';
import { Card } from '../ui/primitives';

/** Account access: who is signed in, the organizations the account administers, restore reauthorization, audited elevation and authenticator enrollment. */
export function AccountPage(): React.JSX.Element {
 const s = React.useContext(SessionContext);
 if (!s) return <PageHead title="Account access" noScope />;
 const { session } = s;
 return (
  <>
   <PageHead title="Account access" sub="Your account, elevation and authenticator" noScope />
   <Content>
    <Card title="Signed in" titleId="acct-id">
     <dl><dt>Account ID</dt><dd><code>{session.user}</code></dd><dt>Session expires</dt><dd>{new Date(Number(BigInt(session.expires) * 1000n)).toLocaleString()}</dd></dl>
    </Card>
    {s.error && <p role="alert" className="error">{s.error}</p>}
    <Card title="Organization access" titleId="acct-orgs">
     {s.orgState && <p>{s.orgState}</p>}
     {s.orgs.length > 0 && <ul>{s.orgs.map((org) => <li key={org.id}>{org.name} <code>{org.id}</code></li>)}</ul>}
     <p className="t2">Administrative visibility does not imply permission to read telemetry, replay, artifacts or profiles.</p>
    </Card>
    {session.restore && <RestorePanel csrf={session.csrf} pending={session.restore.pending} />}
    <ElevationControls />
    <Card title="Multi-factor authentication" titleId="acct-mfa">
     <p>Enrollment replaces the current authenticator only after a valid confirmation. Keep recovery codes offline.</p>
     <button type="button" disabled={s.busy} onClick={() => { void s.action('totp/start'); }}>Start authenticator enrollment</button>
     {s.secret && (
      <form onSubmit={(event) => { void s.action('totp/confirm', event); }}>
       <label>Enrollment secret<output className="secret">{s.secret}</output></label>
       <label>Authenticator code<input name="code" required autoComplete="one-time-code" /></label>
       <button disabled={s.busy}>Confirm authenticator</button>
      </form>
     )}
     {s.codes.length > 0 && (
      <div>
       <h3>Save these one-use recovery codes now</h3>
       <ul>{s.codes.map((code) => <li key={code}><code>{code}</code></li>)}</ul>
       <button type="button" onClick={s.clearCodes}>I saved these offline; hide codes</button>
      </div>
     )}
    </Card>
   </Content>
  </>
 );
}
