// Session check, then hydrate the store from /api/v1/bootstrap. Sign-in is OIDC (IAM Identity Center, MFA) and,
// on self-hosted staging only, optional operator sign-in by email (admin-only network; refused in production).
import React, { useState } from 'react';
import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import Container from '@cloudscape-design/components/container';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Spinner from '@cloudscape-design/components/spinner';
import { ApiError, api, loginUrl, queryClient } from '@/api/client';
import { useAuthConfig, useBootstrap, useLiveEvents, useMe } from '@/api/hooks';
import { useAppStore } from '@/store';

function Screen({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20 }}>
      <div style={{ width: '100%', maxWidth: 460 }}>{children}</div>
    </div>
  );
}

function OperatorSignIn() {
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await api('/api/v1/auth/operator-login', { method: 'POST', json: { email: email.trim() } });
      await queryClient.invalidateQueries({ queryKey: ['me'] });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  };
  return (
    <form onSubmit={e => { e.preventDefault(); if (email.includes('@')) void submit(); }}>
      <SpaceBetween size="s">
        {error && <Alert type="error">{error}</Alert>}
        <FormField label="Your email" description="A user provisioned in Users & access. Sign-ins are recorded in the audit trail.">
          <Input value={email} onChange={e => setEmail(e.detail.value)} type="email" placeholder="admin@example.com" autoFocus />
        </FormField>
        <Button variant="primary" fullWidth loading={busy} disabled={!email.includes('@')} formAction="submit">Sign in</Button>
      </SpaceBetween>
    </form>
  );
}

function SignIn({ message }: { message: string | null }) {
  const config = useAuthConfig().data;
  const oidc = config?.oidc_enabled ?? true;
  return (
    <Screen>
      <Container header={<Header variant="h1" description="Centralized AWS WAF security across all member accounts">SAS WAF Security Platform</Header>}>
        <SpaceBetween size="l">
          {message && <Alert type="error">{message}</Alert>}
          {oidc && (
            <SpaceBetween size="xs">
              <Button variant={config?.operator_login ? 'normal' : 'primary'} href={loginUrl} fullWidth>Sign in with SSO</Button>
              <Box variant="small" color="text-body-secondary" textAlign="center">AWS IAM Identity Center. MFA is required.</Box>
            </SpaceBetween>
          )}
          {config?.operator_login && <OperatorSignIn />}
        </SpaceBetween>
      </Container>
    </Screen>
  );
}

function Loading({ text }: { text: string }) {
  return (
    <Screen>
      <Box textAlign="center" color="text-body-secondary"><Spinner size="large" /><Box margin={{ top: 's' }}>{text}</Box></Box>
    </Screen>
  );
}

export function AuthGate({ children }: { children: React.ReactNode }) {
  const me = useMe();
  const signedIn = me.isSuccess;
  const bootstrap = useBootstrap(signedIn);
  useLiveEvents(signedIn);
  const hydrated = useAppStore(s => s.hydrated);

  if (me.isLoading) return <Loading text="Checking your session" />;
  if (me.error) {
    const unauthenticated = me.error instanceof ApiError && me.error.status === 401;
    return <SignIn message={unauthenticated ? null : me.error.message} />;
  }
  if (bootstrap.error) {
    return <Screen><Alert type="error" header="Could not load platform data">{bootstrap.error.message}</Alert></Screen>;
  }
  if (!hydrated) return <Loading text="Loading live platform data" />;
  return <>{children}</>;
}
