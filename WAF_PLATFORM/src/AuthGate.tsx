// Session check, then hydrate the store from /api/v1/bootstrap. Sign-in is OIDC (IAM Identity Center, MFA).
import React from 'react';
import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Spinner from '@cloudscape-design/components/spinner';
import { ApiError, loginUrl } from '@/api/client';
import { useBootstrap, useLiveEvents, useMe } from '@/api/hooks';
import { useAppStore } from '@/store';

function Screen({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20 }}>
      <div style={{ width: '100%', maxWidth: 460 }}>{children}</div>
    </div>
  );
}

function SignIn({ message }: { message: string | null }) {
  return (
    <Screen>
      <Container header={<Header variant="h1" description="Centralized AWS WAF security across all member accounts">SAS WAF Security Platform</Header>}>
        <SpaceBetween size="l">
          {message && <Alert type="error">{message}</Alert>}
          <SpaceBetween size="xs">
            <Button variant="primary" href={loginUrl} fullWidth>Sign in with SSO</Button>
            <Box variant="small" color="text-body-secondary" textAlign="center">AWS IAM Identity Center. MFA is required.</Box>
          </SpaceBetween>
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
