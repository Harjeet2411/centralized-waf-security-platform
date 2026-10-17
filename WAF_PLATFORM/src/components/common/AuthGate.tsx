import React from 'react';
import { ShieldAlert, LogIn, Loader2 } from 'lucide-react';
import { ApiError, loginUrl } from '@/api/client';
import { useBootstrap, useLiveEvents, useMe } from '@/api/hooks';
import { useAppStore } from '@/store';

function Screen({ children }: { children: React.ReactNode }) {
  return (
    <div className="h-screen flex items-center justify-center grid-bg">
      <div className="glass rounded-xl p-8 max-w-md w-full text-center space-y-4">{children}</div>
    </div>
  );
}

/** Session check (IAM Identity Center via OIDC), then hydrate the store from /api/v1/bootstrap. */
export function AuthGate({ children }: { children: React.ReactNode }) {
  const me = useMe();
  const signedIn = me.isSuccess;
  const bootstrap = useBootstrap(signedIn);
  useLiveEvents(signedIn);
  const hydrated = useAppStore(s => s.hydrated);

  if (me.isLoading) {
    return <Screen><Loader2 className="mx-auto animate-spin text-cyan-400" size={20} /></Screen>;
  }
  if (me.error) {
    const unauthenticated = me.error instanceof ApiError && me.error.status === 401;
    return (
      <Screen>
        <ShieldAlert className="mx-auto text-cyan-400" size={24} />
        <div className="text-[14px] font-semibold text-white/85">SAS WAF Security Platform</div>
        <div className="text-[11px] text-white/40">
          {unauthenticated ? 'Sign in with your organisation account (MFA required).' : me.error.message}
        </div>
        <a href={loginUrl} className="btn btn-primary btn-sm inline-flex items-center gap-2">
          <LogIn size={12} /> Sign in
        </a>
      </Screen>
    );
  }
  if (bootstrap.error) {
    return <Screen><div className="text-[12px] text-rose-400">Could not load platform data: {bootstrap.error.message}</div></Screen>;
  }
  if (!hydrated) {
    return <Screen><div className="text-[11px] text-white/40 flex items-center justify-center gap-2"><Loader2 className="animate-spin" size={14} /> Loading live platform data…</div></Screen>;
  }
  return <>{children}</>;
}
