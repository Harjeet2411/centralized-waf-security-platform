// React Query hooks over the FastAPI contract. Server state lives here; src/store.ts keeps UI state plus the
// hydrated bootstrap snapshot the existing views read.
import { useEffect } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { api, connectEvents, queryClient } from '@/api/client';
import { useAppStore } from '@/store';
import type { Bootstrap, CampaignDetailView, EntityDetailView, Principal, SimulationResult } from '@/types';

export function useMe() {
  return useQuery({ queryKey: ['me'], queryFn: () => api<Principal>('/api/v1/me') });
}

/** Plain GET for on-demand views (changes, allow-list, audit, users...). */
export function useGet<T>(path: string | null, key: unknown[] = [path]) {
  return useQuery({ queryKey: key, queryFn: () => api<T>(path!), enabled: Boolean(path) });
}

export interface AuthConfig {
  oidc_enabled: boolean;
  operator_login: boolean; // self-hosted staging only; the backend refuses it in production
}

export function useAuthConfig() {
  return useQuery({ queryKey: ['auth-config'], queryFn: () => api<AuthConfig>('/api/v1/auth/config'), staleTime: Infinity });
}

export function useBootstrap(enabled: boolean) {
  const hydrate = useAppStore(s => s.hydrate);
  const query = useQuery({ queryKey: ['bootstrap'], queryFn: () => api<Bootstrap>('/api/v1/bootstrap'), enabled });
  useEffect(() => {
    if (query.data) hydrate(query.data);
  }, [query.data, hydrate]);
  return query;
}

export function useEntityDetail(entityId: string | null | undefined) {
  return useQuery({
    queryKey: ['entity', entityId],
    queryFn: () => api<EntityDetailView>(`/api/v1/entities/${entityId}`),
    enabled: Boolean(entityId),
  });
}

export function useCampaignDetail(campaignId: string | null | undefined) {
  return useQuery({
    queryKey: ['campaign', campaignId],
    queryFn: () => api<CampaignDetailView>(`/api/v1/campaigns/${campaignId}`),
    enabled: Boolean(campaignId),
  });
}

export interface SimulationRequest {
  title: string;
  proposal: {
    type: 'BLOCK_IPS' | 'BLOCK_JA4' | 'RULE_ACTION' | 'RATE_LIMIT';
    targets?: string[];
    ja4?: string;
    webacl_id?: string;
    rule_name?: string;
    new_action?: 'BLOCK' | 'COUNT';
    limit?: number;
  };
  window_hours?: number;
}

export function useSimulation() {
  return useMutation({
    mutationFn: (body: SimulationRequest) => api<SimulationResult>('/api/v1/simulations', { method: 'POST', json: body }),
  });
}

/** Live updates: refetch the snapshot when a sync finishes or an approval changes; track sync progress. */
export function useLiveEvents(enabled: boolean) {
  const setSyncStatus = useAppStore(s => s.setSyncStatus);
  useEffect(() => {
    if (!enabled) return;
    return connectEvents(event => {
      if (event.type === 'SYNC_STARTED') setSyncStatus({ status: 'syncing', ...event.payload });
      if (event.type === 'SYNC_COMPLETED') {
        setSyncStatus({ status: String(event.payload.status ?? 'SUCCEEDED') });
        queryClient.invalidateQueries();
      }
      if (event.type === 'APPROVAL_REQUESTED' || event.type === 'APPROVAL_UPDATED') {
        queryClient.invalidateQueries({ queryKey: ['bootstrap'] });
      }
    });
  }, [enabled, setSyncStatus]);
}
