import { create } from 'zustand';
import { api, queryClient } from '@/api/client';
import type {
  Page, AWSAccount, Endpoint, WebACL, WafRule, Entity, Campaign, Detection, DriftEvent, Approval,
  PostureDimension, PlatformHealth, ApprovalStatus, Bootstrap, ThreatActivity, SyncStatus,
} from '@/types';

export interface WorkspaceTab {
  id: string;
  title: string;
  type: 'entity' | 'campaign' | 'application' | 'webacl' | 'rule' | 'investigation';
  data: any;
  active: boolean;
}

export type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low';
export type ApprovalFilter = 'all' | ApprovalStatus;

export interface ApprovalRequestBody {
  action_type: 'TEMP_BLOCK_IP' | 'PERM_BLOCK_IP' | 'REMOVE_BLOCK' | 'MODIFY_RULE' | 'ADD_EXCEPTION'
    | 'MODIFY_RATE_LIMIT' | 'ATTACH_WAF' | 'REMEDIATE_DRIFT';
  account_id: string;
  reason: string;
  target?: string;
  targets?: string[];
  ttl_hours?: number;
  simulation_id?: string;
  webacl_id?: string;
  rule_name?: string;
  action?: 'BLOCK' | 'COUNT' | 'ALLOW' | 'CAPTCHA' | 'CHALLENGE';
  limit?: number;
  excluded_rule?: string;
  resource_arn?: string;
  drift_id?: string;
}

const EMPTY_HEALTH: PlatformHealth = {
  overall: 'critical', collectors: [], last_sync: '', data_freshness: 'no sync yet',
  aws_api: { status: 'unavailable', detail: 'Not loaded', last_check: '' },
  queue: { status: 'unavailable', detail: 'Not loaded', last_check: '' },
  workers: { status: 'unavailable', detail: 'Not loaded', last_check: '' },
  database: { status: 'unavailable', detail: 'Not loaded', last_check: '' },
  threat_intel: { status: 'unavailable', detail: 'Not loaded', last_check: '' },
};

interface AppState {
  // Navigation
  currentPage: Page;
  setPage: (page: Page) => void;
  sidebarCollapsed: boolean;
  toggleSidebar: () => void;
  globalSearch: string;
  setGlobalSearch: (q: string) => void;

  // Drawer + workspace tabs + breadcrumb
  selectedEntity: Entity | null;
  setSelectedEntity: (e: Entity | null) => void;
  drawerOpen: boolean;
  drawerContent: 'entity' | 'campaign' | 'approval' | 'drift' | 'webacl' | 'rule';
  drawerData: any;
  openDrawer: (content: AppState['drawerContent'], data: any) => void;
  closeDrawer: () => void;
  workspaceTabs: WorkspaceTab[];
  activeWorkspaceTab: string | null;
  openWorkspaceTab: (tab: Omit<WorkspaceTab, 'active'>) => void;
  closeWorkspaceTab: (id: string) => void;
  setActiveWorkspaceTab: (id: string) => void;
  contextPath: { label: string; page?: Page; entityId?: string }[];
  pushContext: (item: { label: string; page?: Page; entityId?: string }) => void;
  popContext: () => void;
  resetContext: () => void;
  severityFilter: SeverityFilter;
  setSeverityFilter: (f: SeverityFilter) => void;

  // Live platform data (GET /api/v1/bootstrap) — never mock data (CLAUDE.md constraint #4)
  hydrated: boolean;
  hydrate: (b: Bootstrap) => void;
  accounts: AWSAccount[];
  endpoints: Endpoint[];
  webacls: WebACL[];
  rules: Map<string, WafRule[]>;
  entities: Entity[];
  campaigns: Campaign[];
  detections: Detection[];
  driftEvents: DriftEvent[];
  approvals: Approval[];
  postureDimensions: PostureDimension[];
  platformHealth: PlatformHealth;
  threatActivity: ThreatActivity[];
  dataLastUpdated: number;

  // Sync + controlled response (all AWS changes go through the backend approval lifecycle)
  syncStatus: SyncStatus | null;
  setSyncStatus: (s: SyncStatus | null) => void;
  lastError: string | null;
  clearError: () => void;
  triggerRefresh: (force?: boolean) => Promise<SyncStatus | null>;
  approveRequest: (approvalId: string, comment?: string) => Promise<boolean>;
  rejectRequest: (approvalId: string, comment?: string) => Promise<boolean>;
  rollbackChange: (changeId: string, reason?: string) => Promise<boolean>;
  createApprovalRequest: (body: ApprovalRequestBody) => Promise<string | null>;
}

const refetchSnapshot = () => queryClient.invalidateQueries({ queryKey: ['bootstrap'] });

export const useAppStore = create<AppState>((set, get) => {
  /** Run an API call; surface failures (e.g. "DENIED: Protected Entity") in lastError instead of throwing. */
  async function act<T>(call: () => Promise<T>): Promise<T | null> {
    try {
      const result = await call();
      set({ lastError: null });
      return result;
    } catch (error) {
      set({ lastError: error instanceof Error ? error.message : String(error) });
      return null;
    } finally {
      // Failures change server state too (e.g. APPROVED with verification FAILED, GUARDRAIL_DENIED): always refetch.
      await refetchSnapshot();
    }
  }

  return {
    currentPage: 'command-center',
    setPage: (page) => set({ currentPage: page }),
    sidebarCollapsed: false,
    toggleSidebar: () => set(s => ({ sidebarCollapsed: !s.sidebarCollapsed })),
    globalSearch: '',
    setGlobalSearch: (q) => set({ globalSearch: q }),

    selectedEntity: null,
    setSelectedEntity: (e) => set({ selectedEntity: e }),
    drawerOpen: false,
    drawerContent: 'entity',
    drawerData: null,
    openDrawer: (content, data) => set({ drawerOpen: true, drawerContent: content, drawerData: data }),
    closeDrawer: () => set({ drawerOpen: false }),
    workspaceTabs: [],
    activeWorkspaceTab: null,
    openWorkspaceTab: (tab) => set(s => {
      const exists = s.workspaceTabs.find(t => t.id === tab.id);
      if (exists) {
        return { workspaceTabs: s.workspaceTabs.map(t => ({ ...t, active: t.id === tab.id })), activeWorkspaceTab: tab.id };
      }
      return {
        workspaceTabs: [...s.workspaceTabs.map(t => ({ ...t, active: false })), { ...tab, active: true }],
        activeWorkspaceTab: tab.id,
      };
    }),
    closeWorkspaceTab: (id) => set(s => {
      const filtered = s.workspaceTabs.filter(t => t.id !== id);
      const newActive = s.activeWorkspaceTab === id ? (filtered[filtered.length - 1]?.id || null) : s.activeWorkspaceTab;
      return { workspaceTabs: filtered.map(t => ({ ...t, active: t.id === newActive })), activeWorkspaceTab: newActive };
    }),
    setActiveWorkspaceTab: (id) => set(s => ({
      workspaceTabs: s.workspaceTabs.map(t => ({ ...t, active: t.id === id })),
      activeWorkspaceTab: id,
    })),
    contextPath: [{ label: 'GLOBAL' }],
    pushContext: (item) => set(s => ({ contextPath: [...s.contextPath, item] })),
    popContext: () => set(s => ({ contextPath: s.contextPath.slice(0, -1) })),
    resetContext: () => set({ contextPath: [{ label: 'GLOBAL' }] }),
    severityFilter: 'all',
    setSeverityFilter: (f) => set({ severityFilter: f }),

    hydrated: false,
    hydrate: (b) => set({
      hydrated: true,
      accounts: b.accounts,
      endpoints: b.endpoints,
      webacls: b.webacls,
      rules: new Map(Object.entries(b.rules)),
      entities: b.entities,
      campaigns: b.campaigns,
      detections: b.detections,
      driftEvents: b.drift_events,
      approvals: b.approvals,
      postureDimensions: b.posture_dimensions,
      platformHealth: b.platform_health,
      threatActivity: b.threat_activity,
      dataLastUpdated: Date.parse(b.platform_health.last_sync || b.generated_at),
    }),
    accounts: [],
    endpoints: [],
    webacls: [],
    rules: new Map(),
    entities: [],
    campaigns: [],
    detections: [],
    driftEvents: [],
    approvals: [],
    postureDimensions: [],
    platformHealth: EMPTY_HEALTH,
    threatActivity: [],
    dataLastUpdated: 0,

    syncStatus: null,
    setSyncStatus: (s) => set({ syncStatus: s }),
    lastError: null,
    clearError: () => set({ lastError: null }),
    triggerRefresh: async (force = false) => {
      const status = await act(() => api<SyncStatus>(`/api/v1/refresh${force ? '?force=true' : ''}`, { method: 'POST' }));
      if (status) get().setSyncStatus(status);
      return status;
    },
    approveRequest: async (approvalId, comment) => (await act(() => api(`/api/v1/approvals/${approvalId}/decide`, {
      method: 'POST', json: { decision: 'APPROVE', comment },
    }))) !== null,
    rejectRequest: async (approvalId, comment) => (await act(() => api(`/api/v1/approvals/${approvalId}/decide`, {
      method: 'POST', json: { decision: 'REJECT', comment },
    }))) !== null,
    rollbackChange: async (changeId, reason = 'Manual rollback') => (await act(() => api(
      `/api/v1/changes/${changeId}/rollback`, { method: 'POST', json: { reason } },
    ))) !== null,
    createApprovalRequest: async (body) => {
      const created = await act(() => api<{ approval: Approval }>('/api/v1/approvals', { method: 'POST', json: body }));
      return created?.approval.id ?? null;
    },
  };
});
