import { create } from 'zustand';
import type {
  Page, AWSAccount, Endpoint, WebACL, WafRule, Entity, Campaign,
  Detection, DriftEvent, Approval, SecurityPosture, PostureDimension,
  PlatformHealth, AttackPhase, ApprovalStatus,
} from '@/types';
import {
  ACCOUNTS, generateEndpoints, generateRules, generateEntities, WEBACLS,
  CAMPAIGNS as MOCK_CAMPAIGNS, DRIFT_EVENTS as MOCK_DRIFT, APPROVALS as MOCK_APPROVALS,
  DETECTIONS as MOCK_DETECTIONS, POSTURE_DIMENSIONS as MOCK_POSTURE,
  PLATFORM_HEALTH as MOCK_HEALTH, ATTACK_STORY_PHASES, THREAT_ACTIVITY, randInt,
} from '@/data/mockData';

export interface WorkspaceTab {
  id: string;
  title: string;
  type: 'entity' | 'campaign' | 'application' | 'webacl' | 'rule' | 'investigation';
  data: any;
  active: boolean;
}

export type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low';
export type ApprovalFilter = 'all' | ApprovalStatus;

interface AppState {
  // Navigation
  currentPage: Page;
  setPage: (page: Page) => void;

  // Sidebar collapsed
  sidebarCollapsed: boolean;
  toggleSidebar: () => void;

  // Search
  globalSearch: string;
  setGlobalSearch: (q: string) => void;

  // Selected entity for drawer/investigation
  selectedEntity: Entity | null;
  setSelectedEntity: (e: Entity | null) => void;

  // Drawer
  drawerOpen: boolean;
  drawerContent: 'entity' | 'campaign' | 'approval' | 'drift' | 'webacl' | 'rule';
  drawerData: any;
  openDrawer: (content: AppState['drawerContent'], data: any) => void;
  closeDrawer: () => void;

  // Workspace tabs (multi-panel)
  workspaceTabs: WorkspaceTab[];
  activeWorkspaceTab: string | null;
  openWorkspaceTab: (tab: Omit<WorkspaceTab, 'active'>) => void;
  closeWorkspaceTab: (id: string) => void;
  setActiveWorkspaceTab: (id: string) => void;

  // Context breadcrumb
  contextPath: { label: string; page?: Page; entityId?: string }[];
  pushContext: (item: { label: string; page?: Page; entityId?: string }) => void;
  popContext: () => void;
  resetContext: () => void;

  // Filters
  severityFilter: SeverityFilter;
  setSeverityFilter: (f: SeverityFilter) => void;

  // Data (mock)
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
  threatActivity: typeof THREAT_ACTIVITY;
  attackStoryPhases: typeof ATTACK_STORY_PHASES;

  // Real-time simulation
  dataLastUpdated: number;
  tick: () => void;
}

const allRules = new Map<string, WafRule[]>();
const allEndpoints: Endpoint[] = [];
ACCOUNTS.forEach(acc => {
  const eps = generateEndpoints(acc.id, acc.name, acc.region);
  allEndpoints.push(...eps);
  WEBACLS.filter(w => w.account_id === acc.id).forEach(wacl => {
    allRules.set(wacl.id, generateRules(wacl.id));
  });
});
const entities = generateEntities(60);

export const useAppStore = create<AppState>((set) => ({
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
      return { workspaceTabs: s.workspaceTabs.map(t => t.id === tab.id ? { ...t, active: true } : { ...t, active: false }), activeWorkspaceTab: tab.id };
    }
    return {
      workspaceTabs: [...s.workspaceTabs.map(t => ({ ...t, active: false })), { ...tab, active: true }],
      activeWorkspaceTab: tab.id,
    };
  }),
  closeWorkspaceTab: (id) => set(s => {
    const filtered = s.workspaceTabs.filter(t => t.id !== id);
    const newActive = s.activeWorkspaceTab === id ? (filtered[filtered.length - 1]?.id || null) : s.activeWorkspaceTab;
    return {
      workspaceTabs: filtered.map(t => ({ ...t, active: t.id === newActive })),
      activeWorkspaceTab: newActive,
    };
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

  accounts: ACCOUNTS.map(a => ({
    ...a,
    status: a.env === 'prod' ? 'healthy' : a.env === 'uat' ? 'healthy' : a.env === 'dev' ? 'healthy' : 'healthy',
    last_discovered: new Date(Date.now() - randInt(1, 6) * 3600000).toISOString(),
    waf_coverage: randInt(55, 95),
    security_score: randInt(50, 92),
    endpoint_count: allEndpoints.filter(e => e.account_id === a.id).length,
    webacl_count: WEBACLS.filter(w => w.account_id === a.id).length,
    logging_visibility: ['full', 'sampled', 'metrics', 'none'][randInt(0, 3)] as any,
  })),
  endpoints: allEndpoints,
  webacls: WEBACLS,
  rules: allRules,
  entities,
  campaigns: MOCK_CAMPAIGNS,
  detections: MOCK_DETECTIONS,
  driftEvents: MOCK_DRIFT,
  approvals: MOCK_APPROVALS,
  postureDimensions: MOCK_POSTURE,
  platformHealth: MOCK_HEALTH,
  threatActivity: THREAT_ACTIVITY,
  attackStoryPhases: ATTACK_STORY_PHASES,

  dataLastUpdated: Date.now(),
  tick: () => set(s => ({ dataLastUpdated: Date.now() })),
}));
