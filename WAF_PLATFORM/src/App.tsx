// AWS-console shell: top navigation (search, refresh, notifications, user), side navigation, breadcrumbs,
// flash notifications and an optional split panel. Pages are lazy-loaded per module.
import React, { Suspense, lazy, useEffect, useMemo, useState } from 'react';
import { Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import AppLayout from '@cloudscape-design/components/app-layout';
import Autosuggest from '@cloudscape-design/components/autosuggest';
import BreadcrumbGroup from '@cloudscape-design/components/breadcrumb-group';
import Flashbar from '@cloudscape-design/components/flashbar';
import SideNavigation, { type SideNavigationProps } from '@cloudscape-design/components/side-navigation';
import Spinner from '@cloudscape-design/components/spinner';
import SplitPanel from '@cloudscape-design/components/split-panel';
import TopNavigation from '@cloudscape-design/components/top-navigation';
import Badge from '@cloudscape-design/components/badge';
import { api, queryClient } from '@/api/client';
import { useAuthConfig, useMe } from '@/api/hooks';
import { useAppStore } from '@/store';
import { ago, notify, useFlash, useSplit } from '@/ui';

const named = <K extends string>(load: () => Promise<Record<K, React.ComponentType>>, key: K) =>
  lazy(() => load().then(m => ({ default: m[key] })));
const threats = () => import('@/pages/Threats');
const inventory = () => import('@/pages/Inventory');
const response = () => import('@/pages/Response');
const governance = () => import('@/pages/Governance');

const Dashboard = named(() => import('@/pages/Dashboard'), 'Dashboard');
const Detections = named(threats, 'DetectionsPage');
const Campaigns = named(threats, 'CampaignsPage');
const CampaignDetail = named(threats, 'CampaignDetailPage');
const Entities = named(threats, 'EntitiesPage');
const EntityDetail = named(threats, 'EntityDetailPage');
const Accounts = named(inventory, 'AccountsPage');
const WebAcls = named(inventory, 'WebAclsPage');
const WebAclDetail = named(inventory, 'WebAclDetailPage');
const Endpoints = named(inventory, 'EndpointsPage');
const Drift = named(inventory, 'DriftPage');
const Simulate = named(response, 'SimulatePage');
const Approvals = named(response, 'ApprovalsPage');
const ApprovalDetail = named(response, 'ApprovalDetailPage');
const Changes = named(response, 'ChangesPage');
const AllowList = named(response, 'AllowListPage');
const Audit = named(governance, 'AuditPage');
const Users = named(governance, 'UsersPage');
const Health = named(governance, 'HealthPage');

const CRUMBS: Record<string, string> = {
  detections: 'Detections', campaigns: 'Campaigns', entities: 'Entities', inventory: 'WAF inventory',
  accounts: 'Accounts', webacls: 'Web ACLs', endpoints: 'Endpoints', drift: 'Configuration drift',
  response: 'Controlled response', simulate: 'Simulate a change', approvals: 'Approvals',
  changes: 'Changes & active blocks', 'allow-list': 'Allow list', governance: 'Governance', audit: 'Audit trail',
  users: 'Users & access', health: 'Platform health',
};
const SECTIONS = new Set(['inventory', 'response', 'governance']); // no page of their own: link to the child

function useBreadcrumbs() {
  const { pathname } = useLocation();
  const parts = pathname.split('/').filter(Boolean);
  return [{ text: 'WAF Security', href: '/' }, ...parts.map((part, i) => ({
    text: CRUMBS[part] ?? 'Details',
    href: `/${parts.slice(0, SECTIONS.has(part) ? i + 2 : i + 1).join('/')}`,
  }))];
}

function Navigation() {
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const pending = useAppStore(s => s.approvals.filter(a => a.status === 'pending').length);
  const openDetections = useAppStore(s => s.detections.filter(d => d.status !== 'actioned' && d.status !== 'false_positive').length);
  const drift = useAppStore(s => s.driftEvents.filter(d => d.status === 'open').length);
  const count = (n: number) => (n ? <Badge color="red">{n}</Badge> : undefined);
  const items: SideNavigationProps.Item[] = [
    { type: 'link', text: 'Security overview', href: '/' },
    { type: 'section', text: 'Threat detection', items: [
      { type: 'link', text: 'Detections', href: '/detections', info: count(openDetections) },
      { type: 'link', text: 'Campaigns', href: '/campaigns' },
      { type: 'link', text: 'Entities', href: '/entities' },
    ] },
    { type: 'section', text: 'WAF inventory', items: [
      { type: 'link', text: 'Accounts', href: '/inventory/accounts' },
      { type: 'link', text: 'Web ACLs', href: '/inventory/webacls' },
      { type: 'link', text: 'Endpoints', href: '/inventory/endpoints' },
      { type: 'link', text: 'Configuration drift', href: '/inventory/drift', info: count(drift) },
    ] },
    { type: 'section', text: 'Controlled response', items: [
      { type: 'link', text: 'Simulate a change', href: '/response/simulate' },
      { type: 'link', text: 'Approvals', href: '/response/approvals', info: count(pending) },
      { type: 'link', text: 'Changes & active blocks', href: '/response/changes' },
      { type: 'link', text: 'Allow list', href: '/response/allow-list' },
    ] },
    { type: 'section', text: 'Governance', items: [
      { type: 'link', text: 'Audit trail', href: '/governance/audit' },
      { type: 'link', text: 'Users & access', href: '/governance/users' },
      { type: 'link', text: 'Platform health', href: '/governance/health' },
    ] },
  ];
  const hrefs = items.flatMap(i => (i.type === 'section' ? i.items : [i])).map(i => (i as { href: string }).href);
  const active = hrefs.filter(h => h === pathname || (h !== '/' && pathname.startsWith(h)))
    .sort((a, b) => b.length - a.length)[0] ?? '/';
  return (
    <SideNavigation
      header={{ text: 'WAF Security Platform', href: '/' }}
      activeHref={active}
      items={items}
      onFollow={e => { e.preventDefault(); navigate(e.detail.href); }}
    />
  );
}

function GlobalSearch() {
  const navigate = useNavigate();
  const [value, setValue] = useState('');
  const { entities, accounts, webacls, campaigns } = useAppStore();
  const options = useMemo(() => [
    { label: 'Entities', options: entities.map(e => ({
      value: `/entities/${e.id}`, label: e.value, description: `${e.type.toUpperCase()} - ${e.risk_level} risk`,
      tags: [e.country ?? '', e.asn ?? ''].filter(Boolean),
    })) },
    { label: 'Campaigns', options: campaigns.map(c => ({ value: `/campaigns/${c.id}`, label: c.campaign_code, description: c.name })) },
    { label: 'Web ACLs', options: webacls.map(w => ({ value: `/inventory/webacls/${w.id}`, label: w.name, description: `${w.account_name} - ${w.region}` })) },
    { label: 'Accounts', options: accounts.map(a => ({ value: `/inventory/accounts#${a.account_id}`, label: a.name, description: a.account_id })) },
  ], [entities, accounts, webacls, campaigns]);
  return (
    <Autosuggest
      value={value}
      onChange={e => setValue(e.detail.value)}
      onSelect={e => { if (e.detail.value.startsWith('/')) { navigate(e.detail.value); setValue(''); } }}
      options={options}
      filteringType="auto"
      enteredTextLabel={v => `Search: ${v}`}
      placeholder="Search IPs, JA4, campaigns, Web ACLs, accounts"
      ariaLabel="Search"
      empty="No matches"
    />
  );
}

const LOGO = `data:image/svg+xml;utf8,${encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path fill="#ff9900" d="M12 2 3 6v6c0 5 3.8 9.7 9 10 5.2-.3 9-5 9-10V6l-9-4Z"/><path fill="#232f3e" d="m10.5 15.5-3-3 1.4-1.4 1.6 1.6 4.6-4.6 1.4 1.4-6 6Z"/></svg>',
)}`;

function TopBar() {
  const navigate = useNavigate();
  const me = useMe().data;
  const auth = useAuthConfig().data;
  const { triggerRefresh, syncStatus, dataLastUpdated } = useAppStore();
  const pending = useAppStore(s => s.approvals.filter(a => a.status === 'pending').length);
  const [refreshing, setRefreshing] = useState(false);
  const demo = auth && (auth.environment === 'local' || auth.environment === 'test');

  const refresh = async () => {
    if (refreshing) return;
    setRefreshing(true);
    const status = await triggerRefresh();
    setRefreshing(false);
    if (!status) return;
    if (status.status === 'ready') notify('success', `Data is current (last sync ${ago(status.last_sync)}). No AWS calls were needed.`);
    else notify('info', 'Sync started across member accounts. The console refreshes when it completes.', 'Refreshing WAF data');
  };
  const signOut = async () => {
    await api('/api/v1/auth/logout', { method: 'POST' }).catch(() => null);
    queryClient.clear();
    window.location.assign('/');
  };
  const freshness = refreshing || syncStatus?.status === 'syncing' ? 'Syncing...'
    : dataLastUpdated ? `Data ${ago(new Date(dataLastUpdated).toISOString())}` : 'Refresh data';

  return (
    <TopNavigation
      identity={{
        href: '/', title: 'SAS WAF Security Platform', logo: { src: LOGO, alt: 'SAS' },
        onFollow: e => { e.preventDefault(); navigate('/'); },
      }}
      search={<GlobalSearch />}
      utilities={[
        ...(demo ? [{ type: 'button' as const, text: 'Local demo', iconName: 'status-warning' as const,
                      title: 'Synthetic demo data, not connected to AWS' }] : []),
        { type: 'button', text: freshness, iconName: 'refresh', ariaLabel: 'Refresh WAF data', onClick: refresh },
        { type: 'button', iconName: 'notification', title: 'Pending approvals', ariaLabel: `Pending approvals (${pending})`,
          badge: pending > 0, onClick: () => navigate('/response/approvals') },
        {
          type: 'menu-dropdown', text: me?.full_name ?? 'Account', description: `${me?.email ?? ''} (${me?.role ?? ''})`,
          iconName: 'user-profile',
          items: [
            { id: 'role', text: `Role: ${me?.role ?? '-'}`, disabled: true },
            { id: 'mfa', text: me?.mfa ? 'MFA session: yes' : 'MFA session: no', disabled: true },
            { id: 'audit', text: 'Audit trail' },
            { id: 'signout', text: 'Sign out' },
          ],
          onItemClick: e => {
            if (e.detail.id === 'signout') void signOut();
            if (e.detail.id === 'audit') navigate('/governance/audit');
          },
        },
      ]}
    />
  );
}

export default function App() {
  const flash = useFlash(s => s.items);
  const { lastError, clearError } = useAppStore();
  const panel = useSplit(s => s.panel);
  const closeSplit = useSplit(s => s.close);
  const [navOpen, setNavOpen] = useState(true);
  const breadcrumbs = useBreadcrumbs();
  const navigate = useNavigate();
  const { pathname } = useLocation();

  useEffect(() => {
    if (lastError) { notify('error', lastError, 'Request failed'); clearError(); }
  }, [lastError, clearError]);
  useEffect(() => { closeSplit(); }, [pathname, closeSplit]);

  return (
    <>
      <div id="top-nav" style={{ position: 'sticky', top: 0, zIndex: 1002 }}><TopBar /></div>
      <AppLayout
        headerSelector="#top-nav"
        navigation={<Navigation />}
        navigationOpen={navOpen}
        onNavigationChange={e => setNavOpen(e.detail.open)}
        breadcrumbs={<BreadcrumbGroup items={breadcrumbs} onFollow={e => { e.preventDefault(); navigate(e.detail.href); }} />}
        notifications={<Flashbar items={flash} />}
        toolsHide
        splitPanel={panel ? <SplitPanel header={panel.header} hidePreferencesButton closeBehavior="hide">{panel.content}</SplitPanel> : undefined}
        splitPanelOpen={Boolean(panel)}
        onSplitPanelToggle={e => { if (!e.detail.open) closeSplit(); }}
        content={
          <Suspense fallback={<div style={{ padding: 40, textAlign: 'center' }}><Spinner size="large" /></div>}>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/detections" element={<Detections />} />
              <Route path="/campaigns" element={<Campaigns />} />
              <Route path="/campaigns/:id" element={<CampaignDetail />} />
              <Route path="/entities" element={<Entities />} />
              <Route path="/entities/:id" element={<EntityDetail />} />
              <Route path="/inventory/accounts" element={<Accounts />} />
              <Route path="/inventory/webacls" element={<WebAcls />} />
              <Route path="/inventory/webacls/:id" element={<WebAclDetail />} />
              <Route path="/inventory/endpoints" element={<Endpoints />} />
              <Route path="/inventory/drift" element={<Drift />} />
              <Route path="/response/simulate" element={<Simulate />} />
              <Route path="/response/approvals" element={<Approvals />} />
              <Route path="/response/approvals/:id" element={<ApprovalDetail />} />
              <Route path="/response/changes" element={<Changes />} />
              <Route path="/response/allow-list" element={<AllowList />} />
              <Route path="/governance/audit" element={<Audit />} />
              <Route path="/governance/users" element={<Users />} />
              <Route path="/governance/health" element={<Health />} />
              <Route path="*" element={<Dashboard />} />
            </Routes>
          </Suspense>
        }
      />
    </>
  );
}
