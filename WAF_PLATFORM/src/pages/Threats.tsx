// Threat detection module: detections (split-panel triage), correlated campaigns, entities (IP / JA4 / ASN ...).
import React, { useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import Alert from '@cloudscape-design/components/alert';
import BarChart from '@cloudscape-design/components/bar-chart';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Container from '@cloudscape-design/components/container';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import KeyValuePairs from '@cloudscape-design/components/key-value-pairs';
import SegmentedControl from '@cloudscape-design/components/segmented-control';
import Select from '@cloudscape-design/components/select';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Spinner from '@cloudscape-design/components/spinner';
import Table from '@cloudscape-design/components/table';
import Tabs from '@cloudscape-design/components/tabs';
import { useCampaignDetail, useEntityDetail } from '@/api/hooks';
import { useAppStore } from '@/store';
import type { Detection, Entity } from '@/types';
import { Counter, ResourceTable, RouterLink, Status, ago, dash, dateTime, humanize, num, severityRank, useSplit } from '@/ui';

const SEVERITIES = ['all', 'critical', 'high', 'medium', 'low'];
const opt = (v: string) => ({ value: v, label: v === 'all' ? 'All severities' : humanize(v) });

// Simulator deep links: the simulation page reads these query parameters to prefill its form.
const simulateBlockHref = (targets: string[]) => `/response/simulate?type=BLOCK_IPS&targets=${encodeURIComponent(targets.join(','))}`;
const simulateJa4Href = (ja4: string) => `/response/simulate?type=BLOCK_JA4&ja4=${encodeURIComponent(ja4)}`;

export function Loading() {
  return <Box textAlign="center" padding="xxl"><Spinner size="large" /></Box>;
}

// --- detections -----------------------------------------------------------------------------------------------

function DetectionDetail({ d }: { d: Detection }) {
  const entities = useAppStore(s => s.entities).filter(e => d.entity_ids.includes(e.id)); // select, then filter: a filtering selector loops
  return (
    <ColumnLayout columns={2} variant="text-grid">
      <SpaceBetween size="s">
        <Box>{d.description}</Box>
        <KeyValuePairs columns={2} items={[
          { label: 'Severity', value: <Status value={d.severity} /> },
          { label: 'Status', value: <Status value={d.status} /> },
          { label: 'Confidence', value: `${d.confidence}%` },
          { label: 'Detected', value: dateTime(d.timestamp) },
          { label: 'Accounts', value: d.affected_accounts.join(', ') || '-' },
          { label: 'Campaign', value: d.campaign_id ? <RouterLink to={`/campaigns/${d.campaign_id}`}>Open campaign</RouterLink> : '-' },
        ]} />
        <Alert type="info" header="Recommended action">{d.recommended_action}</Alert>
      </SpaceBetween>
      <SpaceBetween size="s">
        <Box variant="h4">Evidence</Box>
        <KeyValuePairs columns={1} items={d.evidence.map(e => ({
          label: e.label,
          value: <>{e.value}{e.detail ? <Box variant="small" display="block" color="text-body-secondary">{e.detail}</Box> : null}</>,
        }))} />
        <Box variant="h4">Entities</Box>
        <SpaceBetween size="xxs">
          {entities.map(e => <RouterLink key={e.id} to={`/entities/${e.id}`}>{`${e.type.toUpperCase()} ${e.value}`}</RouterLink>)}
          {entities.length === 0 && <Box color="text-body-secondary">No entity records</Box>}
        </SpaceBetween>
      </SpaceBetween>
    </ColumnLayout>
  );
}

export function DetectionsPage() {
  const detections = useAppStore(s => s.detections);
  const openSplit = useSplit(s => s.open);
  const [severity, setSeverity] = useState('all');
  const [selected, setSelected] = useState<Detection[]>([]);
  const items = detections.filter(d => severity === 'all' || d.severity === severity);
  return (
    <ResourceTable<Detection>
      title="Detections"
      description="Attack patterns found by the detection engines. Select a detection to see its evidence."
      items={items}
      selectionType="single"
      selected={selected}
      onSelect={sel => { setSelected(sel); if (sel[0]) openSplit(sel[0].title, <DetectionDetail d={sel[0]} />); }}
      defaultSort="severity"
      filters={
        <div style={{ width: 200 }}>
          <Select selectedOption={opt(severity)} options={SEVERITIES.map(opt)} onChange={e => setSeverity(e.detail.selectedOption.value!)} />
        </div>
      }
      columns={[
        { id: 'title', header: 'Detection', cell: d => d.title, sort: d => d.title, width: 380 },
        { id: 'severity', header: 'Severity', cell: d => <Status value={d.severity} />, sort: d => severityRank(d.severity) },
        { id: 'type', header: 'Type', cell: d => humanize(d.type), sort: d => d.type },
        { id: 'status', header: 'Status', cell: d => <Status value={d.status} />, sort: d => d.status },
        { id: 'confidence', header: 'Confidence', cell: d => `${d.confidence}%`, sort: d => d.confidence },
        { id: 'accounts', header: 'Accounts', cell: d => d.affected_accounts.length, sort: d => d.affected_accounts.length },
        { id: 'time', header: 'Detected', cell: d => ago(d.timestamp), sort: d => d.timestamp },
      ]}
    />
  );
}

// --- campaigns ------------------------------------------------------------------------------------------------

export function CampaignsPage() {
  const campaigns = useAppStore(s => s.campaigns);
  return (
    <ResourceTable
      title="Campaigns"
      description="Attackers correlated across IPs, ASNs and accounts by shared TLS fingerprint (JA4) and behaviour."
      items={campaigns}
      defaultSort="risk"
      columns={[
        { id: 'code', header: 'Campaign', cell: c => <RouterLink to={`/campaigns/${c.id}`}>{c.campaign_code}</RouterLink>, sort: c => c.campaign_code },
        { id: 'name', header: 'Name', cell: c => c.name, sort: c => c.name, width: 340 },
        { id: 'risk', header: 'Risk', cell: c => <Status value={c.risk_level} />, sort: c => severityRank(c.risk_level) },
        { id: 'status', header: 'Status', cell: c => <Status value={c.status} />, sort: c => c.status },
        { id: 'ips', header: 'IPs', cell: c => c.ip_count, sort: c => c.ip_count },
        { id: 'accounts', header: 'Accounts', cell: c => c.account_count, sort: c => c.account_count },
        { id: 'allowed', header: 'Allowed requests', cell: c => num(c.waf_action_breakdown.ALLOW), sort: c => c.waf_action_breakdown.ALLOW },
        { id: 'last', header: 'Last active', cell: c => ago(c.last_seen), sort: c => c.last_seen },
      ]}
    />
  );
}

export function CampaignDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const fromStore = useAppStore(s => s.campaigns.find(c => c.id === id));
  const detail = useCampaignDetail(id);
  const campaign = detail.data?.campaign ?? fromStore;
  if (detail.isLoading && !campaign) return <Loading />;
  if (!campaign) return <Alert type="error" header="Campaign not found">{detail.error?.message}</Alert>;
  const members = detail.data?.members ?? [];
  const memberIps = members.filter(m => m.type === 'ip' && !m.is_allow_listed).map(m => m.value);
  const ja4 = members.find(m => m.type === 'ja4')?.value;
  const b = campaign.waf_action_breakdown;
  return (
    <ContentLayout header={
      <Header variant="h1" description={campaign.name}
        actions={<SpaceBetween direction="horizontal" size="xs">
          {ja4 && <Button onClick={() => navigate(simulateJa4Href(ja4))}>Simulate JA4 block</Button>}
          <Button variant="primary" disabled={memberIps.length === 0} onClick={() => navigate(simulateBlockHref(memberIps))}>
            Simulate blocking member IPs
          </Button>
        </SpaceBetween>}>
        {campaign.campaign_code}
      </Header>}>
      <SpaceBetween size="l">
        <Container header={<Header variant="h2">Summary</Header>}>
          <ColumnLayout columns={4} variant="text-grid">
            <Counter label="Risk" value={<Status value={campaign.risk_level} />} />
            <Counter label="Requests blocked" value={num(b.BLOCK)} />
            <Counter label="Requests allowed" value={num(b.ALLOW)} info={b.ALLOW ? 'Reached the application' : undefined} />
            <Counter label="Requests counted only" value={num(b.COUNT)} />
          </ColumnLayout>
        </Container>
        <Container header={<Header variant="h2">Attack story</Header>}>
          <SpaceBetween size="m">
            <Box>{campaign.description}</Box>
            <KeyValuePairs columns={4} items={[
              { label: 'IPs', value: campaign.ip_count }, { label: 'ASNs', value: campaign.asn_count },
              { label: 'Countries', value: campaign.country_count }, { label: 'Accounts targeted', value: campaign.account_count },
              { label: 'First seen', value: dateTime(campaign.first_seen) }, { label: 'Last active', value: ago(campaign.last_seen) },
              { label: 'Confidence', value: humanize(campaign.confidence) }, { label: 'Status', value: <Status value={campaign.status} /> },
            ]} />
            <Alert type="info" header="Recommended action">{campaign.recommended_action}</Alert>
          </SpaceBetween>
        </Container>
        {detail.data && (
          <Tabs tabs={[
            { id: 'evidence', label: 'Correlation evidence', content: (
              <Table variant="container" items={detail.data.correlation_evidence} trackBy="label"
                columnDefinitions={[
                  { id: 'label', header: 'Signal', cell: e => e.label },
                  { id: 'value', header: 'Value', cell: e => <Box variant="code">{e.value}</Box> },
                  { id: 'detail', header: 'Detail', cell: e => dash(e.detail) },
                ]} />) },
            { id: 'members', label: `Entities (${members.length})`, content: <EntityTable items={members} variant="container" title="Member entities" /> },
            { id: 'targets', label: 'Targets', content: (
              <Container header={<Header variant="h2">Most-targeted URIs</Header>}>
                <SpaceBetween size="xxs">
                  {detail.data.targeted_uris.map(u => <Box key={u} variant="code">{u}</Box>)}
                  <Box variant="small">Techniques: {detail.data.techniques.join(', ') || 'none matched; correlated by fingerprint'}</Box>
                </SpaceBetween>
              </Container>) },
          ]} />
        )}
      </SpaceBetween>
    </ContentLayout>
  );
}

// --- entities -------------------------------------------------------------------------------------------------

function EntityTable({ items, variant, title = 'Entities' }: { items: Entity[]; variant?: 'container'; title?: string }) {
  return (
    <ResourceTable
      title={title}
      variant={variant}
      description={variant ? undefined : 'Every IP, JA4 fingerprint, ASN and other actor seen in WAF traffic, ranked by risk.'}
      items={items}
      defaultSort="risk"
      sortDescending
      columns={[
        { id: 'value', header: 'Entity', cell: e => <RouterLink to={`/entities/${e.id}`}>{e.value}</RouterLink>, sort: e => e.value, width: 320 },
        { id: 'type', header: 'Type', cell: e => e.type.toUpperCase(), sort: e => e.type },
        { id: 'risk', header: 'Final risk', cell: e => <Status value={e.risk_level} label={`${Math.round(e.final_risk)} (${e.risk_level})`} />, sort: e => e.final_risk },
        { id: 'class', header: 'Classification', cell: e => <Status value={e.classification} />, sort: e => e.classification },
        { id: 'requests', header: 'Requests', cell: e => num(e.request_count), sort: e => e.request_count },
        { id: 'geo', header: 'Country / ASN', cell: e => [e.country, e.asn].filter(Boolean).join(' / ') || '-' },
        { id: 'allow', header: 'Protected', cell: e => (e.is_allow_listed ? <Status value="passed" label="Allow-listed" /> : '-') },
        { id: 'last', header: 'Last seen', cell: e => ago(e.last_seen), sort: e => e.last_seen },
      ]}
    />
  );
}

export function EntitiesPage() {
  const entities = useAppStore(s => s.entities);
  const [type, setType] = useState('all');
  const items = entities.filter(e => type === 'all' || e.type === type);
  return (
    <SpaceBetween size="m">
      <SegmentedControl selectedId={type} onChange={e => setType(e.detail.selectedId)} label="Entity type"
        options={[{ id: 'all', text: 'All' }, { id: 'ip', text: 'IP addresses' }, { id: 'ja4', text: 'JA4 fingerprints' }, { id: 'asn', text: 'ASNs' }]} />
      <EntityTable items={items} />
    </SpaceBetween>
  );
}

const EVENT_COLUMNS = ['timestamp', 'client_ip', 'http_method', 'uri', 'action', 'matched_rule_name', 'source'];

function eventCell(key: string, row: Record<string, unknown>): React.ReactNode {
  const v = row[key];
  if (key === 'timestamp') return dateTime(String(v));
  if (key === 'action') return <Status value={String(v)} label={String(v)} />;
  return dash(v === null || v === undefined ? null : String(v));
}

export function EntityDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const detail = useEntityDetail(id);
  if (detail.isLoading) return <Loading />;
  if (!detail.data) return <Alert type="error" header="Entity not found">{detail.error?.message}</Alert>;
  const { entity: e, timeline, allowed_explanations: allowed, graph, recent_events: events, visibility } = detail.data;
  return (
    <ContentLayout header={
      <Header variant="h1"
        description={`${e.type.toUpperCase()} - ${e.organization ?? e.asn ?? 'unknown network'}${e.country ? `, ${e.country}` : ''}`}
        actions={<SpaceBetween direction="horizontal" size="xs">
          {e.type === 'ja4' && <Button onClick={() => navigate(simulateJa4Href(e.value))}>Simulate JA4 block</Button>}
          {e.type === 'ip' && (
            <Button variant="primary" disabled={e.is_allow_listed} onClick={() => navigate(simulateBlockHref([e.value]))}>Simulate block</Button>
          )}
        </SpaceBetween>}>
        {e.value}
      </Header>}>
      <SpaceBetween size="l">
        {e.is_allow_listed && (
          <Alert type="warning" header="Protected entity">
            This entity is on the allow list. Guardrails deny automated blocking; investigate only.
          </Alert>
        )}
        <Container header={<Header variant="h2">Risk assessment</Header>}>
          <SpaceBetween size="m">
            <ColumnLayout columns={4} variant="text-grid">
              <Counter label="Final risk" value={<Status value={e.risk_level} label={`${Math.round(e.final_risk)} (${e.risk_level})`} />} />
              <Counter label="Threat score" value={Math.round(e.threat_score)} />
              <Counter label="Confidence" value={`${Math.round(e.confidence_score)}%`} />
              <Counter label="Business impact" value={Math.round(e.business_impact)} />
            </ColumnLayout>
            {detail.data.recommended_action && <Alert type="info" header="Recommended action">{detail.data.recommended_action}</Alert>}
          </SpaceBetween>
        </Container>
        <Tabs tabs={[
          { id: 'overview', label: 'Overview', content: (
            <SpaceBetween size="l">
              <Container header={<Header variant="h2">Details</Header>}>
                <KeyValuePairs columns={3} items={[
                  { label: 'Classification', value: <Status value={e.classification} /> },
                  { label: 'Requests', value: num(e.request_count) },
                  { label: 'Distinct URIs', value: e.uri_diversity },
                  { label: 'First seen', value: dateTime(e.first_seen) },
                  { label: 'Last seen', value: dateTime(e.last_seen) },
                  { label: '404 ratio', value: `${Math.round(e.not_found_ratio * 100)}%` },
                  { label: 'JA4', value: e.ja4 ? <Box variant="code">{e.ja4}</Box> : '-' },
                  { label: 'User agent', value: dash(e.user_agent) },
                  { label: 'Techniques', value: e.techniques.join(', ') || '-' },
                  { label: 'Web ACLs', value: e.webacls.join(', ') || '-' },
                  { label: 'Campaigns', value: e.campaigns.join(', ') || '-' },
                  { label: 'Evidence', value: Object.entries(visibility).map(([k, v]) => `${humanize(k.toLowerCase())}: ${num(v)}`).join(', ') || '-' },
                ]} />
              </Container>
              <Table variant="container" header={<Header variant="h2">Threat intelligence</Header>}
                items={e.threat_intel} trackBy="source"
                columnDefinitions={[
                  { id: 'src', header: 'Provider', cell: t => humanize(t.source) },
                  { id: 'score', header: 'Score', cell: t => t.score },
                  { id: 'class', header: 'Classification', cell: t => <Status value={t.classification} /> },
                  { id: 'conf', header: 'Confidence', cell: t => humanize(t.confidence) },
                  { id: 'exp', header: 'Expires', cell: t => ago(t.expires_at) },
                ]}
                empty={<Box textAlign="center">No threat intelligence for this entity</Box>} />
            </SpaceBetween>) },
          { id: 'timeline', label: 'Traffic timeline', content: (
            <Container header={<Header variant="h2" description="Requests per time bucket by WAF action">Traffic timeline</Header>}>
              <BarChart stackedBars height={260} hideFilter xScaleType="categorical"
                series={(['BLOCK', 'ALLOW', 'COUNT'] as const).map(k => ({
                  title: k, type: 'bar' as const,
                  data: timeline.map(t => ({ x: new Date(t.bucket).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }), y: t[k] })),
                }))}
                empty={<Box textAlign="center" color="inherit">No requests in the window</Box>} />
            </Container>) },
          { id: 'allowed', label: 'Why was it allowed?', content: (
            <Table variant="container"
              header={<Header variant="h2" description="Per Web ACL: why requests from this entity got through">Allowed traffic analysis</Header>}
              items={allowed} trackBy="webacl_id"
              columnDefinitions={[
                { id: 'acl', header: 'Web ACL', cell: a => <RouterLink to={`/inventory/webacls/${a.webacl_id}`}>{a.webacl_name}</RouterLink> },
                { id: 'n', header: 'Allowed requests', cell: a => num(a.allowed_requests) },
                { id: 'def', header: 'Default action', cell: a => a.default_action },
                { id: 'count', header: 'COUNT-mode rules matched', cell: a => a.count_mode_rules.join(', ') || '-' },
                { id: 'rules', header: 'Rules matched', cell: a => a.matched_rules.join(', ') || 'None (default action)' },
                { id: 'drift', header: 'Open drift', cell: a => a.open_drift.length },
              ]}
              empty={<Box textAlign="center">No requests from this entity were allowed</Box>} />) },
          { id: 'related', label: 'Relationships', content: (
            <Table variant="container" header={<Header variant="h2">Related entities</Header>}
              items={graph.edges} trackBy={x => `${x.source}-${x.target}-${x.type}`}
              columnDefinitions={[
                { id: 'type', header: 'Relationship', cell: x => humanize(x.type.toLowerCase()) },
                { id: 'target', header: 'Entity', cell: x => {
                  const other = x.source === e.id ? x.target : x.source;
                  const node = graph.nodes.find(n => n.id === other);
                  return <RouterLink to={`/entities/${other}`}>{node?.label ?? other}</RouterLink>;
                } },
                { id: 'count', header: 'Observations', cell: x => num(x.count) },
              ]}
              empty={<Box textAlign="center">No related entities</Box>} />) },
          { id: 'events', label: 'Recent requests', content: (
            <Table variant="container" header={<Header variant="h2" counter={`(${events.length})`}>Recent requests</Header>}
              items={events} trackBy={x => String(x.event_hash ?? x.id ?? x.timestamp)}
              columnDefinitions={EVENT_COLUMNS.map(k => ({ id: k, header: humanize(k), cell: (x: Record<string, unknown>) => eventCell(k, x) }))}
              empty={<Box textAlign="center">No raw events stored for this entity</Box>} />) },
        ]} />
      </SpaceBetween>
    </ContentLayout>
  );
}
