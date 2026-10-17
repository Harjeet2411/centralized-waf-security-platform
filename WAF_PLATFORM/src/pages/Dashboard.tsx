// Home: the one screen a cloud engineer opens first. Every widget links to the module that owns the data.
import React from 'react';
import { useNavigate } from 'react-router-dom';
import Alert from '@cloudscape-design/components/alert';
import BarChart from '@cloudscape-design/components/bar-chart';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Container from '@cloudscape-design/components/container';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Grid from '@cloudscape-design/components/grid';
import Header from '@cloudscape-design/components/header';
import PieChart from '@cloudscape-design/components/pie-chart';
import ProgressBar from '@cloudscape-design/components/progress-bar';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Table from '@cloudscape-design/components/table';
import { useAppStore } from '@/store';
import { colorChartsStatusCritical, colorChartsStatusHigh, colorChartsStatusLow, colorChartsStatusMedium } from '@cloudscape-design/design-tokens';
import { Counter, RouterLink, Status, actionLabel, ago, humanize, num, severityRank } from '@/ui';

const COMPONENTS = [
  ['aws_api', 'AWS API'], ['queue', 'Sync queue'], ['workers', 'Workers'], ['database', 'Database'],
  ['threat_intel', 'Threat intelligence'],
] as const;

export function Dashboard() {
  const navigate = useNavigate();
  const s = useAppStore();
  const exposed = s.endpoints.filter(e => e.internet_facing && e.status !== 'protected');
  const openDetections = s.detections.filter(d => d.status !== 'actioned' && d.status !== 'false_positive');
  const activeCampaigns = s.campaigns.filter(c => c.status === 'active');
  const pending = s.approvals.filter(a => a.status === 'pending');
  const sampled = s.accounts.filter(a => a.logging_visibility !== 'full');
  const health = s.platformHealth;
  const degraded = [
    ...COMPONENTS.filter(([k]) => health[k].status !== 'healthy').map(([k, label]) => `${label}: ${health[k].detail}`),
    ...health.collectors.filter(c => c.status !== 'healthy').map(c => `${c.account_name}: ${c.error ?? c.status}`),
  ];
  const overall = s.postureDimensions.find(d => d.key === 'overall')?.value
    ?? s.accounts.reduce((t, a) => t + a.security_score, 0) / Math.max(1, s.accounts.length);
  const dims = s.postureDimensions.filter(d => d.key !== 'overall');
  const riskyEntities = [...s.entities].sort((a, b) => b.final_risk - a.final_risk).slice(0, 5);
  const colors: Record<string, string> = {
    critical: colorChartsStatusCritical, high: colorChartsStatusHigh, medium: colorChartsStatusMedium, low: colorChartsStatusLow,
  };
  const bySeverity = ['critical', 'high', 'medium', 'low']
    .map(sev => ({ title: humanize(sev), value: s.detections.filter(d => d.severity === sev).length, color: colors[sev] }))
    .filter(d => d.value > 0);
  const activity = [...s.threatActivity].sort((a, b) => severityRank(a.severity) - severityRank(b.severity)).slice(0, 6);
  const scoreColor = overall >= 80 ? 'text-status-success' : overall >= 60 ? 'text-status-warning' : 'text-status-error';

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description={`AWS WAF posture, threats and controlled response across ${s.accounts.length} accounts and ${s.webacls.length} Web ACLs. Last sync ${ago(health.last_sync)}.`}
          actions={
            <SpaceBetween direction="horizontal" size="xs">
              <Button onClick={() => navigate('/governance/audit')}>Audit trail</Button>
              <Button variant="primary" onClick={() => navigate('/response/simulate')}>Simulate a change</Button>
            </SpaceBetween>
          }
        >
          Security overview
        </Header>
      }
    >
      <SpaceBetween size="l">
        {degraded.length > 0 && (
          <Alert type="warning" header="Some data sources are degraded"
            action={<Button onClick={() => navigate('/governance/health')}>View platform health</Button>}>
            {degraded.slice(0, 3).join(' | ')}{degraded.length > 3 ? ` and ${degraded.length - 3} more` : ''}
          </Alert>
        )}
        {sampled.length > 0 && (
          <Alert type="info" header={`${sampled.length} of ${s.accounts.length} accounts have sampled visibility`}>
            These accounts do not ship full WAF logs. Their request counts are lower bounds from GetSampledRequests, not
            complete totals.
          </Alert>
        )}

        <Container header={<Header variant="h2" description="Live counts from the latest sync">Overview</Header>}>
          <ColumnLayout columns={6} variant="text-grid" minColumnWidth={140}>
            <Counter label="Accounts monitored" value={s.accounts.length} to="/inventory/accounts"
              info={`${s.accounts.filter(a => a.status !== 'healthy').length} degraded`} />
            <Counter label="Web ACLs" value={s.webacls.length} to="/inventory/webacls"
              info={`${num(s.webacls.reduce((t, w) => t + w.requests_24h, 0))} requests (24h)`} />
            <Counter label="Exposed endpoints" value={exposed.length} to="/inventory/endpoints"
              info="Internet-facing, not fully protected" />
            <Counter label="Open detections" value={openDetections.length} to="/detections"
              info={`${openDetections.filter(d => d.severity === 'critical').length} critical`} />
            <Counter label="Active campaigns" value={activeCampaigns.length} to="/campaigns" info="Correlated attackers" />
            <Counter label="Pending approvals" value={pending.length} to="/response/approvals" info="Changes awaiting review" />
          </ColumnLayout>
        </Container>

        <Grid gridDefinition={[{ colspan: { default: 12, s: 5 } }, { colspan: { default: 12, s: 7 } }]}>
          <Container fitHeight header={<Header variant="h2" description="Weighted score across all Web ACLs">Security posture</Header>}>
            <SpaceBetween size="m">
              <div>
                <Box variant="awsui-key-label">Overall score</Box>
                <Box variant="awsui-value-large" color={scoreColor}>{Math.round(overall)} / 100</Box>
              </div>
              {dims.map(d => (
                <ProgressBar key={d.key} value={Math.round(d.value)} label={d.label}
                  description={d.why[0] ? `${d.why[0].label}: ${d.why[0].value}` : undefined} />
              ))}
              {dims.length === 0 && <Box color="text-body-secondary">No posture data yet. Run a sync.</Box>}
            </SpaceBetween>
          </Container>

          <Table
            variant="container"
            header={<Header variant="h2" counter={`(${s.threatActivity.length})`} description="Highest severity first"
              actions={<Button onClick={() => navigate('/detections')}>View detections</Button>}>Threat activity</Header>}
            items={activity}
            trackBy="id"
            columnDefinitions={[
              { id: 'title', header: 'Activity', cell: t => (t.campaign_id
                ? <RouterLink to={`/campaigns/${t.campaign_id}`}>{t.title}</RouterLink> : t.title) },
              { id: 'sev', header: 'Severity', cell: t => <Status value={t.severity} /> },
              { id: 'target', header: 'Target', cell: t => t.target || '-' },
              { id: 'waf', header: 'WAF action', cell: t => <Status value={t.waf_action} label={t.waf_action} /> },
              { id: 'time', header: 'Seen', cell: t => ago(t.time) },
            ]}
            empty={<Box textAlign="center">No threat activity in the last 24 hours</Box>}
          />
        </Grid>

        <Grid gridDefinition={[{ colspan: { default: 12, s: 5 } }, { colspan: { default: 12, s: 4 } }, { colspan: { default: 12, s: 3 } }]}>
          <Container fitHeight header={<Header variant="h2" description="Requests evaluated, last 24 hours">Traffic by Web ACL</Header>}>
            <BarChart
              series={[{ title: 'Requests (24h)', type: 'bar', data: s.webacls.map(w => ({ x: w.name, y: w.requests_24h })) }]}
              horizontalBars hideFilter hideLegend height={200}
              i18nStrings={{ yTickFormatter: v => (v >= 1e6 ? `${(v / 1e6).toFixed(1)}M` : v >= 1e3 ? `${Math.round(v / 1e3)}k` : String(v)) }}
              empty={<Box textAlign="center" color="inherit">No Web ACLs</Box>}
            />
          </Container>
          <Container fitHeight header={<Header variant="h2" description="All detections">Detections by severity</Header>}>
            <PieChart
              data={bySeverity}
              variant="donut" size="medium" hideFilter
              innerMetricDescription="detections" innerMetricValue={String(s.detections.length)}
              empty={<Box textAlign="center" color="inherit">No detections</Box>}
            />
          </Container>
          <Container fitHeight header={<Header variant="h2" description={`Freshness: ${health.data_freshness}`}>Platform health</Header>}>
            <SpaceBetween size="xs">
              {COMPONENTS.map(([k, label]) => (
                <div key={k} style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                  <Box>{label}</Box><Status value={health[k].status} />
                </div>
              ))}
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                <Box>Collectors</Box>
                <Box>{health.collectors.filter(c => c.status === 'healthy').length}/{health.collectors.length} healthy</Box>
              </div>
              <RouterLink to="/governance/health">View details</RouterLink>
            </SpaceBetween>
          </Container>
        </Grid>

        <Grid gridDefinition={[{ colspan: { default: 12, s: 4 } }, { colspan: { default: 12, s: 4 } }, { colspan: { default: 12, s: 4 } }]}>
          <Table
            variant="container"
            header={<Header variant="h2" counter={`(${pending.length})`}>Pending approvals</Header>}
            items={pending.slice(0, 5)}
            trackBy="id"
            columnDefinitions={[
              { id: 'code', header: 'Request', cell: a => <RouterLink to={`/response/approvals/${a.id}`}>{actionLabel(a.action_type)}</RouterLink> },
              { id: 'target', header: 'Target', cell: a => a.target },
              { id: 'age', header: 'Requested', cell: a => ago(a.requested_at) },
            ]}
            empty={<Box textAlign="center">Nothing awaiting approval</Box>}
          />
          <Table
            variant="container"
            header={<Header variant="h2" counter={`(${exposed.length})`}>Exposed endpoints</Header>}
            items={exposed.slice(0, 5)}
            trackBy="id"
            columnDefinitions={[
              { id: 'name', header: 'Endpoint', cell: e => <RouterLink to="/inventory/endpoints">{e.name}</RouterLink> },
              { id: 'type', header: 'Type', cell: e => e.type },
              { id: 'status', header: 'WAF', cell: e => <Status value={e.status} /> },
            ]}
            empty={<Box textAlign="center">All internet-facing endpoints are protected</Box>}
          />
          <Table
            variant="container"
            header={<Header variant="h2" description="By final risk score">Riskiest entities</Header>}
            items={riskyEntities}
            trackBy="id"
            columnDefinitions={[
              { id: 'value', header: 'Entity', cell: e => <RouterLink to={`/entities/${e.id}`}>{e.value.length > 24 ? `${e.value.slice(0, 24)}...` : e.value}</RouterLink> },
              { id: 'type', header: 'Type', cell: e => e.type.toUpperCase() },
              { id: 'risk', header: 'Risk', cell: e => <Status value={e.risk_level} label={`${Math.round(e.final_risk)} (${e.risk_level})`} /> },
            ]}
            empty={<Box textAlign="center">No entities observed</Box>}
          />
        </Grid>

        <Container header={<Header variant="h2" description="Every AWS change goes through simulation, guardrails and approval">Common tasks</Header>}>
          <ColumnLayout columns={3} variant="text-grid">
            <SpaceBetween size="xxs">
              <Box variant="h4">Investigate</Box>
              <RouterLink to="/detections">Triage open detections</RouterLink>
              <RouterLink to="/campaigns">Review correlated campaigns</RouterLink>
              <RouterLink to="/entities">Look up an IP, JA4 or ASN</RouterLink>
            </SpaceBetween>
            <SpaceBetween size="xxs">
              <Box variant="h4">Respond</Box>
              <RouterLink to="/response/simulate">Simulate an IP block or rule change</RouterLink>
              <RouterLink to="/response/approvals">Approve or reject pending changes</RouterLink>
              <RouterLink to="/response/changes">Roll back a change</RouterLink>
            </SpaceBetween>
            <SpaceBetween size="xxs">
              <Box variant="h4">Govern</Box>
              <RouterLink to="/inventory/drift">Remediate configuration drift</RouterLink>
              <RouterLink to="/inventory/accounts">Register an AWS account</RouterLink>
              <RouterLink to="/governance/audit">Export the audit trail (CSV)</RouterLink>
            </SpaceBetween>
          </ColumnLayout>
        </Container>
      </SpaceBetween>
    </ContentLayout>
  );
}
