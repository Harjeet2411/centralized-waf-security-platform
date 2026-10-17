// WAF inventory module: accounts (with registration), Web ACLs (rules, score evidence, false-positive candidates),
// endpoints (attach a Web ACL) and configuration drift (remediate). Changes go through ApprovalModal.
import React, { useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ButtonDropdown from '@cloudscape-design/components/button-dropdown';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Container from '@cloudscape-design/components/container';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Form from '@cloudscape-design/components/form';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import KeyValuePairs from '@cloudscape-design/components/key-value-pairs';
import Modal from '@cloudscape-design/components/modal';
import ProgressBar from '@cloudscape-design/components/progress-bar';
import Select from '@cloudscape-design/components/select';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Table from '@cloudscape-design/components/table';
import Tabs from '@cloudscape-design/components/tabs';
import Toggle from '@cloudscape-design/components/toggle';
import { api, queryClient } from '@/api/client';
import { useGet } from '@/api/hooks';
import { useAppStore } from '@/store';
import type { DriftEvent, Endpoint, WafRule } from '@/types';
import { ApprovalModal, Counter, ResourceTable, RouterLink, Status, ago, dateTime, humanize, notify, num, severityRank, useCan } from '@/ui';

// --- accounts -------------------------------------------------------------------------------------------------

const ENVIRONMENTS = ['production', 'staging', 'development', 'shared-services', 'security'];
const EMPTY_ACCOUNT = { account_id: '', name: '', environment: 'production', owner: '', regions: 'us-east-1' };

function RegisterAccountModal({ visible, onDismiss }: { visible: boolean; onDismiss: () => void }) {
  const [form, setForm] = useState(EMPTY_ACCOUNT);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const set = (k: keyof typeof form) => (e: { detail: { value: string } }) => setForm({ ...form, [k]: e.detail.value });
  const idValid = /^[0-9]{12}$/.test(form.account_id);
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await api('/api/v1/governance/accounts', {
        method: 'POST', json: { ...form, regions: form.regions.split(/[\s,;]+/).filter(Boolean) },
      });
      notify('success', `Account ${form.name} (${form.account_id}) registered. It is included from the next sync.`, 'Account registered');
      setForm(EMPTY_ACCOUNT);
      onDismiss();
      await queryClient.invalidateQueries({ queryKey: ['bootstrap'] });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal visible={visible} onDismiss={onDismiss} header="Register AWS account"
      footer={<Box float="right"><SpaceBetween direction="horizontal" size="xs">
        <Button variant="link" onClick={onDismiss}>Cancel</Button>
        <Button variant="primary" loading={busy} disabled={!idValid || form.name.length < 2 || form.owner.length < 2}
          onClick={submit}>Register</Button>
      </SpaceBetween></Box>}>
      <Form errorText={error}>
        <SpaceBetween size="m">
          <FormField label="Account ID" constraintText="12 digits"
            errorText={form.account_id && !idValid ? 'Must be exactly 12 digits' : undefined}>
            <Input value={form.account_id} onChange={set('account_id')} placeholder="123456789012" inputMode="numeric" />
          </FormField>
          <FormField label="Account name"><Input value={form.name} onChange={set('name')} placeholder="prod-payments-01" /></FormField>
          <FormField label="Environment">
            <Select selectedOption={{ value: form.environment, label: humanize(form.environment) }}
              options={ENVIRONMENTS.map(v => ({ value: v, label: humanize(v) }))}
              onChange={e => setForm({ ...form, environment: e.detail.selectedOption.value! })} />
          </FormField>
          <FormField label="Owner team"><Input value={form.owner} onChange={set('owner')} placeholder="payments-platform" /></FormField>
          <FormField label="Regions" constraintText="Comma-separated, for example eu-west-1, us-east-1">
            <Input value={form.regions} onChange={set('regions')} />
          </FormField>
          <Box variant="small" color="text-body-secondary">
            The SASWafDiscoveryRole and SASWafResponseRole ARNs are derived from the account ID (deployed by the StackSet).
          </Box>
        </SpaceBetween>
      </Form>
    </Modal>
  );
}

export function AccountsPage() {
  const accounts = useAppStore(s => s.accounts);
  const can = useCan();
  const [registering, setRegistering] = useState(false);
  return (
    <>
      <ResourceTable
        title="Accounts"
        description="Member AWS accounts discovered through the cross-account discovery role."
        items={accounts}
        defaultSort="score"
        actions={<Button variant="primary" disabled={!can('MANAGE_USERS')} onClick={() => setRegistering(true)}>Register account</Button>}
        columns={[
          { id: 'name', header: 'Account', cell: a => a.name, sort: a => a.name, width: 220 },
          { id: 'id', header: 'Account ID', cell: a => a.account_id, sort: a => a.account_id, width: 150 },
          { id: 'env', header: 'Environment', cell: a => humanize(a.environment), sort: a => a.environment },
          { id: 'status', header: 'Collector', cell: a => <Status value={a.status} />, sort: a => a.status },
          { id: 'coverage', header: 'WAF coverage', cell: a => <ProgressBar value={Math.round(a.waf_coverage)} />, sort: a => a.waf_coverage },
          { id: 'score', header: 'Score', cell: a => Math.round(a.security_score), sort: a => a.security_score },
          { id: 'visibility', header: 'Visibility', cell: a => <Status value={a.logging_visibility} />, sort: a => a.logging_visibility },
          { id: 'res', header: 'Web ACLs / endpoints', cell: a => `${a.webacl_count} / ${a.endpoint_count}` },
          { id: 'regions', header: 'Regions', cell: a => a.regions.join(', ') },
          { id: 'disc', header: 'Last discovered', cell: a => ago(a.last_discovered), sort: a => a.last_discovered },
        ]}
      />
      <RegisterAccountModal visible={registering} onDismiss={() => setRegistering(false)} />
    </>
  );
}

// --- web ACLs -------------------------------------------------------------------------------------------------

export function WebAclsPage() {
  const webacls = useAppStore(s => s.webacls);
  return (
    <ResourceTable
      title="Web ACLs"
      description="AWS WAF web ACLs across all member accounts, scored on coverage, blocking, drift and rule hygiene."
      items={webacls}
      defaultSort="score"
      columns={[
        { id: 'name', header: 'Name', cell: w => <RouterLink to={`/inventory/webacls/${w.id}`}>{w.name}</RouterLink>, sort: w => w.name, width: 220 },
        { id: 'account', header: 'Account', cell: w => w.account_name, sort: w => w.account_name },
        { id: 'scope', header: 'Scope', cell: w => (w.scope === 'CLOUDFRONT' ? 'CloudFront' : `Regional (${w.region})`), sort: w => w.scope },
        { id: 'default', header: 'Default action', cell: w => <Status value={w.default_action} label={w.default_action} /> },
        { id: 'score', header: 'Score', cell: w => `${Math.round(w.security_score)} (${w.score_confidence.toLowerCase()})`, sort: w => w.security_score },
        { id: 'rules', header: 'Rules', cell: w => w.rule_count, sort: w => w.rule_count },
        { id: 'drift', header: 'Open drift', cell: w => (w.drift_count ? <Status value="open" label={String(w.drift_count)} /> : '0'), sort: w => w.drift_count },
        { id: 'logging', header: 'Logging', cell: w => <Status value={w.logging_enabled ? 'healthy' : 'unknown'} label={w.logging_enabled ? 'Enabled' : 'Off (sampled)'} /> },
        { id: 'req', header: 'Requests (24h)', cell: w => num(w.requests_24h), sort: w => w.requests_24h },
      ]}
    />
  );
}

interface FalsePositive {
  matched_rule_name: string; rule_name: string; sub_rule: string | null; blocked: number; distinct_ips: number;
  distinct_uris: number; sample_uris: string[]; suggested_remediation: string;
}
interface Dimension { value: number; weight: number; inputs?: Record<string, unknown> }

function versionLabel(r: WafRule) {
  if (!r.managed_version) return '-';
  const outdated = r.version_status === 'outdated';
  return <Status value={outdated ? 'degraded' : 'healthy'} label={`${r.managed_version}${outdated ? ` (latest ${r.latest_version})` : ''}`} />;
}

export function WebAclDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const acl = useAppStore(s => s.webacls.find(w => w.id === id));
  const allRules = useAppStore(s => s.rules);
  const allDrift = useAppStore(s => s.driftEvents);
  const fps = useGet<FalsePositive[]>(id ? `/api/v1/simulations/false-positives?webacl_id=${id}` : null);
  if (!acl) return <Alert type="error" header="Web ACL not found">It may have been deleted since the last sync.</Alert>;
  const rules = [...(allRules.get(acl.id) ?? [])].sort((a, b) => a.priority - b.priority);
  const drift = allDrift.filter(d => d.webacl_id === acl.id);
  const dims = Object.entries((acl.score_evidence.dimensions ?? {}) as Record<string, Dimension>);
  const simulate = (query: string) => navigate(`/response/simulate?webacl=${acl.id}&${query}`);
  return (
    <ContentLayout header={
      <Header variant="h1" description={acl.arn}
        actions={<Button onClick={() => simulate('type=RULE_ACTION')}>Simulate a rule change</Button>}>
        {acl.name}
      </Header>}>
      <SpaceBetween size="l">
        {acl.visibility_level !== 'full' && (
          <Alert type="info" header="Sampled visibility">
            Logging is not enabled for this Web ACL. Request counts come from sampled requests and are lower bounds.
          </Alert>
        )}
        <Container header={<Header variant="h2">Web ACL details</Header>}>
          <SpaceBetween size="l">
            <ColumnLayout columns={4} variant="text-grid">
              <Counter label="Security score" value={Math.round(acl.security_score)} info={`Confidence: ${acl.score_confidence.toLowerCase()}`} />
              <Counter label="Requests (24h)" value={num(acl.requests_24h)} />
              <Counter label="Managed rule health" value={`${Math.round(acl.managed_rule_health)}%`} />
              <Counter label="Open drift" value={acl.drift_count} />
            </ColumnLayout>
            <KeyValuePairs columns={4} items={[
              { label: 'Account', value: `${acl.account_name} (${acl.account_id})` },
              { label: 'Scope', value: acl.scope === 'CLOUDFRONT' ? 'CloudFront (global)' : `Regional (${acl.region})` },
              { label: 'Default action', value: <Status value={acl.default_action} label={acl.default_action} /> },
              { label: 'Logging', value: acl.logging_enabled ? 'Enabled' : 'Disabled' },
            ]} />
          </SpaceBetween>
        </Container>
        <Tabs tabs={[
          { id: 'rules', label: `Rules (${rules.length})`, content: (
            <Table variant="container" header={<Header variant="h2" description="In priority order">Rules</Header>}
              items={rules} trackBy="id"
              columnDefinitions={[
                { id: 'p', header: 'Priority', cell: r => r.priority },
                { id: 'name', header: 'Name', cell: r => r.name, width: 300 },
                { id: 'type', header: 'Type', cell: r => humanize(r.rule_type.toLowerCase()) },
                { id: 'action', header: 'Action', cell: r => <Status value={r.action} label={r.action} /> },
                { id: 'matches', header: 'Matches (24h)', cell: r => num(r.match_count) },
                { id: 'eff', header: 'Effectiveness', cell: r => `${Math.round(r.effectiveness)}%` },
                { id: 'ver', header: 'Version', cell: versionLabel },
                { id: 'act', header: 'Actions', cell: r => (
                  <ButtonDropdown variant="inline-icon" ariaLabel={`Actions for ${r.name}`} expandToViewport
                    items={[
                      { id: 'BLOCK', text: 'Simulate switching to BLOCK', disabled: r.action === 'BLOCK' },
                      { id: 'COUNT', text: 'Simulate switching to COUNT', disabled: r.action === 'COUNT' },
                      ...(r.rule_type === 'RATE_BASED' ? [{ id: 'RATE', text: 'Simulate a new rate limit' }] : []),
                    ]}
                    onItemClick={e => simulate(e.detail.id === 'RATE'
                      ? `type=RATE_LIMIT&rule=${encodeURIComponent(r.name)}`
                      : `type=RULE_ACTION&rule=${encodeURIComponent(r.name)}&action=${e.detail.id}`)} />
                ) },
              ]}
              empty={<Box textAlign="center">No rules</Box>} />) },
          { id: 'score', label: 'Score breakdown', content: (
            <Table variant="container" header={<Header variant="h2" description="How the security score is computed">Score dimensions</Header>}
              items={dims} trackBy={([k]) => k}
              columnDefinitions={[
                { id: 'dim', header: 'Dimension', cell: ([k]) => humanize(k) },
                { id: 'value', header: 'Value', cell: ([, d]) => <ProgressBar value={Math.round(d.value)} /> },
                { id: 'weight', header: 'Weight', cell: ([, d]) => `${Math.round(d.weight * 100)}%` },
                { id: 'inputs', header: 'Inputs', cell: ([, d]) => (d.inputs ? Object.entries(d.inputs).map(([k, v]) => `${humanize(k)}: ${JSON.stringify(v)}`).join('; ') : '-') },
              ]}
              empty={<Box textAlign="center">No score evidence recorded (sampled visibility)</Box>} />) },
          { id: 'fp', label: 'False-positive candidates', content: (
            <Table variant="container" loading={fps.isLoading}
              header={<Header variant="h2" description="Rules blocking traffic with no evidence of hostility, last 7 days">False-positive candidates</Header>}
              items={fps.data ?? []} trackBy="matched_rule_name"
              columnDefinitions={[
                { id: 'rule', header: 'Rule', cell: f => f.rule_name },
                { id: 'sub', header: 'Sub-rule', cell: f => f.sub_rule ?? '-' },
                { id: 'blocked', header: 'Blocked', cell: f => num(f.blocked) },
                { id: 'ips', header: 'Distinct IPs', cell: f => f.distinct_ips },
                { id: 'uris', header: 'Sample URIs', cell: f => f.sample_uris.join(', ') },
                { id: 'fix', header: 'Suggested remediation', cell: f => f.suggested_remediation },
              ]}
              empty={<Box textAlign="center">No likely false positives</Box>} />) },
          { id: 'drift', label: `Drift (${drift.length})`, content: <DriftTable items={drift} variant="container" /> },
        ]} />
      </SpaceBetween>
    </ContentLayout>
  );
}

// --- endpoints ------------------------------------------------------------------------------------------------

const PROTECTION_ORDER = ['unprotected', 'partially_protected', 'unknown', 'protected'];

export function EndpointsPage() {
  const endpoints = useAppStore(s => s.endpoints);
  const webacls = useAppStore(s => s.webacls);
  const [exposedOnly, setExposedOnly] = useState(false);
  const [selected, setSelected] = useState<Endpoint[]>([]);
  const [attach, setAttach] = useState<Endpoint | null>(null);
  const [aclId, setAclId] = useState<string | null>(null);
  const items = endpoints.filter(e => !exposedOnly || (e.internet_facing && e.status !== 'protected'));
  const compatible = attach ? webacls.filter(w => w.account_id === attach.account_id
    && (attach.type === 'CloudFront' ? w.scope === 'CLOUDFRONT' : w.scope === 'REGIONAL' && w.region === attach.region)) : [];
  const target = selected[0];
  return (
    <>
      <ResourceTable
        title="Endpoints"
        description="ALBs, API Gateway stages and CloudFront distributions, and whether a Web ACL protects them."
        items={items}
        selectionType="single"
        selected={selected}
        onSelect={setSelected}
        defaultSort="status"
        filters={<Toggle checked={exposedOnly} onChange={e => setExposedOnly(e.detail.checked)}>Exposed only</Toggle>}
        actions={<Button variant="primary" disabled={!target || target.waf_enabled}
          onClick={() => { setAttach(target); setAclId(null); }}>Attach Web ACL</Button>}
        columns={[
          { id: 'name', header: 'Name', cell: e => e.name, sort: e => e.name, width: 240 },
          { id: 'type', header: 'Type', cell: e => e.type, sort: e => e.type },
          { id: 'status', header: 'Protection', cell: e => <Status value={e.status} />, sort: e => PROTECTION_ORDER.indexOf(e.status) },
          { id: 'internet', header: 'Internet-facing', cell: e => (e.internet_facing ? 'Yes' : 'No'), sort: e => String(e.internet_facing) },
          { id: 'account', header: 'Account', cell: e => e.account_name, sort: e => e.account_name },
          { id: 'region', header: 'Region', cell: e => e.region, sort: e => e.region },
          { id: 'dns', header: 'DNS name', cell: e => e.dns_name },
          { id: 'logging', header: 'Visibility', cell: e => <Status value={e.visibility_level} /> },
        ]}
      />
      <ApprovalModal
        title="Attach Web ACL"
        body={attach && { action_type: 'ATTACH_WAF', account_id: attach.account_id, resource_arn: attach.resource_arn, webacl_id: aclId ?? undefined }}
        valid={Boolean(aclId)}
        onDismiss={() => setAttach(null)}
        summary={attach && <KeyValuePairs columns={2} items={[{ label: 'Endpoint', value: attach.name }, { label: 'Account', value: attach.account_name }]} />}>
        <FormField label="Web ACL" description="Only Web ACLs in the same account with a compatible scope and region are listed."
          errorText={attach && compatible.length === 0 ? 'No compatible Web ACL in this account.' : undefined}>
          <Select
            selectedOption={compatible.filter(w => w.id === aclId).map(w => ({ value: w.id, label: w.name }))[0] ?? null}
            options={compatible.map(w => ({ value: w.id, label: w.name, description: w.arn }))}
            onChange={e => setAclId(e.detail.selectedOption.value ?? null)} placeholder="Choose a Web ACL" />
        </FormField>
      </ApprovalModal>
    </>
  );
}

// --- drift ----------------------------------------------------------------------------------------------------

function DriftTable({ items, variant }: { items: DriftEvent[]; variant?: 'container' }) {
  const [selected, setSelected] = useState<DriftEvent[]>([]);
  const [remediate, setRemediate] = useState<DriftEvent | null>(null);
  return (
    <>
      <ResourceTable
        title="Configuration drift"
        variant={variant}
        description={variant ? undefined : 'Differences between the approved baseline and the live Web ACL configuration.'}
        items={items}
        selectionType="single"
        selected={selected}
        onSelect={setSelected}
        defaultSort="severity"
        actions={<Button variant="primary" disabled={!selected[0] || selected[0].status !== 'open'}
          onClick={() => setRemediate(selected[0])}>Remediate</Button>}
        columns={[
          { id: 'code', header: 'Drift ID', cell: d => d.drift_code, sort: d => d.drift_code },
          { id: 'type', header: 'Type', cell: d => humanize(d.drift_type.toLowerCase()), sort: d => d.drift_type },
          { id: 'severity', header: 'Severity', cell: d => <Status value={d.severity} />, sort: d => severityRank(d.severity) },
          { id: 'acl', header: 'Web ACL', cell: d => <RouterLink to={`/inventory/webacls/${d.webacl_id}`}>{d.webacl_name}</RouterLink>, sort: d => d.webacl_name },
          { id: 'expected', header: 'Expected', cell: d => <Box variant="code">{d.expected}</Box> },
          { id: 'actual', header: 'Actual', cell: d => <Box variant="code">{d.actual}</Box> },
          { id: 'status', header: 'Status', cell: d => <Status value={d.status} />, sort: d => d.status },
          { id: 'time', header: 'Detected', cell: d => ago(d.detected_at), sort: d => d.detected_at },
        ]}
      />
      <ApprovalModal
        title="Remediate drift"
        body={remediate && { action_type: 'REMEDIATE_DRIFT', account_id: remediate.account_id, drift_id: remediate.id, webacl_id: remediate.webacl_id }}
        onDismiss={() => setRemediate(null)}
        summary={remediate && (
          <KeyValuePairs columns={2} items={[
            { label: 'Web ACL', value: remediate.webacl_name }, { label: 'Detected', value: dateTime(remediate.detected_at) },
            { label: 'Expected (baseline)', value: <Box variant="code">{remediate.expected}</Box> },
            { label: 'Actual (live)', value: <Box variant="code">{remediate.actual}</Box> },
          ]} />
        )} />
    </>
  );
}

export function DriftPage() {
  const drift = useAppStore(s => s.driftEvents);
  return <DriftTable items={drift} />;
}
