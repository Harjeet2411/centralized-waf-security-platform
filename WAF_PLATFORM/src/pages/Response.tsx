// Controlled response module: simulate -> request approval -> approve/reject -> execute/verify -> rollback.
// The browser never calls AWS: every action here is a FastAPI call that the backend guards, executes and audits.
import React, { useState } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Container from '@cloudscape-design/components/container';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Form from '@cloudscape-design/components/form';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import KeyValuePairs from '@cloudscape-design/components/key-value-pairs';
import Modal from '@cloudscape-design/components/modal';
import SegmentedControl from '@cloudscape-design/components/segmented-control';
import Select from '@cloudscape-design/components/select';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Steps, { type StepsProps } from '@cloudscape-design/components/steps';
import Table from '@cloudscape-design/components/table';
import Tabs from '@cloudscape-design/components/tabs';
import Textarea from '@cloudscape-design/components/textarea';
import Tiles from '@cloudscape-design/components/tiles';
import { api, queryClient } from '@/api/client';
import { useGet, useSimulation, type SimulationRequest } from '@/api/hooks';
import { useAppStore, type ApprovalRequestBody } from '@/store';
import type { Approval, SimulationResult } from '@/types';
import { ApprovalModal, Counter, actionLabel, ResourceTable, RouterLink, Status, ago, dash, dateTime, humanize, notify, num, useCan } from '@/ui';
import { Loading } from '@/pages/Threats';

// --- simulate -------------------------------------------------------------------------------------------------

type ProposalType = SimulationRequest['proposal']['type'];
const WINDOWS = [24, 72, 168, 720].map(h => ({ value: String(h), label: h < 168 ? `Last ${h} hours` : `Last ${h / 24} days` }));
const TTLS = [
  { value: '1', label: '1 hour' }, { value: '4', label: '4 hours' }, { value: '24', label: '24 hours' },
  { value: '72', label: '3 days' }, { value: '168', label: '7 days' }, { value: 'perm', label: 'Permanent' },
];
const GOOD_BAD: Record<string, string> = { HIGH: 'low', MEDIUM: 'medium', LOW: 'high' }; // risk reduction: high is good
const IMPACT: Record<string, string> = { NONE: 'low', LOW: 'low', MEDIUM: 'medium', HIGH: 'critical' };

function SimulationResultView({ r }: { r: SimulationResult }) {
  return (
    <Container header={<Header variant="h2" description={`${num(r.evaluated_requests)} historical requests replayed over ${r.window_hours} hours`}>Simulation result</Header>}>
      <SpaceBetween size="l">
        {!r.allow_list_passed && (
          <Alert type="error" header="Guardrail: protected entities matched">
            {num(r.protected_requests_matched)} requests from allow-listed entities match this change. An approval request
            will be denied unless the targets are narrowed.
          </Alert>
        )}
        {r.visibility_note && <Alert type="info" header="Evidence visibility">{r.visibility_note}</Alert>}
        <ColumnLayout columns={4} variant="text-grid">
          <Counter label="Would block" value={num(r.would_block)} info={`${num(r.malicious_matched)} known malicious`} />
          <Counter label="Potential false positives" value={num(r.potential_false_positives)} info={`${r.fp_rate_percent.toFixed(3)}% of matched traffic`} />
          <Counter label="Risk reduction" value={<Status value={GOOD_BAD[r.risk_reduction]} label={humanize(r.risk_reduction.toLowerCase())} />} />
          <Counter label="Legitimate impact" value={<Status value={IMPACT[r.legitimate_impact]} label={humanize(r.legitimate_impact.toLowerCase())} />} />
        </ColumnLayout>
        <KeyValuePairs columns={4} items={[
          { label: 'Would allow', value: num(r.would_allow) },
          { label: 'Newly allowed', value: num(r.newly_allowed) },
          { label: 'Allow-list check', value: <Status value={r.allow_list_passed ? 'passed' : 'blocked_protected_entity'} label={r.allow_list_passed ? 'Passed' : 'Protected entity matched'} /> },
          { label: 'Affected accounts / Web ACLs', value: `${r.affected_accounts.length} / ${r.affected_webacls.length}` },
        ]} />
        {r.false_positive_samples.length > 0 && (
          <Table variant="embedded" header={<Header variant="h3">Sample requests that look legitimate</Header>}
            items={r.false_positive_samples} trackBy={x => `${x.timestamp}-${x.client_ip}-${x.uri}`}
            columnDefinitions={['timestamp', 'client_ip', 'http_method', 'uri', 'action', 'matched_rule_name'].map(k => ({
              id: k, header: humanize(k), cell: (x: Record<string, unknown>) => (k === 'timestamp' ? dateTime(String(x[k])) : dash(x[k] as string)),
            }))} />
        )}
      </SpaceBetween>
    </Container>
  );
}

export function SimulatePage() {
  const [params] = useSearchParams();
  const { webacls, rules, accounts } = useAppStore();
  const simulation = useSimulation();
  const [type, setType] = useState<ProposalType>((params.get('type') as ProposalType) || 'BLOCK_IPS');
  const [targets, setTargets] = useState((params.get('targets') ?? '').split(',').filter(Boolean).join('\n'));
  const [ja4, setJa4] = useState(params.get('ja4') ?? '');
  const [webaclId, setWebaclId] = useState(params.get('webacl') ?? '');
  const [ruleName, setRuleName] = useState(params.get('rule') ?? '');
  const [action, setAction] = useState<'BLOCK' | 'COUNT'>((params.get('action') as 'BLOCK' | 'COUNT') || 'BLOCK');
  const [limit, setLimit] = useState('100');
  const [windowHours, setWindowHours] = useState('168');
  const [result, setResult] = useState<SimulationResult | null>(null);
  const [ttl, setTtl] = useState('24');
  const [blockAcl, setBlockAcl] = useState('');
  const [approval, setApproval] = useState<Omit<ApprovalRequestBody, 'reason'> | null>(null);

  const targetList = targets.split(/[\s,]+/).map(t => t.trim()).filter(Boolean);
  const acl = webacls.find(w => w.id === webaclId);
  const aclRules = (rules.get(webaclId) ?? []).filter(r => type !== 'RATE_LIMIT' || r.rule_type === 'RATE_BASED');
  const limitNum = Number(limit);
  const ready = type === 'BLOCK_IPS' ? targetList.length > 0
    : type === 'BLOCK_JA4' ? ja4.trim().length > 0
      : Boolean(webaclId && ruleName) && (type !== 'RATE_LIMIT' || limitNum >= 10);
  const title = type === 'BLOCK_IPS' ? `Block ${targetList.length} IP(s): ${targetList.slice(0, 3).join(', ')}`
    : type === 'BLOCK_JA4' ? `Block JA4 ${ja4.slice(0, 20)}`
      : type === 'RULE_ACTION' ? `${ruleName} -> ${action}` : `${ruleName} rate limit -> ${limitNum}`;

  const run = async () => {
    setResult(null);
    const out = await simulation.mutateAsync({
      title,
      window_hours: Number(windowHours),
      proposal: type === 'BLOCK_IPS' ? { type, targets: targetList }
        : type === 'BLOCK_JA4' ? { type, ja4: ja4.trim() }
          : type === 'RULE_ACTION' ? { type, webacl_id: webaclId, rule_name: ruleName, new_action: action }
            : { type, webacl_id: webaclId, rule_name: ruleName, limit: limitNum },
    }).catch(e => { notify('error', e instanceof Error ? e.message : String(e), 'Simulation failed'); return null; });
    setResult(out);
    // Default the block target to an affected Web ACL that carries the platform blocklist IP-set rule.
    const withBlocklist = out?.affected_webacls.find(id => (rules.get(id) ?? []).some(r => r.rule_type === 'IP_SET'));
    setBlockAcl(withBlocklist ?? out?.affected_webacls[0] ?? '');
  };

  const requestBody = (): Omit<ApprovalRequestBody, 'reason'> | null => {
    if (!result) return null;
    if (type === 'BLOCK_IPS') {
      const target = webacls.find(w => w.id === blockAcl);
      if (!target) return null;
      return {
        action_type: ttl === 'perm' ? 'PERM_BLOCK_IP' : 'TEMP_BLOCK_IP', account_id: target.account_id, webacl_id: target.id,
        target: targetList[0], targets: targetList.slice(1), ttl_hours: ttl === 'perm' ? undefined : Number(ttl), simulation_id: result.id,
      };
    }
    if (!acl) return null;
    return type === 'RULE_ACTION'
      ? { action_type: 'MODIFY_RULE', account_id: acl.account_id, webacl_id: acl.id, rule_name: ruleName, action, simulation_id: result.id }
      : { action_type: 'MODIFY_RATE_LIMIT', account_id: acl.account_id, webacl_id: acl.id, rule_name: ruleName, limit: limitNum, simulation_id: result.id };
  };

  const aclOption = (id: string) => {
    const w = webacls.find(x => x.id === id);
    return w ? { value: w.id, label: w.name, description: `${w.account_name} - ${w.scope === 'CLOUDFRONT' ? 'CloudFront' : w.region}` } : null;
  };
  const aclOptions = webacls.map(w => aclOption(w.id)!);

  return (
    <ContentLayout header={
      <Header variant="h1" description="Replay a proposed WAF change against historical traffic. Simulation never changes AWS and is required before an approval request.">
        Simulate a change
      </Header>}>
      <SpaceBetween size="l">
        <form onSubmit={e => { e.preventDefault(); if (ready) void run(); }}>
          <Form actions={<Button variant="primary" loading={simulation.isPending} disabled={!ready} formAction="submit">Run simulation</Button>}>
            <Container header={<Header variant="h2" description="Step 1: describe the change">Proposed change</Header>}>
              <SpaceBetween size="l">
                <FormField label="Change type" stretch>
                  <Tiles value={type} onChange={e => { setType(e.detail.value as ProposalType); setResult(null); }} columns={4} items={[
                    { value: 'BLOCK_IPS', label: 'Block IP addresses', description: 'Add IPs or CIDRs to the platform blocklist' },
                    { value: 'BLOCK_JA4', label: 'Block JA4 fingerprint', description: 'Impact of blocking a TLS fingerprint' },
                    { value: 'RULE_ACTION', label: 'Change rule action', description: 'Switch a rule between BLOCK and COUNT' },
                    { value: 'RATE_LIMIT', label: 'Change rate limit', description: 'New threshold for a rate-based rule' },
                  ]} />
                </FormField>
                {type === 'BLOCK_IPS' && (
                  <FormField label="IP addresses or CIDRs" description="One per line or comma-separated." constraintText={`${targetList.length} target(s)`}>
                    <Textarea value={targets} onChange={e => setTargets(e.detail.value)} placeholder={'185.220.101.42\n45.155.205.0/24'} rows={4} />
                  </FormField>
                )}
                {type === 'BLOCK_JA4' && (
                  <FormField label="JA4 fingerprint">
                    <Input value={ja4} onChange={e => setJa4(e.detail.value)} placeholder="t13d1516h2_8daaf6152771_b186095e22b6" />
                  </FormField>
                )}
                {(type === 'RULE_ACTION' || type === 'RATE_LIMIT') && (
                  <ColumnLayout columns={3}>
                    <FormField label="Web ACL">
                      <Select selectedOption={aclOption(webaclId)} placeholder="Choose a Web ACL" filteringType="auto" options={aclOptions}
                        onChange={e => { setWebaclId(e.detail.selectedOption.value!); setRuleName(''); }} />
                    </FormField>
                    <FormField label="Rule">
                      <Select selectedOption={ruleName ? { value: ruleName, label: ruleName } : null} placeholder="Choose a rule"
                        options={aclRules.map(r => ({ value: r.name, label: r.name, description: `Currently ${r.action}${r.rate_limit ? `, limit ${r.rate_limit}` : ''}` }))}
                        onChange={e => setRuleName(e.detail.selectedOption.value!)} disabled={!webaclId}
                        empty={type === 'RATE_LIMIT' ? 'No rate-based rules in this Web ACL' : 'No rules'} />
                    </FormField>
                    {type === 'RULE_ACTION' ? (
                      <FormField label="New action">
                        <SegmentedControl selectedId={action} onChange={e => setAction(e.detail.selectedId as 'BLOCK' | 'COUNT')}
                          options={[{ id: 'BLOCK', text: 'BLOCK' }, { id: 'COUNT', text: 'COUNT' }]} />
                      </FormField>
                    ) : (
                      <FormField label="Requests per 5 minutes per IP" errorText={limitNum < 10 ? 'Minimum is 10' : undefined}>
                        <Input type="number" value={limit} onChange={e => setLimit(e.detail.value)} />
                      </FormField>
                    )}
                  </ColumnLayout>
                )}
                <FormField label="Evaluation window">
                  <Select selectedOption={WINDOWS.find(w => w.value === windowHours)!} options={WINDOWS} onChange={e => setWindowHours(e.detail.selectedOption.value!)} />
                </FormField>
              </SpaceBetween>
            </Container>
          </Form>
        </form>

        {result && <SimulationResultView r={result} />}

        {result && type === 'BLOCK_JA4' && (
          <Alert type="info" header="JA4 blocks are simulation-only">
            The approval workflow does not create JA4 rules. To act, block the campaign's member IPs or roll out a JA4 rule
            through your infrastructure-as-code pipeline.
          </Alert>
        )}

        {result && type !== 'BLOCK_JA4' && (
          <Container header={<Header variant="h2" description="Step 2: guardrails check the request and route it to the required approvers">Request approval</Header>}>
            <SpaceBetween size="m">
              {type === 'BLOCK_IPS' && (
                <ColumnLayout columns={2}>
                  <FormField label="Block in Web ACL" description="Its platform blocklist IP set receives the targets.">
                    <Select selectedOption={aclOption(blockAcl)} placeholder="Choose a Web ACL" filteringType="auto" options={aclOptions}
                      onChange={e => setBlockAcl(e.detail.selectedOption.value!)} />
                  </FormField>
                  <FormField label="Duration" description="Temporary blocks expire automatically. Permanent blocks need a Security Admin.">
                    <Select selectedOption={TTLS.find(t => t.value === ttl)!} options={TTLS} onChange={e => setTtl(e.detail.selectedOption.value!)} />
                  </FormField>
                </ColumnLayout>
              )}
              {type !== 'BLOCK_IPS' && acl && (
                <KeyValuePairs columns={3} items={[
                  { label: 'Account', value: accounts.find(a => a.account_id === acl.account_id)?.name ?? acl.account_id },
                  { label: 'Web ACL', value: acl.name }, { label: 'Rule', value: ruleName },
                ]} />
              )}
              <Box><Button variant="primary" disabled={!requestBody()} onClick={() => setApproval(requestBody())}>Request approval</Button></Box>
            </SpaceBetween>
          </Container>
        )}
      </SpaceBetween>
      <ApprovalModal title="Request approval" body={approval} onDismiss={() => setApproval(null)}
        summary={approval && <KeyValuePairs columns={2} items={[
          { label: 'Change', value: title },
          { label: 'Simulation', value: `${num(result?.would_block)} would block, ${num(result?.potential_false_positives)} potential false positives` },
        ]} />} />
    </ContentLayout>
  );
}

// --- approvals ------------------------------------------------------------------------------------------------

const STATUS_FILTERS = ['all', 'pending', 'approved', 'completed', 'rejected', 'failed', 'rolled_back'];
const statusOption = (v: string) => ({ value: v, label: v === 'all' ? 'All statuses' : humanize(v) });

export function ApprovalsPage() {
  const approvals = useAppStore(s => s.approvals);
  const [status, setStatus] = useState('all');
  const items = approvals.filter(a => status === 'all' || a.status === status);
  return (
    <ResourceTable<Approval>
      title="Approvals"
      description="Every AWS change request: simulation, guardrail check, approvers, execution and verification."
      items={items}
      defaultSort="requested"
      sortDescending
      filters={<div style={{ width: 200 }}>
        <Select selectedOption={statusOption(status)} options={STATUS_FILTERS.map(statusOption)} onChange={e => setStatus(e.detail.selectedOption.value!)} />
      </div>}
      columns={[
        { id: 'code', header: 'Request', cell: a => <RouterLink to={`/response/approvals/${a.id}`}>{a.approval_code}</RouterLink>, sort: a => a.approval_code },
        { id: 'action', header: 'Action', cell: a => actionLabel(a.action_type), sort: a => a.action_type },
        { id: 'target', header: 'Target', cell: a => a.target, sort: a => a.target },
        { id: 'status', header: 'Status', cell: a => <Status value={a.status} />, sort: a => a.status },
        { id: 'risk', header: 'Risk', cell: a => <Status value={a.risk_level.toLowerCase()} />, sort: a => a.risk_level },
        { id: 'guard', header: 'Guardrails', cell: a => <Status value={a.allow_list_check} /> },
        { id: 'by', header: 'Requested by', cell: a => a.requested_by, sort: a => a.requested_by },
        { id: 'requested', header: 'Requested', cell: a => ago(a.requested_at), sort: a => a.requested_at },
      ]}
    />
  );
}

interface Change {
  id: string; approval_id: string; account_id: string; aws_request_id: string | null; execution_status: string;
  verification_status: string | null; ttl_status: string | null; expires_at: string | null; executed_at: string;
  rolled_back_at: string | null; rolled_back_by: string | null; rollback_available: boolean;
}
interface ApprovalDetail {
  approval: Approval;
  lifecycle: { step: string; state: 'completed' | 'skipped' | 'blocked' | 'active' | 'pending' }[];
  decisions: { slot: string; decided_by: string; role: string; decision: string; comment: string | null; decided_at: string }[];
  proposed_state: Record<string, unknown>;
  previous_state: Record<string, unknown>;
  changes: Change[];
}
const STEP_STATUS: Record<string, StepsProps.Status> = {
  completed: 'success', skipped: 'stopped', blocked: 'error', active: 'in-progress', pending: 'pending',
};
const json = (v: unknown) => <pre style={{ margin: 0, whiteSpace: 'pre-wrap', fontSize: 12 }}>{JSON.stringify(v, null, 2)}</pre>;

export function ApprovalDetailPage() {
  const { id } = useParams();
  const can = useCan();
  const { approveRequest, rejectRequest } = useAppStore();
  const detail = useGet<ApprovalDetail>(id ? `/api/v1/approvals/${id}` : null, ['approval', id]);
  const [decision, setDecision] = useState<'APPROVE' | 'REJECT' | null>(null);
  const [comment, setComment] = useState('');
  const [busy, setBusy] = useState(false);
  if (detail.isLoading) return <Loading />;
  if (!detail.data) return <Alert type="error" header="Approval not found">{detail.error?.message}</Alert>;
  const { approval: a, lifecycle, decisions, proposed_state, previous_state, changes } = detail.data;

  const decide = async () => {
    const approving = decision === 'APPROVE';
    setBusy(true);
    const ok = await (approving ? approveRequest : rejectRequest)(a.id, comment || undefined);
    setBusy(false);
    setDecision(null);
    setComment('');
    await queryClient.invalidateQueries({ queryKey: ['approval', id] });
    if (ok) notify('success', approving ? 'Decision recorded. When all required approvals are in, the change is executed and verified.' : 'Request rejected.');
  };

  return (
    <ContentLayout header={
      <Header variant="h1" description={`${actionLabel(a.action_type)}: ${a.target}`}
        actions={a.status === 'pending' && (
          <SpaceBetween direction="horizontal" size="xs">
            <Button disabled={!can('APPROVE')} onClick={() => setDecision('REJECT')}>Reject</Button>
            <Button variant="primary" disabled={!can('APPROVE')} onClick={() => setDecision('APPROVE')}>Approve</Button>
          </SpaceBetween>
        )}>
        {a.approval_code}
      </Header>}>
      <SpaceBetween size="l">
        {a.status === 'failed' && (
          <Alert type="error" header="Execution or verification failed">
            The approval was recorded, but the AWS change did not complete or could not be verified. The error is recorded in
            the <RouterLink to="/governance/audit">audit trail</RouterLink>.
          </Alert>
        )}
        <Container header={<Header variant="h2" description="Detect to audit; nothing reaches AWS before approval">Change lifecycle</Header>}>
          <Steps orientation="horizontal" steps={lifecycle.map(s => ({ status: STEP_STATUS[s.state], header: humanize(s.step.toLowerCase()) }))} />
        </Container>
        <Container header={<Header variant="h2">Request details</Header>}>
          <SpaceBetween size="m">
            <KeyValuePairs columns={4} items={[
              { label: 'Status', value: <Status value={a.status} /> },
              { label: 'Risk', value: <Status value={a.risk_level.toLowerCase()} /> },
              { label: 'Guardrails', value: <Status value={a.allow_list_check} /> },
              { label: 'Required approvers', value: a.required_approver_role },
              { label: 'Requested by', value: a.requested_by },
              { label: 'Requested', value: dateTime(a.requested_at) },
              { label: 'Approver', value: dash(a.approver) },
              { label: 'Expires', value: a.expires_at ? dateTime(a.expires_at) : 'Never' },
              { label: 'Simulation', value: dash(a.simulation_result) },
              { label: 'Impact', value: `${a.impact.affected_accounts} account(s), ${a.impact.affected_webacls} Web ACL(s)` },
              { label: 'Verification', value: a.verification_status ? <Status value={a.verification_status} /> : '-' },
              { label: 'AWS request ID', value: a.aws_request_id ? <Box variant="code">{a.aws_request_id}</Box> : '-' },
            ]} />
            <div><Box variant="awsui-key-label">Justification</Box><Box>{a.reason}</Box></div>
          </SpaceBetween>
        </Container>
        <Tabs tabs={[
          { id: 'diff', label: 'Proposed change', content: (
            <ColumnLayout columns={2}>
              <Container header={<Header variant="h3">Current state</Header>}>{json(previous_state)}</Container>
              <Container header={<Header variant="h3">Proposed state</Header>}>{json(proposed_state)}</Container>
            </ColumnLayout>) },
          { id: 'decisions', label: `Decisions (${decisions.length})`, content: (
            <Table variant="container" items={decisions} trackBy={d => `${d.slot}-${d.decided_by}`}
              columnDefinitions={[
                { id: 'slot', header: 'Approval slot', cell: d => d.slot },
                { id: 'by', header: 'Decided by', cell: d => `${d.decided_by} (${d.role})` },
                { id: 'decision', header: 'Decision', cell: d => <Status value={d.decision === 'APPROVE' ? 'approved' : 'rejected'} label={d.decision} /> },
                { id: 'comment', header: 'Comment', cell: d => dash(d.comment) },
                { id: 'at', header: 'When', cell: d => dateTime(d.decided_at) },
              ]}
              empty={<Box textAlign="center">No decisions yet</Box>} />) },
          { id: 'changes', label: `Executions (${changes.length})`, content: <ChangeTable items={changes} variant="container" /> },
        ]} />
      </SpaceBetween>
      <Modal visible={decision !== null} onDismiss={() => setDecision(null)} header={decision === 'APPROVE' ? 'Approve change' : 'Reject change'}
        footer={<Box float="right"><SpaceBetween direction="horizontal" size="xs">
          <Button variant="link" onClick={() => setDecision(null)}>Cancel</Button>
          <Button variant="primary" loading={busy} onClick={decide}>{decision === 'APPROVE' ? 'Approve' : 'Reject'}</Button>
        </SpaceBetween></Box>}>
        <SpaceBetween size="m">
          {decision === 'APPROVE' && (
            <Alert type="warning">
              If this completes the required approvals, the change executes in AWS immediately. The backend then re-reads AWS
              to verify the result and records everything in the audit trail.
            </Alert>
          )}
          <FormField label="Comment" description="Optional. Recorded in the audit trail.">
            <Textarea value={comment} onChange={e => setComment(e.detail.value)} rows={3} />
          </FormField>
        </SpaceBetween>
      </Modal>
    </ContentLayout>
  );
}

// --- changes & active blocks ----------------------------------------------------------------------------------

function ChangeTable({ items, variant, loading }: { items: Change[]; variant?: 'container'; loading?: boolean }) {
  const can = useCan();
  const rollbackChange = useAppStore(s => s.rollbackChange);
  const [selected, setSelected] = useState<Change[]>([]);
  const [rollback, setRollback] = useState<Change | null>(null);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    if (!rollback) return;
    setBusy(true);
    const ok = await rollbackChange(rollback.id, reason.trim());
    setBusy(false);
    setRollback(null);
    setReason('');
    await queryClient.invalidateQueries({ queryKey: ['changes'] });
    await queryClient.invalidateQueries({ queryKey: ['active-blocks'] });
    await queryClient.invalidateQueries({ queryKey: ['approval'] });
    if (ok) notify('success', 'Change rolled back and verified in AWS.', 'Rollback complete');
  };
  return (
    <>
      <ResourceTable<Change>
        title="Change history"
        variant={variant}
        items={items}
        loading={loading}
        selectionType="single"
        selected={selected}
        onSelect={setSelected}
        defaultSort="executed"
        sortDescending
        actions={<Button disabled={!selected[0]?.rollback_available || !can('ROLLBACK')} onClick={() => setRollback(selected[0])}>Roll back</Button>}
        columns={[
          { id: 'approval', header: 'Approval', cell: c => <RouterLink to={`/response/approvals/${c.approval_id}`}>View request</RouterLink> },
          { id: 'account', header: 'Account', cell: c => c.account_id, sort: c => c.account_id },
          { id: 'exec', header: 'Execution', cell: c => <Status value={c.execution_status} />, sort: c => c.execution_status },
          { id: 'verify', header: 'Verification', cell: c => (c.verification_status ? <Status value={c.verification_status} /> : '-') },
          { id: 'ttl', header: 'Expiry', cell: c => (c.expires_at ? `${humanize((c.ttl_status ?? 'active').toLowerCase())}, ${ago(c.expires_at)}` : '-') },
          { id: 'req', header: 'AWS request ID', cell: c => dash(c.aws_request_id) },
          { id: 'executed', header: 'Executed', cell: c => ago(c.executed_at), sort: c => c.executed_at },
          { id: 'rolled', header: 'Rolled back', cell: c => (c.rolled_back_at ? `${ago(c.rolled_back_at)} by ${c.rolled_back_by}` : '-') },
        ]}
        empty="No changes executed yet"
      />
      <Modal visible={rollback !== null} onDismiss={() => setRollback(null)} header="Roll back change"
        footer={<Box float="right"><SpaceBetween direction="horizontal" size="xs">
          <Button variant="link" onClick={() => setRollback(null)}>Cancel</Button>
          <Button variant="primary" loading={busy} disabled={reason.trim().length < 3} onClick={submit}>Roll back</Button>
        </SpaceBetween></Box>}>
        <SpaceBetween size="m">
          <Alert type="warning">This restores the previous AWS state immediately and is recorded in the audit trail.</Alert>
          <FormField label="Reason"><Textarea value={reason} onChange={e => setReason(e.detail.value)} rows={3} /></FormField>
        </SpaceBetween>
      </Modal>
    </>
  );
}

interface ActiveBlock {
  id: string; account_id: string; expires_at: string | null; ttl_status: string | null; executed_at: string;
  approval_code: string; target: string; action_type: string;
}

export function ChangesPage() {
  const changes = useGet<Change[]>('/api/v1/changes', ['changes']);
  const blocks = useGet<ActiveBlock[]>('/api/v1/response/active-blocks', ['active-blocks']);
  return (
    <ContentLayout header={<Header variant="h1" description="Executed changes, live IP blocks and their expiry. Roll back any change with a recorded previous state.">Changes & active blocks</Header>}>
      <Tabs tabs={[
        { id: 'blocks', label: `Active blocks (${blocks.data?.length ?? 0})`, content: (
          <ResourceTable<ActiveBlock> title="Active blocks" variant="container" items={blocks.data ?? []} loading={blocks.isLoading}
            defaultSort="expires" empty="No IP blocks are active"
            columns={[
              { id: 'target', header: 'Target', cell: b => <Box variant="code">{b.target}</Box>, sort: b => b.target },
              { id: 'type', header: 'Type', cell: b => (b.action_type === 'TEMP_BLOCK_IP' ? 'Temporary' : 'Permanent'), sort: b => b.action_type },
              { id: 'account', header: 'Account', cell: b => b.account_id, sort: b => b.account_id },
              { id: 'code', header: 'Approval', cell: b => b.approval_code },
              { id: 'executed', header: 'Blocked since', cell: b => ago(b.executed_at), sort: b => b.executed_at },
              { id: 'expires', header: 'Expires', cell: b => (b.expires_at ? ago(b.expires_at) : 'Never'), sort: b => b.expires_at ?? '9' },
              { id: 'ttl', header: 'Expiry status', cell: b => (b.ttl_status ? humanize(b.ttl_status.toLowerCase()) : '-') },
            ]} />) },
        { id: 'history', label: 'Change history', content: <ChangeTable items={changes.data ?? []} variant="container" loading={changes.isLoading} /> },
      ]} />
    </ContentLayout>
  );
}

// --- allow list -----------------------------------------------------------------------------------------------

interface AllowEntry {
  id: string; cidr_or_value: string; entity_type: string; name: string; category: string; owner: string;
  reason: string; is_active: boolean; created_by: string; created_at: string;
}
const CATEGORIES = ['INTERNAL_NETWORK', 'PAYMENT_GATEWAY', 'PARTNER_API', 'MONITORING', 'SECURITY_SCANNER'];
const ENTRY_TYPES = ['IP_CIDR', 'ASN', 'HEALTH_CHECK'];
const EMPTY_ENTRY = { cidr_or_value: '', entity_type: 'IP_CIDR', name: '', category: 'PARTNER_API', owner: '', reason: '' };
const enumOption = (v: string) => ({ value: v, label: humanize(v.toLowerCase()) });

export function AllowListPage() {
  const can = useCan();
  const list = useGet<AllowEntry[]>('/api/v1/allow-list', ['allow-list']);
  const [showInactive, setShowInactive] = useState(false);
  const [selected, setSelected] = useState<AllowEntry[]>([]);
  const [adding, setAdding] = useState(false);
  const [form, setForm] = useState(EMPTY_ENTRY);
  const [removing, setRemoving] = useState<AllowEntry | null>(null);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const items = (list.data ?? []).filter(e => showInactive || e.is_active);
  const set = (k: keyof typeof form) => (e: { detail: { value: string } }) => setForm({ ...form, [k]: e.detail.value });
  const valid = form.cidr_or_value.trim() !== '' && form.name.length >= 2 && form.owner.length >= 2 && form.reason.length >= 5;

  const call = async (fn: () => Promise<unknown>, done: string) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      notify('success', done);
      setAdding(false);
      setRemoving(null);
      setForm(EMPTY_ENTRY);
      setReason('');
      setSelected([]);
      await queryClient.invalidateQueries({ queryKey: ['allow-list'] });
      await queryClient.invalidateQueries({ queryKey: ['bootstrap'] });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <ResourceTable<AllowEntry>
        title="Allow list"
        description="Protected entities (payment gateways, partners, internal networks). Guardrails deny any block that matches them."
        items={items}
        loading={list.isLoading}
        selectionType="single"
        selected={selected}
        onSelect={setSelected}
        defaultSort="name"
        filters={<SegmentedControl selectedId={showInactive ? 'all' : 'active'} onChange={e => setShowInactive(e.detail.selectedId === 'all')}
          options={[{ id: 'active', text: 'Active' }, { id: 'all', text: 'All' }]} />}
        actions={<SpaceBetween direction="horizontal" size="xs">
          <Button disabled={!selected[0]?.is_active || !can('APPROVE')} onClick={() => { setError(null); setRemoving(selected[0]); }}>Deactivate</Button>
          <Button variant="primary" disabled={!can('MANAGE_TI')} onClick={() => { setError(null); setAdding(true); }}>Add entry</Button>
        </SpaceBetween>}
        columns={[
          { id: 'name', header: 'Name', cell: e => e.name, sort: e => e.name },
          { id: 'value', header: 'Value', cell: e => <Box variant="code">{e.cidr_or_value}</Box>, sort: e => e.cidr_or_value },
          { id: 'type', header: 'Type', cell: e => humanize(e.entity_type.toLowerCase()) },
          { id: 'category', header: 'Category', cell: e => humanize(e.category.toLowerCase()), sort: e => e.category },
          { id: 'owner', header: 'Owner', cell: e => e.owner, sort: e => e.owner },
          { id: 'status', header: 'Status', cell: e => <Status value={e.is_active ? 'healthy' : 'stopped'} label={e.is_active ? 'Active' : 'Inactive'} /> },
          { id: 'created', header: 'Added', cell: e => `${ago(e.created_at)} by ${e.created_by}`, sort: e => e.created_at },
        ]}
      />
      <Modal visible={adding} onDismiss={() => setAdding(false)} header="Add allow-list entry"
        footer={<Box float="right"><SpaceBetween direction="horizontal" size="xs">
          <Button variant="link" onClick={() => setAdding(false)}>Cancel</Button>
          <Button variant="primary" loading={busy} disabled={!valid}
            onClick={() => call(() => api('/api/v1/allow-list', { method: 'POST', json: form }), `${form.name} is now protected from blocking.`)}>Add</Button>
        </SpaceBetween></Box>}>
        <Form errorText={error}>
          <SpaceBetween size="m">
            <ColumnLayout columns={2}>
              <FormField label="Type">
                <Select selectedOption={enumOption(form.entity_type)} options={ENTRY_TYPES.map(enumOption)}
                  onChange={e => setForm({ ...form, entity_type: e.detail.selectedOption.value! })} />
              </FormField>
              <FormField label={form.entity_type === 'ASN' ? 'ASN' : 'CIDR or IP'}>
                <Input value={form.cidr_or_value} onChange={set('cidr_or_value')} placeholder={form.entity_type === 'ASN' ? 'AS64500' : '203.0.113.0/24'} />
              </FormField>
            </ColumnLayout>
            <FormField label="Name"><Input value={form.name} onChange={set('name')} placeholder="Payment PSP callbacks" /></FormField>
            <ColumnLayout columns={2}>
              <FormField label="Category">
                <Select selectedOption={enumOption(form.category)} options={CATEGORIES.map(enumOption)}
                  onChange={e => setForm({ ...form, category: e.detail.selectedOption.value! })} />
              </FormField>
              <FormField label="Owner team"><Input value={form.owner} onChange={set('owner')} /></FormField>
            </ColumnLayout>
            <FormField label="Reason" constraintText="At least 5 characters"><Textarea value={form.reason} onChange={set('reason')} rows={2} /></FormField>
          </SpaceBetween>
        </Form>
      </Modal>
      <Modal visible={removing !== null} onDismiss={() => setRemoving(null)} header="Deactivate allow-list entry"
        footer={<Box float="right"><SpaceBetween direction="horizontal" size="xs">
          <Button variant="link" onClick={() => setRemoving(null)}>Cancel</Button>
          <Button variant="primary" loading={busy} disabled={reason.trim().length < 3}
            onClick={() => call(() => api(`/api/v1/allow-list/${removing!.id}/deactivate`, { method: 'POST', json: { reason } }), `${removing!.name} is no longer protected.`)}>Deactivate</Button>
        </SpaceBetween></Box>}>
        <Form errorText={error}>
          <SpaceBetween size="m">
            <Alert type="warning">{removing?.name} ({removing?.cidr_or_value}) will no longer be protected from automated blocking. Security Admin only.</Alert>
            <FormField label="Reason"><Textarea value={reason} onChange={e => setReason(e.detail.value)} rows={2} /></FormField>
          </SpaceBetween>
        </Form>
      </Modal>
    </>
  );
}
