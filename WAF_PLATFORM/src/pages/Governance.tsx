// Governance module: append-only audit trail (filter + CSV export), users & access (RBAC), platform health.
import React, { useState } from 'react';
import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Container from '@cloudscape-design/components/container';
import ContentLayout from '@cloudscape-design/components/content-layout';
import DatePicker from '@cloudscape-design/components/date-picker';
import Form from '@cloudscape-design/components/form';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import KeyValuePairs from '@cloudscape-design/components/key-value-pairs';
import Modal from '@cloudscape-design/components/modal';
import Multiselect from '@cloudscape-design/components/multiselect';
import Select from '@cloudscape-design/components/select';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Table from '@cloudscape-design/components/table';
import Toggle from '@cloudscape-design/components/toggle';
import { api, queryClient } from '@/api/client';
import { useGet, useMe } from '@/api/hooks';
import { useAppStore } from '@/store';
import { Counter, ResourceTable, RouterLink, Status, ago, dash, dateTime, humanize, notify, useCan, useSplit } from '@/ui';

// --- audit trail ----------------------------------------------------------------------------------------------

interface AuditRow {
  audit_code: string; timestamp: string; user_email: string; user_role: string; account_id: string; region: string;
  action: string; target_resource: string; previous_state: unknown; new_state: unknown; reason: string;
  risk_level: string; approver: string | null; approval_id: string | null; execution_status: string;
  aws_request_id: string | null; verification_status: string | null; rollback_available: boolean;
}

const json = (v: unknown) => <pre style={{ margin: 0, whiteSpace: 'pre-wrap', fontSize: 12 }}>{v ? JSON.stringify(v, null, 2) : '-'}</pre>;

function AuditDetail({ r }: { r: AuditRow }) {
  return (
    <SpaceBetween size="l">
      <KeyValuePairs columns={4} items={[
        { label: 'Actor', value: `${r.user_email} (${r.user_role})` },
        { label: 'Action', value: r.action },
        { label: 'Target', value: <Box variant="code">{r.target_resource}</Box> },
        { label: 'Account / region', value: `${r.account_id} / ${r.region}` },
        { label: 'Approval', value: r.approval_id ? <RouterLink to={`/response/approvals/${r.approval_id}`}>View request</RouterLink> : '-' },
        { label: 'Approver', value: dash(r.approver) },
        { label: 'AWS request ID', value: dash(r.aws_request_id) },
        { label: 'Verification', value: r.verification_status ? <Status value={r.verification_status} /> : '-' },
      ]} />
      <div><Box variant="awsui-key-label">Reason</Box><Box>{r.reason}</Box></div>
      <ColumnLayout columns={2}>
        <Container header={<Header variant="h3">Previous state</Header>}>{json(r.previous_state)}</Container>
        <Container header={<Header variant="h3">New state</Header>}>{json(r.new_state)}</Container>
      </ColumnLayout>
    </SpaceBetween>
  );
}

export function AuditPage() {
  const accounts = useAppStore(s => s.accounts);
  const openSplit = useSplit(s => s.open);
  const [action, setAction] = useState('');
  const [account, setAccount] = useState('');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [selected, setSelected] = useState<AuditRow[]>([]);
  const query = new URLSearchParams({
    ...(action.trim() ? { action: action.trim() } : {}), ...(account ? { account_id: account } : {}),
    ...(from ? { from: `${from}T00:00:00Z` } : {}), ...(to ? { to: `${to}T23:59:59Z` } : {}),
  }).toString();
  const rows = useGet<AuditRow[]>(`/api/v1/governance/audit?${query}`, ['audit', query]);
  const accountOptions = [
    { value: '', label: 'All accounts' }, { value: 'GLOBAL', label: 'Global (platform)' },
    ...accounts.map(a => ({ value: a.account_id, label: `${a.name} (${a.account_id})` })),
  ];

  return (
    <ResourceTable<AuditRow>
      title="Audit trail"
      description="Append-only record of every action: who, what, where, why, approver, AWS request ID and verification."
      items={rows.data ?? []}
      loading={rows.isLoading}
      trackBy="audit_code"
      selectionType="single"
      selected={selected}
      onSelect={sel => { setSelected(sel); if (sel[0]) openSplit(`${sel[0].audit_code}: ${sel[0].action}`, <AuditDetail r={sel[0]} />); }}
      defaultSort="time"
      sortDescending
      actions={<Button iconName="download" href={`/api/v1/governance/audit?format=csv&limit=10000&${query}`}>Export CSV</Button>}
      filters={<>
        <div style={{ width: 200 }}><Input value={action} onChange={e => setAction(e.detail.value)} placeholder="Action, e.g. APPROVE" type="search" /></div>
        <div style={{ width: 260 }}>
          <Select selectedOption={accountOptions.find(o => o.value === account) ?? accountOptions[0]} options={accountOptions}
            onChange={e => setAccount(e.detail.selectedOption.value ?? '')} />
        </div>
        <DatePicker value={from} onChange={e => setFrom(e.detail.value)} placeholder="From YYYY/MM/DD" />
        <DatePicker value={to} onChange={e => setTo(e.detail.value)} placeholder="To YYYY/MM/DD" />
      </>}
      columns={[
        { id: 'time', header: 'Time', cell: r => dateTime(r.timestamp), sort: r => r.timestamp, width: 190 },
        { id: 'code', header: 'Audit ID', cell: r => r.audit_code, sort: r => r.audit_code, width: 240 },
        { id: 'action', header: 'Action', cell: r => r.action, sort: r => r.action },
        { id: 'user', header: 'Actor', cell: r => r.user_email, sort: r => r.user_email },
        { id: 'target', header: 'Target', cell: r => r.target_resource, sort: r => r.target_resource },
        { id: 'account', header: 'Account', cell: r => r.account_id, sort: r => r.account_id },
        { id: 'risk', header: 'Risk', cell: r => <Status value={r.risk_level.toLowerCase()} />, sort: r => r.risk_level },
        { id: 'status', header: 'Result', cell: r => <Status value={r.execution_status} />, sort: r => r.execution_status },
      ]}
      empty="No audit events match the filters"
    />
  );
}

// --- users & access -------------------------------------------------------------------------------------------

interface UserRow {
  id: string; email: string; full_name: string; role: string; sso_subject_id: string; scoped_account_ids: string[];
  is_active: boolean; last_login_at: string | null;
}
const ROLES = ['Security Admin', 'Security Analyst', 'SOC Analyst', 'AWS Administrator', 'Application Owner', 'Auditor', 'Executive', 'Read Only'];
const EMPTY_USER = { email: '', full_name: '', role: 'SOC Analyst', sso_subject_id: '', scoped_account_ids: [] as string[] };

function MyAccess() {
  const me = useMe().data;
  return (
    <ContentLayout header={<Header variant="h1">Users & access</Header>}>
      <Container header={<Header variant="h2">Your access</Header>}>
        <SpaceBetween size="m">
          <KeyValuePairs columns={3} items={[
            { label: 'User', value: `${me?.full_name ?? ''} (${me?.email ?? ''})` },
            { label: 'Role', value: me?.role }, { label: 'MFA session', value: me?.mfa ? 'Yes' : 'No' },
          ]} />
          <div><Box variant="awsui-key-label">Permissions</Box><Box>{me?.permissions.join(', ')}</Box></div>
          <Alert type="info">Only a Security Admin can provision users and change roles.</Alert>
        </SpaceBetween>
      </Container>
    </ContentLayout>
  );
}

function UserAdmin() {
  const accounts = useAppStore(s => s.accounts);
  const users = useGet<UserRow[]>('/api/v1/governance/users', ['users']);
  const [selected, setSelected] = useState<UserRow[]>([]);
  const [editing, setEditing] = useState<UserRow | 'new' | null>(null);
  const [form, setForm] = useState(EMPTY_USER);
  const [active, setActive] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const accountOptions = accounts.map(a => ({ value: a.account_id, label: a.name, description: a.account_id }));
  const isNew = editing === 'new';
  const valid = form.full_name.length >= 2
    && (!isNew || (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(form.email) && form.sso_subject_id.length > 0));

  const open = (u: UserRow | 'new') => {
    setError(null);
    setEditing(u);
    setForm(u === 'new' ? EMPTY_USER
      : { email: u.email, full_name: u.full_name, role: u.role, sso_subject_id: u.sso_subject_id, scoped_account_ids: u.scoped_account_ids });
    setActive(u === 'new' || u.is_active);
  };
  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      if (editing === 'new') await api('/api/v1/governance/users', { method: 'POST', json: form });
      else if (editing) {
        await api(`/api/v1/governance/users/${editing.id}`, {
          method: 'PATCH', json: { full_name: form.full_name, role: form.role, scoped_account_ids: form.scoped_account_ids, is_active: active },
        });
      }
      notify('success', isNew ? `${form.email} provisioned. They can now sign in with SSO.` : `${form.email} updated.`);
      setEditing(null);
      await queryClient.invalidateQueries({ queryKey: ['users'] });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <ResourceTable<UserRow>
        title="Users"
        description="People who can sign in. Users are never auto-provisioned from SSO; access is granted here."
        items={users.data ?? []}
        loading={users.isLoading}
        selectionType="single"
        selected={selected}
        onSelect={setSelected}
        defaultSort="email"
        actions={<SpaceBetween direction="horizontal" size="xs">
          <Button disabled={!selected[0]} onClick={() => open(selected[0])}>Edit</Button>
          <Button variant="primary" onClick={() => open('new')}>Provision user</Button>
        </SpaceBetween>}
        columns={[
          { id: 'email', header: 'Email', cell: u => u.email, sort: u => u.email },
          { id: 'name', header: 'Name', cell: u => u.full_name, sort: u => u.full_name },
          { id: 'role', header: 'Role', cell: u => u.role, sort: u => u.role },
          { id: 'scope', header: 'Account scope', cell: u => (u.scoped_account_ids.length ? u.scoped_account_ids.join(', ') : 'All accounts') },
          { id: 'active', header: 'Status', cell: u => <Status value={u.is_active ? 'healthy' : 'stopped'} label={u.is_active ? 'Active' : 'Deactivated'} />, sort: u => String(u.is_active) },
          { id: 'login', header: 'Last sign-in', cell: u => ago(u.last_login_at), sort: u => u.last_login_at ?? '' },
        ]}
      />
      <Modal visible={editing !== null} onDismiss={() => setEditing(null)} header={isNew ? 'Provision user' : `Edit ${form.email}`}
        footer={<Box float="right"><SpaceBetween direction="horizontal" size="xs">
          <Button variant="link" onClick={() => setEditing(null)}>Cancel</Button>
          <Button variant="primary" loading={busy} disabled={!valid} onClick={save}>{isNew ? 'Provision' : 'Save'}</Button>
        </SpaceBetween></Box>}>
        <Form errorText={error}>
          <SpaceBetween size="m">
            {isNew && <FormField label="Email"><Input value={form.email} onChange={e => setForm({ ...form, email: e.detail.value })} placeholder="name@example.com" /></FormField>}
            <FormField label="Full name"><Input value={form.full_name} onChange={e => setForm({ ...form, full_name: e.detail.value })} /></FormField>
            {isNew && (
              <FormField label="SSO subject" description="The 'sub' claim from IAM Identity Center for this person.">
                <Input value={form.sso_subject_id} onChange={e => setForm({ ...form, sso_subject_id: e.detail.value })} />
              </FormField>
            )}
            <FormField label="Role">
              <Select selectedOption={{ value: form.role, label: form.role }} options={ROLES.map(r => ({ value: r, label: r }))}
                onChange={e => setForm({ ...form, role: e.detail.selectedOption.value! })} />
            </FormField>
            <FormField label="Account scope" description="Leave empty for all accounts. Scoped roles only see and change these accounts.">
              <Multiselect selectedOptions={accountOptions.filter(o => form.scoped_account_ids.includes(o.value))} options={accountOptions}
                onChange={e => setForm({ ...form, scoped_account_ids: e.detail.selectedOptions.map(o => o.value!) })} placeholder="All accounts" />
            </FormField>
            {!isNew && <Toggle checked={active} onChange={e => setActive(e.detail.checked)}>Active (deactivating ends their sessions)</Toggle>}
          </SpaceBetween>
        </Form>
      </Modal>
    </>
  );
}

export function UsersPage() {
  return useCan()('MANAGE_USERS') ? <UserAdmin /> : <MyAccess />;
}

// --- platform health ------------------------------------------------------------------------------------------

const COMPONENTS = [
  ['aws_api', 'AWS API (STS, WAFv2)'], ['queue', 'Sync queue (Step Functions)'], ['workers', 'Pipeline workers'],
  ['database', 'Database'], ['threat_intel', 'Threat intelligence providers'],
] as const;

export function HealthPage() {
  const health = useAppStore(s => s.platformHealth);
  return (
    <ContentLayout header={<Header variant="h1" description="Pipeline components and per-account collectors. A degraded collector means stale or partial data for that account.">Platform health</Header>}>
      <SpaceBetween size="l">
        <Container header={<Header variant="h2">Summary</Header>}>
          <ColumnLayout columns={3} variant="text-grid">
            <Counter label="Overall" value={<Status value={health.overall === 'critical' ? 'unavailable' : health.overall} label={humanize(health.overall)} />} />
            <Counter label="Last sync" value={ago(health.last_sync)} info={dateTime(health.last_sync)} />
            <Counter label="Data freshness" value={health.data_freshness} />
          </ColumnLayout>
        </Container>
        <Table variant="container" header={<Header variant="h2">Components</Header>} items={[...COMPONENTS]} trackBy={([k]) => k}
          columnDefinitions={[
            { id: 'name', header: 'Component', cell: ([, label]) => label },
            { id: 'status', header: 'Status', cell: ([k]) => <Status value={health[k].status} /> },
            { id: 'detail', header: 'Detail', cell: ([k]) => health[k].detail },
            { id: 'check', header: 'Last check', cell: ([k]) => ago(health[k].last_check) },
          ]} />
        <Table variant="container" header={<Header variant="h2" counter={`(${health.collectors.length})`}>Account collectors</Header>}
          items={health.collectors} trackBy="account_id"
          columnDefinitions={[
            { id: 'account', header: 'Account', cell: c => `${c.account_name} (${c.account_id})` },
            { id: 'status', header: 'Status', cell: c => <Status value={c.status} /> },
            { id: 'last', header: 'Last success', cell: c => ago(c.last_success) },
            { id: 'error', header: 'Error', cell: c => dash(c.error) },
            { id: 'modules', header: 'Affected modules', cell: c => c.affected_modules.join(', ') || '-' },
          ]}
          empty={<Box textAlign="center">No collectors have reported yet</Box>} />
      </SpaceBetween>
    </ContentLayout>
  );
}
