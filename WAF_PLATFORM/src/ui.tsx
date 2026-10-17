// Shared console building blocks (Cloudscape): status mapping, formatting, flash notifications, permission checks,
// and one generic resource table so every list page filters, sorts and paginates the same way.
import React from 'react';
import { create } from 'zustand';
import { useNavigate } from 'react-router-dom';
import { useCollection } from '@cloudscape-design/collection-hooks';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import Header from '@cloudscape-design/components/header';
import Link from '@cloudscape-design/components/link';
import Pagination from '@cloudscape-design/components/pagination';
import StatusIndicator, { type StatusIndicatorProps } from '@cloudscape-design/components/status-indicator';
import Table, { type TableProps } from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';
import type { FlashbarProps } from '@cloudscape-design/components/flashbar';
import Form from '@cloudscape-design/components/form';
import FormField from '@cloudscape-design/components/form-field';
import Modal from '@cloudscape-design/components/modal';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Textarea from '@cloudscape-design/components/textarea';
import { useMe } from '@/api/hooks';
import { useAppStore, type ApprovalRequestBody } from '@/store';

// --- status ---------------------------------------------------------------------------------------------------

const STATUS: Record<string, StatusIndicatorProps.Type> = {
  critical: 'error', high: 'warning', medium: 'info', low: 'success', none: 'stopped', unknown: 'stopped',
  healthy: 'success', degraded: 'warning', unavailable: 'error',
  protected: 'success', partially_protected: 'warning', unprotected: 'error',
  pending: 'pending', approved: 'success', rejected: 'stopped', executing: 'in-progress', completed: 'success',
  failed: 'error', rolled_back: 'stopped', active: 'error', monitoring: 'warning', resolved: 'success',
  suppressed: 'stopped', open: 'warning', acknowledged: 'info', new: 'warning', investigating: 'in-progress',
  correlated: 'info', actioned: 'success', false_positive: 'stopped',
  block: 'success', allow: 'error', count: 'warning', captcha: 'info', challenge: 'info',
  passed: 'success', blocked_protected_entity: 'error', verified: 'success', executed: 'success',
  malicious: 'error', suspicious: 'warning', legitimate: 'success',
  full: 'success', sampled: 'warning', metrics: 'info',
};

export function Status({ value, label }: { value: string | null | undefined; label?: string }) {
  const key = String(value ?? 'unknown').toLowerCase();
  return <StatusIndicator type={STATUS[key] ?? 'info'}>{label ?? humanize(key)}</StatusIndicator>;
}

const ACTION_LABELS: Record<string, string> = {
  TEMP_BLOCK_IP: 'Temporary IP block', PERM_BLOCK_IP: 'Permanent IP block', REMOVE_BLOCK: 'Remove IP block',
  MODIFY_RULE: 'Change rule action', ADD_EXCEPTION: 'Add rule exception', MODIFY_RATE_LIMIT: 'Change rate limit',
  ATTACH_WAF: 'Attach Web ACL', REMEDIATE_DRIFT: 'Remediate drift',
};
export const actionLabel = (t: string) => ACTION_LABELS[t] ?? humanize(t.toLowerCase());

export const humanize = (s: string) => s.replace(/[_-]+/g, ' ').replace(/^\w/, c => c.toUpperCase());

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, healthy: 4, none: 5, unknown: 6 };
export const severityRank = (s: string) => SEVERITY_ORDER[s] ?? 9;

// --- formatting -----------------------------------------------------------------------------------------------

export const num = (n: number | null | undefined) => (n ?? 0).toLocaleString();

export function ago(iso: string | null | undefined): string {
  if (!iso) return '-';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '-';
  const s = Math.round((Date.now() - t) / 1000);
  if (s < 0) return `in ${Math.max(1, Math.round(-s / 60))} min`;
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

export const dateTime = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString() : '-');

export const dash = (v: React.ReactNode) => (v === null || v === undefined || v === '' ? '-' : v);

// --- notifications --------------------------------------------------------------------------------------------

interface FlashState {
  items: FlashbarProps.MessageDefinition[];
  push: (type: FlashbarProps.Type, content: React.ReactNode, header?: React.ReactNode) => void;
  dismiss: (id: string) => void;
}

export const useFlash = create<FlashState>((set, get) => ({
  items: [],
  push: (type, content, header) => {
    const id = crypto.randomUUID();
    const dismiss = () => get().dismiss(id);
    set(s => ({ items: [{ id, type, content, header, dismissible: true, onDismiss: dismiss }, ...s.items].slice(0, 5) }));
    if (type === 'success') setTimeout(dismiss, 8_000);
  },
  dismiss: id => set(s => ({ items: s.items.filter(i => i.id !== id) })),
}));

export const notify = (type: FlashbarProps.Type, content: React.ReactNode, header?: React.ReactNode) =>
  useFlash.getState().push(type, content, header);

// --- split panel (AppLayout bottom panel, set by list pages for the selected row) ---------------------------

interface SplitState {
  panel: { header: string; content: React.ReactNode } | null;
  open: (header: string, content: React.ReactNode) => void;
  close: () => void;
}

export const useSplit = create<SplitState>(set => ({
  panel: null,
  open: (header, content) => set({ panel: { header, content } }),
  close: () => set({ panel: null }),
}));

// --- permissions (UI hint only; the API enforces RBAC) -------------------------------------------------------

export function useCan() {
  const perms = useMe().data?.permissions ?? [];
  return (perm: string) => perms.some(p => p === perm || p.startsWith(`${perm}:`));
}

// --- navigation-aware link ------------------------------------------------------------------------------------

export function RouterLink({ to, children, fontSize }: { to: string; children: React.ReactNode; fontSize?: 'display-l' }) {
  const navigate = useNavigate();
  return <Link href={to} fontSize={fontSize} onFollow={e => { e.preventDefault(); navigate(to); }}>{children}</Link>;
}

// --- generic resource table -----------------------------------------------------------------------------------

export interface Column<T> {
  id: string;
  header: string;
  cell: (item: T) => React.ReactNode;
  sort?: (item: T) => string | number;
  width?: number;
}

interface ResourceTableProps<T> {
  title: string;
  description?: React.ReactNode;
  items: T[];
  columns: Column<T>[];
  trackBy?: string;
  actions?: React.ReactNode;
  filters?: React.ReactNode;
  pageSize?: number;
  loading?: boolean;
  empty?: string;
  selectionType?: TableProps.SelectionType;
  selected?: T[];
  onSelect?: (items: T[]) => void;
  variant?: TableProps.Variant;
  defaultSort?: string;
  sortDescending?: boolean;
}

function comparator<T>(c: Column<T>) {
  return (a: T, b: T) => {
    const x = c.sort!(a), y = c.sort!(b);
    return typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y));
  };
}

export function ResourceTable<T>(props: ResourceTableProps<T>) {
  const { items, columns, pageSize = 20 } = props;
  const fullPage = !props.variant || props.variant === 'full-page';
  const sortColumn = columns.find(c => c.id === props.defaultSort && c.sort);
  const { items: page, collectionProps, filterProps, paginationProps, filteredItemsCount } = useCollection(items, {
    filtering: { empty: props.empty ?? 'No resources', noMatch: 'No matches' },
    pagination: { pageSize },
    sorting: sortColumn ? {
      defaultState: {
        sortingColumn: { sortingField: sortColumn.id, sortingComparator: comparator(sortColumn) },
        isDescending: props.sortDescending,
      },
    } : {},
  });
  const definitions: TableProps.ColumnDefinition<T>[] = columns.map(c => ({
    id: c.id, header: c.header, cell: c.cell, width: c.width,
    sortingField: c.sort ? c.id : undefined, sortingComparator: c.sort ? comparator(c) : undefined,
  }));
  const counter = filterProps.filteringText ? `(${filteredItemsCount}/${items.length})` : `(${items.length})`;
  return (
    <Table
      {...collectionProps}
      variant={props.variant ?? 'full-page'}
      columnDefinitions={definitions}
      items={page}
      trackBy={props.trackBy ?? 'id'}
      loading={props.loading}
      loadingText="Loading"
      resizableColumns
      stickyHeader={fullPage}
      selectionType={props.selectionType}
      selectedItems={props.selected}
      onSelectionChange={e => props.onSelect?.(e.detail.selectedItems as T[])}
      header={
        <Header variant={fullPage ? 'awsui-h1-sticky' : 'h2'} counter={counter} description={props.description}
          actions={props.actions}>{props.title}</Header>
      }
      filter={
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ flex: '1 1 260px', maxWidth: 420 }}>
            <TextFilter {...filterProps} filteringPlaceholder={`Find ${props.title.toLowerCase()}`} />
          </div>
          {props.filters}
        </div>
      }
      pagination={<Pagination {...paginationProps} />}
      empty={<Box textAlign="center" color="inherit"><b>{props.empty ?? 'No resources'}</b></Box>}
    />
  );
}

export function RefreshButton({ onClick, loading }: { onClick: () => void; loading?: boolean }) {
  return <Button iconName="refresh" ariaLabel="Refresh" loading={loading} onClick={onClick} />;
}

/** Big number with a label, as on AWS service dashboards. */
export function Counter({ label, value, to, info }: { label: string; value: React.ReactNode; to?: string; info?: React.ReactNode }) {
  return (
    <div>
      <Box variant="awsui-key-label">{label}</Box>
      <Box variant="awsui-value-large">{to ? <RouterLink to={to} fontSize="display-l">{value}</RouterLink> : value}</Box>
      {info && <Box variant="small" display="block" color="text-body-secondary">{info}</Box>}
    </div>
  );
}

/**
 * Every AWS-mutating action ends here: it creates an approval request (never a direct change). The backend runs
 * guardrails, routes it to approvers, executes, verifies and audits it.
 */
export function ApprovalModal({ body, title, summary, children, valid = true, onDismiss }: {
  body: Omit<ApprovalRequestBody, 'reason'> | null;
  title: string;
  summary?: React.ReactNode;
  children?: React.ReactNode;
  valid?: boolean;
  onDismiss: () => void;
}) {
  const createApprovalRequest = useAppStore(s => s.createApprovalRequest);
  const [reason, setReason] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const tooShort = reason.trim().length < 10;
  const submit = async () => {
    if (!body) return;
    setBusy(true);
    const id = await createApprovalRequest({ ...body, reason: reason.trim() });
    setBusy(false);
    if (id) {
      notify('success', <>Request submitted for approval. <RouterLink to={`/response/approvals/${id}`}>View request</RouterLink></>, 'Approval requested');
      setReason('');
      onDismiss();
    }
  };
  return (
    <Modal visible={Boolean(body)} onDismiss={onDismiss} header={title} size="medium"
      footer={
        <Box float="right">
          <SpaceBetween direction="horizontal" size="xs">
            <Button variant="link" onClick={onDismiss}>Cancel</Button>
            <Button variant="primary" loading={busy} disabled={tooShort || !valid} onClick={submit}>Request approval</Button>
          </SpaceBetween>
        </Box>
      }>
      <Form>
        <SpaceBetween size="m">
          {summary}
          {children}
          <FormField label="Business justification" constraintText="At least 10 characters. Recorded in the audit trail."
            errorText={reason && tooShort ? 'Justification is too short' : undefined}>
            <Textarea value={reason} onChange={e => setReason(e.detail.value)} placeholder="Why is this change needed?" rows={3} />
          </FormField>
          <Box variant="small" color="text-body-secondary">
            Nothing changes in AWS until the request passes guardrails and is approved by the required role(s).
          </Box>
        </SpaceBetween>
      </Form>
    </Modal>
  );
}
