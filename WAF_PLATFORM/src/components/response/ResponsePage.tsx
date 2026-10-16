import React, { useState } from 'react';
import { useAppStore } from '@/store';
import { Shield, ShieldAlert, Clock, CheckCircle2, XCircle, AlertTriangle, ChevronDown, ChevronUp } from 'lucide-react';
import type { Approval, ApprovalStatus } from '@/types';
import { EntityDetailPanel } from '@/components/entities/EntityDetailPanel';

function StatusBadge({ status }: { status: ApprovalStatus }) {
  const cls: Record<string, string> = {
    pending: 'severity-medium',
    approved: 'severity-healthy',
    rejected: 'severity-critical',
    executing: 'severity-low',
    completed: 'severity-healthy',
    failed: 'severity-critical',
    rolled_back: 'severity-high',
  };
  return (
    <span className={`${cls[status] || 'bg-white/5 text-white/30'} px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider`}>
      {status.replace('_', ' ')}
    </span>
  );
}

function LifecycleStage({ stage, currentStage }: { stage: string; currentStage: string }) {
  const stages = ['detect', 'understand', 'correlate', 'score', 'simulate', 'guardrails', 'approval', 'execution', 'verification', 'audit'];
  const idx = stages.indexOf(stage);
  const curIdx = stages.indexOf(currentStage);
  const active = idx <= curIdx;
  const current = idx === curIdx;

  return (
    <div className="flex items-center gap-1">
      <div className={`
        w-2 h-2 rounded-full transition-all
        ${current ? 'bg-cyan-400 animate-pulse-glow' : active ? 'bg-white/30' : 'bg-white/5'}
      `} />
      <span className={`text-[8px] uppercase tracking-wider ${current ? 'text-cyan-400 font-medium' : active ? 'text-white/30' : 'text-white/10'}`}>
        {stage}
      </span>
    </div>
  );
}

function ApprovalCard({ approval }: { approval: Approval }) {
  const [expanded, setExpanded] = useState(false);
  const { openDrawer } = useAppStore();

  const stageOrder = ['detect', 'understand', 'correlate', 'score', 'simulate', 'guardrails', 'approval', 'execution', 'verification', 'audit'];
  const curIdx = stageOrder.indexOf(approval.lifecycle_stage);

  return (
    <div className="glass rounded-xl overflow-hidden">
      <div className="p-4 cursor-pointer hover:bg-white/[0.01] transition-colors" onClick={() => setExpanded(!expanded)}>
        <div className="flex items-start justify-between">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <ShieldAlert size={12} className={approval.status === 'pending' ? 'text-amber-400' : 'text-white/20'} />
              <span className="text-[12px] font-semibold text-white/80">{approval.action_type}</span>
              <StatusBadge status={approval.status} />
            </div>
            <div className="text-[11px] text-white/40 font-mono mb-1">{approval.target}</div>
            <div className="text-[10px] text-white/25 leading-relaxed line-clamp-2">{approval.reason}</div>
            <div className="flex items-center gap-3 mt-2">
              <span className="text-[9px] text-white/20">by {approval.requested_by}</span>
              <span className="text-[9px] text-white/15">{new Date(approval.requested_at).toLocaleString()}</span>
            </div>
          </div>
          <div className="ml-3 flex flex-col items-center">
            {expanded ? <ChevronUp size={14} className="text-white/20" /> : <ChevronDown size={14} className="text-white/20" />}
          </div>
        </div>

        {/* Mini lifecycle */}
        <div className="flex items-center gap-1.5 mt-3 pt-3 border-t border-white/[0.04] overflow-x-auto">
          {stageOrder.map(stage => (
            <LifecycleStage key={stage} stage={stage} currentStage={approval.lifecycle_stage} />
          ))}
        </div>
      </div>

      {expanded && (
        <div className="border-t border-white/[0.05] p-4 animate-fade-in space-y-4">
          {/* Impact */}
          <div>
            <div className="section-label">Impact Analysis</div>
            <div className="grid grid-cols-2 gap-2">
              {Object.entries(approval.impact).map(([k, v]) => (
                <div key={k} className="flex items-center justify-between px-3 py-2 rounded-lg bg-white/[0.015]">
                  <span className="text-[10px] text-white/35 uppercase tracking-wider">{k.replace(/_/g, ' ')}</span>
                  <span className="text-[11px] font-semibold text-white/65">{typeof v === 'number' ? v.toLocaleString() : v}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Simulation */}
          {approval.simulation_result && (
            <div>
              <div className="section-label">Simulation Result</div>
              <div className="px-3 py-2 rounded-lg bg-emerald-500/[0.04] border border-emerald-500/15">
                <div className="text-[11px] text-emerald-400 font-medium">{approval.simulation_result}</div>
              </div>
            </div>
          )}

          <div className="flex gap-2">
            <button className="btn btn-primary btn-sm flex-1">Approve</button>
            <button className="btn btn-danger btn-sm">Reject</button>
            <button className="btn btn-ghost btn-sm">View Evidence</button>
          </div>
        </div>
      )}
    </div>
  );
}

export function ResponsePage() {
  const { approvals } = useAppStore();
  const [filter, setFilter] = useState<ApprovalStatus | 'all'>('all');

  const filtered = filter === 'all' ? approvals : approvals.filter(a => a.status === filter);
  const pendingCount = approvals.filter(a => a.status === 'pending').length;

  return (
    <div className="space-y-4 animate-fade-in">
      <div>
        <div className="text-[13px] font-semibold text-white/85">Controlled Response</div>
        <div className="text-[11px] text-white/30 mt-0.5">AWS-changing actions follow the full approval lifecycle — no shortcuts</div>
      </div>

      {pendingCount > 0 && (
        <div className="glass rounded-xl p-4 border border-amber-500/15 bg-amber-500/[0.03] flex items-center gap-3">
          <AlertTriangle size={16} className="text-amber-400 flex-shrink-0" />
          <div>
            <div className="text-[12px] font-semibold text-amber-400">{pendingCount} actions pending approval</div>
            <div className="text-[10px] text-white/30">Every AWS-changing operation requires human approval before execution</div>
          </div>
        </div>
      )}

      <div className="flex items-center gap-1">
        {(['all', 'pending', 'approved', 'executing', 'completed', 'rejected', 'failed'] as const).map(f => {
          const count = f === 'all' ? approvals.length : approvals.filter(a => a.status === f).length;
          return (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`
                px-3 py-1.5 rounded text-[10px] font-semibold uppercase tracking-wider transition-all
                ${filter === f ? 'bg-white/[0.08] text-white/80 border border-white/[0.1]' : 'text-white/25 hover:text-white/50 border border-transparent'}
              `}
            >
              {f === 'all' ? `All (${approvals.length})` : `${f} (${count})`}
            </button>
          );
        })}
      </div>

      {/* Lifecycle pipeline */}
      <div className="glass rounded-xl p-4">
        <div className="section-label">Approval Lifecycle</div>
        <div className="flex items-center gap-1 overflow-x-auto pb-2">
          {['DETECT', 'UNDERSTAND', 'CORRELATE', 'SCORE', 'SIMULATE', 'GUARDRAILS', 'APPROVE', 'EXECUTE', 'VERIFY', 'AUDIT'].map((stage, i) => (
            <React.Fragment key={stage}>
              {i > 0 && <div className="w-3 h-[1px] bg-white/10 flex-shrink-0" />}
              <div className="flex flex-col items-center gap-0.5 flex-shrink-0">
                <div className={`w-5 h-5 rounded-full flex items-center justify-center text-[8px] font-bold ${
                  i <= 6 ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/25' : 'bg-white/[0.03] text-white/15'
                }`}>
                  {i + 1}
                </div>
                <span className={`text-[7px] uppercase tracking-wider ${i <= 6 ? 'text-white/40' : 'text-white/15'}`}>{stage}</span>
              </div>
            </React.Fragment>
          ))}
        </div>
      </div>

      <div className="space-y-3" style={{ maxHeight: 'calc(100vh - 400px)', overflowY: 'auto' }}>
        {filtered.map(approval => (
          <ApprovalCard key={approval.id} approval={approval} />
        ))}
      </div>
    </div>
  );
}
