import React, { useState } from 'react';
import { useAppStore } from '@/store';
import { AlertTriangle, CheckCircle2, XCircle, RefreshCw, Globe, Clock, Shield, Server } from 'lucide-react';
import type { PlatformHealth, CollectorHealth, DriftEvent } from '@/types';

function PlatformHealthDashboard() {
  const { platformHealth } = useAppStore();
  const [selectedCollector, setSelectedCollector] = useState<CollectorHealth | null>(null);

  const overallIcon = platformHealth.overall === 'healthy' ? <CheckCircle2 size={16} className="text-emerald-400" />
    : platformHealth.overall === 'degraded' ? <AlertTriangle size={16} className="text-amber-400" />
    : <XCircle size={16} className="text-rose-400" />;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-[13px] font-semibold text-white/85">Platform Health</div>
          <div className="text-[11px] text-white/30 mt-0.5">Operational dependency map — data freshness {platformHealth.data_freshness}</div>
        </div>
        <div className="flex items-center gap-2">
          {overallIcon}
          <span className="text-[11px] text-white/50 font-medium uppercase tracking-wider">{platformHealth.overall}</span>
        </div>
      </div>

      {/* Dependency pipeline */}
      <div className="glass rounded-xl p-5">
        <div className="section-label mb-4">Data Pipeline</div>
        <div className="flex items-center gap-1 overflow-x-auto pb-3">
          {[
            { label: 'Collectors', status: platformHealth.collectors.some(c => c.status !== 'healthy') ? 'degraded' : 'healthy', count: `${platformHealth.collectors.filter(c => c.status === 'healthy').length}/${platformHealth.collectors.length}` },
            { label: 'AWS APIs', status: platformHealth.aws_api.status },
            { label: 'Queue', status: platformHealth.queue.status },
            { label: 'Workers', status: platformHealth.workers.status },
            { label: 'Database', status: platformHealth.database.status },
            { label: 'Threat Intel', status: platformHealth.threat_intel.status },
            { label: 'API', status: 'healthy' },
            { label: 'UI', status: 'healthy' },
          ].map((comp, i) => {
            const statusColor = comp.status === 'healthy' ? 'text-emerald-400 bg-emerald-500/10' : comp.status === 'degraded' ? 'text-amber-400 bg-amber-500/10' : 'text-rose-400 bg-rose-500/10';
            return (
              <React.Fragment key={i}>
                {i > 0 && <div className="w-4 h-[1px] bg-white/10 flex-shrink-0" />}
                <div className={`flex flex-col items-center gap-0.5 px-2 py-1.5 rounded-md ${statusColor} flex-shrink-0`}>
                  <span className="text-[10px] font-semibold">{comp.count || comp.status}</span>
                  <span className="text-[8px] uppercase tracking-wider opacity-70">{comp.label}</span>
                </div>
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* Collector grid */}
      <div className="glass rounded-xl p-5">
        <div className="section-label mb-3">Account Collectors</div>
        <div className="grid grid-cols-4 gap-2">
          {platformHealth.collectors.map(collector => (
            <button
              key={collector.account_id}
              onClick={() => setSelectedCollector(collector)}
              className={`
                text-left p-3 rounded-lg border transition-all
                ${collector.status === 'healthy' ? 'bg-emerald-500/[0.03] border-emerald-500/10' : ''}
                ${collector.status === 'degraded' ? 'bg-amber-500/[0.03] border-amber-500/15' : ''}
                ${collector.status === 'unavailable' ? 'bg-rose-500/[0.03] border-rose-500/15' : ''}
              `}
            >
              <div className="flex items-center gap-1.5 mb-1">
                <Server size={10} className={
                  collector.status === 'healthy' ? 'text-emerald-400' : collector.status === 'degraded' ? 'text-amber-400' : 'text-rose-400'
                } />
                <span className="text-[10px] text-white/40 truncate">{collector.account_name}</span>
              </div>
              <div className="text-[9px] text-white/20">
                {collector.status === 'healthy' ? `OK ${new Date(collector.last_success).toLocaleTimeString()}` : collector.error}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Collector detail */}
      {selectedCollector && (
        <div className="glass rounded-xl p-5 animate-fade-in">
          <div className="flex items-center justify-between mb-3">
            <span className="text-[12px] font-semibold text-white/80">{selectedCollector.account_name}</span>
            <button onClick={() => setSelectedCollector(null)} className="text-white/20 hover:text-white/50 text-xs">✕</button>
          </div>
          <div className="space-y-2">
            <div className="flex items-center justify-between px-3 py-2 rounded-lg bg-white/[0.015]">
              <span className="text-[10px] text-white/35 uppercase tracking-wider">Status</span>
              <span className={`text-[11px] font-semibold ${selectedCollector.status === 'healthy' ? 'text-emerald-400' : selectedCollector.status === 'degraded' ? 'text-amber-400' : 'text-rose-400'}`}>
                {selectedCollector.status.toUpperCase()}
              </span>
            </div>
            <div className="flex items-center justify-between px-3 py-2 rounded-lg bg-white/[0.015]">
              <span className="text-[10px] text-white/35 uppercase tracking-wider">Last Success</span>
              <span className="text-[11px] text-white/50">{new Date(selectedCollector.last_success).toLocaleString()}</span>
            </div>
            {selectedCollector.error && (
              <div className="flex items-center justify-between px-3 py-2 rounded-lg bg-rose-500/[0.04]">
                <span className="text-[10px] text-white/35 uppercase tracking-wider">Error</span>
                <span className="text-[11px] text-rose-400">{selectedCollector.error}</span>
              </div>
            )}
            <div className="flex items-center justify-between px-3 py-2 rounded-lg bg-white/[0.015]">
              <span className="text-[10px] text-white/35 uppercase tracking-wider">Affected Modules</span>
              <span className="text-[11px] text-white/50">{selectedCollector.affected_modules.join(', ')}</span>
            </div>
          </div>
          <div className="flex gap-2 mt-3">
            <button className="btn btn-primary btn-sm flex-1">Retry</button>
            <button className="btn btn-ghost btn-sm">View Logs</button>
          </div>
        </div>
      )}
    </div>
  );
}

function DriftTable() {
  const { driftEvents } = useAppStore();

  return (
    <div className="glass rounded-xl overflow-hidden">
      <div className="p-4 border-b border-white/[0.05]">
        <div className="section-label mb-0">Configuration Drift Events</div>
      </div>
      <div className="overflow-auto" style={{ maxHeight: '400px' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>WebACL</th>
              <th>Account</th>
              <th>Drift Type</th>
              <th>Severity</th>
              <th>Expected</th>
              <th>Actual</th>
              <th>Status</th>
              <th>Detected</th>
            </tr>
          </thead>
          <tbody>
            {driftEvents.map(event => (
              <tr key={event.id} className="clickable">
                <td><span className="text-[11px] text-white/70">{event.webacl_name}</span></td>
                <td><span className="text-[10px] text-white/30 font-mono">{event.account_id}</span></td>
                <td><span className="text-[11px] text-white/50">{event.drift_type}</span></td>
                <td>
                  <span className={`px-2 py-0.5 rounded text-[9px] font-semibold uppercase tracking-wider ${
                    event.severity === 'critical' ? 'severity-critical' :
                    event.severity === 'high' ? 'severity-high' :
                    event.severity === 'medium' ? 'severity-medium' : 'severity-low'
                  }`}>
                    {event.severity}
                  </span>
                </td>
                <td><span className="text-[10px] font-mono text-white/35 truncate max-w-[120px]">{event.expected}</span></td>
                <td><span className="text-[10px] font-mono text-white/35 truncate max-w-[120px]">{event.actual}</span></td>
                <td>
                  <span className={`text-[10px] uppercase tracking-wider ${
                    event.status === 'open' ? 'text-rose-400' :
                    event.status === 'acknowledged' ? 'text-amber-400' :
                    event.status === 'resolved' ? 'text-emerald-400' : 'text-white/30'
                  }`}>
                    {event.status}
                  </span>
                </td>
                <td><span className="text-[10px] text-white/25">{new Date(event.detected_at).toLocaleDateString()}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function GovernancePage() {
  return (
    <div className="space-y-4 animate-fade-in">
      <div>
        <div className="text-[13px] font-semibold text-white/85">Governance</div>
        <div className="text-[11px] text-white/30 mt-0.5">Platform health, configuration drift, RBAC, audit</div>
      </div>
      <PlatformHealthDashboard />
      <DriftTable />
    </div>
  );
}
