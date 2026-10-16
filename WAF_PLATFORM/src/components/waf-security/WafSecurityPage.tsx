import React, { useState } from 'react';
import { useAppStore } from '@/store';
import { Shield, AlertTriangle, ShieldAlert, Eye, RefreshCw, ArrowUpDown, ChevronDown, ChevronUp } from 'lucide-react';
import type { WebACL, WafRule } from '@/types';

function SeverityBadge({ severity, label }: { severity: string; label?: string }) {
  const cls: Record<string, string> = {
    critical: 'severity-critical', high: 'severity-high', medium: 'severity-medium',
    low: 'severity-low', healthy: 'severity-healthy', unknown: 'bg-white/5 text-white/30 border border-white/5',
  };
  return (
    <span className={`${cls[severity] || cls.unknown} px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider`}>
      {label || severity}
    </span>
  );
}

export function ActionBadge({ action }: { action: string }) {
  const cls: Record<string, string> = {
    BLOCK: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
    ALLOW: 'text-rose-400 bg-rose-500/10 border-rose-500/20',
    COUNT: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${cls[action] || 'text-white/30'}`}>
      {action}
    </span>
  );
}

function WebACLCard({ webacl }: { webacl: WebACL }) {
  const [expanded, setExpanded] = useState(false);
  const { rules, openDrawer, setPage, pushContext } = useAppStore.getState();
  const webaclRules = rules.get(webacl.id) || [];
  const ruleDrift = webaclRules.filter(r => r.version_status === 'outdated').length;

  return (
    <div className="glass rounded-xl overflow-hidden">
      <div
        className="p-4 cursor-pointer hover:bg-white/[0.01] transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center justify-between">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <Shield size={13} className="text-cyan-400/50" />
              <span className="text-[12px] font-semibold text-white/80">{webacl.name}</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-white/[0.04] text-white/30 border border-white/[0.06] font-mono">
                {webacl.scope}
              </span>
            </div>
            <div className="text-[10px] text-white/25 font-mono truncate">{webacl.arn}</div>
          </div>
          <div className="flex items-center gap-3">
            <div className="text-right">
              <div className={`text-[14px] font-bold tabular-nums ${webacl.security_score >= 80 ? 'text-emerald-400' : webacl.security_score >= 60 ? 'text-amber-400' : 'text-rose-400'}`}>
                {webacl.security_score}
              </div>
              <div className="text-[9px] text-white/20">score</div>
            </div>
            {ruleDrift > 0 && (
              <div className="flex items-center gap-1 px-2 py-1 rounded bg-amber-500/10 border border-amber-500/20">
                <AlertTriangle size={10} className="text-amber-400" />
                <span className="text-[10px] font-bold text-amber-400">{ruleDrift}</span>
              </div>
            )}
            {expanded ? <ChevronUp size={14} className="text-white/20" /> : <ChevronDown size={14} className="text-white/20" />}
          </div>
        </div>
      </div>

      {expanded && (
        <div className="border-t border-white/[0.05] animate-fade-in">
          <div className="p-4 space-y-3">
            {/* Quick stats */}
            <div className="grid grid-cols-4 gap-2">
              <div className="bg-white/[0.02] rounded-lg p-3 text-center">
                <div className="text-[16px] font-bold text-white/70 tabular-nums">{webacl.rule_count}</div>
                <div className="text-[9px] text-white/25 uppercase tracking-wider">Rules</div>
              </div>
              <div className="bg-white/[0.02] rounded-lg p-3 text-center">
                <div className="text-[16px] font-bold text-white/70 tabular-nums">{webacl.managed_rule_health}%</div>
                <div className="text-[9px] text-white/25 uppercase tracking-wider">MR Health</div>
              </div>
              <div className="bg-white/[0.02] rounded-lg p-3 text-center">
                <div className="text-[16px] font-bold tabular-nums" style={{ color: webacl.drift_count > 0 ? '#f97316' : '#34d399' }}>{webacl.drift_count}</div>
                <div className="text-[9px] text-white/25 uppercase tracking-wider">Drift</div>
              </div>
              <div className="bg-white/[0.02] rounded-lg p-3 text-center">
                <div className="text-[16px] font-bold text-white/70 tabular-nums">{webacl.logging_enabled ? '✓' : '✗'}</div>
                <div className="text-[9px] text-white/25 uppercase tracking-wider">Logging</div>
              </div>
            </div>

            {/* Default action */}
            <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-white/[0.015]">
              <span className="text-[10px] text-white/30 uppercase tracking-wider w-24">Default Action</span>
              <ActionBadge action={webacl.default_action} />
            </div>

            {/* Rules */}
            <div>
              <div className="section-label">Rules ({webaclRules.length})</div>
              <div className="space-y-1 max-h-60 overflow-y-auto pr-1">
                {webaclRules.map(rule => (
                  <div
                    key={rule.id}
                    onClick={() => {
                      pushContext({ label: rule.name });
                      openDrawer('rule', { webacl, rule });
                    }}
                    className="flex items-center gap-2 px-3 py-2 rounded-lg bg-white/[0.01] hover:bg-white/[0.025] border border-white/[0.04] cursor-pointer transition-all group"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-[11px] text-white/70 group-hover:text-white/90 transition-colors truncate">{rule.name}</span>
                        <span className="text-[9px] text-white/15 px-1 rounded bg-white/[0.03]">{rule.type}</span>
                      </div>
                      <div className="flex items-center gap-3 mt-1">
                        <ActionBadge action={rule.action} />
                        <span className="text-[9px] text-white/20">{rule.match_count.toLocaleString()} matches</span>
                        {rule.effectiveness < 70 && (
                          <span className="text-[9px] text-amber-400">low effectiveness ({rule.effectiveness}%)</span>
                        )}
                        {rule.version_status === 'outdated' && (
                          <span className="text-[9px] text-orange-400">outdated ({rule.managed_version} → {rule.latest_version})</span>
                        )}
                      </div>
                    </div>
                    <div className="text-right flex-shrink-0">
                      <div className={`text-[12px] font-bold tabular-nums ${rule.effectiveness >= 80 ? 'text-emerald-400' : rule.effectiveness >= 60 ? 'text-amber-400' : 'text-rose-400'}`}>
                        {rule.effectiveness}%
                      </div>
                      <div className="text-[8px] text-white/15">effectiveness</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <button className="btn btn-primary btn-sm w-full">Investigate WebACL</button>
          </div>
        </div>
      )}
    </div>
  );
}

export function WafSecurityPage() {
  const { webacls } = useAppStore();
  const [filter, setFilter] = useState<'all' | 'critical' | 'high' | 'medium'>('all');

  const filtered = filter === 'all' ? webacls : webacls.filter(w => {
    if (filter === 'critical') return w.security_score < 60 || w.drift_count >= 3;
    if (filter === 'high') return w.security_score >= 60 && w.security_score < 75;
    return w.security_score >= 75;
  });

  const avgScore = Math.round(webacls.reduce((s, w) => s + w.security_score, 0) / webacls.length);
  const totalDrift = webacls.reduce((s, w) => s + w.drift_count, 0);
  const outdatedRules = webacls.filter(w => w.managed_rule_health < 80).length;

  return (
    <div className="space-y-4 animate-fade-in">
      <div>
        <div className="text-[13px] font-semibold text-white/85">WAF Security Governance</div>
        <div className="text-[11px] text-white/30 mt-0.5">WebACL posture, rule effectiveness, managed versions, and drift</div>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Avg Security Score', value: avgScore, sub: `${webacls.length} WebACLs`, color: avgScore >= 80 ? '#34d399' : avgScore >= 60 ? '#fbbf24' : '#f43f5e' },
          { label: 'Total Drift Events', value: totalDrift, sub: 'across all WebACLs', color: totalDrift > 5 ? '#f97316' : '#34d399' },
          { label: 'Outdated Rules', value: outdatedRules, sub: 'managed rules need update', color: outdatedRules > 3 ? '#f97316' : '#34d399' },
          { label: 'Logging Coverage', value: `${webacls.filter(w => w.logging_enabled).length}/${webacls.length}`, sub: 'WebACLs with full logging', color: '#60a5fa' },
        ].map(stat => (
          <div key={stat.label} className="glass rounded-lg p-4">
            <div className="text-[10px] text-white/25 uppercase tracking-wider mb-1">{stat.label}</div>
            <div className="text-[22px] font-bold tabular-nums" style={{ color: stat.color }}>{stat.value}</div>
            <div className="text-[10px] text-white/20 mt-0.5">{stat.sub}</div>
          </div>
        ))}
      </div>

      {/* Filter tabs */}
      <div className="flex items-center gap-1">
        {(['all', 'critical', 'high', 'medium'] as const).map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`
              px-3 py-1.5 rounded text-[10px] font-semibold uppercase tracking-wider transition-all
              ${filter === f ? 'bg-white/[0.08] text-white/80 border border-white/[0.1]' : 'text-white/25 hover:text-white/50 border border-transparent'}
            `}
          >
            {f === 'all' ? `All (${webacls.length})` : `${f} (${filtered.length})`}
          </button>
        ))}
      </div>

      {/* WebACL list */}
      <div className="grid grid-cols-1 gap-3">
        {filtered.map(webacl => (
          <WebACLCard key={webacl.id} webacl={webacl} />
        ))}
      </div>
    </div>
  );
}
