import React, { useState } from 'react';
import { useAppStore } from '@/store';
import { AlertTriangle, ShieldAlert, Clock, Network, Target, Crosshair, Shield, ArrowRight } from 'lucide-react';
import type { Campaign } from '@/types';
import { EntityDetailPanel } from '@/components/entities/EntityDetailPanel';

function SeverityBadge({ severity }: { severity: string }) {
  const cls: Record<string, string> = {
    critical: 'severity-critical', high: 'severity-high', medium: 'severity-medium', low: 'severity-low',
  };
  return (
    <span className={`${cls[severity] || 'bg-white/5 text-white/30 border border-white/5'} px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider`}>
      {severity}
    </span>
  );
}

function CampaignOverview({ campaign }: { campaign: Campaign }) {
  const riskStyle: Record<string, { text: string; bg: string }> = {
    critical: 'text-rose-400 bg-rose-500/10',
    high: 'text-orange-400 bg-orange-500/10',
    medium: 'text-amber-400 bg-amber-500/10',
    low: 'text-blue-400 bg-blue-500/10',
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-[16px] font-bold text-white/90">{campaign.name}</h2>
          <div className="text-[11px] text-white/35 mt-1 font-mono">{campaign.id} · {campaign.description}</div>
        </div>
        <div className="flex items-center gap-2">
          <SeverityBadge severity={campaign.risk_level} />
          <span className={`px-2 py-1 rounded text-[10px] font-semibold uppercase tracking-wider border ${riskStyle[campaign.confidence] || ''}`}>
            {campaign.confidence} confidence
          </span>
        </div>
      </div>

      {/* Infrastructure */}
      <div className="grid grid-cols-6 gap-2">
        {[
          { label: 'IPs', value: campaign.ip_count, icon: <Network size={12} /> },
          { label: 'ASNs', value: campaign.asn_count, icon: <Shield size={12} /> },
          { label: 'Countries', value: campaign.country_count, icon: <Target size={12} /> },
          { label: 'JA4', value: campaign.ja4_count, icon: <Crosshair size={12} /> },
          { label: 'Apps', value: campaign.application_count, icon: <Target size={12} /> },
          { label: 'WebACLs', value: campaign.webacl_count, icon: <ShieldAlert size={12} /> },
        ].map(item => (
          <div key={item.label} className="glass rounded-lg p-3 text-center">
            <div className="flex items-center justify-center gap-1 mb-1">
              <span className="text-white/20">{item.icon}</span>
              <span className="text-[9px] text-white/25 uppercase tracking-wider">{item.label}</span>
            </div>
            <div className="text-[18px] font-bold text-white/80 tabular-nums">{item.value}</div>
          </div>
        ))}
      </div>

      {/* Techniques */}
      <div className="glass rounded-lg p-4">
        <div className="section-label">Techniques</div>
        <div className="flex flex-wrap gap-2">
          {['Scanner', 'Credential Attack', 'SQLi', 'Bot Automation'].map(t => (
            <span key={t} className="px-3 py-1.5 rounded-md bg-rose-500/[0.06] text-[11px] text-rose-400 border border-rose-500/15 font-medium">
              {t}
            </span>
          ))}
        </div>
      </div>

      {/* WAF Action Breakdown */}
      <div className="glass rounded-lg p-4">
        <div className="section-label">WAF Action Distribution</div>
        <div className="space-y-2">
          {Object.entries(campaign.waf_action_breakdown).map(([action, count]) => (
            <div key={action} className="flex items-center gap-3">
              <span className={`text-[10px] font-bold uppercase tracking-wider w-16 ${
                action === 'BLOCK' ? 'text-emerald-400' : action === 'COUNT' ? 'text-amber-400' : 'text-rose-400'
              }`}>{action}</span>
              <div className="flex-1 h-4 bg-white/[0.03] rounded overflow-hidden">
                <div
                  className={`h-full rounded transition-all duration-700 ${
                    action === 'BLOCK' ? 'bg-emerald-500/40' : action === 'COUNT' ? 'bg-amber-500/40' : 'bg-rose-500/40'
                  }`}
                  style={{ width: `${Math.min(100, (count / Math.max(...Object.values(campaign.waf_action_breakdown))) * 100)}%` }}
                />
              </div>
              <span className="text-[11px] font-mono text-white/50 tabular-nums w-16 text-right">{count.toLocaleString()}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Actions */}
      <div className="flex gap-2">
        <button className="btn btn-primary flex-1">Investigate Campaign</button>
        <button className="btn btn-ghost flex-1">View Timeline</button>
        <button className="btn btn-ghost flex-1">View Evidence</button>
        <button className="btn btn-danger flex-1">Simulate Response</button>
      </div>
    </div>
  );
}

function CampaignTimeline() {
  const phases = useAppStore(s => s.attackStoryPhases);

  return (
    <div className="space-y-0">
      {phases.map((phase, i) => (
        <div key={phase.phase} className="flex gap-4">
          <div className="flex flex-col items-center">
            <div className={`
              w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0
              ${phase.completed
                ? 'bg-cyan-500/15 border border-cyan-500/30'
                : 'bg-white/[0.03] border border-white/10'
              }
            `}>
              <span className={`text-[10px] font-bold ${phase.completed ? 'text-cyan-400' : 'text-white/20'}`}>
                {String(i + 1).padStart(2, '0')}
              </span>
            </div>
            {i < phases.length - 1 && (
              <div className={`w-[1px] flex-1 my-1 ${phase.completed ? 'bg-cyan-500/20' : 'bg-white/5'}`} />
            )}
          </div>
          <div className={`pb-5 ${i === phases.length - 1 ? '' : 'mb-2'}`}>
            <div className={`text-[12px] font-semibold ${phase.completed ? 'text-white/75' : 'text-white/30'}`}>
              {phase.label}
            </div>
            <div className="text-[11px] text-white/35 mt-0.5 leading-relaxed max-w-lg">{phase.description}</div>
            <div className="text-[9px] text-white/20 mt-1">{phase.evidence_count} evidence records</div>
          </div>
        </div>
      ))}
    </div>
  );
}

export function CampaignDetail() {
  const { drawerData, closeDrawer } = useAppStore();
  const campaign = drawerData as Campaign | null;
  const [tab, setTab] = useState('overview');

  if (!campaign) return null;

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between px-6 py-4 border-b border-white/[0.05]">
        <h3 className="text-[13px] font-bold text-white/85">Campaign Investigation</h3>
        <button onClick={closeDrawer} className="text-white/25 hover:text-white/60 text-sm">✕</button>
      </div>
      <div className="tab-bar ml-0 !mx-6">
        {['overview', 'timeline', 'evidence', 'targets', 'techniques', 'threat-intel', 'impact'].map(t => (
          <button key={t} onClick={() => setTab(t)} className={`tab-item ${tab === t ? 'active' : ''}`}>
            {t === 'threat-intel' ? 'Threat Intel' : t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>
      <div className="flex-1 overflow-y-auto px-6 pb-6">
        {tab === 'overview' && <CampaignOverview campaign={campaign} />}
        {tab === 'timeline' && <CampaignTimeline />}
        {tab === 'impact' && (
          <div className="glass rounded-lg p-4">
            <div className="section-label">Impact Assessment</div>
            <div className="text-[11px] text-white/40 leading-relaxed">
              {campaign.ip_count} source IPs across {campaign.country_count} countries attacking {campaign.application_count} applications.
              WAF is currently {Object.entries(campaign.waf_action_breakdown).find(([_, v]) => v > 100)?.[0] || 'COUNT'}-only on most rules.
              {campaign.waf_action_breakdown.ALLOW > 0 && (
                <span className="text-rose-400 font-medium"> {campaign.waf_action_breakdown.ALLOW} malicious requests allowed through.</span>
              )}
            </div>
          </div>
        )}
        {tab === 'evidence' && (
          <div className="glass rounded-lg p-4">
            <div className="section-label">Evidence Records</div>
            <div className="text-[11px] text-white/40">Loading evidence...</div>
          </div>
        )}
      </div>
    </div>
  );
}
