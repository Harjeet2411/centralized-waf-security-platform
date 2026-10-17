import React, { useState } from 'react';
import { useAppStore } from '@/store';
import { useCampaignDetail } from '@/api/hooks';
import { Network, Target, Crosshair, Shield, ShieldAlert, Loader2 } from 'lucide-react';
import type { Campaign, CampaignDetailView } from '@/types';

function SeverityBadge({ severity }: { severity: string }) {
  const cls: Record<string, string> = { critical: 'severity-critical', high: 'severity-high', medium: 'severity-medium', low: 'severity-low' };
  return (
    <span className={`${cls[severity] || 'bg-white/5 text-white/30 border border-white/5'} px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider`}>
      {severity}
    </span>
  );
}

function CampaignOverview({ campaign, detail }: { campaign: Campaign; detail?: CampaignDetailView }) {
  const confidenceStyle: Record<string, string> = {
    high: 'text-rose-400 bg-rose-500/10', medium: 'text-amber-400 bg-amber-500/10', low: 'text-blue-400 bg-blue-500/10',
  };
  const breakdown = campaign.waf_action_breakdown;
  const peak = Math.max(1, ...Object.values(breakdown));

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-[16px] font-bold text-white/90">{campaign.name}</h2>
          <div className="text-[11px] text-white/35 mt-1 font-mono">{campaign.campaign_code}</div>
        </div>
        <div className="flex items-center gap-2">
          <SeverityBadge severity={campaign.risk_level} />
          <span className={`px-2 py-1 rounded text-[10px] font-semibold uppercase tracking-wider border ${confidenceStyle[campaign.confidence] || ''}`}>
            {campaign.confidence} confidence
          </span>
        </div>
      </div>

      <div className="glass rounded-lg p-4">
        <div className="section-label">Attack Story</div>
        <div className="text-[11px] text-white/55 leading-relaxed">{campaign.description}</div>
      </div>

      <div className="grid grid-cols-6 gap-2">
        {[
          { label: 'IPs', value: campaign.ip_count, icon: <Network size={12} /> },
          { label: 'ASNs', value: campaign.asn_count, icon: <Shield size={12} /> },
          { label: 'Countries', value: campaign.country_count, icon: <Target size={12} /> },
          { label: 'JA4', value: campaign.ja4_count, icon: <Crosshair size={12} /> },
          { label: 'Accounts', value: campaign.account_count, icon: <Target size={12} /> },
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

      <div className="glass rounded-lg p-4">
        <div className="section-label">Techniques</div>
        <div className="flex flex-wrap gap-2">
          {(detail?.techniques ?? []).map(t => (
            <span key={t} className="px-3 py-1.5 rounded-md bg-rose-500/[0.06] text-[11px] text-rose-400 border border-rose-500/15 font-medium">{t}</span>
          ))}
          {detail && detail.techniques.length === 0 && <span className="text-[11px] text-white/30">No attack signature matched; correlated by shared TLS fingerprint.</span>}
        </div>
      </div>

      <div className="glass rounded-lg p-4">
        <div className="section-label">WAF Action Distribution (24h)</div>
        <div className="space-y-2">
          {Object.entries(breakdown).map(([action, count]) => (
            <div key={action} className="flex items-center gap-3">
              <span className={`text-[10px] font-bold uppercase tracking-wider w-16 ${action === 'BLOCK' ? 'text-emerald-400' : action === 'COUNT' ? 'text-amber-400' : 'text-rose-400'}`}>{action}</span>
              <div className="flex-1 h-4 bg-white/[0.03] rounded overflow-hidden">
                <div className={`h-full rounded transition-all duration-700 ${action === 'BLOCK' ? 'bg-emerald-500/40' : action === 'COUNT' ? 'bg-amber-500/40' : 'bg-rose-500/40'}`}
                  style={{ width: `${(count / peak) * 100}%` }} />
              </div>
              <span className="text-[11px] font-mono text-white/50 tabular-nums w-16 text-right">{count.toLocaleString()}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="glass rounded-lg p-4">
        <div className="section-label">Recommended Response</div>
        <div className="text-[11px] text-white/55">{campaign.recommended_action}</div>
      </div>
    </div>
  );
}

function CorrelationEvidence({ detail }: { detail: CampaignDetailView }) {
  return (
    <div className="space-y-0 pt-2">
      {detail.correlation_evidence.map((ev, i) => (
        <div key={`${ev.type}-${i}`} className="flex gap-4">
          <div className="flex flex-col items-center">
            <div className="w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 bg-cyan-500/15 border border-cyan-500/30">
              <span className="text-[10px] font-bold text-cyan-400">{String(i + 1).padStart(2, '0')}</span>
            </div>
            {i < detail.correlation_evidence.length - 1 && <div className="w-[1px] flex-1 my-1 bg-cyan-500/20" />}
          </div>
          <div className="pb-5 mb-2">
            <div className="text-[12px] font-semibold text-white/75">{ev.label}: <span className="font-mono">{ev.value}</span></div>
            {ev.detail && <div className="text-[11px] text-white/35 mt-0.5 leading-relaxed max-w-lg">{ev.detail}</div>}
          </div>
        </div>
      ))}
    </div>
  );
}

function Members({ detail }: { detail: CampaignDetailView }) {
  const openDrawer = useAppStore(s => s.openDrawer);
  return (
    <table className="data-table mt-2">
      <thead><tr><th>Entity</th><th>Type</th><th>Risk</th><th>Threat</th><th>Requests</th></tr></thead>
      <tbody>
        {detail.members.map(m => (
          <tr key={m.id} className="clickable" onClick={() => openDrawer('entity', m)}>
            <td><span className="text-[11px] font-mono text-white/70">{m.value}</span></td>
            <td><span className="text-[10px] uppercase text-white/35">{m.type}</span></td>
            <td><SeverityBadge severity={m.risk_level} /></td>
            <td><span className="text-[11px] font-mono tabular-nums text-white/55">{m.threat_score}</span></td>
            <td><span className="text-[11px] font-mono tabular-nums text-white/45">{m.request_count.toLocaleString()}</span></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function CampaignDetail() {
  const { drawerData, closeDrawer } = useAppStore();
  const campaign = drawerData as Campaign | null;
  const [tab, setTab] = useState('overview');
  const detail = useCampaignDetail(campaign?.id);

  if (!campaign) return null;

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between px-6 py-4 border-b border-white/[0.05]">
        <h3 className="text-[13px] font-bold text-white/85">Campaign Investigation</h3>
        <button onClick={closeDrawer} className="text-white/25 hover:text-white/60 text-sm">✕</button>
      </div>
      <div className="tab-bar ml-0 !mx-6">
        {['overview', 'evidence', 'entities', 'targets'].map(t => (
          <button key={t} onClick={() => setTab(t)} className={`tab-item ${tab === t ? 'active' : ''}`}>{t.charAt(0).toUpperCase() + t.slice(1)}</button>
        ))}
      </div>
      <div className="flex-1 overflow-y-auto px-6 pb-6">
        {detail.isLoading && <div className="text-[11px] text-white/30 flex items-center gap-2 py-4"><Loader2 size={12} className="animate-spin" /> Loading evidence…</div>}
        {detail.error && <div className="text-[11px] text-rose-400 py-4">{detail.error.message}</div>}
        {tab === 'overview' && <CampaignOverview campaign={campaign} detail={detail.data} />}
        {tab === 'evidence' && detail.data && <CorrelationEvidence detail={detail.data} />}
        {tab === 'entities' && detail.data && <Members detail={detail.data} />}
        {tab === 'targets' && detail.data && (
          <div className="glass rounded-lg p-4 mt-2">
            <div className="section-label">Most-targeted URIs (24h)</div>
            <div className="space-y-1">{detail.data.targeted_uris.map(uri => <div key={uri} className="text-[11px] font-mono text-white/55">{uri}</div>)}</div>
          </div>
        )}
      </div>
    </div>
  );
}
