import React, { useState } from 'react';
import { useAppStore } from '@/store';
import { AlertTriangle, Shield, ShieldAlert, Globe, Activity, Eye, EyeOff, TrendingUp, Zap } from 'lucide-react';
import type { PostureDimension } from '@/types';

function SeverityBadge({ severity }: { severity: string }) {
  const cls: Record<string, string> = {
    critical: 'severity-critical', high: 'severity-high', medium: 'severity-medium',
    low: 'severity-low', healthy: 'severity-healthy', unknown: 'bg-white/5 text-white/30 border border-white/5',
  };
  return (
    <span className={`${cls[severity] || cls.unknown} px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider`}>
      {severity}
    </span>
  );
}

function GlobalStateRow() {
  const { accounts, webacls, endpoints, campaigns, detections } = useAppStore();
  const totalEndpoints = endpoints.length;
  const activeCampaigns = campaigns.filter(c => c.status === 'active').length;
  const criticalDetections = detections.filter(d => d.severity === 'critical').length;

  const items = [
    { label: 'Accounts', value: accounts.length, sub: `${accounts.filter(a => a.status === 'healthy').length} healthy`, icon: <Globe size={14} /> },
    { label: 'WebACLs', value: webacls.length, sub: `${webacls.filter(w => w.security_score >= 80).length} healthy`, icon: <Shield size={14} /> },
    { label: 'Endpoints', value: totalEndpoints, sub: `${endpoints.filter(e => e.waf_enabled).length} protected`, icon: <Activity size={14} /> },
    { label: 'Campaigns', value: campaigns.length, sub: `${activeCampaigns} active`, icon: <ShieldAlert size={14} /> },
    { label: 'Detections', value: detections.length, sub: `${criticalDetections} critical`, icon: <AlertTriangle size={14} /> },
  ];

  return (
    <div className="flex gap-3 mb-5">
      {items.map(item => (
        <div key={item.label} className="glass rounded-lg px-4 py-3 flex-1 min-w-0 hover:border-white/[0.12] transition-colors cursor-default">
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-white/25">{item.icon}</span>
            <span className="text-[10px] font-medium text-white/30 uppercase tracking-wider">{item.label}</span>
          </div>
          <div className="text-[20px] font-bold text-white/90 tabular-nums">{item.value}</div>
          <div className="text-[10px] text-white/25 mt-0.5">{item.sub}</div>
        </div>
      ))}
    </div>
  );
}

function PostureRing({ dimensions, overall }: { dimensions: PostureDimension[]; overall: number }) {
  const [expanded, setExpanded] = useState(false);
  const [selectedDim, setSelectedDim] = useState<PostureDimension | null>(null);

  const circumference = 2 * Math.PI * 54;
  const offset = circumference - (overall / 100) * circumference;
  const color = overall >= 80 ? '#34d399' : overall >= 60 ? '#fbbf24' : '#f43f5e';

  const visibleDims = expanded ? dimensions : dimensions.slice(0, 5);

  return (
    <div className="glass rounded-xl p-5 h-full">
      <div className="section-label">Security Posture</div>
      <div className="flex items-start gap-5">
        {/* Ring */}
        <div className="relative flex-shrink-0">
          <svg width="140" height="140" viewBox="0 0 140 140">
            <circle cx="70" cy="70" r="54" fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="8" />
            <circle cx="70" cy="70" r="54" fill="none" stroke={color} strokeWidth="8"
              strokeDasharray={circumference} strokeDashoffset={offset}
              strokeLinecap="round" transform="rotate(-90 70 70)"
              style={{ transition: 'stroke-dashoffset 1s ease' }}
            />
            <text x="70" y="66" textAnchor="middle" fill="white" fontSize="26" fontWeight="700" fontFamily="ui-monospace, monospace">
              {overall}
            </text>
            <text x="70" y="84" textAnchor="middle" fill="rgba(255,255,255,0.3)" fontSize="10" fontWeight="500">
              / 100
            </text>
          </svg>
        </div>

        {/* Dimensions list */}
        <div className="flex-1 min-w-0">
          <div className="space-y-1.5">
            {visibleDims.map(dim => (
              <button
                key={dim.key}
                onClick={() => setSelectedDim(dim)}
                className={`
                  w-full flex items-center gap-2.5 px-2.5 py-[6px] rounded-md text-left
                  transition-all duration-150 group
                  ${selectedDim?.key === dim.key ? 'bg-cyan-500/[0.08] border border-cyan-500/20' : 'hover:bg-white/[0.02] border border-transparent'}
                `}
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] text-white/55 group-hover:text-white/75 transition-colors">{dim.label}</span>
                    <span className="text-[11px] font-mono font-semibold tabular-nums" style={{ color: dim.value >= 80 ? '#34d399' : dim.value >= 60 ? '#fbbf24' : '#f43f5e' }}>
                      {dim.value}
                    </span>
                  </div>
                  <div className="mt-1 h-[3px] bg-white/[0.04] rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-500"
                      style={{
                        width: `${dim.value}%`,
                        backgroundColor: dim.value >= 80 ? '#34d399' : dim.value >= 60 ? '#fbbf24' : '#f43f5e',
                      }}
                    />
                  </div>
                </div>
              </button>
            ))}
          </div>
          {!expanded && (
            <button onClick={() => setExpanded(true)} className="mt-2 text-[10px] text-white/25 hover:text-white/50 transition-colors">
              +{dimensions.length - 5} more dimensions
            </button>
          )}
        </div>
      </div>

      {/* WHY detail panel */}
      {selectedDim && (
        <div className="mt-4 pt-4 border-t border-white/[0.05] animate-fade-in">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-semibold text-white/40 uppercase tracking-wider">Why This Score</span>
            <button onClick={() => setSelectedDim(null)} className="text-[10px] text-white/20 hover:text-white/50">✕</button>
          </div>
          <div className="space-y-1">
            {selectedDim.why.map((w, i) => (
              <div key={i} className="flex items-center justify-between px-2 py-1 rounded bg-white/[0.01]">
                <span className="text-[11px] text-white/45">{w.label}</span>
                <span className={`text-[11px] font-mono ${w.positive ? 'text-emerald-400' : 'text-rose-400'}`}>
                  {w.positive ? '+' : '-'}{w.value}
                </span>
              </div>
            ))}
          </div>
          <div className="mt-2 flex items-center justify-between">
            <span className="text-[10px] text-white/25">{selectedDim.evidence_count} evidence records</span>
            <button className="btn btn-primary btn-sm">View Evidence</button>
          </div>
        </div>
      )}
    </div>
  );
}

function ThreatActivityStream() {
  const { threatActivity, openDrawer } = useAppStore();
  const [expanded, setExpanded] = useState<string | null>(null);

  return (
    <div className="glass rounded-xl p-5 h-full">
      <div className="section-label">Threat Activity</div>
      <div className="space-y-2">
        {threatActivity.map((item, i) => {
          const severityCls: Record<string, string> = {
            critical: 'border-l-rose-500 bg-rose-500/[0.03]',
            high: 'border-l-orange-500 bg-orange-500/[0.02]',
            medium: 'border-l-amber-500 bg-amber-500/[0.02]',
          };
          return (
            <div
              key={i}
              onClick={() => setExpanded(expanded === `ta-${i}` ? null : `ta-${i}`)}
              className={`
                border-l-2 rounded-r-lg p-3 cursor-pointer transition-all duration-200
                hover:bg-white/[0.02] animate-fade-in
                ${severityCls[item.severity] || severityCls.medium}
              `}
              style={{ animationDelay: `${i * 40}ms` }}
            >
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono text-white/25">{item.time}</span>
                  <SeverityBadge severity={item.severity} />
                </div>
                <Zap size={10} className={item.severity === 'critical' ? 'text-rose-400' : 'text-white/20'} />
              </div>
              <div className="text-[12px] font-semibold text-white/80 mb-1">{item.title}</div>
              <div className="text-[10px] text-white/35">
                {item.ip_count} IPs · {item.asn_count} ASNs · {item.country_count} countries
              </div>
              {expanded === `ta-${i}` && (
                <div className="mt-3 pt-3 border-t border-white/[0.05] animate-fade-in space-y-2">
                  <div className="grid grid-cols-3 gap-2">
                    <div className="bg-white/[0.02] rounded p-2">
                      <div className="text-[9px] text-white/25 uppercase tracking-wider mb-0.5">Target</div>
                      <div className="text-[11px] text-white/70 font-medium">{item.target}</div>
                    </div>
                    <div className="bg-white/[0.02] rounded p-2">
                      <div className="text-[9px] text-white/25 uppercase tracking-wider mb-0.5">Technique</div>
                      <div className="text-[11px] text-white/70 font-medium">{item.technique}</div>
                    </div>
                    <div className="bg-white/[0.02] rounded p-2">
                      <div className="text-[9px] text-white/25 uppercase tracking-wider mb-0.5">WAF Action</div>
                      <div className={`text-[11px] font-semibold ${item.waf_action === 'ALLOW' ? 'text-rose-400' : item.waf_action === 'COUNT' ? 'text-amber-400' : 'text-emerald-400'}`}>
                        {item.waf_action}
                      </div>
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <button className="btn btn-primary btn-sm flex-1">Investigate</button>
                    <button className="btn btn-ghost btn-sm flex-1">View Campaign</button>
                    <button className="btn btn-ghost btn-sm flex-1">Simulate</button>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function VisibilityMatrix() {
  const { webacls } = useAppStore();
  const levels: Array<'FULL' | 'SAMPLED' | 'METRICS' | 'NONE'> = ['FULL', 'SAMPLED', 'METRICS', 'NONE'];
  const colorMap: Record<string, string> = {
    FULL: 'bg-emerald-500',
    SAMPLED: 'bg-blue-500',
    METRICS: 'bg-violet-500',
    NONE: 'bg-white/10',
  };

  return (
    <div className="glass rounded-xl p-5 h-full">
      <div className="section-label">Logging Visibility</div>
      <div className="space-y-1.5">
        {webacls.map(wacl => {
          const vis = wacl.logging_enabled ? 'FULL' : 'METRICS';
          return (
            <div key={wacl.id} className="flex items-center gap-3 py-1">
              <span className="text-[10px] text-white/40 truncate flex-1 font-mono">{wacl.account_name}</span>
              <span className="text-[9px] text-white/20 w-24 truncate">{wacl.name}</span>
              <div className="flex gap-1">
                {levels.map(level => (
                  <div key={level} className={`
                    w-5 h-5 rounded-[3px] transition-all duration-200
                    ${level === vis ? colorMap[level] : 'bg-white/[0.03]'}
                  `} title={`${wacl.name}: ${vis}`}>
                    {level === vis && <div className="w-full h-full flex items-center justify-center">
                      {level === 'FULL' && <Eye size={10} className="text-white/80" />}
                      {level === 'METRICS' && <Eye size={10} className="text-white/50" />}
                      {level === 'NONE' && <EyeOff size={10} className="text-white/20" />}
                    </div>}
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
      <div className="flex items-center gap-4 mt-3 pt-3 border-t border-white/[0.05]">
        <div className="flex items-center gap-1.5">
          <div className="w-2.5 h-2.5 rounded-[2px] bg-emerald-500" />
          <span className="text-[9px] text-white/30">FULL</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-2.5 h-2.5 rounded-[2px] bg-blue-500" />
          <span className="text-[9px] text-white/30">SAMPLED</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-2.5 h-2.5 rounded-[2px] bg-violet-500" />
          <span className="text-[9px] text-white/30">METRICS</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-2.5 h-2.5 rounded-[2px] bg-white/10" />
          <span className="text-[9px] text-white/30">NONE</span>
        </div>
      </div>
    </div>
  );
}

function CampaignSummary() {
  const { campaigns, setPage, pushContext, openDrawer } = useAppStore();

  return (
    <div className="glass rounded-xl p-5 h-full">
      <div className="section-label">Active Campaigns</div>
      <div className="space-y-2">
        {campaigns.filter(c => c.status === 'active').map(campaign => (
          <button
            key={campaign.id}
            onClick={() => {
              pushContext({ label: `CAMPAIGN ${campaign.id.toUpperCase()}` });
              setPage('investigation');
              openDrawer('campaign', campaign);
            }}
            className="w-full text-left p-3 rounded-lg bg-white/[0.015] border border-white/[0.04] hover:border-white/[0.1] hover:bg-white/[0.03] transition-all group"
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[11px] font-semibold text-white/80 group-hover:text-white transition-colors">{campaign.name}</span>
              <SeverityBadge severity={campaign.risk_level} />
            </div>
            <div className="flex items-center gap-3 text-[10px] text-white/30">
              <span>{campaign.ip_count} IPs</span>
              <span className="text-white/10">·</span>
              <span>{campaign.asn_count} ASNs</span>
              <span className="text-white/10">·</span>
              <span>{campaign.country_count} countries</span>
              <span className="text-white/10">·</span>
              <span>{campaign.application_count} apps</span>
            </div>
            <div className="flex items-center gap-1.5 mt-2">
              <span className="text-[9px] px-1.5 py-0.5 rounded bg-white/[0.04] text-white/30 uppercase tracking-wider">
                WAF: {Object.entries(campaign.waf_action_breakdown).map(([k, v]) => `${k} ${v}`).join(' · ')}
              </span>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

function DetectionSummary() {
  const { detections } = useAppStore();
  const bySeverity = (sev: string) => detections.filter(d => d.severity === sev).length;

  return (
    <div className="glass rounded-xl p-5 h-full">
      <div className="section-label">Detections</div>
      <div className="grid grid-cols-4 gap-3 mb-4">
        {(['critical', 'high', 'medium', 'low'] as const).map(sev => (
          <div key={sev} className="text-center">
            <div className={`text-[22px] font-bold tabular-nums ${sev === 'critical' ? 'text-rose-400' : sev === 'high' ? 'text-orange-400' : sev === 'medium' ? 'text-amber-400' : 'text-blue-400'}`}>
              {bySeverity(sev)}
            </div>
            <div className="text-[9px] text-white/25 uppercase tracking-wider mt-0.5">{sev}</div>
          </div>
        ))}
      </div>
      <div className="space-y-1.5">
        {detections.slice(0, 4).map(d => (
          <div key={d.id} className="flex items-center gap-2 px-2 py-1.5 rounded bg-white/[0.01] hover:bg-white/[0.02] transition-colors cursor-pointer">
            <SeverityBadge severity={d.severity} />
            <span className="text-[11px] text-white/60 truncate flex-1">{d.title}</span>
            <span className="text-[9px] text-white/20">{d.confidence}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function CommandCenter() {
  const { postureDimensions } = useAppStore();
  const overall = postureDimensions.reduce((s, d) => s + d.value, 0) / postureDimensions.length;

  return (
    <div className="space-y-5 animate-fade-in">
      <GlobalStateRow />

      <div className="grid grid-cols-12 gap-4" style={{ height: 'calc(100vh - 200px)' }}>
        {/* Threat Activity - left column */}
        <div className="col-span-4">
          <ThreatActivityStream />
        </div>

        {/* Posture + Campaigns - center */}
        <div className="col-span-5 space-y-4">
          <PostureRing dimensions={postureDimensions} overall={Math.round(overall)} />
          <CampaignSummary />
        </div>

        {/* Right column */}
        <div className="col-span-3 space-y-4">
          <DetectionSummary />
          <VisibilityMatrix />
        </div>
      </div>
    </div>
  );
}
