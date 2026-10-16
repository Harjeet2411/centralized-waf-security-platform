import React, { useState } from 'react';
import { useAppStore } from '@/store';
import type { Entity } from '@/types';

function ThreatIntelPanel({ entity }: { entity: Entity }) {
  return (
    <div className="mt-4 pt-4 border-t border-white/[0.05]">
      <div className="section-label">Threat Intelligence</div>
      <div className="space-y-2">
        {entity.threat_intel.map((ti, i) => (
          <div key={i} className="flex items-center justify-between px-3 py-2 rounded-lg bg-white/[0.015] border border-white/[0.04]">
            <div>
              <div className="text-[11px] font-medium text-white/70 capitalize">{ti.source.replace('_', ' ')}</div>
              <div className="text-[10px] text-white/25 mt-0.5">{ti.classification} · {ti.confidence} confidence</div>
            </div>
            <div className="text-right">
              <div className={`text-[14px] font-bold tabular-nums ${ti.score > 70 ? 'text-rose-400' : ti.score > 40 ? 'text-amber-400' : 'text-emerald-400'}`}>
                {ti.score}/100
              </div>
              <div className="text-[9px] text-white/20">{new Date(ti.timestamp).toLocaleTimeString()}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function EntityDetailPanel({ entity }: { entity: Entity }) {
  const riskStyle: Record<string, { text: string; bg: string; border: string }> = {
    critical: { text: 'text-rose-400', bg: 'bg-rose-500/10', border: 'border-rose-500/20' },
    high: { text: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20' },
    medium: { text: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/20' },
    low: { text: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/20' },
  };
  const rs = riskStyle[entity.risk_level] || riskStyle.low;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3">
            <span className="text-[22px] font-mono font-bold text-white/90">{entity.value}</span>
            <span className={`px-3 py-1 rounded-md text-[11px] font-bold uppercase tracking-wider border ${rs.text} ${rs.bg} ${rs.border}`}>
              {entity.risk_level}
            </span>
          </div>
          <div className="flex items-center gap-4 mt-2">
            <span className="text-[11px] text-white/35">Threat Score <span className={`font-bold ${rs.text}`}>{entity.threat_score}</span></span>
            <span className="text-white/10">|</span>
            <span className="text-[11px] text-white/35">Confidence <span className="font-bold text-white/60">{entity.confidence}</span></span>
            <span className="text-white/10">|</span>
            <span className="text-[11px] text-white/35">{entity.request_count.toLocaleString()} requests</span>
          </div>
        </div>
      </div>

      {/* Identity grid */}
      <div className="glass rounded-lg p-4">
        <div className="section-label mb-3">Identity</div>
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'Country', value: entity.country || 'Unknown' },
            { label: 'ASN', value: entity.asn || 'Unknown' },
            { label: 'Organization', value: entity.organization || 'Unknown' },
            { label: 'User Agent', value: entity.user_agent || 'Unknown' },
          ].map(item => (
            <div key={item.label}>
              <div className="text-[9px] text-white/25 uppercase tracking-wider mb-1">{item.label}</div>
              <div className="text-[11px] text-white/60 font-medium truncate">{item.value}</div>
            </div>
          ))}
        </div>
        <div className="grid grid-cols-2 gap-3 mt-3">
          <div>
            <div className="text-[9px] text-white/25 uppercase tracking-wider mb-1">JA3</div>
            <div className="text-[10px] font-mono text-white/40 break-all">{entity.ja3 || '—'}</div>
          </div>
          <div>
            <div className="text-[9px] text-white/25 uppercase tracking-wider mb-1">JA4</div>
            <div className="text-[10px] font-mono text-white/40 break-all">{entity.ja4 || '—'}</div>
          </div>
        </div>
      </div>

      {/* Behavior */}
      <div className="glass rounded-lg p-4">
        <div className="section-label mb-3">Behavioral Profile</div>
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: 'Requests', value: entity.request_count.toLocaleString() },
            { label: 'URI Diversity', value: String(entity.uri_diversity) },
            { label: '404 Ratio', value: `${(entity.not_found_ratio * 100).toFixed(0)}%` },
          ].map(item => (
            <div key={item.label} className="bg-white/[0.02] rounded-md p-2.5">
              <div className="text-[9px] text-white/25 uppercase tracking-wider mb-0.5">{item.label}</div>
              <div className="text-[14px] font-bold font-mono text-white/80 tabular-nums">{item.value}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Applications */}
      <div className="glass rounded-lg p-4">
        <div className="section-label mb-3">Targeted Applications</div>
        <div className="flex flex-wrap gap-1.5">
          {entity.applications.map(app => (
            <span key={app} className="px-2 py-1 rounded bg-white/[0.04] text-[10px] text-white/50 border border-white/[0.05]">
              {app}
            </span>
          ))}
        </div>
      </div>

      {/* Techniques */}
      <div className="glass rounded-lg p-4">
        <div className="section-label mb-3">Attack Techniques</div>
        <div className="flex flex-wrap gap-1.5">
          {entity.techniques.map(t => (
            <span key={t} className="px-2 py-1 rounded bg-rose-500/[0.08] text-[10px] text-rose-400 border border-rose-500/15">
              {t}
            </span>
          ))}
        </div>
      </div>

      <ThreatIntelPanel entity={entity} />
    </div>
  );
}

export { EntityDetailPanel };
