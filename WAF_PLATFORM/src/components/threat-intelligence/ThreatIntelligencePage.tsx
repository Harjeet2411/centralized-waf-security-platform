import React, { useState } from 'react';
import { useAppStore } from '@/store';
import { Search, Globe, Zap, Crosshair } from 'lucide-react';
import type { Entity } from '@/types';
import { EntityDetailPanel } from '@/components/entities/EntityDetailPanel';

function JA4Cluster({ ja4, ipCount, asnCount, countryCount, appCount, accountCount, campaignCount, risk }: {
  ja4: string; ipCount: number; asnCount: number; countryCount: number;
  appCount: number; accountCount: number; campaignCount: number; risk: string;
}) {
  const riskColor = risk === 'critical' ? '#f43f5e' : risk === 'high' ? '#f97316' : risk === 'medium' ? '#fbbf24' : '#60a5fa';

  return (
    <div className="glass rounded-xl p-4 hover:border-white/[0.12] transition-all cursor-pointer group">
      <div className="flex items-start justify-between mb-3">
        <div>
          <div className="text-[12px] font-bold text-white/80 font-mono group-hover:text-white transition-colors">{ja4}</div>
          <div className="text-[10px] text-white/25 mt-0.5">JA4 Fingerprint Cluster</div>
        </div>
        <span className="px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider"
          style={{ color: riskColor, background: `${riskColor}15`, border: `1px solid ${riskColor}25` }}>
          {risk}
        </span>
      </div>
      <div className="grid grid-cols-6 gap-2">
        {[
          { label: 'IPs', value: ipCount }, { label: 'ASNs', value: asnCount },
          { label: 'Countries', value: countryCount }, { label: 'Apps', value: appCount },
          { label: 'Accounts', value: accountCount }, { label: 'Campaigns', value: campaignCount },
        ].map(item => (
          <div key={item.label} className="text-center">
            <div className="text-[16px] font-bold text-white/75 tabular-nums">{item.value}</div>
            <div className="text-[8px] text-white/20 uppercase tracking-wider">{item.label}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

export function ThreatIntelligencePage() {
  const { entities } = useAppStore();
  const [search, setSearch] = useState('');

  const highRisk = entities.filter(e => e.threat_score > 70);
  const ja4Counts = new Map<string, { count: number; entities: Entity[] }>();
  entities.forEach(e => {
    if (e.ja4) {
      const existing = ja4Counts.get(e.ja4) || { count: 0, entities: [] };
      ja4Counts.set(e.ja4, { count: existing.count + 1, entities: [...existing.entities, e] });
    }
  });
  const topJA4s = [...ja4Counts.entries()]
    .filter(([_, v]) => v.count >= 3)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 6);

  return (
    <div className="space-y-4 animate-fade-in">
      <div>
        <div className="text-[13px] font-semibold text-white/85">Threat Intelligence</div>
        <div className="text-[11px] text-white/30 mt-0.5">Entity intelligence, JA4 clusters, threat intel lookups</div>
      </div>

      <div className="relative max-w-sm">
        <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-white/25" />
        <input
          type="text"
          placeholder="Search IP, ASN, JA4, organization..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="search-input !py-1.5 text-[11px]"
        />
      </div>

      {/* JA4 Clusters */}
      <div>
        <div className="section-label">JA4 Fingerprint Clusters</div>
        <div className="grid grid-cols-2 gap-3">
          {topJA4s.map(([ja4, data]) => {
            const avgRisk = data.entities.reduce((s, e) => s + e.threat_score, 0) / data.entities.length;
            const risk = avgRisk > 70 ? 'critical' : avgRisk > 50 ? 'high' : 'medium';
            const countries = new Set(data.entities.map(e => e.country).filter(Boolean)).size;
            const asns = new Set(data.entities.map(e => e.asn).filter(Boolean)).size;
            const apps = new Set(data.entities.flatMap(e => e.applications)).size;
            const accounts = new Set(data.entities.flatMap(e => e.applications)).size;
            return (
              <JA4Cluster
                key={ja4} ja4={ja4} ipCount={data.count} asnCount={asns}
                countryCount={countries} appCount={apps} accountCount={accounts} campaignCount={data.entities.filter(e => e.campaigns.length > 0).length} risk={risk}
              />
            );
          })}
        </div>
      </div>

      {/* High risk entities */}
      <div>
        <div className="section-label">High-Risk Entities ({highRisk.length})</div>
        <div className="glass rounded-xl overflow-hidden">
          <table className="data-table">
            <thead>
              <tr>
                <th>Entity</th>
                <th>Country</th>
                <th>ASN</th>
                <th>JA4</th>
                <th>Threat Score</th>
                <th>Confidence</th>
                <th>Techniques</th>
              </tr>
            </thead>
            <tbody>
              {highRisk.slice(0, 20).map(entity => (
                <tr key={entity.id} className="clickable">
                  <td><span className="font-mono text-[11px] text-white/75">{entity.value}</span></td>
                  <td><span className="text-[11px] text-white/40">{entity.country || '—'}</span></td>
                  <td><span className="text-[10px] font-mono text-white/30">{entity.asn || '—'}</span></td>
                  <td><span className="text-[10px] font-mono text-white/25 truncate max-w-[80px]">{entity.ja4?.slice(0, 14) || '—'}</span></td>
                  <td><span className="text-[12px] font-bold tabular-nums text-rose-400">{entity.threat_score}</span></td>
                  <td><span className="text-[10px] uppercase tracking-wider text-white/35">{entity.confidence}</span></td>
                  <td>
                    <div className="flex flex-wrap gap-1">
                      {entity.techniques.slice(0, 2).map(t => (
                        <span key={t} className="px-1.5 py-0.5 rounded bg-rose-500/[0.06] text-[9px] text-rose-400/80">{t}</span>
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
