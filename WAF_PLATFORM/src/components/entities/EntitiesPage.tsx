import React, { useState, useMemo } from 'react';
import { useAppStore } from '@/store';
import { Search, Filter, ArrowUpDown, ExternalLink, Globe, Shield } from 'lucide-react';
import type { Entity, RiskLevel } from '@/types';

const RISK_COLORS: Record<RiskLevel, { text: string; bg: string; border: string }> = {
  critical: { text: 'text-rose-400', bg: 'bg-rose-500/10', border: 'border-rose-500/20' },
  high: { text: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20' },
  medium: { text: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/20' },
  low: { text: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/20' },
  none: { text: 'text-white/30', bg: 'bg-white/5', border: 'border-white/5' },
};

function EntityTable() {
  const { entities, severityFilter, setSeverityFilter, setPage, pushContext, openDrawer } = useAppStore();
  const [sortKey, setSortKey] = useState<'threat_score' | 'last_seen' | 'request_count'>('threat_score');
  const [sortDir, setSortDir] = useState<'desc' | 'asc'>('desc');
  const [search, setSearch] = useState('');

  const filtered = useMemo(() => {
    let result = [...entities];
    if (search) {
      const q = search.toLowerCase();
      result = result.filter(e => e.value.includes(q) || e.label.toLowerCase().includes(q) || e.asn?.toLowerCase().includes(q));
    }
    if (severityFilter !== 'all') {
      const riskMap: Record<string, RiskLevel> = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' };
      result = result.filter(e => e.risk_level === riskMap[severityFilter]);
    }
    result.sort((a, b) => {
      const aVal = sortKey === 'threat_score' ? a.threat_score : sortKey === 'request_count' ? a.request_count : new Date(a.last_seen).getTime();
      const bVal = sortKey === 'threat_score' ? b.threat_score : sortKey === 'request_count' ? b.request_count : new Date(b.last_seen).getTime();
      return sortDir === 'desc' ? bVal - aVal : aVal - bVal;
    });
    return result;
  }, [entities, search, severityFilter, sortKey, sortDir]);

  const toggleSort = (key: typeof sortKey) => {
    if (sortKey === key) setSortDir(d => d === 'desc' ? 'asc' : 'desc');
    else { setSortKey(key); setSortDir('desc'); }
  };

  const SortIndicator = ({ col }: { col: typeof sortKey }) => (
    <span className="text-white/20">{sortKey === col ? (sortDir === 'desc' ? '↓' : '↑') : ''}</span>
  );

  return (
    <div className="glass rounded-xl overflow-hidden">
      <div className="p-4 flex items-center gap-3 border-b border-white/[0.05]">
        <div className="relative flex-1 max-w-sm">
          <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-white/25" />
          <input
            type="text"
            placeholder="Search IP, ASN, organization..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="search-input !py-1.5 text-[11px]"
          />
        </div>
        <div className="flex items-center gap-1">
          {(['all', 'critical', 'high', 'medium', 'low'] as const).map(f => (
            <button
              key={f}
              onClick={() => setSeverityFilter(f)}
              className={`
                px-2.5 py-1 rounded text-[10px] font-medium uppercase tracking-wider transition-all
                ${severityFilter === f ? 'bg-white/[0.08] text-white/80' : 'text-white/25 hover:text-white/50 hover:bg-white/[0.03]'}
              `}
            >
              {f}
            </button>
          ))}
        </div>
        <div className="ml-auto flex items-center gap-1 text-[10px] text-white/25">
          <Filter size={10} />
          <span>{filtered.length} entities</span>
        </div>
      </div>

      <div className="overflow-auto" style={{ maxHeight: 'calc(100vh - 340px)' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Entity</th>
              <th>Type</th>
              <th>Country</th>
              <th>ASN</th>
              <th>JA4</th>
              <th>
                <button onClick={() => toggleSort('threat_score')} className="flex items-center gap-1">
                  Threat Score <SortIndicator col="threat_score" />
                </button>
              </th>
              <th>Confidence</th>
              <th>Risk</th>
              <th>
                <button onClick={() => toggleSort('request_count')} className="flex items-center gap-1">
                  Requests <SortIndicator col="request_count" />
                </button>
              </th>
              <th>Apps</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 50).map(entity => {
              const riskStyle = RISK_COLORS[entity.risk_level];
              return (
                <tr key={entity.id} className="clickable" onClick={() => {
                  pushContext({ label: `IP ${entity.value}` });
                  openDrawer('entity', entity);
                }}>
                  <td>
                    <div className="flex items-center gap-2">
                      <Globe size={11} className="text-white/20 flex-shrink-0" />
                      <span className="font-mono text-[11px] text-white/75">{entity.value}</span>
                    </div>
                  </td>
                  <td><span className="text-[10px] text-white/30 uppercase tracking-wider">{entity.type}</span></td>
                  <td><span className="text-[11px] text-white/50">{entity.country || '—'}</span></td>
                  <td><span className="text-[10px] font-mono text-white/35">{entity.asn || '—'}</span></td>
                  <td><span className="text-[10px] font-mono text-white/25 truncate max-w-[80px]">{entity.ja4?.slice(0, 14) || '—'}</span></td>
                  <td>
                    <span className={`text-[12px] font-bold tabular-nums ${riskStyle.text}`}>
                      {entity.threat_score}
                    </span>
                  </td>
                  <td>
                    <span className={`text-[10px] uppercase tracking-wider ${entity.confidence === 'high' ? 'text-emerald-400' : entity.confidence === 'medium' ? 'text-amber-400' : 'text-white/30'}`}>
                      {entity.confidence}
                    </span>
                  </td>
                  <td>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider ${riskStyle.text} ${riskStyle.bg} ${riskStyle.border} border`}>
                      {entity.risk_level}
                    </span>
                  </td>
                  <td><span className="text-[11px] font-mono text-white/40 tabular-nums">{entity.request_count.toLocaleString()}</span></td>
                  <td><span className="text-[10px] text-white/30">{entity.applications.length}</span></td>
                  <td><ExternalLink size={10} className="text-white/15" /></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function EntitiesPage() {
  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-[13px] font-semibold text-white/85">Entity Intelligence</div>
          <div className="text-[11px] text-white/30 mt-0.5">IP addresses, ASNs, fingerprints, and organizational data</div>
        </div>
      </div>
      <EntityTable />
    </div>
  );
}
