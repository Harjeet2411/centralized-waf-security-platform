import React from 'react';
import { useAppStore } from '@/store';
import { Command, RefreshCw, Bell, ChevronRight, Clock, Activity } from 'lucide-react';

export function TopBar() {
  const { currentPage, globalSearch, dataLastUpdated, syncStatus, triggerRefresh, lastError, clearError } = useAppStore();
  const syncing = syncStatus?.status === 'syncing';
  const pageTitle = {
    'command-center': 'Command Center',
    'threat-intelligence': 'Threat Intelligence',
    'waf-security': 'WAF Security',
    'investigation': 'Investigation',
    'detection': 'Detection',
    'simulation': 'Simulation',
    'response': 'Response',
    'governance': 'Governance',
    'cost': 'Cost Analysis',
    'reports': 'Reports',
  }[currentPage] || 'Command Center';

  const timeSince = (ts: number) => {
    if (!ts) return 'never';
    const s = Math.floor((Date.now() - ts) / 1000);
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s/60)}m ago`;
    return `${Math.floor(s/3600)}h ago`;
  };

  return (
    <div className="top-bar">
      <div className="flex items-center gap-2">
        <Activity size={13} className="text-cyan-400/60" />
        <span className="text-[12px] font-semibold text-white/85">{pageTitle}</span>
      </div>

      <div className="flex-1 max-w-md mx-4">
        <div className="relative">
          <Command size={11} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-white/20" />
          <input
            type="text"
            placeholder="⌘K — Search entities, campaigns, WebACLs..."
            className="search-input !py-1 text-[11px]"
            value={globalSearch}
            readOnly
          />
        </div>
      </div>

      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1.5 text-[10px] text-white/30">
          <Clock size={10} />
          <span>{syncing ? 'Syncing accounts…' : syncStatus?.status === 'ready' ? 'Data is current (<1h old)' : `Synced ${timeSince(dataLastUpdated)}`}</span>
        </div>
        {lastError && (
          <button onClick={clearError} title="Dismiss" className="text-[10px] text-rose-400 max-w-xs truncate">{lastError}</button>
        )}
        <button onClick={() => triggerRefresh()} disabled={syncing} title="Refresh (starts a sync only if data is older than 1h)"
          className="p-1.5 rounded-md hover:bg-white/[0.04] text-white/30 hover:text-white/60 transition-colors disabled:opacity-40">
          <RefreshCw size={12} className={syncing ? 'animate-spin' : ''} />
        </button>
        <button className="p-1.5 rounded-md hover:bg-white/[0.04] text-white/30 hover:text-white/60 transition-colors relative">
          <Bell size={12} />
          <span className="absolute top-1 right-1 w-1.5 h-1.5 rounded-full bg-rose-500" />
        </button>
      </div>
    </div>
  );
}
