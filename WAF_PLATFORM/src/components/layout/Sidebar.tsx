import React from 'react';
import {
  LayoutDashboard, Shield, Globe, Search, FlaskConical,
  ShieldCheck, Settings, DollarSign, FileText, Radar,
} from 'lucide-react';
import type { Page } from '@/types';
import { useAppStore } from '@/store';

const NAV_ITEMS: { page: Page; label: string; icon: React.ReactNode }[] = [
  { page: 'command-center', label: 'Command Center', icon: <LayoutDashboard size={15} /> },
  { page: 'threat-intelligence', label: 'Threat Intelligence', icon: <Radar size={15} /> },
  { page: 'waf-security', label: 'WAF Security', icon: <Shield size={15} /> },
  { page: 'investigation', label: 'Investigation', icon: <Search size={15} /> },
  { page: 'detection', label: 'Detection', icon: <ShieldCheck size={15} /> },
  { page: 'simulation', label: 'Simulation', icon: <FlaskConical size={15} /> },
  { page: 'response', label: 'Response', icon: <ShieldCheck size={15} /> },
  { page: 'governance', label: 'Governance', icon: <Settings size={15} /> },
  { page: 'cost', label: 'Cost', icon: <DollarSign size={15} /> },
  { page: 'reports', label: 'Reports', icon: <FileText size={15} /> },
];

export function Sidebar() {
  const { currentPage, setPage, sidebarCollapsed, globalSearch, setGlobalSearch, accounts, platformHealth } = useAppStore();
  const reachable = accounts.filter(a => a.status !== 'unavailable').length;

  return (
    <aside className={`sidebar ${sidebarCollapsed ? 'w-[56px] min-w-[56px]' : ''}`}>
      <div className="px-3 py-3 flex items-center gap-2.5 border-b border-white/5">
        <div className="w-7 h-7 rounded-md flex items-center justify-center flex-shrink-0"
          style={{
            background: 'linear-gradient(135deg, rgba(34,211,238,0.2), rgba(96,165,250,0.1))',
            border: '1px solid rgba(34,211,238,0.25)',
          }}>
          <Shield size={14} className="text-cyan-400" />
        </div>
        {!sidebarCollapsed && (
          <div className="min-w-0">
            <div className="text-xs font-bold tracking-wide text-white/90 truncate">WAF Platform</div>
            <div className="text-[9px] text-white/25 tracking-wider uppercase">Security Intelligence</div>
          </div>
        )}
      </div>

      {/* Search */}
      {!sidebarCollapsed && (
        <div className="px-3 py-2">
          <div className="relative">
            <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-white/25" />
            <input
              type="text"
              placeholder="Search entities..."
              value={globalSearch}
              onChange={e => setGlobalSearch(e.target.value)}
              className="search-input text-[11px] !py-1.5"
            />
          </div>
        </div>
      )}

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto py-1 px-1.5 space-y-0.5 scroll-fade">
        {NAV_ITEMS.map(item => {
          const active = currentPage === item.page;
          return (
            <button
              key={item.page}
              onClick={() => setPage(item.page)}
              className={`
                w-full flex items-center gap-2.5 px-2.5 py-[7px] rounded-md text-[12px] font-medium
                transition-all duration-150 group relative
                ${active
                  ? 'bg-cyan-500/[0.08] text-cyan-400'
                  : 'text-white/45 hover:text-white/75 hover:bg-white/[0.03]'
                }
              `}
            >
              {active && (
                <div className="absolute left-0 top-1/2 -translate-y-1/2 w-[2px] h-4 bg-cyan-400 rounded-r-full" />
              )}
              <span className="flex-shrink-0">{item.icon}</span>
              {!sidebarCollapsed && <span className="truncate">{item.label}</span>}
              {active && (
                <span className="ml-auto w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse-glow" />
              )}
            </button>
          );
        })}
      </nav>

      {/* Bottom status */}
      <div className="p-2.5 border-t border-white/5">
        <div className="flex items-center gap-2 px-2 py-1.5 rounded-md bg-white/[0.02]">
          <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse-glow flex-shrink-0" />
          {!sidebarCollapsed && (
            <div className="min-w-0">
              <div className="text-[10px] text-white/50 truncate capitalize">Platform {platformHealth.overall}</div>
              <div className="text-[9px] text-white/25">{reachable}/{accounts.length} accounts reachable</div>
            </div>
          )}
        </div>
      </div>
    </aside>
  );
}
