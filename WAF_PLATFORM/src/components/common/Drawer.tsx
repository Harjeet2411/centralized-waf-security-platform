import React from 'react';
import { X } from 'lucide-react';
import { useAppStore } from '@/store';
import { EntityDetailPanel } from '@/components/entities/EntityDetailPanel';
import { CampaignDetail } from '@/components/investigation/CampaignDetail';

export function Drawer() {
  const { drawerOpen, drawerContent, drawerData, closeDrawer } = useAppStore();

  if (!drawerOpen) return null;

  return (
    <>
      <div className="drawer-overlay" onClick={closeDrawer} />
      <div className="drawer-panel">
        <div className="drawer-handle">
          <div className="w-[2px] h-6 bg-white/10 rounded-full" />
        </div>
        <div className="flex items-center justify-between px-5 py-3 border-b border-white/[0.05] sticky top-0 bg-[#0c1019] z-10">
          <div className="text-[11px] text-white/25 uppercase tracking-wider">
            {drawerContent === 'entity' ? 'Entity Intelligence' :
             drawerContent === 'campaign' ? 'Campaign Investigation' :
             drawerContent === 'approval' ? 'Approval Detail' :
             drawerContent === 'drift' ? 'Drift Event' :
             drawerContent === 'webacl' ? 'WebACL Investigation' :
             drawerContent === 'rule' ? 'Rule Investigation' : 'Detail'}
          </div>
          <button onClick={closeDrawer} className="p-1 rounded hover:bg-white/[0.05] text-white/30 hover:text-white/60 transition-colors">
            <X size={14} />
          </button>
        </div>
        <div className="overflow-y-auto" style={{ height: 'calc(100vh - 48px)' }}>
          {drawerContent === 'entity' && drawerData && (
            <div className="animate-slide-up">
              <EntityDetailPanel entity={drawerData} />
            </div>
          )}
          {drawerContent === 'campaign' && (
            <div className="animate-slide-up">
              <CampaignDetail />
            </div>
          )}
          {drawerContent === 'rule' && drawerData?.rule && (
            <div className="animate-slide-up p-6 space-y-4">
              <div>
                <div className="text-[14px] font-bold text-white/85">{drawerData.rule.name}</div>
                <div className="text-[10px] text-white/25 mt-1 font-mono">{drawerData.webacl?.name}</div>
              </div>
              <div className="glass rounded-lg p-4 space-y-2">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <div className="text-[9px] text-white/25 uppercase tracking-wider mb-1">Action</div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      drawerData.rule.action === 'BLOCK' ? 'text-emerald-400 bg-emerald-500/10' :
                      drawerData.rule.action === 'COUNT' ? 'text-amber-400 bg-amber-500/10' : 'text-rose-400 bg-rose-500/10'
                    }`}>{drawerData.rule.action}</span>
                  </div>
                  <div>
                    <div className="text-[9px] text-white/25 uppercase tracking-wider mb-1">Priority</div>
                    <div className="text-[11px] text-white/60 font-mono">{drawerData.rule.priority}</div>
                  </div>
                  <div>
                    <div className="text-[9px] text-white/25 uppercase tracking-wider mb-1">Match Count</div>
                    <div className="text-[14px] font-bold text-white/70 tabular-nums">{drawerData.rule.match_count.toLocaleString()}</div>
                  </div>
                  <div>
                    <div className="text-[9px] text-white/25 uppercase tracking-wider mb-1">Effectiveness</div>
                    <div className={`text-[14px] font-bold tabular-nums ${drawerData.rule.effectiveness >= 80 ? 'text-emerald-400' : drawerData.rule.effectiveness >= 60 ? 'text-amber-400' : 'text-rose-400'}`}>
                      {drawerData.rule.effectiveness}%
                    </div>
                  </div>
                </div>
              </div>
              {drawerData.rule.version_status === 'outdated' && (
                <div className="glass rounded-lg p-4 border border-amber-500/15 bg-amber-500/[0.03]">
                  <div className="text-[11px] font-semibold text-amber-400 mb-1">Outdated Managed Rule</div>
                  <div className="text-[10px] text-white/40">
                    Current: {drawerData.rule.managed_version} → Latest: {drawerData.rule.latest_version}
                  </div>
                  <button className="btn btn-primary btn-sm mt-2">Request Version Update</button>
                </div>
              )}
              <div className="flex gap-2">
                <button className="btn btn-primary btn-sm flex-1">Investigate</button>
                <button className="btn btn-ghost btn-sm flex-1">Simulate Change</button>
              </div>
            </div>
          )}
          {drawerContent === 'approval' && drawerData && (
            <div className="animate-slide-up p-6">
              <div className="text-[11px] text-white/30">Approval detail view</div>
            </div>
          )}
          {drawerContent === 'drift' && drawerData && (
            <div className="animate-slide-up p-6">
              <div className="text-[11px] text-white/30">Drift event detail view</div>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
