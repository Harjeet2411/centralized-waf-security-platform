import React, { useState } from 'react';
import { useAppStore } from '@/store';
import { Search, Network, Clock, FileText, Crosshair, ShieldAlert } from 'lucide-react';
import { EntityDetailPanel } from '@/components/entities/EntityDetailPanel';
import { CampaignDetail } from '@/components/investigation/CampaignDetail';

export function InvestigationPage() {
  const { drawerOpen, drawerContent, drawerData, closeDrawer } = useAppStore();
  const [mode, setMode] = useState<'graph' | 'timeline' | 'table' | 'attack-story' | 'evidence'>('table');

  return (
    <div className="space-y-4 animate-fade-in">
      <div>
        <div className="text-[13px] font-semibold text-white/85">Investigation Workspace</div>
        <div className="text-[11px] text-white/30 mt-0.5">Multi-panel investigation — entities, campaigns, WebACLs, rules</div>
      </div>

      {/* Mode selector */}
      <div className="tab-bar">
        {(['table', 'graph', 'timeline', 'attack-story', 'evidence'] as const).map(m => (
          <button key={m} onClick={() => setMode(m)} className={`tab-item ${mode === m ? 'active' : ''}`}>
            {m === 'attack-story' ? 'Attack Story' : m.charAt(0).toUpperCase() + m.slice(1)}
          </button>
        ))}
      </div>

      {mode === 'table' && (
        <div className="text-center py-20">
          <Search size={32} className="text-white/10 mx-auto mb-3" />
          <div className="text-[12px] text-white/25">Select an entity from Entities to begin investigation</div>
          <div className="text-[10px] text-white/15 mt-1">Or navigate to Threat Intelligence → Entities</div>
        </div>
      )}

      {mode === 'attack-story' && (
        <div className="glass rounded-xl p-6">
          <div className="section-label">Attack Story</div>
          <div className="text-[11px] text-white/40 mb-4">Evidence-based investigation narrative — click a campaign to view its attack story</div>
          <div className="flex flex-col gap-4">
            {[
              { phase: '01', label: 'Reconnaissance', desc: 'Attacker identified application endpoints. 148 unique URIs probed.', color: '#60a5fa' },
              { phase: '02', label: 'Endpoint Discovery', desc: 'WAF sampling used to map application structure.', color: '#60a5fa' },
              { phase: '03', label: 'Credential Attempts', desc: 'Login endpoints targeted. WAF COUNT action allows requests through.', color: '#fbbf24' },
              { phase: '04', label: 'SQLi Probing', desc: 'SQL injection patterns detected. 156 requests allowed.', color: '#f97316' },
              { phase: '05', label: 'Distributed Campaign', desc: '41 IPs, 11 countries, same JA4. Coordinated attack.', color: '#f43f5e' },
              { phase: '06', label: 'Malicious Traffic Allowed', desc: 'CRITICAL — WAF not blocking high-threat entities.', color: '#f43f5e', pulse: true },
            ].map((step, i) => (
              <div key={i} className="flex items-start gap-4">
                <div className="flex flex-col items-center">
                  <div className={`
                    w-10 h-10 rounded-full flex items-center justify-center text-[12px] font-bold flex-shrink-0
                    border ${step.pulse ? 'animate-threat-pulse' : ''}
                  `} style={{
                    backgroundColor: `${step.color}15`,
                    borderColor: `${step.color}30`,
                    color: step.color,
                  }}>
                    {step.phase}
                  </div>
                  {i < 5 && <div className="w-[2px] h-8 mt-1 bg-white/5" />}
                </div>
                <div className="pt-1">
                  <div className="text-[12px] font-semibold text-white/75">{step.label}</div>
                  <div className="text-[11px] text-white/35 mt-0.5 max-w-lg">{step.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {mode === 'graph' && (
        <div className="glass rounded-xl p-6 text-center">
          <Network size={32} className="text-white/10 mx-auto mb-3" />
          <div className="text-[12px] text-white/25">Relationship graph — select an entity to visualize connections</div>
        </div>
      )}

      {mode === 'timeline' && (
        <div className="glass rounded-xl p-6">
          <div className="section-label">Timeline</div>
          <div className="text-[11px] text-white/40">Select a campaign or entity to view its timeline</div>
        </div>
      )}

      {mode === 'evidence' && (
        <div className="glass rounded-xl p-6">
          <div className="section-label">Evidence</div>
          <div className="text-[11px] text-white/40">Investigation evidence collection — select a detection or entity</div>
        </div>
      )}

      {/* Drawer */}
      {drawerOpen && drawerContent === 'entity' && <EntityDetailPanel entity={drawerData} />}
      {drawerOpen && drawerContent === 'campaign' && <CampaignDetail />}
    </div>
  );
}
