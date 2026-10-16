import React, { useState } from 'react';
import { useAppStore } from '@/store';
import { FlaskConical, ShieldAlert, Eye, ArrowRight, CheckCircle2, XCircle } from 'lucide-react';
import type { WebACL, WafRule } from '@/types';
import { ActionBadge } from '@/components/waf-security/WafSecurityPage';

export function SimulationPage() {
  const { webacls, rules } = useAppStore();
  const [selectedWacl, setSelectedWacl] = useState<WebACL | null>(webacls[0] || null);
  const [selectedRule, setSelectedRule] = useState<WafRule | null>(null);
  const [proposedAction, setProposedAction] = useState<WafRule['action']>('BLOCK');
  const [simulating, setSimulating] = useState(false);
  const [simResult, setSimResult] = useState<any>(null);

  const waclRules = selectedWacl ? (rules.get(selectedWacl.id) || []) : [];

  const runSimulation = () => {
    if (!selectedRule) return;
    setSimulating(true);
    setTimeout(() => {
      const currentBlocked = selectedRule.blocked;
      const wouldBlock = selectedRule.match_count - selectedRule.allowed - selectedRule.counted;
      setSimResult({
        requests_evaluated: selectedRule.match_count,
        would_block: wouldBlock + Math.floor(selectedRule.match_count * 0.3),
        potential_fp: Math.floor(selectedRule.match_count * 0.02),
        security_gain: proposedAction === 'BLOCK' ? 'HIGH' : 'MEDIUM',
        fp_risk: proposedAction === 'BLOCK' ? 'LOW' : 'NONE',
        affected_apps: randInt(2, 5),
        affected_accounts: randInt(1, 3),
      });
      setSimulating(false);
    }, 1500);
  };

  return (
    <div className="space-y-4 animate-fade-in">
      <div>
        <div className="text-[13px] font-semibold text-white/85">Rule Impact Simulator</div>
        <div className="text-[11px] text-white/30 mt-0.5">Evaluate proposed WAF changes against historical data — never executes</div>
      </div>

      <div className="grid grid-cols-12 gap-4">
        {/* WebACL selection */}
        <div className="col-span-3 space-y-2">
          <div className="section-label">Select WebACL</div>
          <div className="space-y-1">
            {webacls.map(wacl => (
              <button
                key={wacl.id}
                onClick={() => { setSelectedWacl(wacl); setSelectedRule(null); setSimResult(null); }}
                className={`
                  w-full text-left px-3 py-2 rounded-lg text-[11px] transition-all
                  ${selectedWacl?.id === wacl.id
                    ? 'bg-cyan-500/[0.08] border border-cyan-500/20 text-cyan-400'
                    : 'bg-white/[0.015] border border-white/[0.04] text-white/50 hover:text-white/70 hover:bg-white/[0.025]'}
                `}
              >
                <div className="font-medium truncate">{wacl.name}</div>
                <div className="text-[9px] mt-0.5 opacity-60">{wacl.account_name}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Rule selection + config */}
        <div className="col-span-4 space-y-4">
          {selectedWacl && (
            <>
              <div className="glass rounded-xl p-4">
                <div className="section-label">Select Rule</div>
                <div className="space-y-1 max-h-72 overflow-y-auto pr-1">
                  {waclRules.map(rule => (
                    <button
                      key={rule.id}
                      onClick={() => { setSelectedRule(rule); setSimResult(null); }}
                      className={`
                        w-full text-left px-3 py-2 rounded-lg text-[11px] transition-all
                        ${selectedRule?.id === rule.id
                          ? 'bg-cyan-500/[0.08] border border-cyan-500/20'
                          : 'bg-white/[0.015] border border-white/[0.04] hover:bg-white/[0.025]'}
                      `}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-white/70 truncate flex-1">{rule.name}</span>
                        <ActionBadge action={rule.action} />
                      </div>
                      <div className="text-[9px] text-white/25 mt-0.5">
                        {rule.match_count.toLocaleString()} matches · {rule.effectiveness}% effective
                      </div>
                    </button>
                  ))}
                </div>
              </div>

              {selectedRule && (
                <div className="glass rounded-xl p-4">
                  <div className="section-label">Proposed Change</div>
                  <div className="space-y-3">
                    <div>
                      <div className="text-[10px] text-white/35 mb-1">Current Action</div>
                      <ActionBadge action={selectedRule.action} />
                    </div>
                    <div className="flex items-center gap-2">
                      <ArrowRight size={14} className="text-white/20" />
                    </div>
                    <div>
                      <div className="text-[10px] text-white/35 mb-1">Proposed Action</div>
                      <div className="flex gap-1.5">
                        {(['BLOCK', 'COUNT', 'ALLOW'] as const).map(action => (
                          <button
                            key={action}
                            onClick={() => { setProposedAction(action); setSimResult(null); }}
                            className={`
                              px-3 py-1.5 rounded text-[11px] font-bold uppercase tracking-wider transition-all border
                              ${proposedAction === action
                                ? action === 'BLOCK' ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
                                  : action === 'COUNT' ? 'border-amber-500/30 bg-amber-500/10 text-amber-400'
                                  : 'border-rose-500/30 bg-rose-500/10 text-rose-400'
                                : 'border-white/[0.06] text-white/30 hover:text-white/50'
                              }
                            `}
                          >
                            {action}
                          </button>
                        ))}
                      </div>
                    </div>
                    <button
                      onClick={runSimulation}
                      disabled={simulating || proposedAction === selectedRule.action}
                      className="btn btn-primary w-full"
                    >
                      {simulating ? (
                        <><RefreshCw size={12} className="animate-spin" /> Simulating...</>
                      ) : (
                        <><FlaskConical size={12} /> Run Simulation</>
                      )}
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* Results */}
        <div className="col-span-5">
          {simResult ? (
            <div className="glass rounded-xl p-5 animate-fade-in">
              <div className="section-label">Historical Impact Analysis</div>
              <div className="space-y-3">
                {[
                  { label: 'Requests Evaluated', value: simResult.requests_evaluated.toLocaleString(), positive: true },
                  { label: 'Would Block', value: `${simResult.would_block.toLocaleString()} (${((simResult.would_block / simResult.requests_evaluated) * 100).toFixed(1)}%)`, positive: true },
                  { label: 'Potential False Positives', value: simResult.potential_fp.toLocaleString(), positive: false },
                  { label: 'Affected Applications', value: String(simResult.affected_apps), positive: true },
                  { label: 'Affected Accounts', value: String(simResult.affected_accounts), positive: true },
                  { label: 'Security Gain', value: simResult.security_gain, positive: true },
                  { label: 'FP Risk', value: simResult.fp_risk, positive: simResult.fp_risk === 'NONE' },
                ].map(item => (
                  <div key={item.label} className="flex items-center justify-between px-3 py-2 rounded-lg bg-white/[0.015] border border-white/[0.04]">
                    <span className="text-[11px] text-white/45">{item.label}</span>
                    <span className={`text-[11px] font-semibold ${item.positive ? 'text-emerald-400' : 'text-amber-400'}`}>
                      {item.value}
                    </span>
                  </div>
                ))}
              </div>
              <div className="flex gap-2 mt-4 pt-4 border-t border-white/[0.05]">
                <button className="btn btn-primary btn-sm flex-1">View Evidence</button>
                <button className="btn btn-ghost btn-sm flex-1">Request Approval</button>
              </div>
            </div>
          ) : (
            <div className="glass rounded-xl p-8 text-center">
              <FlaskConical size={24} className="text-white/10 mx-auto mb-3" />
              <div className="text-[12px] text-white/25">Select a WebACL and rule, then configure a proposed change to run simulation</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function randInt(min: number, max: number) { return Math.floor(Math.random() * (max - min + 1)) + min; }
