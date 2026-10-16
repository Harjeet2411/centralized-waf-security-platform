import React from 'react';
import { useAppStore } from '@/store';
import { DollarSign, TrendingUp, TrendingDown, Receipt } from 'lucide-react';

export function CostPage() {
  const { webacls, accounts } = useAppStore();

  const totalRequests = webacls.reduce((s, w) => s + w.managed_rule_health * 1000, 0);
  const wafCost = (totalRequests / 1000000 * 1).toFixed(2);
  const platformCost = '350.00';

  return (
    <div className="space-y-4 animate-fade-in">
      <div>
        <div className="text-[13px] font-semibold text-white/85">Cost Analysis</div>
        <div className="text-[11px] text-white/30 mt-0.5">WAF cost visibility by account, WebACL, and feature</div>
      </div>

      <div className="grid grid-cols-3 gap-3">
        {[
          { label: 'WAF Monthly', value: `$${wafCost}`, sub: '~1M requests @ $1/M', icon: <Receipt size={14} />, trend: 'up' },
          { label: 'Platform Monthly', value: `$${platformCost}`, sub: 'RDS + Lambda + ElastiCache', icon: <DollarSign size={14} />, trend: 'stable' },
          { label: 'Total Monthly', value: `$${(parseFloat(wafCost) + parseFloat(platformCost)).toFixed(2)}`, sub: 'vs. Firewall Manager ~$3K/acct', icon: <TrendingUp size={14} />, trend: 'down' },
        ].map(stat => (
          <div key={stat.label} className="glass rounded-xl p-4">
            <div className="flex items-center gap-2 mb-2">
              <span className="text-white/25">{stat.icon}</span>
              <span className="text-[10px] text-white/30 uppercase tracking-wider">{stat.label}</span>
            </div>
            <div className="text-[22px] font-bold text-white/85 tabular-nums">{stat.value}</div>
            <div className="text-[10px] text-white/25 mt-1">{stat.sub}</div>
            {stat.trend === 'down' && <div className="text-[10px] text-emerald-400 mt-1 flex items-center gap-1"><TrendingDown size={10} /> ~94% savings vs. managed solution</div>}
          </div>
        ))}
      </div>

      <div className="glass rounded-xl overflow-hidden">
        <div className="p-4 border-b border-white/[0.05]">
          <div className="section-label mb-0">WAF Cost by Account</div>
        </div>
        <table className="data-table">
          <thead>
            <tr>
              <th>Account</th>
              <th>Environment</th>
              <th>WebACLs</th>
              <th>Est. Monthly</th>
              <th>Cost per WAF</th>
            </tr>
          </thead>
          <tbody>
            {accounts.map(acc => {
              const waclCount = webacls.filter(w => w.account_id === acc.id).length;
              const monthly = (waclCount * 5 + randInt(0, 3)).toFixed(2);
              return (
                <tr key={acc.id} className="clickable">
                  <td><span className="text-[11px] text-white/70">{acc.name}</span></td>
                  <td><span className="text-[10px] text-white/30 uppercase">{acc.environment}</span></td>
                  <td><span className="text-[11px] font-mono text-white/50">{waclCount}</span></td>
                  <td><span className="text-[11px] font-mono text-white/60 tabular-nums">${monthly}</span></td>
                  <td><span className="text-[10px] text-white/25">${(parseFloat(monthly) / Math.max(1, waclCount)).toFixed(2)}</span></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function randInt(min: number, max: number) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function TrendingDown({ size }: { size: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="23 18 13.5 8.5 8.5 13.5 1 6" />
      <polyline points="17 18 23 18 23 12" />
    </svg>
  );
}
