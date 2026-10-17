import React from 'react';
import { useAppStore } from '@/store';
import { DollarSign, Receipt, Info } from 'lucide-react';

// AWS WAF list prices (us-east-1). Estimates from the live inventory, not billing data: Cost Explorer actuals
// (FR-08) are not integrated yet, so every figure on this page is labelled as an estimate.
const PRICE = { webacl: 5, rule: 1, perMillionRequests: 0.6 };
// Central platform estimate from infra/README.md (default parameters, on-demand).
const PLATFORM_MONTHLY_ESTIMATE = 406.74;

const usd = (n: number) => `$${n.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;

export function CostPage() {
  const { webacls, accounts } = useAppStore();
  const webaclCost = (w: (typeof webacls)[number]) =>
    PRICE.webacl + w.rule_count * PRICE.rule + ((w.requests_24h * 30) / 1_000_000) * PRICE.perMillionRequests;
  const wafTotal = webacls.reduce((s, w) => s + webaclCost(w), 0);
  const ruleTotal = webacls.reduce((s, w) => s + w.rule_count, 0);

  return (
    <div className="space-y-4 animate-fade-in">
      <div>
        <div className="text-[13px] font-semibold text-white/85">Cost Analysis</div>
        <div className="text-[11px] text-white/30 mt-0.5">WAF cost estimated from the live WebACL inventory at AWS list prices</div>
      </div>

      <div className="grid grid-cols-3 gap-3">
        {[
          { label: 'WAF (est.) / month', value: usd(wafTotal), sub: `${webacls.length} WebACLs · ${ruleTotal} rules · CloudWatch 24h requests × 30`, icon: <Receipt size={14} /> },
          { label: 'Platform (est.) / month', value: usd(PLATFORM_MONTHLY_ESTIMATE), sub: 'On-demand, infra/README.md (~$345 with a 1-yr RDS reservation)', icon: <DollarSign size={14} /> },
          { label: 'Total (est.) / month', value: usd(wafTotal + PLATFORM_MONTHLY_ESTIMATE), sub: 'Platform ceiling: $350/month', icon: <Info size={14} /> },
        ].map(stat => (
          <div key={stat.label} className="glass rounded-xl p-4">
            <div className="flex items-center gap-2 mb-2">
              <span className="text-white/25">{stat.icon}</span>
              <span className="text-[10px] text-white/30 uppercase tracking-wider">{stat.label}</span>
            </div>
            <div className="text-[22px] font-bold text-white/85 tabular-nums">{stat.value}</div>
            <div className="text-[10px] text-white/25 mt-1">{stat.sub}</div>
          </div>
        ))}
      </div>

      <div className="glass rounded-xl overflow-hidden">
        <div className="p-4 border-b border-white/[0.05]">
          <div className="section-label mb-0">Estimated WAF Cost by Account</div>
        </div>
        <table className="data-table">
          <thead>
            <tr><th>Account</th><th>Environment</th><th>WebACLs</th><th>Rules</th><th>Requests (24h)</th><th>Est. Monthly</th></tr>
          </thead>
          <tbody>
            {accounts.map(acc => {
              const owned = webacls.filter(w => w.account_id === acc.account_id);
              return (
                <tr key={acc.id}>
                  <td><span className="text-[11px] text-white/70">{acc.name}</span> <span className="text-[10px] font-mono text-white/25">{acc.account_id}</span></td>
                  <td><span className="text-[10px] text-white/30 uppercase">{acc.environment}</span></td>
                  <td><span className="text-[11px] font-mono text-white/50 tabular-nums">{owned.length}</span></td>
                  <td><span className="text-[11px] font-mono text-white/50 tabular-nums">{owned.reduce((s, w) => s + w.rule_count, 0)}</span></td>
                  <td><span className="text-[11px] font-mono text-white/50 tabular-nums">{owned.reduce((s, w) => s + w.requests_24h, 0).toLocaleString()}</span></td>
                  <td><span className="text-[11px] font-mono text-white/60 tabular-nums">{usd(owned.reduce((s, w) => s + webaclCost(w), 0))}</span></td>
                </tr>
              );
            })}
            {accounts.length === 0 && <tr><td colSpan={6}><span className="text-[11px] text-white/30">No accounts registered yet.</span></td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}
