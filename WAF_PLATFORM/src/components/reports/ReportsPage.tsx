import React from 'react';
import { useAppStore } from '@/store';
import { FileText, Download, Calendar, Shield, TrendingUp } from 'lucide-react';

const REPORTS = [
  { id: 'exec', name: 'Executive Security Report', desc: 'Overall security posture, critical findings, major risks, trend', freq: 'Weekly' },
  { id: 'weekly', name: 'Weekly Threat Report', desc: 'New campaigns, entity trends, technique analysis', freq: 'Weekly' },
  { id: 'posture', name: 'WAF Posture Report', desc: 'WebACL scores, drift summary, rule effectiveness, coverage', freq: 'Monthly' },
  { id: 'drift', name: 'Drift Report', desc: 'Configuration changes, unauthorized modifications, remediation status', freq: 'Daily' },
  { id: 'incident', name: 'Incident Report', desc: 'Active incidents, timeline, impact, resolution status', freq: 'On-demand' },
  { id: 'campaign', name: 'Campaign Report', desc: 'Active campaigns, entities, targets, recommendations', freq: 'Weekly' },
];

export function ReportsPage() {
  return (
    <div className="space-y-4 animate-fade-in">
      <div>
        <div className="text-[13px] font-semibold text-white/85">Reports</div>
        <div className="text-[11px] text-white/30 mt-0.5">Executive and operational reports with evidence and timestamps</div>
      </div>

      <div className="grid grid-cols-3 gap-3">
        {REPORTS.map(report => (
          <div key={report.id} className="glass rounded-xl p-4 hover:border-white/[0.12] transition-colors group cursor-pointer">
            <div className="flex items-start justify-between mb-2">
              <FileText size={16} className="text-white/15" />
              <span className="text-[9px] text-white/20 uppercase tracking-wider px-2 py-0.5 rounded bg-white/[0.03] border border-white/[0.05]">
                {report.freq}
              </span>
            </div>
            <div className="text-[12px] font-semibold text-white/75 group-hover:text-white/90 transition-colors mb-1">{report.name}</div>
            <div className="text-[10px] text-white/30 leading-relaxed">{report.desc}</div>
            <div className="flex gap-2 mt-3 pt-3 border-t border-white/[0.04]">
              <button className="btn btn-primary btn-sm flex-1"><Download size={10} /> Export</button>
              <button className="btn btn-ghost btn-sm"><Calendar size={10} /> Schedule</button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
