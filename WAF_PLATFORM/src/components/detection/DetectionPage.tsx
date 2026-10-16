import React, { useState } from 'react';
import { useAppStore } from '@/store';
import { AlertTriangle, ShieldCheck, Crosshair, Activity, Clock, ChevronDown, ChevronUp } from 'lucide-react';
import type { Detection } from '@/types';

const CONFIDENCE_COLOR = (c: number) => c >= 80 ? 'text-emerald-400' : c >= 60 ? 'text-amber-400' : 'text-white/30';

function DetectionCard({ detection }: { detection: Detection }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className={`
      border-l-2 rounded-r-lg overflow-hidden transition-all duration-200 animate-fade-in
      ${detection.severity === 'critical' ? 'border-l-rose-500 bg-rose-500/[0.02]' : ''}
      ${detection.severity === 'high' ? 'border-l-orange-500 bg-orange-500/[0.02]' : ''}
      ${detection.severity === 'medium' ? 'border-l-amber-500 bg-amber-500/[0.01]' : ''}
      ${detection.severity === 'low' ? 'border-l-blue-500 bg-blue-500/[0.01]' : ''}
    `}>
      <div
        className="p-4 cursor-pointer hover:bg-white/[0.01] transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-start justify-between">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <Crosshair size={12} className={`
                ${detection.severity === 'critical' ? 'text-rose-400' : detection.severity === 'high' ? 'text-orange-400' : 'text-amber-400'}
              `} />
              <span className="text-[12px] font-semibold text-white/80">{detection.title}</span>
              <span className={`
                px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider
                ${detection.severity === 'critical' ? 'severity-critical' : ''}
                ${detection.severity === 'high' ? 'severity-high' : ''}
                ${detection.severity === 'medium' ? 'severity-medium' : ''}
                ${detection.severity === 'low' ? 'severity-low' : ''}
              `}>
                {detection.severity}
              </span>
              <span className={`text-[10px] font-mono ${CONFIDENCE_COLOR(detection.confidence)}`}>
                {detection.confidence}% confidence
              </span>
            </div>
            <p className="text-[11px] text-white/35 leading-relaxed">{detection.description}</p>
            <div className="flex items-center gap-3 mt-2">
              <span className="text-[10px] text-white/20 flex items-center gap-1">
                <Clock size={9} />{new Date(detection.timestamp).toLocaleTimeString()}
              </span>
              <span className="text-[10px] text-white/20">{detection.evidence_count} evidence records</span>
              <span className="text-[10px] text-white/20">{detection.affected_apps.length} apps</span>
              <span className="text-[10px] text-white/20">{detection.affected_accounts.length} accounts</span>
            </div>
          </div>
          <div className="ml-3">
            {expanded ? <ChevronUp size={14} className="text-white/20" /> : <ChevronDown size={14} className="text-white/20" />}
          </div>
        </div>
      </div>

      {expanded && (
        <div className="px-4 pb-4 animate-slide-up">
          <div className="border-t border-white/[0.05] pt-3 space-y-3">
            <div className="section-label">Why Detected</div>
            <div className="grid grid-cols-2 gap-2">
              {detection.evidence.map((ev, i) => (
                <div key={i} className="flex items-start gap-2 px-3 py-2 rounded-md bg-white/[0.015] border border-white/[0.04]">
                  <div className="w-4 h-4 rounded-full bg-emerald-500/15 flex items-center justify-center flex-shrink-0 mt-0.5">
                    <span className="text-[8px] text-emerald-400">✓</span>
                  </div>
                  <div>
                    <div className="text-[10px] text-white/35">{ev.type}</div>
                    <div className="text-[11px] text-white/60">{ev.label}: {ev.value}</div>
                  </div>
                </div>
              ))}
            </div>
            <div className="flex gap-2 pt-2">
              <button className="btn btn-primary btn-sm">Investigate</button>
              <button className="btn btn-ghost btn-sm">View Campaign</button>
              <button className="btn btn-ghost btn-sm">Simulate</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export function DetectionPage() {
  const { detections, severityFilter, setSeverityFilter } = useAppStore();

  const filtered = severityFilter === 'all' ? detections : detections.filter(d => d.severity === severityFilter);

  const counts = {
    critical: detections.filter(d => d.severity === 'critical').length,
    high: detections.filter(d => d.severity === 'high').length,
    medium: detections.filter(d => d.severity === 'medium').length,
    low: detections.filter(d => d.severity === 'low').length,
  };

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-[13px] font-semibold text-white/85">Behavioral Detection</div>
          <div className="text-[11px] text-white/30 mt-0.5">Detections explain themselves — every signal includes evidence and confidence</div>
        </div>
        <div className="flex items-center gap-1">
          {(['all', 'critical', 'high', 'medium', 'low'] as const).map(f => (
            <button
              key={f}
              onClick={() => setSeverityFilter(f)}
              className={`
                px-3 py-1.5 rounded text-[10px] font-semibold uppercase tracking-wider transition-all
                ${severityFilter === f ? 'bg-white/[0.08] text-white/80 border border-white/[0.1]' : 'text-white/25 hover:text-white/50 border border-transparent'}
              `}
            >
              {f === 'all' ? `All (${detections.length})` : `${f} (${counts[f]})`}
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-2" style={{ maxHeight: 'calc(100vh - 180px)', overflowY: 'auto' }}>
        {filtered.map(detection => (
          <DetectionCard key={detection.id} detection={detection} />
        ))}
      </div>
    </div>
  );
}
