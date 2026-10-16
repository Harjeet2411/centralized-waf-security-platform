import React from 'react';
import { useAppStore } from '@/store';
import { ChevronRight } from 'lucide-react';

export function ContextBar() {
  const { contextPath, popContext } = useAppStore();

  return (
    <div className="context-bar">
      {contextPath.map((item, i) => (
        <React.Fragment key={i}>
          {i > 0 && <ChevronRight size={10} className="text-white/15 flex-shrink-0" />}
          <button
            onClick={() => { if (i < contextPath.length - 1) popContext(); }}
            className={`
              hover:text-white/60 transition-colors
              ${i === contextPath.length - 1 ? 'text-white/70 font-medium' : 'text-white/25'}
            `}
          >
            {item.label}
          </button>
        </React.Fragment>
      ))}
    </div>
  );
}
