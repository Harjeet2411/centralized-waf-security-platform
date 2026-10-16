import React from 'react';
import { Sidebar } from '@/components/layout/Sidebar';
import { TopBar } from '@/components/layout/TopBar';
import { ContextBar } from '@/components/layout/ContextBar';
import { Drawer } from '@/components/common/Drawer';
import { CommandCenter } from '@/components/commandCenter/CommandCenter';
import { EntitiesPage } from '@/components/entities/EntitiesPage';
import { WafSecurityPage } from '@/components/waf-security/WafSecurityPage';
import { InvestigationPage } from '@/components/investigation/InvestigationPage';
import { DetectionPage } from '@/components/detection/DetectionPage';
import { SimulationPage } from '@/components/simulation/SimulationPage';
import { ResponsePage } from '@/components/response/ResponsePage';
import { GovernancePage } from '@/components/governance/GovernancePage';
import { CostPage } from '@/components/cost/CostPage';
import { ReportsPage } from '@/components/reports/ReportsPage';
import { ThreatIntelligencePage } from '@/components/threat-intelligence/ThreatIntelligencePage';
import { useAppStore } from '@/store';

export default function App() {
  const currentPage = useAppStore(s => s.currentPage);

  const renderPage = () => {
    switch (currentPage) {
      case 'command-center': return <CommandCenter />;
      case 'threat-intelligence': return <ThreatIntelligencePage />;
      case 'waf-security': return <WafSecurityPage />;
      case 'investigation': return <InvestigationPage />;
      case 'detection': return <DetectionPage />;
      case 'simulation': return <SimulationPage />;
      case 'response': return <ResponsePage />;
      case 'governance': return <GovernancePage />;
      case 'cost': return <CostPage />;
      case 'reports': return <ReportsPage />;
      default: return <CommandCenter />;
    }
  };

  return (
    <div className="shell grid-bg">
      <div className="noise-overlay" />
      <Sidebar />
      <div className="main-area">
        <TopBar />
        <ContextBar />
        <div className="content-area">
          {renderPage()}
        </div>
      </div>
      <Drawer />
    </div>
  );
}
