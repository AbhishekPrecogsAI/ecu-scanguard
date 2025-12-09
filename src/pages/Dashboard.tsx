import { AppLayout } from '@/components/layout/AppLayout';
import { StatsOverview } from '@/components/dashboard/StatsOverview';
import { RecentScans } from '@/components/dashboard/RecentScans';
import { VulnerabilityTrends } from '@/components/dashboard/VulnerabilityTrends';
import { TopCVEs } from '@/components/dashboard/TopCVEs';
import { ComplianceOverview } from '@/components/dashboard/ComplianceOverview';

export default function Dashboard() {
  return (
    <AppLayout>
      <div className="space-y-6">
        {/* Page Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-foreground mb-2">Dashboard</h1>
          <p className="text-muted-foreground">
            Overview of ECU security analysis across all scanned firmware
          </p>
        </div>

        {/* Stats Cards */}
        <StatsOverview />

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Vulnerability Trends - Full width on mobile, 2 cols on desktop */}
          <div className="lg:col-span-2">
            <VulnerabilityTrends />
          </div>

          {/* Top CVEs */}
          <div>
            <TopCVEs />
          </div>
        </div>

        {/* Recent Scans */}
        <RecentScans />

        {/* Compliance Overview */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <ComplianceOverview />

          {/* Quick Actions */}
          <div className="glass-card rounded-xl border border-border p-5">
            <h3 className="text-lg font-semibold text-foreground mb-4">Quick Actions</h3>
            <div className="grid grid-cols-2 gap-3">
              <a
                href="/scan-centre"
                className="p-4 rounded-lg bg-gradient-to-br from-primary/10 to-accent/10 border border-primary/20 hover:border-primary/40 transition-colors group"
              >
                <div className="text-sm font-medium text-foreground group-hover:text-primary transition-colors">
                  Scan Centre
                </div>
                <div className="text-xs text-muted-foreground mt-1">
                  Upload files or scan Git repos
                </div>
              </a>
              <a
                href="/scan-centre?tab=github"
                className="p-4 rounded-lg bg-[#24292e]/5 border border-border hover:border-[#24292e]/40 transition-colors group"
              >
                <div className="text-sm font-medium text-foreground group-hover:text-primary transition-colors">
                  Scan GitHub Repo
                </div>
                <div className="text-xs text-muted-foreground mt-1">
                  Clone & analyze from GitHub
                </div>
              </a>
              <a
                href="/vulnerabilities"
                className="p-4 rounded-lg bg-muted/30 border border-border hover:border-primary/40 transition-colors group"
              >
                <div className="text-sm font-medium text-foreground group-hover:text-primary transition-colors">
                  Vulnerability Database
                </div>
                <div className="text-xs text-muted-foreground mt-1">
                  Search all findings
                </div>
              </a>
              <a
                href="/compliance"
                className="p-4 rounded-lg bg-muted/30 border border-border hover:border-primary/40 transition-colors group"
              >
                <div className="text-sm font-medium text-foreground group-hover:text-primary transition-colors">
                  Compliance Reports
                </div>
                <div className="text-xs text-muted-foreground mt-1">
                  ISO 21434 & MISRA C
                </div>
              </a>
            </div>
          </div>
        </div>
      </div>
    </AppLayout>
  );
}
