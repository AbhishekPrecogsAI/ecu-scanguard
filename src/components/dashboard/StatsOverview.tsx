import { FileSearch, Activity, Shield, Target, Github, GitBranch, Key, AlertTriangle } from 'lucide-react';
import { StatCard } from '@/components/ui/stat-card';
import { useScans, useVulnerabilities } from '@/hooks/useScans';

// GitLab icon component
const GitLabIcon = ({ className }: { className?: string }) => (
  <svg viewBox="0 0 24 24" fill="currentColor" className={className || "w-4 h-4"}>
    <path d="M22.65 14.39L12 22.13 1.35 14.39a.84.84 0 0 1-.3-.94l1.22-3.78 2.44-7.51A.42.42 0 0 1 4.82 2a.43.43 0 0 1 .58 0 .42.42 0 0 1 .11.18l2.44 7.49h8.1l2.44-7.51A.42.42 0 0 1 18.6 2a.43.43 0 0 1 .58 0 .42.42 0 0 1 .11.18l2.44 7.51L23 13.45a.84.84 0 0 1-.35.94z" />
  </svg>
);

export function StatsOverview() {
  const { data: scans = [] } = useScans();
  const { data: vulnerabilities = [] } = useVulnerabilities();

  const totalScans = scans.length;
  const activeScans = scans.filter(s => !['complete', 'failed', 'queued'].includes(s.status || '')).length;
  const totalCritical = vulnerabilities.filter(v => v.severity === 'critical').length;

  // Git repository stats
  const githubScans = scans.filter(s => s.manufacturer === 'GitHub').length;
  const gitlabScans = scans.filter(s => s.manufacturer === 'GitLab').length;
  const binaryScans = totalScans - githubScans - gitlabScans;

  // Secrets and PII from vulnerabilities
  const secretsCount = vulnerabilities.filter(v => v.cwe_id === 'CWE-798').length;
  const piiCount = vulnerabilities.filter(v => v.cwe_id === 'CWE-359').length;

  // Calculate average risk score from completed scans
  const completedScans = scans.filter(s => s.status === 'complete' && s.risk_score !== null);
  const avgRiskScore = completedScans.length > 0
    ? Math.round(completedScans.reduce((acc, s) => acc + (s.risk_score || 0), 0) / completedScans.length)
    : 0;

  // Compliance is inverse of risk score (higher is better)
  const avgCompliance = completedScans.length > 0 ? 100 - avgRiskScore : 0;

  return (
    <div className="space-y-4">
      {/* Main Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Scans"
          value={totalScans}
          subtitle="Binaries & Repositories"
          icon={FileSearch}
          variant="primary"
        />
        <StatCard
          title="Active Scans"
          value={activeScans}
          subtitle="Currently processing"
          icon={Activity}
          variant="default"
        />
        <StatCard
          title="Critical Findings"
          value={totalCritical}
          subtitle="Requires immediate action"
          icon={Shield}
          variant="destructive"
        />
        <StatCard
          title="Avg. Security Score"
          value={`${avgCompliance}%`}
          subtitle="Based on risk analysis"
          icon={Target}
          variant="success"
        />
      </div>

      {/* Git Repository Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="glass-card rounded-xl border border-border p-4">
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm text-muted-foreground">Scan Sources</span>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-[#24292e]/10 flex items-center justify-center">
                <Github className="w-4 h-4 text-[#24292e] dark:text-white" />
              </div>
              <div>
                <div className="text-lg font-bold text-foreground">{githubScans}</div>
                <div className="text-xs text-muted-foreground">GitHub</div>
              </div>
            </div>
            <div className="h-8 w-px bg-border" />
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-[#fc6d26]/10 flex items-center justify-center">
                <GitLabIcon className="w-4 h-4 text-[#fc6d26]" />
              </div>
              <div>
                <div className="text-lg font-bold text-foreground">{gitlabScans}</div>
                <div className="text-xs text-muted-foreground">GitLab</div>
              </div>
            </div>
            <div className="h-8 w-px bg-border" />
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center">
                <FileSearch className="w-4 h-4 text-primary" />
              </div>
              <div>
                <div className="text-lg font-bold text-foreground">{binaryScans}</div>
                <div className="text-xs text-muted-foreground">Binaries</div>
              </div>
            </div>
          </div>
        </div>

        <div className="glass-card rounded-xl border border-border p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-muted-foreground">Secrets Detected</span>
            <Key className="w-4 h-4 text-destructive" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold text-foreground">{secretsCount}</span>
            <span className="text-sm text-muted-foreground">hardcoded credentials</span>
          </div>
          {secretsCount > 0 && (
            <div className="mt-2 text-xs text-destructive flex items-center gap-1">
              <AlertTriangle className="w-3 h-3" />
              Requires immediate remediation
            </div>
          )}
        </div>

        <div className="glass-card rounded-xl border border-border p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-muted-foreground">PII Exposure</span>
            <Shield className="w-4 h-4 text-warning" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold text-foreground">{piiCount}</span>
            <span className="text-sm text-muted-foreground">personal data findings</span>
          </div>
          {piiCount > 0 && (
            <div className="mt-2 text-xs text-warning flex items-center gap-1">
              <AlertTriangle className="w-3 h-3" />
              GDPR compliance risk
            </div>
          )}
        </div>

        <div className="glass-card rounded-xl border border-border p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-muted-foreground">Repository Coverage</span>
            <GitBranch className="w-4 h-4 text-primary" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold text-foreground">
              {totalScans > 0 ? Math.round(((githubScans + gitlabScans) / totalScans) * 100) : 0}%
            </span>
            <span className="text-sm text-muted-foreground">from Git repos</span>
          </div>
          <div className="mt-2 h-1.5 bg-muted rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-primary to-accent rounded-full"
              style={{ width: `${totalScans > 0 ? ((githubScans + gitlabScans) / totalScans) * 100 : 0}%` }}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
