import { FileSearch, Activity, Shield, Target } from 'lucide-react';
import { StatCard } from '@/components/ui/stat-card';
import { useScans, useVulnerabilities, useComplianceResults } from '@/hooks/useScans';

export function StatsOverview() {
  const { data: scans = [] } = useScans();
  const { data: vulnerabilities = [] } = useVulnerabilities();

  const totalScans = scans.length;
  const activeScans = scans.filter(s => !['complete', 'failed', 'queued'].includes(s.status || '')).length;
  const totalCritical = vulnerabilities.filter(v => v.severity === 'critical').length;
  
  // Calculate average risk score from completed scans
  const completedScans = scans.filter(s => s.status === 'complete' && s.risk_score !== null);
  const avgRiskScore = completedScans.length > 0
    ? Math.round(completedScans.reduce((acc, s) => acc + (s.risk_score || 0), 0) / completedScans.length)
    : 0;
  
  // Compliance is inverse of risk score (higher is better)
  const avgCompliance = completedScans.length > 0 ? 100 - avgRiskScore : 0;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      <StatCard
        title="Total ECUs Scanned"
        value={totalScans}
        subtitle="Across all platforms"
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
        title="Critical Vulnerabilities"
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
  );
}
