import { FileText, AlertTriangle, CheckCircle2, TrendingUp } from 'lucide-react';
import type { Scan } from '@/hooks/useScans';

interface ExecutiveSummaryProps {
  scan: Scan;
  vulnerabilityCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  complianceScore: number;
}

export function ExecutiveSummary({ scan, vulnerabilityCounts, complianceScore }: ExecutiveSummaryProps) {
  const riskScore = scan.risk_score || 0;
  
  const getRiskColor = (score: number) => {
    if (score >= 80) return 'text-destructive';
    if (score >= 60) return 'text-warning';
    if (score >= 40) return 'text-yellow-400';
    return 'text-success';
  };

  const getRiskLabel = (score: number) => {
    if (score >= 80) return 'Critical Risk';
    if (score >= 60) return 'High Risk';
    if (score >= 40) return 'Medium Risk';
    return 'Low Risk';
  };

  const totalVulns = vulnerabilityCounts.critical + vulnerabilityCounts.high + 
                     vulnerabilityCounts.medium + vulnerabilityCounts.low;

  return (
    <div className="glass-card rounded-xl border border-border p-6">
      <div className="flex items-start gap-4 mb-6">
        <div className="w-12 h-12 rounded-lg bg-gradient-to-br from-primary/20 to-accent/20 flex items-center justify-center shrink-0">
          <FileText className="w-6 h-6 text-primary" />
        </div>
        <div>
          <h3 className="text-lg font-semibold text-foreground">Executive Summary</h3>
          <p className="text-sm text-muted-foreground">AI-generated security assessment</p>
        </div>
      </div>

      {/* Risk Score */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="p-4 rounded-lg bg-muted/30 border border-border">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="w-4 h-4 text-muted-foreground" />
            <span className="text-sm text-muted-foreground">Risk Score</span>
          </div>
          <div className="flex items-baseline gap-2">
            <span className={`text-3xl font-bold font-mono ${getRiskColor(riskScore)}`}>
              {riskScore}
            </span>
            <span className="text-sm text-muted-foreground">/ 100</span>
          </div>
          <span className={`text-sm font-medium ${getRiskColor(riskScore)}`}>
            {getRiskLabel(riskScore)}
          </span>
        </div>

        <div className="p-4 rounded-lg bg-muted/30 border border-border">
          <div className="flex items-center gap-2 mb-2">
            <CheckCircle2 className="w-4 h-4 text-muted-foreground" />
            <span className="text-sm text-muted-foreground">Compliance Score</span>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-foreground">
              {complianceScore}%
            </span>
          </div>
          <span className="text-sm text-muted-foreground">
            {scan.compliance_frameworks?.join(', ') || 'ISO 21434 / MISRA C'}
          </span>
        </div>

        <div className="p-4 rounded-lg bg-muted/30 border border-border">
          <div className="flex items-center gap-2 mb-2">
            <TrendingUp className="w-4 h-4 text-muted-foreground" />
            <span className="text-sm text-muted-foreground">Total Issues</span>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-foreground">
              {totalVulns}
            </span>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <span className="text-destructive">{vulnerabilityCounts.critical} critical</span>
            <span className="text-muted-foreground">•</span>
            <span className="text-warning">{vulnerabilityCounts.high} high</span>
          </div>
        </div>
      </div>

      {/* Summary Text */}
      {scan.executive_summary && (
        <div className="prose prose-invert prose-sm max-w-none">
          <p className="text-muted-foreground leading-relaxed whitespace-pre-line">
            {scan.executive_summary}
          </p>
        </div>
      )}
    </div>
  );
}
