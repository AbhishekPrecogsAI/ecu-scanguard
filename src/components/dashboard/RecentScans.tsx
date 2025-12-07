import { useNavigate } from 'react-router-dom';
import { Eye, Download, Trash2, MoreVertical, Cpu, Plus } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { StatusBadge } from '@/components/ui/status-badge';
import { SeverityBadge } from '@/components/ui/severity-badge';
import { ProgressBar } from '@/components/ui/progress-bar';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { useScans, useVulnerabilities } from '@/hooks/useScans';
import { cn } from '@/lib/utils';
import { format } from 'date-fns';
import type { ScanStatus } from '@/types/scan';

export function RecentScans() {
  const navigate = useNavigate();
  const { data: scans = [], isLoading } = useScans();
  const { data: vulnerabilities = [] } = useVulnerabilities();

  // Get vulnerability counts per scan
  const getVulnCounts = (scanId: string) => {
    const scanVulns = vulnerabilities.filter(v => v.scan_id === scanId);
    return {
      critical: scanVulns.filter(v => v.severity === 'critical').length,
      high: scanVulns.filter(v => v.severity === 'high').length,
      medium: scanVulns.filter(v => v.severity === 'medium').length,
      low: scanVulns.filter(v => v.severity === 'low').length,
    };
  };

  // Take only the 5 most recent scans
  const recentScans = scans.slice(0, 5);

  if (isLoading) {
    return (
      <div className="glass-card rounded-xl border border-border p-8">
        <div className="animate-pulse space-y-4">
          {[1, 2, 3].map((i) => (
            <div key={i} className="flex items-center gap-4">
              <div className="w-10 h-10 rounded-lg bg-muted" />
              <div className="flex-1 space-y-2">
                <div className="h-4 bg-muted rounded w-1/3" />
                <div className="h-3 bg-muted rounded w-1/2" />
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (recentScans.length === 0) {
    return (
      <div className="glass-card rounded-xl border border-border p-8 text-center">
        <Cpu className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
        <h3 className="text-lg font-semibold text-foreground mb-2">No Scans Yet</h3>
        <p className="text-muted-foreground mb-4">
          Upload your first ECU binary to start vulnerability analysis.
        </p>
        <Button onClick={() => navigate('/upload')}>
          <Plus className="w-4 h-4 mr-2" />
          Start First Scan
        </Button>
      </div>
    );
  }

  return (
    <div className="glass-card rounded-xl border border-border overflow-hidden">
      <div className="p-5 border-b border-border flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold text-foreground">Recent Scans</h3>
          <p className="text-sm text-muted-foreground">Latest ECU analysis results</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => navigate('/scans')}>
          View All
        </Button>
      </div>
      
      <div className="divide-y divide-border">
        {recentScans.map((scan, index) => {
          const vulnCounts = getVulnCounts(scan.id);
          
          return (
            <div 
              key={scan.id}
              className={cn(
                "p-4 hover:bg-muted/30 transition-colors cursor-pointer animate-fade-in",
              )}
              style={{ animationDelay: `${index * 50}ms` }}
              onClick={() => navigate(`/scans/${scan.id}`)}
            >
              <div className="flex items-center gap-4">
                {/* ECU Icon */}
                <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-primary/20 to-accent/20 flex items-center justify-center shrink-0">
                  <Cpu className="w-5 h-5 text-primary" />
                </div>
                
                {/* Main Info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <h4 className="font-medium text-foreground truncate">{scan.ecu_name}</h4>
                    <StatusBadge status={(scan.status || 'queued') as ScanStatus} />
                  </div>
                  <div className="flex items-center gap-4 text-xs text-muted-foreground">
                    <span>{scan.ecu_type}</span>
                    {scan.manufacturer && (
                      <>
                        <span>•</span>
                        <span>{scan.manufacturer}</span>
                      </>
                    )}
                    {scan.version && (
                      <>
                        <span>•</span>
                        <span className="font-mono">{scan.version}</span>
                      </>
                    )}
                  </div>
                </div>

                {/* Progress or Vulnerabilities */}
                <div className="w-48 shrink-0">
                  {scan.status === 'complete' ? (
                    <div className="flex items-center gap-2">
                      <div className="flex items-center gap-1">
                        <span className="text-xs font-medium text-destructive">{vulnCounts.critical}</span>
                        <SeverityBadge severity="critical" showLabel={false} size="sm" />
                      </div>
                      <div className="flex items-center gap-1">
                        <span className="text-xs font-medium text-warning">{vulnCounts.high}</span>
                        <SeverityBadge severity="high" showLabel={false} size="sm" />
                      </div>
                      <div className="flex items-center gap-1">
                        <span className="text-xs font-medium text-yellow-400">{vulnCounts.medium}</span>
                        <SeverityBadge severity="medium" showLabel={false} size="sm" />
                      </div>
                      <div className="flex items-center gap-1">
                        <span className="text-xs font-medium text-success">{vulnCounts.low}</span>
                        <SeverityBadge severity="low" showLabel={false} size="sm" />
                      </div>
                    </div>
                  ) : scan.status !== 'queued' && scan.status !== 'failed' ? (
                    <ProgressBar value={scan.progress || 0} size="sm" showLabel />
                  ) : null}
                </div>

                {/* Timestamp */}
                <div className="w-32 text-right shrink-0">
                  <span className="text-xs text-muted-foreground">
                    {scan.created_at ? format(new Date(scan.created_at), 'MMM d, HH:mm') : 'N/A'}
                  </span>
                </div>

                {/* Actions */}
                <DropdownMenu>
                  <DropdownMenuTrigger asChild onClick={(e) => e.stopPropagation()}>
                    <Button variant="ghost" size="icon" className="shrink-0">
                      <MoreVertical className="w-4 h-4" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem onClick={(e) => { e.stopPropagation(); navigate(`/scans/${scan.id}`); }}>
                      <Eye className="w-4 h-4 mr-2" />
                      View Details
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={(e) => e.stopPropagation()} disabled={scan.status !== 'complete'}>
                      <Download className="w-4 h-4 mr-2" />
                      Download Report
                    </DropdownMenuItem>
                    <DropdownMenuItem 
                      className="text-destructive focus:text-destructive"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <Trash2 className="w-4 h-4 mr-2" />
                      Delete
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
