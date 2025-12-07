import { useState, useMemo } from 'react';
import { CheckCircle2, XCircle, AlertCircle, FileText } from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { Badge } from '@/components/ui/badge';
import { useScans } from '@/hooks/useScans';
import { cn } from '@/lib/utils';
import { Skeleton } from '@/components/ui/skeleton';
import { ScanSelector } from '@/components/ui/scan-selector';
import { supabase } from '@/integrations/supabase/client';
import { useQuery } from '@tanstack/react-query';

const frameworks = ['MISRA C:2012', 'ISO 21434', 'AUTOSAR', 'ISO 26262'];

export default function Compliance() {
  const [selectedScan, setSelectedScan] = useState('all');
  const { data: scans = [] } = useScans();
  
  // Fetch all compliance results
  const { data: allComplianceResults = [], isLoading } = useQuery({
    queryKey: ['compliance-results-all'],
    queryFn: async () => {
      const { data, error } = await supabase
        .from('compliance_results')
        .select('*')
        .order('created_at', { ascending: false });
      if (error) throw error;
      return data;
    },
  });

  // Filter by selected scan
  const complianceResults = useMemo(() => {
    if (selectedScan === 'all') return allComplianceResults;
    return allComplianceResults.filter(r => r.scan_id === selectedScan);
  }, [allComplianceResults, selectedScan]);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'pass':
        return <CheckCircle2 className="w-4 h-4 text-success" />;
      case 'fail':
        return <XCircle className="w-4 h-4 text-destructive" />;
      default:
        return <AlertCircle className="w-4 h-4 text-warning" />;
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'pass':
        return 'bg-success/20 text-success border-success/30';
      case 'fail':
        return 'bg-destructive/20 text-destructive border-destructive/30';
      default:
        return 'bg-warning/20 text-warning border-warning/30';
    }
  };

  const getFrameworkStats = (framework: string) => {
    // Normalize framework names for matching
    const normalizedFramework = framework.replace(':2012', '').toLowerCase();
    const results = complianceResults.filter((r) => 
      r.framework.toLowerCase().includes(normalizedFramework.split(' ')[0])
    );
    return {
      passed: results.filter((r) => r.status === 'pass').length,
      failed: results.filter((r) => r.status === 'fail').length,
      warnings: results.filter((r) => r.status === 'warning').length,
      total: results.length,
    };
  };

  if (isLoading) {
    return (
      <AppLayout>
        <div className="space-y-6">
          <Skeleton className="h-20 w-full" />
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[1, 2, 3, 4].map((i) => (
              <Skeleton key={i} className="h-48" />
            ))}
          </div>
        </div>
      </AppLayout>
    );
  }

  return (
    <AppLayout>
      <div className="space-y-6">
        {/* Page Header */}
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-primary/20 to-success/20 flex items-center justify-center">
              <FileText className="w-5 h-5 text-primary" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-foreground">Compliance Reports</h1>
              <p className="text-muted-foreground">
                Automotive security compliance analysis and reporting
              </p>
            </div>
          </div>
          <ScanSelector 
            value={selectedScan} 
            onChange={setSelectedScan}
            className="w-[250px] bg-muted/50"
          />
        </div>

        {/* Framework Overview */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {frameworks.map((framework) => {
            const stats = getFrameworkStats(framework);
            const passRate = stats.total > 0 ? Math.round((stats.passed / stats.total) * 100) : 0;
            
            return (
              <div key={framework} className="glass-card rounded-xl border border-border p-5">
                <h3 className="font-semibold text-foreground mb-4">{framework}</h3>
                
                {/* Progress Ring */}
                <div className="relative w-24 h-24 mx-auto mb-4">
                  <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                    <path
                      className="text-muted"
                      strokeWidth="3"
                      stroke="currentColor"
                      fill="none"
                      d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                    />
                    <path
                      className="text-primary"
                      strokeWidth="3"
                      stroke="currentColor"
                      fill="none"
                      strokeDasharray={`${passRate}, 100`}
                      strokeLinecap="round"
                      d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className="text-2xl font-bold font-mono text-foreground">{passRate}%</span>
                  </div>
                </div>

                <div className="flex justify-center gap-4 text-sm">
                  <div className="flex items-center gap-1 text-success">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>{stats.passed}</span>
                  </div>
                  <div className="flex items-center gap-1 text-destructive">
                    <XCircle className="w-4 h-4" />
                    <span>{stats.failed}</span>
                  </div>
                  <div className="flex items-center gap-1 text-warning">
                    <AlertCircle className="w-4 h-4" />
                    <span>{stats.warnings}</span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Detailed Results */}
        <div className="glass-card rounded-xl border border-border overflow-hidden">
          <div className="p-5 border-b border-border">
            <h3 className="text-lg font-semibold text-foreground">Compliance Check Results</h3>
            <p className="text-sm text-muted-foreground">Detailed rule-by-rule analysis</p>
          </div>
          
          {complianceResults.length === 0 ? (
            <div className="p-8 text-center text-muted-foreground">
              No compliance results yet. Upload and scan an ECU binary to generate compliance reports.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border bg-muted/30">
                    <th className="text-left p-4 text-sm font-medium text-muted-foreground">Framework</th>
                    <th className="text-left p-4 text-sm font-medium text-muted-foreground">Rule ID</th>
                    <th className="text-left p-4 text-sm font-medium text-muted-foreground">Description</th>
                    <th className="text-left p-4 text-sm font-medium text-muted-foreground">Status</th>
                    <th className="text-left p-4 text-sm font-medium text-muted-foreground">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {complianceResults.map((result, index) => (
                    <tr 
                      key={result.id}
                      className={cn(
                        "hover:bg-muted/30 transition-colors animate-fade-in",
                      )}
                      style={{ animationDelay: `${index * 30}ms` }}
                    >
                      <td className="p-4">
                        <span className="text-sm font-medium text-foreground">{result.framework}</span>
                      </td>
                      <td className="p-4">
                        <span className="text-sm font-mono text-primary">{result.rule_id}</span>
                      </td>
                      <td className="p-4 max-w-md">
                        <span className="text-sm text-muted-foreground">{result.rule_description}</span>
                      </td>
                      <td className="p-4">
                        <Badge 
                          variant="outline" 
                          className={cn("gap-1", getStatusBadge(result.status || 'pass'))}
                        >
                          {getStatusIcon(result.status || 'pass')}
                          <span className="capitalize">{result.status}</span>
                        </Badge>
                      </td>
                      <td className="p-4 max-w-xs">
                        <span className="text-sm text-muted-foreground">{result.details || '—'}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </AppLayout>
  );
}