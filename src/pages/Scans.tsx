import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQueryClient } from '@tanstack/react-query';
import { Plus, Search, Filter, Eye, Download, Trash2, Cpu, Loader2 } from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { StatusBadge } from '@/components/ui/status-badge';
import { SeverityBadge } from '@/components/ui/severity-badge';
import { ProgressBar } from '@/components/ui/progress-bar';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { useScans, useVulnerabilities, useGenerateReport } from '@/hooks/useScans';
import { supabase } from '@/integrations/supabase/client';
import { format } from 'date-fns';
import { cn } from '@/lib/utils';
import { toast } from '@/hooks/use-toast';
import type { ScanStatus } from '@/types/scan';

export default function Scans() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');

  const { data: scans = [], isLoading } = useScans();
  const { data: allVulnerabilities = [] } = useVulnerabilities();
  const generateReport = useGenerateReport();

  // Real-time subscription for scan updates
  useEffect(() => {
    const channel = supabase
      .channel('scans-list')
      .on(
        'postgres_changes',
        {
          event: '*',
          schema: 'public',
          table: 'scans',
        },
        () => {
          queryClient.invalidateQueries({ queryKey: ['scans'] });
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [queryClient]);

  // Get vulnerability counts per scan
  const getVulnCounts = (scanId: string) => {
    const scanVulns = allVulnerabilities.filter(v => v.scan_id === scanId);
    return {
      critical: scanVulns.filter(v => v.severity === 'critical').length,
      high: scanVulns.filter(v => v.severity === 'high').length,
      medium: scanVulns.filter(v => v.severity === 'medium').length,
      low: scanVulns.filter(v => v.severity === 'low').length,
    };
  };

  const filteredScans = scans.filter((scan) => {
    const matchesSearch = scan.ecu_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (scan.manufacturer || '').toLowerCase().includes(searchQuery.toLowerCase());
    const matchesStatus = statusFilter === 'all' || scan.status === statusFilter;
    const matchesType = typeFilter === 'all' || scan.ecu_type === typeFilter;
    return matchesSearch && matchesStatus && matchesType;
  });

  const handleDownloadReport = async (scanId: string, ecuName: string) => {
    try {
      const result = await generateReport.mutateAsync({ scanId, format: 'markdown' });
      
      const blob = new Blob([result.content], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `scan-report-${ecuName}.md`;
      a.click();
      URL.revokeObjectURL(url);
      
      toast({
        title: 'Report downloaded',
        description: 'Security report has been downloaded successfully.',
      });
    } catch (error) {
      toast({
        title: 'Download failed',
        description: error instanceof Error ? error.message : 'Failed to generate report',
        variant: 'destructive',
      });
    }
  };

  const handleDeleteScan = async (scanId: string) => {
    try {
      const { error } = await supabase.from('scans').delete().eq('id', scanId);
      if (error) throw error;
      
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      toast({
        title: 'Scan deleted',
        description: 'The scan has been deleted successfully.',
      });
    } catch (error) {
      toast({
        title: 'Delete failed',
        description: error instanceof Error ? error.message : 'Failed to delete scan',
        variant: 'destructive',
      });
    }
  };

  if (isLoading) {
    return (
      <AppLayout>
        <div className="flex flex-col items-center justify-center h-96">
          <Loader2 className="w-8 h-8 animate-spin text-primary mb-4" />
          <p className="text-muted-foreground">Loading scans...</p>
        </div>
      </AppLayout>
    );
  }

  return (
    <AppLayout>
      <div className="space-y-6">
        {/* Page Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-foreground mb-2">All Scans</h1>
            <p className="text-muted-foreground">
              View and manage all ECU security scans
            </p>
          </div>
          <Button onClick={() => navigate('/upload')} className="gap-2">
            <Plus className="w-4 h-4" />
            New Scan
          </Button>
        </div>

        {/* Filters */}
        <div className="glass-card rounded-xl border border-border p-4">
          <div className="flex flex-col md:flex-row gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Search ECUs, manufacturers..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10 bg-muted/50"
              />
            </div>
            <div className="flex gap-3">
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="w-[150px] bg-muted/50">
                  <Filter className="w-4 h-4 mr-2" />
                  <SelectValue placeholder="Status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Status</SelectItem>
                  <SelectItem value="queued">Queued</SelectItem>
                  <SelectItem value="parsing">Parsing</SelectItem>
                  <SelectItem value="decompiling">Decompiling</SelectItem>
                  <SelectItem value="analyzing">Analyzing</SelectItem>
                  <SelectItem value="enriching">Enriching</SelectItem>
                  <SelectItem value="complete">Complete</SelectItem>
                  <SelectItem value="failed">Failed</SelectItem>
                </SelectContent>
              </Select>
              <Select value={typeFilter} onValueChange={setTypeFilter}>
                <SelectTrigger className="w-[150px] bg-muted/50">
                  <SelectValue placeholder="ECU Type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Types</SelectItem>
                  <SelectItem value="Engine">Engine</SelectItem>
                  <SelectItem value="Transmission">Transmission</SelectItem>
                  <SelectItem value="BCM">BCM</SelectItem>
                  <SelectItem value="TCU">TCU</SelectItem>
                  <SelectItem value="ADAS">ADAS</SelectItem>
                  <SelectItem value="Infotainment">Infotainment</SelectItem>
                  <SelectItem value="Gateway">Gateway</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </div>

        {/* Scans Table */}
        <div className="glass-card rounded-xl border border-border overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  <th className="text-left p-4 text-sm font-medium text-muted-foreground">ECU</th>
                  <th className="text-left p-4 text-sm font-medium text-muted-foreground">Type</th>
                  <th className="text-left p-4 text-sm font-medium text-muted-foreground">Status</th>
                  <th className="text-left p-4 text-sm font-medium text-muted-foreground">Vulnerabilities</th>
                  <th className="text-left p-4 text-sm font-medium text-muted-foreground">Date</th>
                  <th className="text-right p-4 text-sm font-medium text-muted-foreground">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {filteredScans.map((scan, index) => {
                  const vulnCounts = getVulnCounts(scan.id);
                  
                  return (
                    <tr 
                      key={scan.id}
                      className={cn(
                        "hover:bg-muted/30 cursor-pointer transition-colors animate-fade-in",
                      )}
                      style={{ animationDelay: `${index * 30}ms` }}
                      onClick={() => navigate(`/scans/${scan.id}`)}
                    >
                      <td className="p-4">
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-primary/20 to-accent/20 flex items-center justify-center shrink-0">
                            <Cpu className="w-5 h-5 text-primary" />
                          </div>
                          <div>
                            <div className="font-medium text-foreground">{scan.ecu_name}</div>
                            <div className="text-xs text-muted-foreground">
                              {scan.manufacturer || 'Unknown'} • <span className="font-mono">{scan.version || 'N/A'}</span>
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="p-4">
                        <span className="text-sm text-muted-foreground">{scan.ecu_type}</span>
                      </td>
                      <td className="p-4">
                        <div className="space-y-1">
                          <StatusBadge status={(scan.status || 'queued') as ScanStatus} />
                          {!['complete', 'failed', 'queued'].includes(scan.status || '') && (
                            <ProgressBar value={scan.progress || 0} size="sm" className="w-24" />
                          )}
                        </div>
                      </td>
                      <td className="p-4">
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
                        ) : (
                          <span className="text-sm text-muted-foreground">—</span>
                        )}
                      </td>
                      <td className="p-4">
                        <span className="text-sm text-muted-foreground">
                          {scan.created_at ? format(new Date(scan.created_at), 'MMM d, yyyy') : 'N/A'}
                        </span>
                      </td>
                      <td className="p-4">
                        <div className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
                          <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => navigate(`/scans/${scan.id}`)}>
                            <Eye className="w-4 h-4" />
                          </Button>
                          <Button 
                            variant="ghost" 
                            size="icon" 
                            className="h-8 w-8"
                            onClick={() => handleDownloadReport(scan.id, scan.ecu_name)}
                            disabled={scan.status !== 'complete' || generateReport.isPending}
                          >
                            <Download className="w-4 h-4" />
                          </Button>
                          <Button 
                            variant="ghost" 
                            size="icon" 
                            className="h-8 w-8 text-destructive hover:text-destructive"
                            onClick={() => handleDeleteScan(scan.id)}
                          >
                            <Trash2 className="w-4 h-4" />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {filteredScans.length === 0 && (
            <div className="p-8 text-center">
              <Cpu className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-muted-foreground mb-4">
                {scans.length === 0 ? 'No scans yet. Upload your first ECU binary to get started.' : 'No scans found matching your criteria.'}
              </p>
              {scans.length === 0 && (
                <Button onClick={() => navigate('/upload')}>
                  <Plus className="w-4 h-4 mr-2" />
                  Start First Scan
                </Button>
              )}
            </div>
          )}
        </div>
      </div>
    </AppLayout>
  );
}
