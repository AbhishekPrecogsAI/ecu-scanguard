import { useParams, useNavigate } from 'react-router-dom';
import { useEffect, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, Download, RefreshCw, Cpu, Calendar, Hash, HardDrive, Microchip, Loader2, Shield, Key, FileCode, ClipboardCheck } from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { Button } from '@/components/ui/button';
import { StatusBadge } from '@/components/ui/status-badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { PipelineStatus } from '@/components/scan/PipelineStatus';
import { ExecutiveSummary } from '@/components/scan/ExecutiveSummary';
import { VulnerabilityList } from '@/components/scan/VulnerabilityList';
import { CodeViewer } from '@/components/scan/CodeViewer';
import { SecretsFindings } from '@/components/scan/SecretsFindings';
import { useScan, useVulnerabilities, useComplianceResults, useAnalysisLogs, useGenerateReport } from '@/hooks/useScans';
import { supabase } from '@/integrations/supabase/client';
import { format } from 'date-fns';
import { toast } from '@/hooks/use-toast';
import type { ScanStatus } from '@/types/scan';

export default function ScanDetails() {
  const { id } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  
  const { data: scan, isLoading: scanLoading } = useScan(id);
  const { data: vulnerabilities = [], isLoading: vulnsLoading } = useVulnerabilities(id);
  const { data: complianceResults = [] } = useComplianceResults(id);
  const { data: logs = [] } = useAnalysisLogs(id);
  const generateReport = useGenerateReport();

  // Real-time subscription for scan updates
  useEffect(() => {
    if (!id) return;

    const channel = supabase
      .channel(`scan-${id}`)
      .on(
        'postgres_changes',
        {
          event: '*',
          schema: 'public',
          table: 'scans',
          filter: `id=eq.${id}`,
        },
        () => {
          queryClient.invalidateQueries({ queryKey: ['scan', id] });
        }
      )
      .on(
        'postgres_changes',
        {
          event: 'INSERT',
          schema: 'public',
          table: 'vulnerabilities',
          filter: `scan_id=eq.${id}`,
        },
        () => {
          queryClient.invalidateQueries({ queryKey: ['vulnerabilities', id] });
        }
      )
      .on(
        'postgres_changes',
        {
          event: 'INSERT',
          schema: 'public',
          table: 'analysis_logs',
          filter: `scan_id=eq.${id}`,
        },
        () => {
          queryClient.invalidateQueries({ queryKey: ['logs', id] });
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [id, queryClient]);

  const handleDownloadReport = async () => {
    if (!id) return;
    
    try {
      const result = await generateReport.mutateAsync({ scanId: id, format: 'markdown' });
      
      // Create download
      const blob = new Blob([result.content], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `scan-report-${scan?.ecu_name || id}.md`;
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

  if (scanLoading) {
    return (
      <AppLayout>
        <div className="flex flex-col items-center justify-center h-96">
          <Loader2 className="w-8 h-8 animate-spin text-primary mb-4" />
          <p className="text-muted-foreground">Loading scan details...</p>
        </div>
      </AppLayout>
    );
  }

  if (!scan) {
    return (
      <AppLayout>
        <div className="flex flex-col items-center justify-center h-96">
          <h2 className="text-xl font-semibold text-foreground mb-2">Scan not found</h2>
          <p className="text-muted-foreground mb-4">The requested scan could not be found.</p>
          <Button onClick={() => navigate('/scans')}>View All Scans</Button>
        </div>
      </AppLayout>
    );
  }

  const formatFileSize = (bytes: number | null) => {
    if (!bytes) return 'N/A';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  // Count vulnerabilities by severity
  const vulnCounts = {
    critical: vulnerabilities.filter(v => v.severity === 'critical').length,
    high: vulnerabilities.filter(v => v.severity === 'high').length,
    medium: vulnerabilities.filter(v => v.severity === 'medium').length,
    low: vulnerabilities.filter(v => v.severity === 'low').length,
  };

  // Count secrets and PII findings
  const secretsCount = vulnerabilities.filter(v => v.cwe_id === 'CWE-798').length;
  const piiCount = vulnerabilities.filter(v => v.cwe_id === 'CWE-359').length;

  // Calculate compliance score
  const passCount = complianceResults.filter(r => r.status === 'pass').length;
  const complianceScore = complianceResults.length > 0 
    ? Math.round((passCount / complianceResults.length) * 100) 
    : 0;

  return (
    <AppLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-start justify-between">
          <div>
            <Button 
              variant="ghost" 
              size="sm" 
              onClick={() => navigate('/scans')}
              className="mb-4 -ml-2"
            >
              <ArrowLeft className="w-4 h-4 mr-2" />
              Back to Scans
            </Button>
            
            <div className="flex items-center gap-4 mb-2">
              <div className="w-12 h-12 rounded-lg bg-gradient-to-br from-primary/20 to-accent/20 flex items-center justify-center">
                <Cpu className="w-6 h-6 text-primary" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-foreground">{scan.ecu_name}</h1>
                <div className="flex items-center gap-3 text-sm text-muted-foreground">
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
            </div>
          </div>

          <div className="flex items-center gap-3">
            <StatusBadge status={(scan.status || 'queued') as ScanStatus} />
            <Button variant="outline" size="sm" disabled>
              <RefreshCw className="w-4 h-4 mr-2" />
              Re-scan
            </Button>
            <Button 
              size="sm" 
              className="gap-2"
              onClick={handleDownloadReport}
              disabled={scan.status !== 'complete' || generateReport.isPending}
            >
              {generateReport.isPending ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Download className="w-4 h-4" />
              )}
              Download Report
            </Button>
          </div>
        </div>

        {/* Binary Metadata */}
        <div className="glass-card rounded-xl border border-border p-5">
          <h3 className="text-sm font-medium text-muted-foreground mb-4">Binary Metadata</h3>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-muted flex items-center justify-center">
                <Hash className="w-4 h-4 text-muted-foreground" />
              </div>
              <div>
                <div className="text-xs text-muted-foreground">File</div>
                <div className="text-sm font-mono text-foreground truncate max-w-[120px]" title={scan.file_name}>
                  {scan.file_name}
                </div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-muted flex items-center justify-center">
                <HardDrive className="w-4 h-4 text-muted-foreground" />
              </div>
              <div>
                <div className="text-xs text-muted-foreground">File Size</div>
                <div className="text-sm font-mono text-foreground">{formatFileSize(scan.file_size)}</div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-muted flex items-center justify-center">
                <Microchip className="w-4 h-4 text-muted-foreground" />
              </div>
              <div>
                <div className="text-xs text-muted-foreground">Architecture</div>
                <div className="text-sm font-mono text-foreground">{scan.architecture || 'Unknown'}</div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-muted flex items-center justify-center">
                <Calendar className="w-4 h-4 text-muted-foreground" />
              </div>
              <div>
                <div className="text-xs text-muted-foreground">Scanned</div>
                <div className="text-sm text-foreground">
                  {scan.created_at ? format(new Date(scan.created_at), 'MMM d, yyyy HH:mm') : 'N/A'}
                </div>
              </div>
            </div>
            {scan.completed_at && (
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-muted flex items-center justify-center">
                  <Calendar className="w-4 h-4 text-muted-foreground" />
                </div>
                <div>
                  <div className="text-xs text-muted-foreground">Completed</div>
                  <div className="text-sm text-foreground">
                    {format(new Date(scan.completed_at), 'MMM d, yyyy HH:mm')}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Pipeline Status */}
        <PipelineStatus 
          currentStatus={(scan.status || 'queued') as ScanStatus} 
          progress={scan.progress || 0} 
        />

        {/* Analysis Logs (show during analysis) */}
        {scan.status !== 'complete' && scan.status !== 'failed' && logs.length > 0 && (
          <div className="glass-card rounded-xl border border-border p-5">
            <h3 className="text-sm font-medium text-muted-foreground mb-4">Analysis Logs</h3>
            <div className="space-y-2 max-h-48 overflow-y-auto font-mono text-xs">
              {logs.map((log) => (
                <div 
                  key={log.id} 
                  className={`flex gap-2 ${
                    log.log_level === 'error' ? 'text-destructive' : 
                    log.log_level === 'warning' ? 'text-warning' : 
                    'text-muted-foreground'
                  }`}
                >
                  <span className="text-muted-foreground/50">
                    [{log.created_at ? format(new Date(log.created_at), 'HH:mm:ss') : ''}]
                  </span>
                  <span className="uppercase w-16">[{log.stage}]</span>
                  <span>{log.message}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Executive Summary (only show if complete) */}
        {scan.status === 'complete' && (
          <ExecutiveSummary 
            scan={scan}
            vulnerabilityCounts={vulnCounts}
            complianceScore={complianceScore}
          />
        )}

        {/* Tabbed Results (only show if complete) */}
        {scan.status === 'complete' && vulnerabilities.length > 0 && (
          <Tabs defaultValue="vulnerabilities" className="space-y-4">
            <TabsList className="grid w-full grid-cols-3 lg:w-auto lg:inline-grid">
              <TabsTrigger value="vulnerabilities" className="gap-2">
                <Shield className="w-4 h-4" />
                Vulnerabilities
                <span className="ml-1 text-xs bg-muted px-1.5 py-0.5 rounded">
                  {vulnerabilities.length - secretsCount - piiCount}
                </span>
              </TabsTrigger>
              <TabsTrigger value="secrets" className="gap-2">
                <Key className="w-4 h-4" />
                Secrets & PII
                {(secretsCount + piiCount) > 0 && (
                  <span className="ml-1 text-xs bg-destructive/20 text-destructive px-1.5 py-0.5 rounded">
                    {secretsCount + piiCount}
                  </span>
                )}
              </TabsTrigger>
              <TabsTrigger value="code" className="gap-2">
                <FileCode className="w-4 h-4" />
                Code View
              </TabsTrigger>
            </TabsList>

            <TabsContent value="vulnerabilities" className="space-y-4">
              <VulnerabilityList 
                vulnerabilities={vulnerabilities.filter(v => v.cwe_id !== 'CWE-798' && v.cwe_id !== 'CWE-359')} 
              />
            </TabsContent>

            <TabsContent value="secrets" className="space-y-4">
              <SecretsFindings vulnerabilities={vulnerabilities} />
            </TabsContent>

            <TabsContent value="code" className="space-y-4">
              <CodeViewer vulnerabilities={vulnerabilities} fileName={scan.file_name} />
            </TabsContent>
          </Tabs>
        )}

        {/* Show message if scan is in progress */}
        {scan.status !== 'complete' && scan.status !== 'failed' && (
          <div className="glass-card rounded-xl border border-border p-8 text-center">
            <div className="animate-pulse">
              <div className="w-16 h-16 rounded-full bg-primary/20 mx-auto mb-4 flex items-center justify-center">
                <Cpu className="w-8 h-8 text-primary" />
              </div>
              <h3 className="text-lg font-semibold text-foreground mb-2">Analysis in Progress</h3>
              <p className="text-muted-foreground">
                Please wait while we analyze your ECU binary. Results will appear here automatically.
              </p>
            </div>
          </div>
        )}

        {/* Show failed message */}
        {scan.status === 'failed' && (
          <div className="glass-card rounded-xl border border-destructive/50 p-8 text-center bg-destructive/5">
            <div className="w-16 h-16 rounded-full bg-destructive/20 mx-auto mb-4 flex items-center justify-center">
              <Cpu className="w-8 h-8 text-destructive" />
            </div>
            <h3 className="text-lg font-semibold text-foreground mb-2">Analysis Failed</h3>
            <p className="text-muted-foreground mb-4">
              An error occurred during the analysis. Please try again or contact support.
            </p>
            <Button onClick={() => navigate('/upload')}>Start New Scan</Button>
          </div>
        )}
      </div>
    </AppLayout>
  );
}
