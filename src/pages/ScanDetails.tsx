import { useParams, useNavigate } from 'react-router-dom';
import { useEffect } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, Download, RefreshCw, Cpu, Calendar, Hash, HardDrive, Microchip, Loader2, Shield, Key, FileCode, FileText, FileDown, Package, Target, ClipboardCheck, Info, GitCompare } from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { Button } from '@/components/ui/button';
import { StatusBadge } from '@/components/ui/status-badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { PipelineStatus } from '@/components/scan/PipelineStatus';
import { ExecutiveSummary } from '@/components/scan/ExecutiveSummary';
import { VulnerabilityList } from '@/components/scan/VulnerabilityList';
import { CodeViewer } from '@/components/scan/CodeViewer';
import { SecretsFindings } from '@/components/scan/SecretsFindings';
import { SBOMTab } from '@/components/scan/SBOMTab';
import { TARATab } from '@/components/scan/TARATab';
import { ComplianceTab } from '@/components/scan/ComplianceTab';
import { BinaryMetadataTab } from '@/components/scan/BinaryMetadataTab';
import { VersionComparisonTab } from '@/components/scan/VersionComparisonTab';
import { useScan, useVulnerabilities, useComplianceResults, useAnalysisLogs, useGenerateReport, useSBOMComponents, useScans } from '@/hooks/useScans';
import { supabase } from '@/integrations/supabase/client';
import { format } from 'date-fns';
import { toast } from '@/hooks/use-toast';
import { jsPDF } from 'jspdf';
import type { ScanStatus } from '@/types/scan';

export default function ScanDetails() {
  const { id } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  
  const { data: scan, isLoading: scanLoading } = useScan(id);
  const { data: vulnerabilities = [] } = useVulnerabilities(id);
  const { data: complianceResults = [] } = useComplianceResults(id);
  const { data: sbomComponents = [] } = useSBOMComponents(id);
  const { data: logs = [] } = useAnalysisLogs(id);
  const { data: allScans = [] } = useScans();
  const generateReport = useGenerateReport();

  useEffect(() => {
    if (!id) return;

    const channel = supabase
      .channel(`scan-${id}`)
      .on('postgres_changes', { event: '*', schema: 'public', table: 'scans', filter: `id=eq.${id}` }, () => {
        queryClient.invalidateQueries({ queryKey: ['scan', id] });
      })
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'vulnerabilities', filter: `scan_id=eq.${id}` }, () => {
        queryClient.invalidateQueries({ queryKey: ['vulnerabilities', id] });
      })
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'analysis_logs', filter: `scan_id=eq.${id}` }, () => {
        queryClient.invalidateQueries({ queryKey: ['logs', id] });
      })
      .subscribe();

    return () => { supabase.removeChannel(channel); };
  }, [id, queryClient]);

  const handleDownloadReport = async (format: 'markdown' | 'json' | 'pdf') => {
    if (!id) return;
    
    try {
      const result = await generateReport.mutateAsync({ scanId: id, format });
      const ecuName = scan?.ecu_name || id;
      
      if (format === 'pdf') {
        const reportData = typeof result.content === 'string' ? JSON.parse(result.content) : result.content;
        const pdf = new jsPDF();
        
        pdf.setFontSize(20);
        pdf.setTextColor(30, 30, 30);
        pdf.text('ECU Vulnerability Scan Report', 20, 20);
        
        pdf.setFontSize(12);
        pdf.setTextColor(80, 80, 80);
        pdf.text(`ECU: ${reportData.scan.ecu_name}`, 20, 35);
        pdf.text(`Type: ${reportData.scan.ecu_type}`, 20, 42);
        pdf.text(`Risk Score: ${reportData.scan.risk_score || 'N/A'}/100`, 20, 49);
        pdf.text(`Generated: ${new Date().toLocaleString()}`, 20, 56);
        
        pdf.setFontSize(14);
        pdf.setTextColor(30, 30, 30);
        pdf.text('Vulnerability Summary', 20, 70);
        
        pdf.setFontSize(10);
        pdf.setTextColor(80, 80, 80);
        const vulnBreakdown = reportData.summary.vulnerability_breakdown;
        pdf.text(`Critical: ${vulnBreakdown.critical} | High: ${vulnBreakdown.high} | Medium: ${vulnBreakdown.medium} | Low: ${vulnBreakdown.low}`, 20, 80);
        
        if (reportData.scan.executive_summary) {
          pdf.setFontSize(14);
          pdf.setTextColor(30, 30, 30);
          pdf.text('Executive Summary', 20, 95);
          
          pdf.setFontSize(9);
          pdf.setTextColor(80, 80, 80);
          const splitSummary = pdf.splitTextToSize(reportData.scan.executive_summary, 170);
          pdf.text(splitSummary, 20, 105);
        }
        
        pdf.addPage();
        pdf.setFontSize(14);
        pdf.setTextColor(30, 30, 30);
        pdf.text('Vulnerabilities', 20, 20);
        
        let yPos = 35;
        reportData.vulnerabilities?.slice(0, 15).forEach((vuln: any, index: number) => {
          if (yPos > 270) { pdf.addPage(); yPos = 20; }
          
          pdf.setFontSize(10);
          pdf.text(`${index + 1}. [${vuln.severity.toUpperCase()}] ${vuln.title}`, 20, yPos);
          yPos += 12;
        });
        
        pdf.save(`scan-report-${ecuName}.pdf`);
      } else if (format === 'markdown') {
        const content = typeof result.content === 'string' ? result.content : JSON.stringify(result.content, null, 2);
        const blob = new Blob([content], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `scan-report-${ecuName}.md`;
        a.click();
        URL.revokeObjectURL(url);
      } else {
        const content = typeof result.content === 'string' ? result.content : JSON.stringify(result.content, null, 2);
        const blob = new Blob([content], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `scan-report-${ecuName}.json`;
        a.click();
        URL.revokeObjectURL(url);
      }
      
      toast({ title: 'Report downloaded', description: `Security report (${format.toUpperCase()}) has been downloaded.` });
    } catch (error) {
      toast({ title: 'Download failed', description: error instanceof Error ? error.message : 'Failed to generate report', variant: 'destructive' });
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

  const vulnCounts = {
    critical: vulnerabilities.filter(v => v.severity === 'critical').length,
    high: vulnerabilities.filter(v => v.severity === 'high').length,
    medium: vulnerabilities.filter(v => v.severity === 'medium').length,
    low: vulnerabilities.filter(v => v.severity === 'low').length,
  };

  const secretsCount = vulnerabilities.filter(v => v.cwe_id === 'CWE-798').length;
  const piiCount = vulnerabilities.filter(v => v.cwe_id === 'CWE-359').length;

  const passCount = complianceResults.filter(r => r.status === 'pass').length;
  const complianceScore = complianceResults.length > 0 ? Math.round((passCount / complianceResults.length) * 100) : 0;

  return (
    <AppLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-start justify-between">
          <div>
            <Button variant="ghost" size="sm" onClick={() => navigate('/scans')} className="mb-4 -ml-2">
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
                  {scan.manufacturer && (<><span>•</span><span>{scan.manufacturer}</span></>)}
                  {scan.version && (<><span>•</span><span className="font-mono">{scan.version}</span></>)}
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
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button size="sm" className="gap-2" disabled={scan.status !== 'complete' || generateReport.isPending}>
                  {generateReport.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
                  Download Report
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => handleDownloadReport('pdf')}><FileDown className="w-4 h-4 mr-2" />Download as PDF</DropdownMenuItem>
                <DropdownMenuItem onClick={() => handleDownloadReport('markdown')}><FileText className="w-4 h-4 mr-2" />Download as Markdown</DropdownMenuItem>
                <DropdownMenuItem onClick={() => handleDownloadReport('json')}><FileCode className="w-4 h-4 mr-2" />Download as JSON</DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>

        {/* Quick Metadata */}
        <div className="glass-card rounded-xl border border-border p-5">
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-muted flex items-center justify-center"><Hash className="w-4 h-4 text-muted-foreground" /></div>
              <div>
                <div className="text-xs text-muted-foreground">File</div>
                <div className="text-sm font-mono text-foreground truncate max-w-[120px]" title={scan.file_name}>{scan.file_name}</div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-muted flex items-center justify-center"><HardDrive className="w-4 h-4 text-muted-foreground" /></div>
              <div>
                <div className="text-xs text-muted-foreground">Size</div>
                <div className="text-sm font-mono text-foreground">{formatFileSize(scan.file_size)}</div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-muted flex items-center justify-center"><Microchip className="w-4 h-4 text-muted-foreground" /></div>
              <div>
                <div className="text-xs text-muted-foreground">Arch</div>
                <div className="text-sm font-mono text-foreground">{scan.architecture || 'Unknown'}</div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-muted flex items-center justify-center"><Calendar className="w-4 h-4 text-muted-foreground" /></div>
              <div>
                <div className="text-xs text-muted-foreground">Scanned</div>
                <div className="text-sm text-foreground">{scan.created_at ? format(new Date(scan.created_at), 'MMM d, HH:mm') : 'N/A'}</div>
              </div>
            </div>
            {scan.completed_at && (
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-muted flex items-center justify-center"><Calendar className="w-4 h-4 text-muted-foreground" /></div>
                <div>
                  <div className="text-xs text-muted-foreground">Done</div>
                  <div className="text-sm text-foreground">{format(new Date(scan.completed_at), 'MMM d, HH:mm')}</div>
                </div>
              </div>
            )}
          </div>
        </div>

        <PipelineStatus currentStatus={(scan.status || 'queued') as ScanStatus} progress={scan.progress || 0} />

        {scan.status !== 'complete' && scan.status !== 'failed' && logs.length > 0 && (
          <div className="glass-card rounded-xl border border-border p-5">
            <h3 className="text-sm font-medium text-muted-foreground mb-4">Analysis Logs</h3>
            <div className="space-y-2 max-h-48 overflow-y-auto font-mono text-xs">
              {logs.map((log) => (
                <div key={log.id} className={`flex gap-2 ${log.log_level === 'error' ? 'text-destructive' : 'text-muted-foreground'}`}>
                  <span className="text-muted-foreground/50">[{log.created_at ? format(new Date(log.created_at), 'HH:mm:ss') : ''}]</span>
                  <span className="uppercase w-16">[{log.stage}]</span>
                  <span>{log.message}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {scan.status === 'complete' && <ExecutiveSummary scan={scan} vulnerabilityCounts={vulnCounts} complianceScore={complianceScore} />}

        {scan.status === 'complete' && (
          <Tabs defaultValue="vulnerabilities" className="space-y-4">
            <TabsList className="flex flex-wrap h-auto gap-1 bg-muted/50 p-1">
              <TabsTrigger value="vulnerabilities" className="gap-1.5 text-xs">
                <Shield className="w-3.5 h-3.5" />Vulnerabilities
                <span className="text-[10px] bg-muted px-1 rounded">{vulnerabilities.length - secretsCount - piiCount}</span>
              </TabsTrigger>
              <TabsTrigger value="secrets" className="gap-1.5 text-xs">
                <Key className="w-3.5 h-3.5" />Secrets & PII
                {(secretsCount + piiCount) > 0 && <span className="text-[10px] bg-destructive/20 text-destructive px-1 rounded">{secretsCount + piiCount}</span>}
              </TabsTrigger>
              <TabsTrigger value="sbom" className="gap-1.5 text-xs">
                <Package className="w-3.5 h-3.5" />SBOM
                <span className="text-[10px] bg-muted px-1 rounded">{sbomComponents.length}</span>
              </TabsTrigger>
              <TabsTrigger value="tara" className="gap-1.5 text-xs">
                <Target className="w-3.5 h-3.5" />TARA
              </TabsTrigger>
              <TabsTrigger value="compliance" className="gap-1.5 text-xs">
                <ClipboardCheck className="w-3.5 h-3.5" />Compliance
              </TabsTrigger>
              <TabsTrigger value="metadata" className="gap-1.5 text-xs">
                <Info className="w-3.5 h-3.5" />Binary Info
              </TabsTrigger>
              <TabsTrigger value="comparison" className="gap-1.5 text-xs">
                <GitCompare className="w-3.5 h-3.5" />Compare
              </TabsTrigger>
              <TabsTrigger value="code" className="gap-1.5 text-xs">
                <FileCode className="w-3.5 h-3.5" />Code View
              </TabsTrigger>
            </TabsList>

            <TabsContent value="vulnerabilities"><VulnerabilityList vulnerabilities={vulnerabilities.filter(v => v.cwe_id !== 'CWE-798' && v.cwe_id !== 'CWE-359')} /></TabsContent>
            <TabsContent value="secrets"><SecretsFindings vulnerabilities={vulnerabilities} /></TabsContent>
            <TabsContent value="sbom"><SBOMTab scanId={id!} components={sbomComponents} ecuName={scan.ecu_name} /></TabsContent>
            <TabsContent value="tara"><TARATab vulnerabilities={vulnerabilities} ecuName={scan.ecu_name} riskScore={scan.risk_score} /></TabsContent>
            <TabsContent value="compliance"><ComplianceTab results={complianceResults} ecuName={scan.ecu_name} /></TabsContent>
            <TabsContent value="metadata"><BinaryMetadataTab scan={scan} /></TabsContent>
            <TabsContent value="comparison"><VersionComparisonTab currentScan={scan} currentVulnerabilities={vulnerabilities} allScans={allScans} /></TabsContent>
            <TabsContent value="code"><CodeViewer vulnerabilities={vulnerabilities} fileName={scan.file_name} /></TabsContent>
          </Tabs>
        )}

        {scan.status !== 'complete' && scan.status !== 'failed' && (
          <div className="glass-card rounded-xl border border-border p-8 text-center">
            <div className="animate-pulse">
              <div className="w-16 h-16 rounded-full bg-primary/20 mx-auto mb-4 flex items-center justify-center">
                <Cpu className="w-8 h-8 text-primary" />
              </div>
              <h3 className="text-lg font-semibold text-foreground mb-2">Analysis in Progress</h3>
              <p className="text-muted-foreground">Please wait while we analyze your ECU binary.</p>
            </div>
          </div>
        )}

        {scan.status === 'failed' && (
          <div className="glass-card rounded-xl border border-destructive/50 p-8 text-center bg-destructive/5">
            <div className="w-16 h-16 rounded-full bg-destructive/20 mx-auto mb-4 flex items-center justify-center">
              <Cpu className="w-8 h-8 text-destructive" />
            </div>
            <h3 className="text-lg font-semibold text-foreground mb-2">Analysis Failed</h3>
            <p className="text-muted-foreground mb-4">An error occurred during the analysis.</p>
            <Button onClick={() => navigate('/upload')}>Start New Scan</Button>
          </div>
        )}
      </div>
    </AppLayout>
  );
}