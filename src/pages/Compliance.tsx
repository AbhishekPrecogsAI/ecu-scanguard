import { useState, useMemo } from 'react';
import { CheckCircle2, XCircle, AlertCircle, FileText, Download, Plus, ChevronRight, Shield, File, Trash2, RefreshCw, Eye, Settings, ListChecks, TrendingUp, Calendar, Palette } from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { useScans } from '@/hooks/useScans';
import { cn } from '@/lib/utils';
import { Skeleton } from '@/components/ui/skeleton';
import { ScanSelector } from '@/components/ui/scan-selector';
import { supabase } from '@/integrations/supabase/client';
import { useQuery } from '@tanstack/react-query';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { toast } from '@/hooks/use-toast';
import { format } from 'date-fns';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { BrandingSettings } from '@/components/report/BrandingSettings';
import { generatePDFReport, downloadPDF, type ReportBranding, type ReportData } from '@/lib/pdfReportGenerator';

const frameworks = ['MISRA C:2023', 'ISO 21434:2021', 'AUTOSAR R22-11', 'ISO 26262:2018', 'UNECE WP.29'];

interface GeneratedReport {
  id: string;
  name: string;
  framework: string;
  date: Date;
  scope: number;
}

export default function Compliance() {
  const [selectedScan, setSelectedScan] = useState('all');
  const [isWizardOpen, setIsWizardOpen] = useState(false);
  const [wizardStep, setWizardStep] = useState(1);
  const [wizardData, setWizardData] = useState({
    dateRange: { start: '', end: '' },
    selectedEcus: [] as string[],
    frameworks: [] as string[],
    includeExecutiveSummary: true,
    includeTechnicalDetails: true,
    includeRemediation: true,
    includeSBOM: false,
  });
  const [branding, setBranding] = useState<Partial<ReportBranding>>({
    companyName: 'ECU Security Scanner',
    primaryColor: '#3b82f6',
    secondaryColor: '#1e40af',
    footerText: 'Confidential - For Internal Use Only',
  });
  const [isGenerating, setIsGenerating] = useState(false);
  
  const { data: scans = [] } = useScans();
  
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

  // Mock generated reports
  const [generatedReports] = useState<GeneratedReport[]>([
    { id: '1', name: 'UNECE-155 Q4 Compliance Report', framework: 'UNECE WP.29', date: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), scope: 12 },
    { id: '2', name: 'ISO 21434 Annual Assessment', framework: 'ISO 21434:2021', date: new Date(Date.now() - 14 * 24 * 60 * 60 * 1000), scope: 8 },
    { id: '3', name: 'MISRA C Code Quality Report', framework: 'MISRA C:2023', date: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), scope: 5 },
  ]);

  const complianceResults = useMemo(() => {
    if (selectedScan === 'all') return allComplianceResults;
    return allComplianceResults.filter(r => r.scan_id === selectedScan);
  }, [allComplianceResults, selectedScan]);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'pass': return <CheckCircle2 className="w-4 h-4 text-success" />;
      case 'fail': return <XCircle className="w-4 h-4 text-destructive" />;
      default: return <AlertCircle className="w-4 h-4 text-warning" />;
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'pass': return 'bg-success/20 text-success border-success/30';
      case 'fail': return 'bg-destructive/20 text-destructive border-destructive/30';
      default: return 'bg-warning/20 text-warning border-warning/30';
    }
  };

  const getFrameworkStats = (framework: string) => {
    const normalizedFramework = framework.replace(':2023', '').replace(':2021', '').replace(':2018', '').replace(' R22-11', '').replace(' WP.29', '').toLowerCase();
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

  const overallUNECE = getFrameworkStats('UNECE WP.29');
  const overallISO21434 = getFrameworkStats('ISO 21434:2021');
  const uneceScore = overallUNECE.total > 0 ? Math.round((overallUNECE.passed / overallUNECE.total) * 100) : 0;
  const iso21434Score = overallISO21434.total > 0 ? Math.round((overallISO21434.passed / overallISO21434.total) * 100) : 0;

  const handleGenerateReport = async () => {
    setIsGenerating(true);
    try {
      // Fetch vulnerabilities for selected ECUs
      const scanIds = wizardData.selectedEcus.length > 0 ? wizardData.selectedEcus : scans.filter(s => s.status === 'complete').map(s => s.id);
      
      const { data: vulnerabilities = [] } = await supabase
        .from('vulnerabilities')
        .select('*')
        .in('scan_id', scanIds);

      const { data: sbomComponents = [] } = await supabase
        .from('sbom_components')
        .select('*')
        .in('scan_id', scanIds);

      // Use the first selected scan for scan details, or first complete scan
      const primaryScan = scans.find(s => scanIds.includes(s.id)) || scans[0];
      
      if (!primaryScan) {
        toast({ title: 'Error', description: 'No scan data available for report generation.', variant: 'destructive' });
        return;
      }

      const reportData: ReportData = {
        scan: {
          id: primaryScan.id,
          ecu_name: primaryScan.ecu_name,
          ecu_type: primaryScan.ecu_type,
          version: primaryScan.version || undefined,
          manufacturer: primaryScan.manufacturer || undefined,
          architecture: primaryScan.architecture || undefined,
          file_name: primaryScan.file_name,
          file_hash: primaryScan.file_hash || undefined,
          risk_score: primaryScan.risk_score || undefined,
          executive_summary: primaryScan.executive_summary || undefined,
          created_at: primaryScan.created_at || undefined,
          completed_at: primaryScan.completed_at || undefined,
        },
        vulnerabilities: vulnerabilities.map(v => ({
          title: v.title,
          severity: v.severity,
          cve_id: v.cve_id || undefined,
          cwe_id: v.cwe_id || undefined,
          cvss_score: v.cvss_score || undefined,
          description: v.description || undefined,
          affected_component: v.affected_component || undefined,
          remediation: v.remediation || undefined,
        })),
        complianceResults: complianceResults.map(c => ({
          framework: c.framework,
          rule_id: c.rule_id,
          status: c.status || 'warning',
          rule_description: c.rule_description || undefined,
        })),
        sbomComponents: sbomComponents.map(s => ({
          component_name: s.component_name,
          version: s.version || undefined,
          license: s.license || undefined,
        })),
        options: {
          includeExecutiveSummary: wizardData.includeExecutiveSummary,
          includeTechnicalDetails: wizardData.includeTechnicalDetails,
          includeRemediation: wizardData.includeRemediation,
          includeSBOM: wizardData.includeSBOM,
          frameworks: wizardData.frameworks,
        },
      };

      const pdf = generatePDFReport(reportData, branding);
      const filename = `compliance-report-${primaryScan.ecu_name.replace(/\s+/g, '-')}-${format(new Date(), 'yyyy-MM-dd')}.pdf`;
      downloadPDF(pdf, filename);

      toast({ title: 'Report Generated', description: 'Your compliance report has been downloaded.' });
      setIsWizardOpen(false);
      setWizardStep(1);
    } catch (error) {
      console.error('Report generation error:', error);
      toast({ title: 'Error', description: 'Failed to generate report. Please try again.', variant: 'destructive' });
    } finally {
      setIsGenerating(false);
    }
  };

  if (isLoading) {
    return (
      <AppLayout>
        <div className="space-y-6">
          <Skeleton className="h-20 w-full" />
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[1, 2, 3, 4].map((i) => (<Skeleton key={i} className="h-48" />))}
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
            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-slate-500/20 to-blue-500/20 flex items-center justify-center">
              <FileText className="w-5 h-5 text-primary" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-foreground">Compliance Reports</h1>
              <p className="text-muted-foreground">Automotive security compliance analysis and reporting</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <ScanSelector value={selectedScan} onChange={setSelectedScan} className="w-[200px] bg-muted/50" />
            <Dialog open={isWizardOpen} onOpenChange={setIsWizardOpen}>
              <DialogTrigger asChild>
                <Button className="gap-2">
                  <Plus className="w-4 h-4" />
                  Generate Report
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl">
                <DialogHeader>
                  <DialogTitle>Generate Compliance Report</DialogTitle>
                </DialogHeader>
                
                {/* Wizard Steps */}
                <div className="flex items-center gap-2 my-4">
                  {[1, 2, 3, 4].map((step) => (
                    <div key={step} className="flex items-center">
                      <div className={cn(
                        "w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium",
                        wizardStep >= step ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground"
                      )}>
                        {step}
                      </div>
                      {step < 4 && <ChevronRight className={cn("w-4 h-4 mx-1", wizardStep > step ? "text-primary" : "text-muted-foreground")} />}
                    </div>
                  ))}
                </div>

                {wizardStep === 1 && (
                  <div className="space-y-4">
                    <h4 className="font-medium">Step 1: Select Scope</h4>
                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label>Start Date</Label>
                        <input type="date" className="w-full h-10 px-3 rounded-md border border-input bg-background" 
                          value={wizardData.dateRange.start} 
                          onChange={(e) => setWizardData({ ...wizardData, dateRange: { ...wizardData.dateRange, start: e.target.value } })} 
                        />
                      </div>
                      <div className="space-y-2">
                        <Label>End Date</Label>
                        <input type="date" className="w-full h-10 px-3 rounded-md border border-input bg-background" 
                          value={wizardData.dateRange.end} 
                          onChange={(e) => setWizardData({ ...wizardData, dateRange: { ...wizardData.dateRange, end: e.target.value } })} 
                        />
                      </div>
                    </div>
                    <div className="space-y-2">
                      <Label>Select ECUs</Label>
                      <div className="max-h-40 overflow-y-auto border rounded-md p-2 space-y-2">
                        {scans.filter(s => s.status === 'complete').map((scan) => (
                          <div key={scan.id} className="flex items-center space-x-2">
                            <Checkbox id={scan.id} 
                              checked={wizardData.selectedEcus.includes(scan.id)}
                              onCheckedChange={(checked) => {
                                if (checked) {
                                  setWizardData({ ...wizardData, selectedEcus: [...wizardData.selectedEcus, scan.id] });
                                } else {
                                  setWizardData({ ...wizardData, selectedEcus: wizardData.selectedEcus.filter(id => id !== scan.id) });
                                }
                              }}
                            />
                            <label htmlFor={scan.id} className="text-sm">{scan.ecu_name}</label>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                {wizardStep === 2 && (
                  <div className="space-y-4">
                    <h4 className="font-medium">Step 2: Select Framework</h4>
                    <div className="grid grid-cols-1 gap-3">
                      {[
                        { id: 'unece', name: 'UNECE WP.29 R155/R156', desc: 'Cybersecurity and software update regulations' },
                        { id: 'iso21434', name: 'ISO/SAE 21434:2021', desc: 'Road vehicles cybersecurity engineering' },
                        { id: 'iso26262', name: 'ISO 26262:2018', desc: 'Functional safety for road vehicles' },
                        { id: 'misra', name: 'MISRA C:2023', desc: 'C coding guidelines for safety-critical systems' },
                        { id: 'autosar', name: 'AUTOSAR R22-11', desc: 'Automotive software architecture standard' },
                      ].map((fw) => (
                        <div key={fw.id} className="flex items-start space-x-3 p-3 border rounded-lg hover:bg-muted/50">
                          <Checkbox id={fw.id} 
                            checked={wizardData.frameworks.includes(fw.id)}
                            onCheckedChange={(checked) => {
                              if (checked) {
                                setWizardData({ ...wizardData, frameworks: [...wizardData.frameworks, fw.id] });
                              } else {
                                setWizardData({ ...wizardData, frameworks: wizardData.frameworks.filter(id => id !== fw.id) });
                              }
                            }}
                          />
                          <div>
                            <label htmlFor={fw.id} className="text-sm font-medium">{fw.name}</label>
                            <p className="text-xs text-muted-foreground">{fw.desc}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {wizardStep === 3 && (
                  <div className="space-y-4">
                    <h4 className="font-medium">Step 3: Report Customization</h4>
                    <Tabs defaultValue="content" className="w-full">
                      <TabsList className="grid w-full grid-cols-2">
                        <TabsTrigger value="content">Content Options</TabsTrigger>
                        <TabsTrigger value="branding" className="gap-1">
                          <Palette className="w-3 h-3" />
                          Branding
                        </TabsTrigger>
                      </TabsList>
                      <TabsContent value="content" className="space-y-4 mt-4">
                        <div className="flex items-center justify-between">
                          <div>
                            <Label>Include Executive Summary</Label>
                            <p className="text-xs text-muted-foreground">High-level overview for management</p>
                          </div>
                          <Switch checked={wizardData.includeExecutiveSummary} onCheckedChange={(v) => setWizardData({ ...wizardData, includeExecutiveSummary: v })} />
                        </div>
                        <div className="flex items-center justify-between">
                          <div>
                            <Label>Include Technical Details</Label>
                            <p className="text-xs text-muted-foreground">Detailed vulnerability analysis</p>
                          </div>
                          <Switch checked={wizardData.includeTechnicalDetails} onCheckedChange={(v) => setWizardData({ ...wizardData, includeTechnicalDetails: v })} />
                        </div>
                        <div className="flex items-center justify-between">
                          <div>
                            <Label>Include Remediation Guidance</Label>
                            <p className="text-xs text-muted-foreground">Fix recommendations and code examples</p>
                          </div>
                          <Switch checked={wizardData.includeRemediation} onCheckedChange={(v) => setWizardData({ ...wizardData, includeRemediation: v })} />
                        </div>
                        <div className="flex items-center justify-between">
                          <div>
                            <Label>Include SBOM</Label>
                            <p className="text-xs text-muted-foreground">Software Bill of Materials</p>
                          </div>
                          <Switch checked={wizardData.includeSBOM} onCheckedChange={(v) => setWizardData({ ...wizardData, includeSBOM: v })} />
                        </div>
                      </TabsContent>
                      <TabsContent value="branding" className="mt-4">
                        <BrandingSettings branding={branding} onChange={setBranding} />
                      </TabsContent>
                    </Tabs>
                  </div>
                )}

                {wizardStep === 4 && (
                  <div className="space-y-4">
                    <h4 className="font-medium">Step 4: Review & Generate</h4>
                    <div className="p-4 bg-muted/50 rounded-lg space-y-2 text-sm">
                      <div className="flex justify-between"><span className="text-muted-foreground">Date Range:</span><span>{wizardData.dateRange.start || 'All'} - {wizardData.dateRange.end || 'All'}</span></div>
                      <div className="flex justify-between"><span className="text-muted-foreground">ECUs Selected:</span><span>{wizardData.selectedEcus.length || 'All'}</span></div>
                      <div className="flex justify-between"><span className="text-muted-foreground">Frameworks:</span><span>{wizardData.frameworks.length || 'All'}</span></div>
                      <div className="flex justify-between"><span className="text-muted-foreground">Exec Summary:</span><span>{wizardData.includeExecutiveSummary ? 'Yes' : 'No'}</span></div>
                      <div className="flex justify-between"><span className="text-muted-foreground">Technical Details:</span><span>{wizardData.includeTechnicalDetails ? 'Yes' : 'No'}</span></div>
                      <div className="flex justify-between"><span className="text-muted-foreground">SBOM:</span><span>{wizardData.includeSBOM ? 'Yes' : 'No'}</span></div>
                    </div>
                    <div className="p-4 border rounded-lg bg-gradient-to-r from-primary/5 to-primary/10">
                      <div className="flex items-center gap-2 mb-2">
                        <File className="w-5 h-5 text-primary" />
                        <span className="font-medium">Report Preview</span>
                      </div>
                      <p className="text-sm text-muted-foreground">Your compliance report will be generated as a PDF with all selected options.</p>
                    </div>
                  </div>
                )}

                <div className="flex justify-between mt-6">
                  <Button variant="outline" onClick={() => setWizardStep(Math.max(1, wizardStep - 1))} disabled={wizardStep === 1 || isGenerating}>Back</Button>
                  {wizardStep < 4 ? (
                    <Button onClick={() => setWizardStep(wizardStep + 1)}>Continue</Button>
                  ) : (
                    <Button onClick={handleGenerateReport} disabled={isGenerating} className="gap-2">
                      {isGenerating ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin" />
                          Generating...
                        </>
                      ) : (
                        <>
                          <Download className="w-4 h-4" />
                          Generate PDF Report
                        </>
                      )}
                    </Button>
                  )}
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </div>

        {/* Report Templates */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Card className="p-5 border-2 border-blue-500/20 bg-gradient-to-br from-blue-500/5 to-purple-500/5">
            <div className="flex items-start gap-4">
              <div className="w-12 h-12 rounded-lg bg-blue-500/20 flex items-center justify-center">
                <Shield className="w-6 h-6 text-blue-500" />
              </div>
              <div className="flex-1">
                <h3 className="font-semibold text-foreground">UNECE WP.29 R155/R156</h3>
                <p className="text-sm text-muted-foreground mb-3">Cybersecurity & Software Update Compliance</p>
                <div className="text-xs text-muted-foreground mb-3 space-y-1">
                  <p>• Vulnerability assessments</p>
                  <p>• Monitoring processes</p>
                  <p>• Software update management</p>
                </div>
                <Button size="sm" variant="outline" className="gap-1" onClick={() => { setIsWizardOpen(true); setWizardData({ ...wizardData, frameworks: ['unece'] }); }}>
                  <FileText className="w-3 h-3" />Generate Report
                </Button>
              </div>
              <div className="text-right">
                <div className="text-2xl font-bold text-foreground">{uneceScore}%</div>
                <div className="text-xs text-muted-foreground">Compliant</div>
              </div>
            </div>
          </Card>

          <Card className="p-5 border-2 border-purple-500/20 bg-gradient-to-br from-purple-500/5 to-pink-500/5">
            <div className="flex items-start gap-4">
              <div className="w-12 h-12 rounded-lg bg-purple-500/20 flex items-center justify-center">
                <ListChecks className="w-6 h-6 text-purple-500" />
              </div>
              <div className="flex-1">
                <h3 className="font-semibold text-foreground">ISO/SAE 21434:2021</h3>
                <p className="text-sm text-muted-foreground mb-3">Cybersecurity Engineering Standard</p>
                <div className="text-xs text-muted-foreground mb-3 space-y-1">
                  <p>• TARA results</p>
                  <p>• Vulnerability handling</p>
                  <p>• Cybersecurity validation</p>
                </div>
                <Button size="sm" variant="outline" className="gap-1" onClick={() => { setIsWizardOpen(true); setWizardData({ ...wizardData, frameworks: ['iso21434'] }); }}>
                  <FileText className="w-3 h-3" />Generate Report
                </Button>
              </div>
              <div className="text-right">
                <div className="text-2xl font-bold text-foreground">{iso21434Score}%</div>
                <div className="text-xs text-muted-foreground">Compliant</div>
              </div>
            </div>
          </Card>
        </div>

        {/* Compliance Dashboard */}
        <Card className="p-5 border border-border">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold text-foreground">Compliance Status Dashboard</h3>
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <TrendingUp className="w-4 h-4 text-success" />
              <span>+5% from last month</span>
            </div>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            {frameworks.map((framework) => {
              const stats = getFrameworkStats(framework);
              const passRate = stats.total > 0 ? Math.round((stats.passed / stats.total) * 100) : 0;
              
              return (
                <div key={framework} className="text-center">
                  <div className="relative w-16 h-16 mx-auto mb-2">
                    <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                      <path className="text-muted" strokeWidth="3" stroke="currentColor" fill="none"
                        d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                      <path className={passRate >= 80 ? "text-success" : passRate >= 50 ? "text-warning" : "text-destructive"}
                        strokeWidth="3" stroke="currentColor" fill="none" strokeLinecap="round"
                        strokeDasharray={`${passRate}, 100`}
                        d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                    </svg>
                    <div className="absolute inset-0 flex items-center justify-center">
                      <span className="text-sm font-bold">{passRate}%</span>
                    </div>
                  </div>
                  <p className="text-xs font-medium text-foreground truncate">{framework.split(':')[0].split(' ')[0]}</p>
                  <p className="text-xs text-muted-foreground">{stats.total} rules</p>
                </div>
              );
            })}
          </div>
        </Card>

        {/* Generated Reports Library */}
        <Card className="border border-border overflow-hidden">
          <div className="p-5 border-b border-border flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold text-foreground">Generated Reports Library</h3>
              <p className="text-sm text-muted-foreground">Previously generated compliance reports</p>
            </div>
            <Button variant="outline" size="sm" className="gap-1">
              <Calendar className="w-4 h-4" />Filter
            </Button>
          </div>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Report Name</TableHead>
                <TableHead>Framework</TableHead>
                <TableHead>Date Generated</TableHead>
                <TableHead>Scope</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {generatedReports.map((report) => (
                <TableRow key={report.id}>
                  <TableCell className="font-medium">{report.name}</TableCell>
                  <TableCell><Badge variant="outline">{report.framework}</Badge></TableCell>
                  <TableCell>{format(report.date, 'MMM d, yyyy')}</TableCell>
                  <TableCell>{report.scope} ECUs</TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-1">
                      <Button variant="ghost" size="sm"><Download className="w-4 h-4" /></Button>
                      <Button variant="ghost" size="sm"><Eye className="w-4 h-4" /></Button>
                      <Button variant="ghost" size="sm"><RefreshCw className="w-4 h-4" /></Button>
                      <Button variant="ghost" size="sm" className="text-destructive"><Trash2 className="w-4 h-4" /></Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>

        {/* CSMS Evidence Section */}
        <Card className="p-5 border border-border">
          <div className="flex items-center gap-3 mb-4">
            <Settings className="w-5 h-5 text-primary" />
            <div>
              <h3 className="font-semibold text-foreground">CSMS Evidence Collection</h3>
              <p className="text-sm text-muted-foreground">Cybersecurity Management System audit trail</p>
            </div>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 bg-muted/30 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <CheckCircle2 className="w-4 h-4 text-success" />
                <span className="text-sm font-medium">Vulnerability Handling</span>
              </div>
              <Progress value={85} className="h-2 mb-1" />
              <p className="text-xs text-muted-foreground">85% requirements covered</p>
            </div>
            <div className="p-4 bg-muted/30 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <CheckCircle2 className="w-4 h-4 text-success" />
                <span className="text-sm font-medium">TARA Documentation</span>
              </div>
              <Progress value={92} className="h-2 mb-1" />
              <p className="text-xs text-muted-foreground">92% requirements covered</p>
            </div>
            <div className="p-4 bg-muted/30 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <AlertCircle className="w-4 h-4 text-warning" />
                <span className="text-sm font-medium">Incident Response</span>
              </div>
              <Progress value={67} className="h-2 mb-1" />
              <p className="text-xs text-muted-foreground">67% requirements covered</p>
            </div>
          </div>
        </Card>

        {/* Detailed Results Table */}
        <Card className="border border-border overflow-hidden">
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
                    <tr key={result.id} className="hover:bg-muted/30 transition-colors animate-fade-in" style={{ animationDelay: `${index * 30}ms` }}>
                      <td className="p-4"><span className="text-sm font-medium text-foreground">{result.framework}</span></td>
                      <td className="p-4"><span className="text-sm font-mono text-primary">{result.rule_id}</span></td>
                      <td className="p-4 max-w-md"><span className="text-sm text-muted-foreground">{result.rule_description}</span></td>
                      <td className="p-4">
                        <Badge variant="outline" className={cn("gap-1", getStatusBadge(result.status || 'pass'))}>
                          {getStatusIcon(result.status || 'pass')}
                          <span className="capitalize">{result.status}</span>
                        </Badge>
                      </td>
                      <td className="p-4 max-w-xs"><span className="text-sm text-muted-foreground">{result.details || '—'}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </AppLayout>
  );
}