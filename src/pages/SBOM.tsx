import { useState, useMemo } from 'react';
import { Database, Package, AlertTriangle, Shield, Download } from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { SeverityBadge } from '@/components/ui/severity-badge';
import { ScanSelector } from '@/components/ui/scan-selector';
import { useSBOMComponents } from '@/hooks/useScans';
import { Skeleton } from '@/components/ui/skeleton';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';

export default function SBOM() {
  const [exporting, setExporting] = useState(false);
  const [selectedScan, setSelectedScan] = useState('all');
  const { data: allComponents = [], isLoading } = useSBOMComponents();

  // Filter by selected scan
  const sbomData = useMemo(() => {
    if (selectedScan === 'all') return allComponents;
    return allComponents.filter(c => c.scan_id === selectedScan);
  }, [allComponents, selectedScan]);

  const totalComponents = sbomData.length;
  const componentsWithVulns = sbomData.filter((c) => {
    const vulns = c.vulnerabilities as string[] | null;
    return vulns && vulns.length > 0;
  }).length;
  const totalVulnerabilities = sbomData.reduce((acc, c) => {
    const vulns = c.vulnerabilities as string[] | null;
    return acc + (vulns?.length || 0);
  }, 0);

  const getRiskLevel = (vulnCount: number): 'critical' | 'high' | 'medium' | 'low' => {
    if (vulnCount >= 3) return 'critical';
    if (vulnCount >= 2) return 'high';
    if (vulnCount >= 1) return 'medium';
    return 'low';
  };

  const handleExport = async (format: 'cyclonedx' | 'spdx' | 'swid') => {
    if (selectedScan === 'all') {
      toast.error('Please select a specific scan to export SBOM');
      return;
    }
    
    setExporting(true);
    try {
      const { data, error } = await supabase.functions.invoke('export-sbom', {
        body: { scanId: selectedScan, format }
      });

      if (error) throw error;

      // Create and download file
      const blob = new Blob([data.data], { type: data.contentType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = data.filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      toast.success(`SBOM exported as ${format.toUpperCase()}`);
    } catch (error) {
      console.error('Export error:', error);
      toast.error('Failed to export SBOM');
    } finally {
      setExporting(false);
    }
  };

  if (isLoading) {
    return (
      <AppLayout>
        <div className="space-y-6">
          <Skeleton className="h-20 w-full" />
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-24" />
            ))}
          </div>
          <Skeleton className="h-96" />
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
            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-accent/20 to-primary/20 flex items-center justify-center">
              <Database className="w-5 h-5 text-accent" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-foreground">Software Bill of Materials</h1>
              <p className="text-muted-foreground">
                Third-party components and dependencies detected in ECU firmware
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <ScanSelector 
              value={selectedScan} 
              onChange={setSelectedScan}
              className="w-[250px] bg-muted/50"
            />
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" disabled={exporting || selectedScan === 'all'}>
                  <Download className="w-4 h-4 mr-2" />
                  Export SBOM
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => handleExport('cyclonedx')}>
                  CycloneDX (JSON)
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => handleExport('spdx')}>
                  SPDX (JSON)
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => handleExport('swid')}>
                  SWID (XML)
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="glass-card rounded-xl border border-border p-5">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-primary/20 flex items-center justify-center">
                <Package className="w-5 h-5 text-primary" />
              </div>
              <div>
                <div className="text-2xl font-bold text-foreground font-mono">{totalComponents}</div>
                <div className="text-sm text-muted-foreground">Total Components</div>
              </div>
            </div>
          </div>
          <div className="glass-card rounded-xl border border-warning/30 bg-warning/5 p-5">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-warning/20 flex items-center justify-center">
                <AlertTriangle className="w-5 h-5 text-warning" />
              </div>
              <div>
                <div className="text-2xl font-bold text-warning font-mono">{componentsWithVulns}</div>
                <div className="text-sm text-muted-foreground">Vulnerable Components</div>
              </div>
            </div>
          </div>
          <div className="glass-card rounded-xl border border-destructive/30 bg-destructive/5 p-5">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-destructive/20 flex items-center justify-center">
                <Shield className="w-5 h-5 text-destructive" />
              </div>
              <div>
                <div className="text-2xl font-bold text-destructive font-mono">{totalVulnerabilities}</div>
                <div className="text-sm text-muted-foreground">Known Vulnerabilities</div>
              </div>
            </div>
          </div>
        </div>

        {/* Components Table */}
        <div className="glass-card rounded-xl border border-border overflow-hidden">
          <div className="p-5 border-b border-border">
            <h3 className="text-lg font-semibold text-foreground">Detected Components</h3>
            <p className="text-sm text-muted-foreground">Libraries and dependencies identified in firmware</p>
          </div>
          
          {sbomData.length === 0 ? (
            <div className="p-8 text-center text-muted-foreground">
              No SBOM components found. Upload and scan an ECU binary to detect third-party components.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border bg-muted/30">
                    <th className="text-left p-4 text-sm font-medium text-muted-foreground">Component</th>
                    <th className="text-left p-4 text-sm font-medium text-muted-foreground">Version</th>
                    <th className="text-left p-4 text-sm font-medium text-muted-foreground">License</th>
                    <th className="text-left p-4 text-sm font-medium text-muted-foreground">Source File</th>
                    <th className="text-left p-4 text-sm font-medium text-muted-foreground">Risk Level</th>
                    <th className="text-left p-4 text-sm font-medium text-muted-foreground">Vulnerabilities</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {sbomData.map((component, index) => {
                    const vulns = component.vulnerabilities as string[] | null;
                    const vulnCount = vulns?.length || 0;
                    
                    return (
                      <tr 
                        key={component.id}
                        className="hover:bg-muted/30 transition-colors animate-fade-in"
                        style={{ animationDelay: `${index * 30}ms` }}
                      >
                        <td className="p-4">
                          <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded-lg bg-muted flex items-center justify-center">
                              <Package className="w-4 h-4 text-muted-foreground" />
                            </div>
                            <span className="font-medium text-foreground">{component.component_name}</span>
                          </div>
                        </td>
                        <td className="p-4">
                          <span className="text-sm font-mono text-muted-foreground">{component.version || '—'}</span>
                        </td>
                        <td className="p-4">
                          <Badge variant="outline" className="text-xs">{component.license || 'Unknown'}</Badge>
                        </td>
                        <td className="p-4">
                          <span className="text-sm font-mono text-muted-foreground">{component.source_file || '—'}</span>
                        </td>
                        <td className="p-4">
                          <SeverityBadge severity={getRiskLevel(vulnCount)} />
                        </td>
                        <td className="p-4">
                          {vulnCount > 0 ? (
                            <div className="flex flex-wrap gap-1">
                              {vulns?.slice(0, 3).map((cve, i) => (
                                <span key={i} className="text-xs font-mono text-destructive bg-destructive/10 px-2 py-0.5 rounded">
                                  {typeof cve === 'string' ? cve : 'CVE'}
                                </span>
                              ))}
                              {vulnCount > 3 && (
                                <span className="text-xs text-muted-foreground">+{vulnCount - 3} more</span>
                              )}
                            </div>
                          ) : (
                            <span className="text-sm text-success">No known vulnerabilities</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </AppLayout>
  );
}
