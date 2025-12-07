import { useState } from 'react';
import { Download, Package, AlertTriangle, ExternalLink, FileJson, Shield, CheckCircle, AlertCircle, XCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { toast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import type { SBOMComponent } from '@/hooks/useScans';

interface SBOMTabProps {
  scanId: string;
  components: SBOMComponent[];
  ecuName: string;
}

export function SBOMTab({ scanId, components, ecuName }: SBOMTabProps) {
  const [isExporting, setIsExporting] = useState(false);
  const [selectedFormat, setSelectedFormat] = useState<'spdx' | 'cyclonedx' | 'swid'>('spdx');
  const [spdxDocument, setSpdxDocument] = useState<string | null>(null);

  const getLicenseCompliance = (license: string | null): 'compliant' | 'review' | 'violation' => {
    if (!license) return 'review';
    const compliantLicenses = ['MIT', 'Apache-2.0', 'BSD-3-Clause', 'BSD-2-Clause', 'ISC'];
    const violationLicenses = ['GPL-3.0', 'AGPL-3.0', 'GPL-2.0'];
    
    if (compliantLicenses.some(l => license.toLowerCase().includes(l.toLowerCase()))) return 'compliant';
    if (violationLicenses.some(l => license.toLowerCase().includes(l.toLowerCase()))) return 'violation';
    return 'review';
  };

  const handleExport = async (format: 'spdx' | 'cyclonedx' | 'swid') => {
    setIsExporting(true);
    try {
      const { data, error } = await supabase.functions.invoke('export-sbom', {
        body: { scanId, format },
      });

      if (error) throw error;

      const blob = new Blob([data.content], { type: data.contentType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = data.filename;
      a.click();
      URL.revokeObjectURL(url);

      if (format === 'spdx') {
        setSpdxDocument(data.content);
      }

      toast({
        title: 'SBOM exported',
        description: `${format.toUpperCase()} document downloaded successfully.`,
      });
    } catch (error) {
      toast({
        title: 'Export failed',
        description: error instanceof Error ? error.message : 'Failed to export SBOM',
        variant: 'destructive',
      });
    } finally {
      setIsExporting(false);
    }
  };

  const getVulnCount = (component: SBOMComponent): number => {
    if (!component.vulnerabilities) return 0;
    if (Array.isArray(component.vulnerabilities)) return component.vulnerabilities.length;
    return 0;
  };

  return (
    <div className="space-y-6">
      {/* Header with Export Buttons */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
            <Package className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h3 className="font-semibold text-foreground">FOSS Components</h3>
            <p className="text-sm text-muted-foreground">{components.length} components detected</p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button 
            variant="outline" 
            size="sm" 
            onClick={() => handleExport('spdx')}
            disabled={isExporting}
          >
            <Download className="w-4 h-4 mr-2" />
            Download SPDX
          </Button>
          <Button 
            variant="outline" 
            size="sm" 
            onClick={() => handleExport('cyclonedx')}
            disabled={isExporting}
          >
            <Download className="w-4 h-4 mr-2" />
            CycloneDX
          </Button>
          <Button 
            variant="outline" 
            size="sm" 
            onClick={() => handleExport('swid')}
            disabled={isExporting}
          >
            <Download className="w-4 h-4 mr-2" />
            SWID
          </Button>
        </div>
      </div>

      <Tabs defaultValue="components" className="space-y-4">
        <TabsList>
          <TabsTrigger value="components">Component Table</TabsTrigger>
          <TabsTrigger value="document">SPDX Document</TabsTrigger>
        </TabsList>

        <TabsContent value="components">
          <Card className="border border-border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Component Name</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead>License</TableHead>
                  <TableHead>Vulnerabilities</TableHead>
                  <TableHead>Usage / Source</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {components.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center text-muted-foreground py-8">
                      No SBOM components detected
                    </TableCell>
                  </TableRow>
                ) : (
                  components.map((component) => {
                    const compliance = getLicenseCompliance(component.license);
                    const vulnCount = getVulnCount(component);
                    
                    return (
                      <TableRow key={component.id}>
                        <TableCell className="font-medium">
                          <div className="flex items-center gap-2">
                            <Package className="w-4 h-4 text-muted-foreground" />
                            {component.component_name}
                          </div>
                        </TableCell>
                        <TableCell>
                          <code className="text-xs bg-muted px-1.5 py-0.5 rounded">
                            {component.version || 'Unknown'}
                          </code>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            {compliance === 'compliant' && (
                              <CheckCircle className="w-4 h-4 text-green-500" />
                            )}
                            {compliance === 'review' && (
                              <AlertCircle className="w-4 h-4 text-yellow-500" />
                            )}
                            {compliance === 'violation' && (
                              <XCircle className="w-4 h-4 text-red-500" />
                            )}
                            <span className="text-sm">{component.license || 'Unknown'}</span>
                          </div>
                        </TableCell>
                        <TableCell>
                          {vulnCount > 0 ? (
                            <Badge variant="destructive" className="gap-1">
                              <AlertTriangle className="w-3 h-3" />
                              {vulnCount} CVE{vulnCount > 1 ? 's' : ''}
                            </Badge>
                          ) : (
                            <Badge variant="outline" className="text-green-600 border-green-600/30">
                              <Shield className="w-3 h-3 mr-1" />
                              None
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell className="max-w-[200px] truncate">
                          <code className="text-xs text-muted-foreground">
                            {component.source_file || 'N/A'}
                          </code>
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </Card>
        </TabsContent>

        <TabsContent value="document">
          <Card className="border border-border p-4">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <FileJson className="w-5 h-5 text-primary" />
                <span className="font-medium">SPDX Document Viewer</span>
              </div>
              {!spdxDocument && (
                <Button 
                  variant="outline" 
                  size="sm" 
                  onClick={() => handleExport('spdx')}
                  disabled={isExporting}
                >
                  Load SPDX Document
                </Button>
              )}
            </div>
            <ScrollArea className="h-[400px] border rounded-lg bg-muted/30">
              <pre className="p-4 text-xs font-mono text-muted-foreground">
                {spdxDocument || 'Click "Load SPDX Document" to view the formatted SBOM'}
              </pre>
            </ScrollArea>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}