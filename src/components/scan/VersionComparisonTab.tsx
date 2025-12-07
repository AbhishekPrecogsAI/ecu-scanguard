import { useState } from 'react';
import { GitCompare, Plus, Minus, RefreshCw, TrendingUp, TrendingDown, AlertTriangle, CheckCircle, ArrowRight } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Progress } from '@/components/ui/progress';
import type { Vulnerability, Scan } from '@/hooks/useScans';

interface VersionComparisonTabProps {
  currentScan: Scan;
  currentVulnerabilities: Vulnerability[];
  allScans: Scan[];
}

export function VersionComparisonTab({ currentScan, currentVulnerabilities, allScans }: VersionComparisonTabProps) {
  const [baselineScanId, setBaselineScanId] = useState<string | null>(null);

  // Filter scans for the same ECU type
  const availableBaselines = allScans.filter(s => 
    s.id !== currentScan.id && 
    s.ecu_name === currentScan.ecu_name &&
    s.status === 'complete'
  );

  // Simulated comparison data (in real implementation, would fetch baseline vulnerabilities)
  const comparisonData = baselineScanId ? {
    newVulnerabilities: [
      { id: '1', title: 'New Buffer Overflow in CAN Handler', severity: 'critical', cve: 'CVE-2024-1234' },
      { id: '2', title: 'Memory Leak in Diagnostic Protocol', severity: 'high', cve: null },
    ],
    fixedVulnerabilities: [
      { id: '3', title: 'SQL Injection in Configuration Parser', severity: 'high', cve: 'CVE-2023-9876' },
      { id: '4', title: 'Integer Overflow in Timer Handler', severity: 'medium', cve: null },
      { id: '5', title: 'Use After Free in Memory Allocator', severity: 'critical', cve: 'CVE-2023-5432' },
    ],
    reopenedVulnerabilities: [
      { id: '6', title: 'Hardcoded Credentials Regression', severity: 'critical', cve: null },
    ],
    binaryDiff: {
      added: 1247,
      removed: 892,
      modified: 3456,
      unchanged: 45678,
    },
    changeImpactScore: 72,
  } : null;

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/10 text-red-600 border-red-500/30';
      case 'high': return 'bg-orange-500/10 text-orange-600 border-orange-500/30';
      case 'medium': return 'bg-yellow-500/10 text-yellow-600 border-yellow-500/30';
      case 'low': return 'bg-blue-500/10 text-blue-600 border-blue-500/30';
      default: return 'bg-gray-500/10 text-gray-600 border-gray-500/30';
    }
  };

  if (availableBaselines.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16">
        <div className="w-16 h-16 rounded-full bg-muted flex items-center justify-center mb-4">
          <GitCompare className="w-8 h-8 text-muted-foreground" />
        </div>
        <h3 className="text-lg font-semibold text-foreground mb-2">No Baseline Available</h3>
        <p className="text-muted-foreground text-center max-w-md">
          Version comparison requires at least one other completed scan of the same ECU ({currentScan.ecu_name}).
          Upload and scan a previous version to enable comparison.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header with Baseline Selection */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
            <GitCompare className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h3 className="font-semibold text-foreground">Version Comparison</h3>
            <p className="text-sm text-muted-foreground">Compare against previous scan versions</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-sm text-muted-foreground">Compare with:</span>
          <Select value={baselineScanId || ''} onValueChange={setBaselineScanId}>
            <SelectTrigger className="w-[250px]">
              <SelectValue placeholder="Select baseline scan" />
            </SelectTrigger>
            <SelectContent>
              {availableBaselines.map((scan) => (
                <SelectItem key={scan.id} value={scan.id}>
                  {scan.version || 'Unknown'} - {new Date(scan.created_at || '').toLocaleDateString()}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {!baselineScanId ? (
        <Card className="p-8 border border-dashed border-border text-center">
          <GitCompare className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
          <p className="text-muted-foreground">Select a baseline scan to view comparison</p>
        </Card>
      ) : comparisonData && (
        <>
          {/* Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card className="p-4 border border-green-500/30 bg-green-500/5">
              <div className="flex items-center gap-2 mb-2">
                <Minus className="w-4 h-4 text-green-500" />
                <span className="text-sm font-medium text-green-600">Fixed</span>
              </div>
              <div className="text-2xl font-bold text-green-600">
                {comparisonData.fixedVulnerabilities.length}
              </div>
              <p className="text-xs text-muted-foreground mt-1">vulnerabilities resolved</p>
            </Card>

            <Card className="p-4 border border-red-500/30 bg-red-500/5">
              <div className="flex items-center gap-2 mb-2">
                <Plus className="w-4 h-4 text-red-500" />
                <span className="text-sm font-medium text-red-600">New</span>
              </div>
              <div className="text-2xl font-bold text-red-600">
                {comparisonData.newVulnerabilities.length}
              </div>
              <p className="text-xs text-muted-foreground mt-1">vulnerabilities introduced</p>
            </Card>

            <Card className="p-4 border border-orange-500/30 bg-orange-500/5">
              <div className="flex items-center gap-2 mb-2">
                <RefreshCw className="w-4 h-4 text-orange-500" />
                <span className="text-sm font-medium text-orange-600">Reopened</span>
              </div>
              <div className="text-2xl font-bold text-orange-600">
                {comparisonData.reopenedVulnerabilities.length}
              </div>
              <p className="text-xs text-muted-foreground mt-1">regressions detected</p>
            </Card>

            <Card className="p-4 border border-border">
              <div className="flex items-center gap-2 mb-2">
                <TrendingUp className="w-4 h-4 text-primary" />
                <span className="text-sm font-medium">Change Impact</span>
              </div>
              <div className={`text-2xl font-bold ${
                comparisonData.changeImpactScore > 70 ? 'text-red-500' : 
                comparisonData.changeImpactScore > 40 ? 'text-yellow-500' : 'text-green-500'
              }`}>
                {comparisonData.changeImpactScore}%
              </div>
              <p className="text-xs text-muted-foreground mt-1">security impact score</p>
            </Card>
          </div>

          {/* Binary Diff Statistics */}
          <Card className="p-4 border border-border">
            <h4 className="font-medium text-foreground mb-4">Binary Diff Statistics</h4>
            <div className="flex items-center gap-4">
              <div className="flex-1">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs text-muted-foreground">Code Changes</span>
                  <span className="text-xs font-mono">
                    +{comparisonData.binaryDiff.added} / -{comparisonData.binaryDiff.removed}
                  </span>
                </div>
                <div className="flex h-3 rounded-full overflow-hidden bg-muted">
                  <div 
                    className="bg-green-500" 
                    style={{ width: `${(comparisonData.binaryDiff.added / (comparisonData.binaryDiff.added + comparisonData.binaryDiff.removed + comparisonData.binaryDiff.modified + comparisonData.binaryDiff.unchanged)) * 100}%` }}
                  />
                  <div 
                    className="bg-red-500" 
                    style={{ width: `${(comparisonData.binaryDiff.removed / (comparisonData.binaryDiff.added + comparisonData.binaryDiff.removed + comparisonData.binaryDiff.modified + comparisonData.binaryDiff.unchanged)) * 100}%` }}
                  />
                  <div 
                    className="bg-yellow-500" 
                    style={{ width: `${(comparisonData.binaryDiff.modified / (comparisonData.binaryDiff.added + comparisonData.binaryDiff.removed + comparisonData.binaryDiff.modified + comparisonData.binaryDiff.unchanged)) * 100}%` }}
                  />
                </div>
              </div>
              <div className="flex gap-4 text-xs">
                <div className="flex items-center gap-1">
                  <div className="w-2 h-2 rounded-full bg-green-500" />
                  <span className="text-muted-foreground">Added: {comparisonData.binaryDiff.added}</span>
                </div>
                <div className="flex items-center gap-1">
                  <div className="w-2 h-2 rounded-full bg-red-500" />
                  <span className="text-muted-foreground">Removed: {comparisonData.binaryDiff.removed}</span>
                </div>
                <div className="flex items-center gap-1">
                  <div className="w-2 h-2 rounded-full bg-yellow-500" />
                  <span className="text-muted-foreground">Modified: {comparisonData.binaryDiff.modified}</span>
                </div>
              </div>
            </div>
          </Card>

          {/* Fixed Vulnerabilities */}
          <Card className="border border-border overflow-hidden">
            <div className="flex items-center gap-2 p-4 border-b border-border bg-green-500/5">
              <CheckCircle className="w-5 h-5 text-green-500" />
              <h4 className="font-medium text-foreground">Fixed Vulnerabilities</h4>
              <Badge variant="secondary" className="ml-auto bg-green-500/10 text-green-600">
                {comparisonData.fixedVulnerabilities.length}
              </Badge>
            </div>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Vulnerability</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>CVE</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {comparisonData.fixedVulnerabilities.map((vuln) => (
                  <TableRow key={vuln.id} className="bg-green-500/5">
                    <TableCell className="font-medium">{vuln.title}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className={getSeverityColor(vuln.severity)}>
                        {vuln.severity}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <code className="text-xs">{vuln.cve || 'N/A'}</code>
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary" className="bg-green-500/10 text-green-600">
                        <CheckCircle className="w-3 h-3 mr-1" /> Fixed
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>

          {/* New Vulnerabilities */}
          <Card className="border border-border overflow-hidden">
            <div className="flex items-center gap-2 p-4 border-b border-border bg-red-500/5">
              <AlertTriangle className="w-5 h-5 text-red-500" />
              <h4 className="font-medium text-foreground">New Vulnerabilities</h4>
              <Badge variant="destructive" className="ml-auto">
                {comparisonData.newVulnerabilities.length}
              </Badge>
            </div>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Vulnerability</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>CVE</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {comparisonData.newVulnerabilities.map((vuln) => (
                  <TableRow key={vuln.id} className="bg-red-500/5">
                    <TableCell className="font-medium">{vuln.title}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className={getSeverityColor(vuln.severity)}>
                        {vuln.severity}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <code className="text-xs">{vuln.cve || 'N/A'}</code>
                    </TableCell>
                    <TableCell>
                      <Badge variant="destructive">
                        <Plus className="w-3 h-3 mr-1" /> New
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>

          {/* Reopened Vulnerabilities */}
          {comparisonData.reopenedVulnerabilities.length > 0 && (
            <Card className="border border-border overflow-hidden">
              <div className="flex items-center gap-2 p-4 border-b border-border bg-orange-500/5">
                <RefreshCw className="w-5 h-5 text-orange-500" />
                <h4 className="font-medium text-foreground">Reopened Vulnerabilities</h4>
                <Badge variant="secondary" className="ml-auto bg-orange-500/10 text-orange-600">
                  {comparisonData.reopenedVulnerabilities.length}
                </Badge>
              </div>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Vulnerability</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>CVE</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {comparisonData.reopenedVulnerabilities.map((vuln) => (
                    <TableRow key={vuln.id} className="bg-orange-500/5">
                      <TableCell className="font-medium">{vuln.title}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className={getSeverityColor(vuln.severity)}>
                          {vuln.severity}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <code className="text-xs">{vuln.cve || 'N/A'}</code>
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary" className="bg-orange-500/10 text-orange-600">
                          <RefreshCw className="w-3 h-3 mr-1" /> Reopened
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Card>
          )}
        </>
      )}
    </div>
  );
}