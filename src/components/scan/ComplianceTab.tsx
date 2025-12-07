import { useState } from 'react';
import { Download, CheckCircle, XCircle, AlertTriangle, FileText, Shield } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Progress } from '@/components/ui/progress';
import { toast } from '@/hooks/use-toast';
import type { ComplianceResult } from '@/hooks/useScans';

interface ComplianceTabProps {
  results: ComplianceResult[];
  ecuName: string;
}

const frameworks = [
  { id: 'misra', name: 'MISRA C:2023', icon: '🔧' },
  { id: 'iso26262', name: 'ISO 26262:2018', icon: '🛡️' },
  { id: 'iso21434', name: 'ISO 21434:2021', icon: '🔒' },
  { id: 'autosar', name: 'AUTOSAR R22-11', icon: '🚗' },
  { id: 'unece', name: 'UNECE WP.29 R155', icon: '📋' },
];

export function ComplianceTab({ results, ecuName }: ComplianceTabProps) {
  const [isGenerating, setIsGenerating] = useState<string | null>(null);

  const getFrameworkResults = (frameworkId: string) => {
    const frameworkMap: Record<string, string[]> = {
      misra: ['MISRA', 'misra'],
      iso26262: ['ISO 26262', 'iso26262', 'ISO-26262'],
      iso21434: ['ISO 21434', 'iso21434', 'ISO-21434', 'ISO/SAE 21434'],
      autosar: ['AUTOSAR', 'autosar'],
      unece: ['UNECE', 'WP.29', 'R155', 'R156'],
    };

    const searchTerms = frameworkMap[frameworkId] || [];
    return results.filter(r => 
      searchTerms.some(term => 
        r.framework.toLowerCase().includes(term.toLowerCase())
      )
    );
  };

  const getFrameworkStats = (frameworkId: string) => {
    const frameworkResults = getFrameworkResults(frameworkId);
    return {
      pass: frameworkResults.filter(r => r.status === 'pass').length,
      fail: frameworkResults.filter(r => r.status === 'fail').length,
      warning: frameworkResults.filter(r => r.status === 'warning').length,
      total: frameworkResults.length,
    };
  };

  const handleGenerateReport = async (frameworkId: string, frameworkName: string) => {
    setIsGenerating(frameworkId);
    setTimeout(() => {
      setIsGenerating(null);
      toast({
        title: 'Compliance Report Generated',
        description: `${frameworkName} compliance report has been generated.`,
      });
    }, 1500);
  };

  const FrameworkHeader = ({ frameworkId, frameworkName }: { frameworkId: string; frameworkName: string }) => {
    const stats = getFrameworkStats(frameworkId);
    const score = stats.total > 0 ? Math.round((stats.pass / stats.total) * 100) : 0;

    return (
      <div className="flex items-center justify-between p-4 border-b border-border">
        <div className="flex items-center gap-4">
          <div className="flex gap-3">
            <Badge variant="secondary" className="bg-green-500/10 text-green-600 border-green-500/30">
              <CheckCircle className="w-3 h-3 mr-1" /> {stats.pass} Pass
            </Badge>
            <Badge variant="secondary" className="bg-red-500/10 text-red-600 border-red-500/30">
              <XCircle className="w-3 h-3 mr-1" /> {stats.fail} Fail
            </Badge>
            <Badge variant="secondary" className="bg-yellow-500/10 text-yellow-600 border-yellow-500/30">
              <AlertTriangle className="w-3 h-3 mr-1" /> {stats.warning} Warning
            </Badge>
          </div>
          <div className="flex items-center gap-2">
            <Progress value={score} className="w-24 h-2" />
            <span className={`text-sm font-bold ${score >= 80 ? 'text-green-500' : score >= 50 ? 'text-yellow-500' : 'text-red-500'}`}>
              {score}%
            </span>
          </div>
        </div>
        <Button 
          variant="outline" 
          size="sm"
          onClick={() => handleGenerateReport(frameworkId, frameworkName)}
          disabled={isGenerating === frameworkId}
        >
          <Download className="w-4 h-4 mr-2" />
          {isGenerating === frameworkId ? 'Generating...' : 'Generate Report'}
        </Button>
      </div>
    );
  };

  const RuleViolationsTable = ({ frameworkId }: { frameworkId: string }) => {
    const frameworkResults = getFrameworkResults(frameworkId);

    return (
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Rule ID</TableHead>
            <TableHead>Description</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Details</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {frameworkResults.length === 0 ? (
            <TableRow>
              <TableCell colSpan={4} className="text-center text-muted-foreground py-8">
                No compliance results for this framework
              </TableCell>
            </TableRow>
          ) : (
            frameworkResults.map((result) => (
              <TableRow key={result.id}>
                <TableCell>
                  <code className="text-xs bg-muted px-1.5 py-0.5 rounded font-mono">
                    {result.rule_id}
                  </code>
                </TableCell>
                <TableCell className="max-w-[300px]">
                  <span className="text-sm">{result.rule_description || 'No description'}</span>
                </TableCell>
                <TableCell>
                  {result.status === 'pass' && (
                    <Badge variant="secondary" className="bg-green-500/10 text-green-600">
                      <CheckCircle className="w-3 h-3 mr-1" /> Pass
                    </Badge>
                  )}
                  {result.status === 'fail' && (
                    <Badge variant="destructive">
                      <XCircle className="w-3 h-3 mr-1" /> Fail
                    </Badge>
                  )}
                  {result.status === 'warning' && (
                    <Badge variant="secondary" className="bg-yellow-500/10 text-yellow-600">
                      <AlertTriangle className="w-3 h-3 mr-1" /> Warning
                    </Badge>
                  )}
                </TableCell>
                <TableCell className="max-w-[200px] truncate">
                  <span className="text-xs text-muted-foreground">{result.details || '-'}</span>
                </TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
    );
  };

  return (
    <div className="space-y-6">
      {/* Overview Header */}
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
          <Shield className="w-5 h-5 text-primary" />
        </div>
        <div>
          <h3 className="font-semibold text-foreground">Compliance Results</h3>
          <p className="text-sm text-muted-foreground">Assessment against automotive security frameworks</p>
        </div>
      </div>

      {/* Framework Tabs */}
      <Tabs defaultValue="misra" className="space-y-4">
        <TabsList className="grid grid-cols-5 w-full">
          {frameworks.map((fw) => (
            <TabsTrigger key={fw.id} value={fw.id} className="text-xs">
              <span className="mr-1">{fw.icon}</span>
              {fw.name.split(':')[0]}
            </TabsTrigger>
          ))}
        </TabsList>

        {frameworks.map((fw) => (
          <TabsContent key={fw.id} value={fw.id}>
            <Card className="border border-border overflow-hidden">
              <FrameworkHeader frameworkId={fw.id} frameworkName={fw.name} />
              <RuleViolationsTable frameworkId={fw.id} />
            </Card>
          </TabsContent>
        ))}
      </Tabs>
    </div>
  );
}