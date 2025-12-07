import { useState } from 'react';
import { Bell, Shield, AlertTriangle, FileText, Gauge, Target, Lock, Eye, Zap } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Progress } from '@/components/ui/progress';
import { toast } from '@/hooks/use-toast';
import type { Vulnerability } from '@/hooks/useScans';

interface TARATabProps {
  vulnerabilities: Vulnerability[];
  ecuName: string;
  riskScore: number | null;
}

interface CIAScore {
  confidentiality: number;
  integrity: number;
  availability: number;
}

export function TARATab({ vulnerabilities, ecuName, riskScore }: TARATabProps) {
  const [isGenerating, setIsGenerating] = useState(false);

  // Calculate CIA scores based on vulnerabilities
  const calculateCIAScores = (): CIAScore => {
    const criticalCount = vulnerabilities.filter(v => v.severity === 'critical').length;
    const highCount = vulnerabilities.filter(v => v.severity === 'high').length;
    const mediumCount = vulnerabilities.filter(v => v.severity === 'medium').length;

    // Simplified CIA calculation based on vulnerability profile
    const baseScore = 100;
    const confidentiality = Math.max(0, baseScore - (criticalCount * 20) - (highCount * 10) - (mediumCount * 3));
    const integrity = Math.max(0, baseScore - (criticalCount * 25) - (highCount * 12) - (mediumCount * 4));
    const availability = Math.max(0, baseScore - (criticalCount * 15) - (highCount * 8) - (mediumCount * 2));

    return { confidentiality, integrity, availability };
  };

  const ciaScores = calculateCIAScores();

  // Identify vulnerabilities that introduce attack paths
  const attackPathVulns = vulnerabilities.filter(v => 
    v.severity === 'critical' || 
    v.attack_vector?.toLowerCase().includes('network') ||
    v.attack_vector?.toLowerCase().includes('remote') ||
    v.cwe_id === 'CWE-78' || // Command injection
    v.cwe_id === 'CWE-120'   // Buffer overflow
  );

  const handleGenerateTARAUpdate = () => {
    setIsGenerating(true);
    setTimeout(() => {
      setIsGenerating(false);
      toast({
        title: 'TARA Update Request Generated',
        description: 'The assessment update request has been created and sent to the security team.',
      });
    }, 1500);
  };

  const mitigatingControls = [
    { id: 1, name: 'Input Validation', status: 'implemented', coverage: 65 },
    { id: 2, name: 'Memory Protection', status: 'partial', coverage: 40 },
    { id: 3, name: 'Authentication', status: 'missing', coverage: 0 },
    { id: 4, name: 'Secure Boot', status: 'implemented', coverage: 100 },
    { id: 5, name: 'Network Firewall', status: 'partial', coverage: 50 },
  ];

  const GaugeDisplay = ({ label, value, icon: Icon, color }: { label: string; value: number; icon: any; color: string }) => (
    <Card className="p-4 border border-border">
      <div className="flex items-center gap-2 mb-3">
        <Icon className={`w-5 h-5 ${color}`} />
        <span className="font-medium text-sm">{label}</span>
      </div>
      <div className="relative">
        <Progress value={value} className="h-3" />
        <div className="flex justify-between mt-1">
          <span className="text-xs text-muted-foreground">0</span>
          <span className={`text-lg font-bold ${value >= 70 ? 'text-green-500' : value >= 40 ? 'text-yellow-500' : 'text-red-500'}`}>
            {value}%
          </span>
          <span className="text-xs text-muted-foreground">100</span>
        </div>
      </div>
    </Card>
  );

  return (
    <div className="space-y-6">
      {/* TARA Assessment Overview */}
      <Card className="p-6 border border-border">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
              <Target className="w-5 h-5 text-primary" />
            </div>
            <div>
              <h3 className="font-semibold text-foreground">TARA Assessment</h3>
              <p className="text-sm text-muted-foreground">Threat Analysis and Risk Assessment for {ecuName}</p>
            </div>
          </div>
          <Badge variant={riskScore && riskScore > 70 ? 'destructive' : riskScore && riskScore > 40 ? 'default' : 'secondary'}>
            Risk Score: {riskScore || 'N/A'}/100
          </Badge>
        </div>

        {/* CIA Gauges */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <GaugeDisplay label="Confidentiality" value={ciaScores.confidentiality} icon={Lock} color="text-blue-500" />
          <GaugeDisplay label="Integrity" value={ciaScores.integrity} icon={Shield} color="text-green-500" />
          <GaugeDisplay label="Availability" value={ciaScores.availability} icon={Zap} color="text-yellow-500" />
        </div>

        {/* Mitigating Controls */}
        <div>
          <h4 className="text-sm font-medium text-foreground mb-3 flex items-center gap-2">
            <Shield className="w-4 h-4" />
            Mitigating Controls
          </h4>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {mitigatingControls.map((control) => (
              <div key={control.id} className="flex items-center justify-between p-3 rounded-lg bg-muted/50 border border-border">
                <div className="flex items-center gap-2">
                  <div className={`w-2 h-2 rounded-full ${
                    control.status === 'implemented' ? 'bg-green-500' :
                    control.status === 'partial' ? 'bg-yellow-500' : 'bg-red-500'
                  }`} />
                  <span className="text-sm">{control.name}</span>
                </div>
                <span className="text-xs text-muted-foreground">{control.coverage}%</span>
              </div>
            ))}
          </div>
        </div>
      </Card>

      {/* Vulnerability Impact on TARA */}
      <Card className="p-6 border border-border">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-destructive/10 flex items-center justify-center">
              <AlertTriangle className="w-5 h-5 text-destructive" />
            </div>
            <div>
              <h3 className="font-semibold text-foreground">Vulnerability Impact on TARA</h3>
              <p className="text-sm text-muted-foreground">{attackPathVulns.length} vulnerabilities introduce new attack paths</p>
            </div>
          </div>
          <Button onClick={handleGenerateTARAUpdate} disabled={isGenerating}>
            <FileText className="w-4 h-4 mr-2" />
            {isGenerating ? 'Generating...' : 'Generate TARA Update Request'}
          </Button>
        </div>

        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Vulnerability</TableHead>
              <TableHead>Attack Path</TableHead>
              <TableHead>Original Risk</TableHead>
              <TableHead>Modified Risk</TableHead>
              <TableHead>Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {attackPathVulns.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center text-muted-foreground py-8">
                  No new attack paths identified
                </TableCell>
              </TableRow>
            ) : (
              attackPathVulns.map((vuln) => {
                const originalRisk = vuln.severity === 'critical' ? 30 : vuln.severity === 'high' ? 50 : 70;
                const modifiedRisk = vuln.severity === 'critical' ? 95 : vuln.severity === 'high' ? 80 : 60;
                
                return (
                  <TableRow key={vuln.id}>
                    <TableCell>
                      <div>
                        <div className="font-medium text-sm">{vuln.title}</div>
                        <div className="text-xs text-muted-foreground">{vuln.cve_id || vuln.cwe_id}</div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <code className="text-xs bg-muted px-1.5 py-0.5 rounded">
                        {vuln.attack_vector || 'Local'}
                      </code>
                    </TableCell>
                    <TableCell>
                      <span className="text-sm text-green-600 font-medium">{originalRisk}%</span>
                    </TableCell>
                    <TableCell>
                      <span className={`text-sm font-bold ${modifiedRisk >= 80 ? 'text-red-500' : 'text-yellow-500'}`}>
                        {modifiedRisk}%
                      </span>
                    </TableCell>
                    <TableCell>
                      <Badge variant="destructive" className="gap-1">
                        <Bell className="w-3 h-3" />
                        Requires Update
                      </Badge>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </Card>
    </div>
  );
}