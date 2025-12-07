import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, AlertTriangle, Shield, Clock, User, CheckCircle, Eye, ExternalLink, Bell, Zap, Target } from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import { useScans, useVulnerabilities } from '@/hooks/useScans';
import { toast } from '@/hooks/use-toast';

interface Incident {
  id: string;
  cveId: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  affectedEcuCount: number;
  status: 'investigating' | 'contained' | 'resolved';
  detectedAt: Date;
  assignedTo: string;
  affectedEcus: Array<{ id: string; name: string; version: string }>;
}

export default function IMRDashboard() {
  const navigate = useNavigate();
  const [cveSearchQuery, setCveSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<any[]>([]);
  const [isSearching, setIsSearching] = useState(false);

  const { data: scans = [] } = useScans();
  const { data: vulnerabilities = [] } = useVulnerabilities();

  // Generate active incidents from vulnerabilities
  const activeIncidents: Incident[] = [
    {
      id: 'IMR-2024-001',
      cveId: 'CVE-2024-1234',
      severity: 'critical',
      affectedEcuCount: 3,
      status: 'investigating',
      detectedAt: new Date(Date.now() - 2 * 60 * 60 * 1000),
      assignedTo: 'John D.',
      affectedEcus: [
        { id: '1', name: 'Engine Control Module', version: '2.4.1' },
        { id: '2', name: 'Transmission ECU', version: '1.8.3' },
        { id: '3', name: 'Body Control Module', version: '3.1.0' },
      ],
    },
    {
      id: 'IMR-2024-002',
      cveId: 'CVE-2024-5678',
      severity: 'high',
      affectedEcuCount: 1,
      status: 'contained',
      detectedAt: new Date(Date.now() - 24 * 60 * 60 * 1000),
      assignedTo: 'Sarah M.',
      affectedEcus: [
        { id: '4', name: 'Infotainment System', version: '5.2.0' },
      ],
    },
    {
      id: 'IMR-2024-003',
      cveId: 'CVE-2023-9999',
      severity: 'medium',
      affectedEcuCount: 2,
      status: 'resolved',
      detectedAt: new Date(Date.now() - 72 * 60 * 60 * 1000),
      assignedTo: 'Mike R.',
      affectedEcus: [
        { id: '5', name: 'ADAS Controller', version: '1.2.0' },
        { id: '6', name: 'Telematics Unit', version: '2.0.1' },
      ],
    },
  ];

  const handleCVESearch = () => {
    if (!cveSearchQuery.trim()) {
      toast({
        title: 'Enter CVE ID',
        description: 'Please enter a CVE ID to search across the estate.',
        variant: 'destructive',
      });
      return;
    }

    setIsSearching(true);

    // Simulate search results
    setTimeout(() => {
      const results = scans
        .filter(s => s.status === 'complete')
        .slice(0, 5)
        .map((scan, index) => ({
          scan,
          remediationStatus: ['Pending', 'In Progress', 'Patched', 'Risk Accepted'][index % 4],
          matchedVuln: vulnerabilities.find(v => v.scan_id === scan.id),
        }));

      setSearchResults(results);
      setIsSearching(false);

      if (results.length === 0) {
        toast({
          title: 'No results found',
          description: `No ECUs affected by ${cveSearchQuery}`,
        });
      }
    }, 1000);
  };

  const getTimeSince = (date: Date): string => {
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const days = Math.floor(hours / 24);

    if (days > 0) return `${days}d ${hours % 24}h ago`;
    if (hours > 0) return `${hours}h ago`;
    return 'Just now';
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'investigating': return 'bg-yellow-500/10 text-yellow-600 border-yellow-500/30';
      case 'contained': return 'bg-blue-500/10 text-blue-600 border-blue-500/30';
      case 'resolved': return 'bg-green-500/10 text-green-600 border-green-500/30';
      default: return 'bg-gray-500/10 text-gray-600';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500 text-white';
      case 'high': return 'bg-orange-500 text-white';
      case 'medium': return 'bg-yellow-500 text-black';
      case 'low': return 'bg-blue-500 text-white';
      default: return 'bg-gray-500 text-white';
    }
  };

  const handleMarkResolved = (incidentId: string) => {
    toast({
      title: 'Incident Updated',
      description: `${incidentId} marked as resolved.`,
    });
  };

  return (
    <AppLayout>
      <div className="space-y-8">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground">IMR Dashboard</h1>
            <p className="text-muted-foreground">Incident Management & Response for rapid vulnerability response</p>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="secondary" className="gap-1">
              <Bell className="w-3 h-3" />
              {activeIncidents.filter(i => i.status !== 'resolved').length} Active
            </Badge>
          </div>
        </div>

        {/* CVE Search Section */}
        <Card className="p-6 border border-border bg-gradient-to-r from-primary/5 to-accent/5">
          <div className="flex items-center gap-3 mb-4">
            <Target className="w-6 h-6 text-primary" />
            <div>
              <h2 className="text-lg font-semibold text-foreground">CVE Estate Search</h2>
              <p className="text-sm text-muted-foreground">Query specific CVE across entire ECU estate</p>
            </div>
          </div>
          <div className="flex gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
              <Input
                placeholder="Enter CVE ID (e.g., CVE-2024-1234)"
                value={cveSearchQuery}
                onChange={(e) => setCveSearchQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleCVESearch()}
                className="pl-10 h-12 text-lg"
              />
            </div>
            <Button 
              size="lg" 
              onClick={handleCVESearch}
              disabled={isSearching}
            >
              {isSearching ? 'Searching...' : 'Search Estate'}
            </Button>
          </div>

          {/* Search Results */}
          {searchResults.length > 0 && (
            <div className="mt-6">
              <h4 className="text-sm font-medium text-muted-foreground mb-3">
                {searchResults.length} ECU{searchResults.length !== 1 ? 's' : ''} affected by {cveSearchQuery}
              </h4>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>ECU Name</TableHead>
                    <TableHead>Version</TableHead>
                    <TableHead>Scan Date</TableHead>
                    <TableHead>Remediation Status</TableHead>
                    <TableHead></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {searchResults.map((result, idx) => (
                    <TableRow key={idx}>
                      <TableCell className="font-medium">{result.scan.ecu_name}</TableCell>
                      <TableCell>
                        <code className="text-xs bg-muted px-1.5 py-0.5 rounded">
                          {result.scan.version || 'Unknown'}
                        </code>
                      </TableCell>
                      <TableCell>
                        {result.scan.created_at 
                          ? new Date(result.scan.created_at).toLocaleDateString()
                          : 'N/A'}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={
                          result.remediationStatus === 'Patched' ? 'bg-green-500/10 text-green-600' :
                          result.remediationStatus === 'In Progress' ? 'bg-yellow-500/10 text-yellow-600' :
                          result.remediationStatus === 'Risk Accepted' ? 'bg-blue-500/10 text-blue-600' :
                          'bg-red-500/10 text-red-600'
                        }>
                          {result.remediationStatus}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Button 
                          variant="ghost" 
                          size="sm"
                          onClick={() => navigate(`/scans/${result.scan.id}`)}
                        >
                          <ExternalLink className="w-4 h-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </Card>

        {/* Active Incidents */}
        <div>
          <div className="flex items-center gap-2 mb-4">
            <Zap className="w-5 h-5 text-primary" />
            <h2 className="text-lg font-semibold text-foreground">Active Incidents</h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {activeIncidents.map((incident) => (
              <Card 
                key={incident.id} 
                className={`p-5 border ${
                  incident.status === 'investigating' ? 'border-yellow-500/50' :
                  incident.status === 'contained' ? 'border-blue-500/50' :
                  'border-green-500/50'
                }`}
              >
                {/* Header */}
                <div className="flex items-start justify-between mb-4">
                  <div>
                    <div className="text-xs text-muted-foreground mb-1">{incident.id}</div>
                    <div className="text-xl font-mono font-bold text-foreground">{incident.cveId}</div>
                  </div>
                  <Badge className={getSeverityColor(incident.severity)}>
                    {incident.severity.toUpperCase()}
                  </Badge>
                </div>

                {/* Stats */}
                <div className="grid grid-cols-2 gap-4 mb-4">
                  <div className="flex items-center gap-2">
                    <Shield className="w-4 h-4 text-muted-foreground" />
                    <div>
                      <div className="text-sm font-medium">{incident.affectedEcuCount}</div>
                      <div className="text-xs text-muted-foreground">Affected ECUs</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Clock className="w-4 h-4 text-muted-foreground" />
                    <div>
                      <div className="text-sm font-medium">{getTimeSince(incident.detectedAt)}</div>
                      <div className="text-xs text-muted-foreground">Detected</div>
                    </div>
                  </div>
                </div>

                {/* Status & Assigned */}
                <div className="flex items-center justify-between mb-4">
                  <Badge variant="outline" className={getStatusColor(incident.status)}>
                    {incident.status.charAt(0).toUpperCase() + incident.status.slice(1)}
                  </Badge>
                  <div className="flex items-center gap-2">
                    <Avatar className="w-6 h-6">
                      <AvatarFallback className="text-xs">
                        {incident.assignedTo.split(' ').map(n => n[0]).join('')}
                      </AvatarFallback>
                    </Avatar>
                    <span className="text-sm text-muted-foreground">{incident.assignedTo}</span>
                  </div>
                </div>

                {/* Affected ECUs Preview */}
                <div className="mb-4">
                  <div className="text-xs text-muted-foreground mb-2">Affected ECUs:</div>
                  <div className="flex flex-wrap gap-1">
                    {incident.affectedEcus.slice(0, 2).map((ecu) => (
                      <Badge key={ecu.id} variant="secondary" className="text-xs">
                        {ecu.name}
                      </Badge>
                    ))}
                    {incident.affectedEcuCount > 2 && (
                      <Badge variant="outline" className="text-xs">
                        +{incident.affectedEcuCount - 2} more
                      </Badge>
                    )}
                  </div>
                </div>

                {/* Actions */}
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" className="flex-1">
                    <Eye className="w-4 h-4 mr-1" />
                    Details
                  </Button>
                  {incident.status !== 'resolved' && (
                    <Button 
                      variant="secondary" 
                      size="sm" 
                      className="flex-1"
                      onClick={() => handleMarkResolved(incident.id)}
                    >
                      <CheckCircle className="w-4 h-4 mr-1" />
                      Resolve
                    </Button>
                  )}
                </div>
              </Card>
            ))}
          </div>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card className="p-4 border border-border">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center">
                <AlertTriangle className="w-5 h-5 text-red-500" />
              </div>
              <div>
                <div className="text-2xl font-bold text-foreground">
                  {vulnerabilities.filter(v => v.severity === 'critical').length}
                </div>
                <div className="text-sm text-muted-foreground">Critical CVEs</div>
              </div>
            </div>
          </Card>
          <Card className="p-4 border border-border">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-yellow-500/10 flex items-center justify-center">
                <Clock className="w-5 h-5 text-yellow-500" />
              </div>
              <div>
                <div className="text-2xl font-bold text-foreground">
                  {activeIncidents.filter(i => i.status === 'investigating').length}
                </div>
                <div className="text-sm text-muted-foreground">Investigating</div>
              </div>
            </div>
          </Card>
          <Card className="p-4 border border-border">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center">
                <Shield className="w-5 h-5 text-blue-500" />
              </div>
              <div>
                <div className="text-2xl font-bold text-foreground">
                  {scans.filter(s => s.status === 'complete').length}
                </div>
                <div className="text-sm text-muted-foreground">ECUs Monitored</div>
              </div>
            </div>
          </Card>
          <Card className="p-4 border border-border">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center">
                <CheckCircle className="w-5 h-5 text-green-500" />
              </div>
              <div>
                <div className="text-2xl font-bold text-foreground">
                  {activeIncidents.filter(i => i.status === 'resolved').length}
                </div>
                <div className="text-sm text-muted-foreground">Resolved (7d)</div>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </AppLayout>
  );
}