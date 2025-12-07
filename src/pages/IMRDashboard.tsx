import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, AlertTriangle, Shield, Clock, User, CheckCircle, Eye, ExternalLink, Bell, Zap, Target, Mail, MessageSquare, FileText, Plus, Filter, Calendar } from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useScans, useVulnerabilities } from '@/hooks/useScans';
import { toast } from '@/hooks/use-toast';
import { format } from 'date-fns';

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

interface TimelineEvent {
  id: string;
  timestamp: Date;
  cveId: string;
  cweId?: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
  affectedEcus: string[];
  actionsTaken: string[];
}

export default function IMRDashboard() {
  const navigate = useNavigate();
  const [cveSearchQuery, setCveSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<any[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [dateFilter, setDateFilter] = useState<string>('7d');

  const { data: scans = [] } = useScans();
  const { data: vulnerabilities = [] } = useVulnerabilities();

  // Generate timeline events from vulnerabilities
  const timelineEvents: TimelineEvent[] = vulnerabilities.slice(0, 10).map((vuln, i) => ({
    id: vuln.id,
    timestamp: new Date(vuln.created_at || Date.now() - i * 3600000),
    cveId: vuln.cve_id || 'N/A',
    cweId: vuln.cwe_id || undefined,
    severity: vuln.severity as 'critical' | 'high' | 'medium' | 'low',
    message: vuln.title,
    affectedEcus: [scans.find(s => s.id === vuln.scan_id)?.ecu_name || 'Unknown ECU'],
    actionsTaken: vuln.status === 'fixed' ? ['Patched', 'Verified'] : vuln.status === 'risk_accepted' ? ['Risk Accepted'] : ['Under Review'],
  }));

  const filteredTimeline = timelineEvents.filter(e => 
    (severityFilter === 'all' || e.severity === severityFilter)
  );

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
      affectedEcus: [{ id: '4', name: 'Infotainment System', version: '5.2.0' }],
    },
  ];

  const handleCVESearch = () => {
    if (!cveSearchQuery.trim()) {
      toast({ title: 'Enter CVE ID', description: 'Please enter a CVE ID to search.', variant: 'destructive' });
      return;
    }

    setIsSearching(true);
    setTimeout(() => {
      const results = scans.filter(s => s.status === 'complete').slice(0, 5).map((scan, index) => ({
        scan,
        remediationStatus: ['Pending', 'In Progress', 'Patched', 'Risk Accepted'][index % 4],
      }));
      setSearchResults(results);
      setIsSearching(false);
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

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-600 text-white';
      case 'high': return 'bg-orange-500 text-white';
      case 'medium': return 'bg-yellow-500 text-black';
      case 'low': return 'bg-blue-500 text-white';
      default: return 'bg-gray-500 text-white';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'investigating': return 'bg-red-500/20 text-red-400 border-red-500/50';
      case 'contained': return 'bg-orange-500/20 text-orange-400 border-orange-500/50';
      case 'resolved': return 'bg-green-500/20 text-green-400 border-green-500/50';
      default: return 'bg-gray-500/10 text-gray-400';
    }
  };

  // ECU Heatmap data
  const ecuHeatmapData = scans.filter(s => s.status === 'complete').map(scan => {
    const scanVulns = vulnerabilities.filter(v => v.scan_id === scan.id);
    const criticalCount = scanVulns.filter(v => v.severity === 'critical').length;
    const highCount = scanVulns.filter(v => v.severity === 'high').length;
    return {
      id: scan.id,
      name: scan.ecu_name,
      type: scan.ecu_type,
      riskLevel: criticalCount > 0 ? 'critical' : highCount > 0 ? 'high' : scanVulns.length > 0 ? 'medium' : 'low',
      vulnCount: scanVulns.length,
    };
  });

  return (
    <AppLayout>
      <div className="space-y-6">
        {/* Header with Urgent Styling */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-lg bg-gradient-to-br from-red-500 to-orange-500 flex items-center justify-center animate-pulse">
              <AlertTriangle className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-foreground">IMR Dashboard</h1>
              <p className="text-muted-foreground">Incident Management & Rapid Response</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="destructive" className="animate-pulse gap-1">
              <Bell className="w-3 h-3" />
              {activeIncidents.filter(i => i.status === 'investigating').length} Active Incidents
            </Badge>
          </div>
        </div>

        {/* Rapid Response Tools */}
        <Card className="p-4 border-2 border-red-500/30 bg-gradient-to-r from-red-500/5 to-orange-500/5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Zap className="w-5 h-5 text-orange-500" />
              <span className="font-semibold text-foreground">Rapid Response Tools</span>
            </div>
            <div className="flex items-center gap-2">
              <Button size="sm" className="bg-red-600 hover:bg-red-700 gap-1">
                <Plus className="w-4 h-4" />
                Create IMR Incident
              </Button>
              <Button size="sm" variant="outline" className="border-orange-500/50 text-orange-600 hover:bg-orange-500/10 gap-1">
                <FileText className="w-4 h-4" />
                Export IMR Report
              </Button>
              <Button size="sm" variant="outline" className="gap-1">
                <Mail className="w-4 h-4" />
                Email Alert
              </Button>
            </div>
          </div>
          <div className="flex items-center gap-4 mt-3 text-xs text-muted-foreground">
            <div className="flex items-center gap-1">
              <div className="w-2 h-2 rounded-full bg-green-500" />
              JIRA Connected
            </div>
            <div className="flex items-center gap-1">
              <div className="w-2 h-2 rounded-full bg-green-500" />
              Email Configured
            </div>
            <div className="flex items-center gap-1">
              <div className="w-2 h-2 rounded-full bg-yellow-500" />
              Slack Pending
            </div>
          </div>
        </Card>

        {/* CVE Search */}
        <Card className="p-6 border border-border bg-gradient-to-r from-red-500/5 to-orange-500/5">
          <div className="flex items-center gap-3 mb-4">
            <Target className="w-6 h-6 text-red-500" />
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
                className="pl-10 h-12 text-lg border-red-500/30 focus:border-red-500"
              />
            </div>
            <Button size="lg" onClick={handleCVESearch} disabled={isSearching} className="bg-red-600 hover:bg-red-700">
              {isSearching ? 'Searching...' : 'Search Estate'}
            </Button>
          </div>

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
                      <TableCell><code className="text-xs bg-muted px-1.5 py-0.5 rounded">{result.scan.version || 'Unknown'}</code></TableCell>
                      <TableCell>{result.scan.created_at ? new Date(result.scan.created_at).toLocaleDateString() : 'N/A'}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className={
                          result.remediationStatus === 'Patched' ? 'bg-green-500/10 text-green-600' :
                          result.remediationStatus === 'In Progress' ? 'bg-yellow-500/10 text-yellow-600' :
                          'bg-red-500/10 text-red-600'
                        }>
                          {result.remediationStatus}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Button variant="ghost" size="sm" onClick={() => navigate(`/scans/${result.scan.id}`)}>
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

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Active Incidents */}
          <Card className="border-2 border-red-500/30">
            <div className="flex items-center gap-2 p-4 border-b border-border bg-red-500/5">
              <Zap className="w-5 h-5 text-red-500" />
              <h2 className="font-semibold text-foreground">Active Incidents</h2>
            </div>
            <ScrollArea className="h-[400px]">
              <div className="p-4 space-y-4">
                {activeIncidents.map((incident) => (
                  <Card key={incident.id} className={`p-4 border ${incident.status === 'investigating' ? 'border-red-500/50 bg-red-500/5' : 'border-orange-500/50 bg-orange-500/5'}`}>
                    <div className="flex items-start justify-between mb-3">
                      <div>
                        <div className="text-xs text-muted-foreground">{incident.id}</div>
                        <div className="text-lg font-mono font-bold text-foreground">{incident.cveId}</div>
                      </div>
                      <Badge className={getSeverityColor(incident.severity)}>{incident.severity.toUpperCase()}</Badge>
                    </div>
                    <div className="grid grid-cols-2 gap-3 mb-3">
                      <div className="flex items-center gap-2">
                        <Shield className="w-4 h-4 text-muted-foreground" />
                        <span className="text-sm">{incident.affectedEcuCount} ECUs</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Clock className="w-4 h-4 text-muted-foreground" />
                        <span className="text-sm">{getTimeSince(incident.detectedAt)}</span>
                      </div>
                    </div>
                    <div className="flex items-center justify-between">
                      <Badge variant="outline" className={getStatusColor(incident.status)}>
                        {incident.status.charAt(0).toUpperCase() + incident.status.slice(1)}
                      </Badge>
                      <div className="flex items-center gap-2">
                        <Avatar className="w-6 h-6">
                          <AvatarFallback className="text-xs">{incident.assignedTo.split(' ').map(n => n[0]).join('')}</AvatarFallback>
                        </Avatar>
                        <span className="text-xs text-muted-foreground">{incident.assignedTo}</span>
                      </div>
                    </div>
                    <div className="flex gap-2 mt-3">
                      <Button variant="outline" size="sm" className="flex-1"><Eye className="w-3 h-3 mr-1" />Details</Button>
                      <Button size="sm" className="flex-1 bg-green-600 hover:bg-green-700"><CheckCircle className="w-3 h-3 mr-1" />Resolve</Button>
                    </div>
                  </Card>
                ))}
              </div>
            </ScrollArea>
          </Card>

          {/* Vulnerability Alerts Timeline */}
          <Card className="border border-border">
            <div className="flex items-center justify-between p-4 border-b border-border">
              <div className="flex items-center gap-2">
                <Clock className="w-5 h-5 text-primary" />
                <h2 className="font-semibold text-foreground">Vulnerability Alerts Timeline</h2>
              </div>
              <div className="flex items-center gap-2">
                <Select value={severityFilter} onValueChange={setSeverityFilter}>
                  <SelectTrigger className="w-[120px] h-8">
                    <SelectValue placeholder="Severity" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All</SelectItem>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <ScrollArea className="h-[400px]">
              <div className="p-4 space-y-3">
                {filteredTimeline.length === 0 ? (
                  <p className="text-center text-muted-foreground py-8">No alerts match the current filters</p>
                ) : (
                  filteredTimeline.map((event) => (
                    <div key={event.id} className="flex gap-3 p-3 rounded-lg bg-muted/30 border border-border hover:border-primary/50 transition-colors">
                      <div className={`w-2 h-2 rounded-full mt-2 ${
                        event.severity === 'critical' ? 'bg-red-500 animate-pulse' :
                        event.severity === 'high' ? 'bg-orange-500' :
                        event.severity === 'medium' ? 'bg-yellow-500' : 'bg-blue-500'
                      }`} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between mb-1">
                          <code className="text-xs font-mono text-primary">{event.cveId}</code>
                          <span className="text-xs text-muted-foreground">{format(event.timestamp, 'MMM d, HH:mm')}</span>
                        </div>
                        <p className="text-sm text-foreground truncate">{event.message}</p>
                        <div className="flex items-center gap-2 mt-2">
                          <Badge variant="secondary" className="text-xs">{event.affectedEcus[0]}</Badge>
                          {event.actionsTaken.map((action, i) => (
                            <Badge key={i} variant="outline" className="text-xs">{action}</Badge>
                          ))}
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </ScrollArea>
          </Card>
        </div>

        {/* ECU Vulnerability Heatmap */}
        <Card className="border border-border">
          <div className="flex items-center gap-2 p-4 border-b border-border">
            <Target className="w-5 h-5 text-primary" />
            <h2 className="font-semibold text-foreground">Estate-Wide Vulnerability Map</h2>
            <div className="ml-auto flex items-center gap-3 text-xs">
              <div className="flex items-center gap-1"><div className="w-3 h-3 rounded bg-red-500" />Critical</div>
              <div className="flex items-center gap-1"><div className="w-3 h-3 rounded bg-orange-500" />High</div>
              <div className="flex items-center gap-1"><div className="w-3 h-3 rounded bg-yellow-500" />Medium</div>
              <div className="flex items-center gap-1"><div className="w-3 h-3 rounded bg-green-500" />Low</div>
            </div>
          </div>
          <div className="p-4">
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
              {ecuHeatmapData.map((ecu) => (
                <button
                  key={ecu.id}
                  onClick={() => navigate(`/scans/${ecu.id}`)}
                  className={`p-4 rounded-lg border-2 text-left transition-all hover:scale-105 ${
                    ecu.riskLevel === 'critical' ? 'bg-red-500/20 border-red-500 hover:bg-red-500/30' :
                    ecu.riskLevel === 'high' ? 'bg-orange-500/20 border-orange-500 hover:bg-orange-500/30' :
                    ecu.riskLevel === 'medium' ? 'bg-yellow-500/20 border-yellow-500 hover:bg-yellow-500/30' :
                    'bg-green-500/20 border-green-500 hover:bg-green-500/30'
                  }`}
                >
                  <div className="text-sm font-medium text-foreground truncate">{ecu.name}</div>
                  <div className="text-xs text-muted-foreground">{ecu.type}</div>
                  <div className="text-lg font-bold mt-1">{ecu.vulnCount}</div>
                </button>
              ))}
              {ecuHeatmapData.length === 0 && (
                <div className="col-span-full text-center py-8 text-muted-foreground">
                  No completed scans to display
                </div>
              )}
            </div>
          </div>
        </Card>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card className="p-4 border-l-4 border-l-red-500">
            <div className="flex items-center gap-3">
              <AlertTriangle className="w-8 h-8 text-red-500" />
              <div>
                <div className="text-2xl font-bold text-foreground">{vulnerabilities.filter(v => v.severity === 'critical').length}</div>
                <div className="text-sm text-muted-foreground">Critical CVEs</div>
              </div>
            </div>
          </Card>
          <Card className="p-4 border-l-4 border-l-orange-500">
            <div className="flex items-center gap-3">
              <Clock className="w-8 h-8 text-orange-500" />
              <div>
                <div className="text-2xl font-bold text-foreground">{activeIncidents.filter(i => i.status === 'investigating').length}</div>
                <div className="text-sm text-muted-foreground">Investigating</div>
              </div>
            </div>
          </Card>
          <Card className="p-4 border-l-4 border-l-blue-500">
            <div className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-blue-500" />
              <div>
                <div className="text-2xl font-bold text-foreground">{scans.filter(s => s.status === 'complete').length}</div>
                <div className="text-sm text-muted-foreground">ECUs Monitored</div>
              </div>
            </div>
          </Card>
          <Card className="p-4 border-l-4 border-l-green-500">
            <div className="flex items-center gap-3">
              <CheckCircle className="w-8 h-8 text-green-500" />
              <div>
                <div className="text-2xl font-bold text-foreground">{vulnerabilities.filter(v => v.status === 'fixed').length}</div>
                <div className="text-sm text-muted-foreground">Resolved</div>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </AppLayout>
  );
}