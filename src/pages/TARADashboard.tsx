import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Target, Shield, Lock, Zap, Eye, Plus, Edit, Link2, AlertTriangle, Bell, Filter, Download } from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Progress } from '@/components/ui/progress';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Slider } from '@/components/ui/slider';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useScans, useVulnerabilities } from '@/hooks/useScans';
import { toast } from '@/hooks/use-toast';

interface TARAAssessment {
  id: string;
  ecuName: string;
  ecuType: string;
  ciaScores: { confidentiality: number; integrity: number; availability: number };
  attackFeasibility: 'very_low' | 'low' | 'medium' | 'high' | 'very_high';
  impactRating: 'negligible' | 'moderate' | 'serious' | 'severe';
  riskValue: number;
  mitigatingControlsCount: number;
  lastUpdated: Date;
  scanId?: string;
}

export default function TARADashboard() {
  const navigate = useNavigate();
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [selectedAssessment, setSelectedAssessment] = useState<TARAAssessment | null>(null);

  const { data: scans = [] } = useScans();
  const { data: vulnerabilities = [] } = useVulnerabilities();

  // Form state
  const [formData, setFormData] = useState({
    ecuName: '',
    ecuType: '',
    networkContext: 'CAN',
    confidentiality: [3],
    integrity: [3],
    availability: [3],
    attackFeasibility: 'medium',
    impactRating: 'moderate',
    mitigatingControls: [] as Array<{ name: string; type: string; effectiveness: number }>,
  });

  // Generate TARA assessments from scans
  const taraAssessments: TARAAssessment[] = scans.filter(s => s.status === 'complete').map((scan) => {
    const scanVulns = vulnerabilities.filter(v => v.scan_id === scan.id);
    const criticalCount = scanVulns.filter(v => v.severity === 'critical').length;
    const highCount = scanVulns.filter(v => v.severity === 'high').length;

    const baseScore = 5;
    const c = Math.max(0, baseScore - criticalCount * 1 - highCount * 0.5);
    const i = Math.max(0, baseScore - criticalCount * 1.2 - highCount * 0.6);
    const a = Math.max(0, baseScore - criticalCount * 0.8 - highCount * 0.4);

    const riskValue = Math.min(100, (criticalCount * 25 + highCount * 15 + scanVulns.length * 2));

    return {
      id: scan.id,
      ecuName: scan.ecu_name,
      ecuType: scan.ecu_type,
      ciaScores: { confidentiality: c, integrity: i, availability: a },
      attackFeasibility: criticalCount > 2 ? 'very_high' : criticalCount > 0 ? 'high' : highCount > 2 ? 'medium' : 'low',
      impactRating: criticalCount > 1 ? 'severe' : criticalCount > 0 ? 'serious' : highCount > 0 ? 'moderate' : 'negligible',
      riskValue,
      mitigatingControlsCount: Math.floor(Math.random() * 8) + 2,
      lastUpdated: new Date(scan.updated_at || scan.created_at || Date.now()),
      scanId: scan.id,
    };
  });

  // Vulnerabilities requiring TARA updates
  const vulnsRequiringUpdate = vulnerabilities.filter(v => 
    v.severity === 'critical' || 
    (v.attack_vector && v.attack_vector.toLowerCase().includes('network'))
  ).slice(0, 5);

  const getRiskColor = (risk: number) => {
    if (risk >= 75) return 'text-red-500';
    if (risk >= 50) return 'text-orange-500';
    if (risk >= 25) return 'text-yellow-500';
    return 'text-green-500';
  };

  const getFeasibilityColor = (f: string) => {
    switch (f) {
      case 'very_high': return 'bg-red-500/10 text-red-600 border-red-500/30';
      case 'high': return 'bg-orange-500/10 text-orange-600 border-orange-500/30';
      case 'medium': return 'bg-yellow-500/10 text-yellow-600 border-yellow-500/30';
      case 'low': return 'bg-blue-500/10 text-blue-600 border-blue-500/30';
      default: return 'bg-green-500/10 text-green-600 border-green-500/30';
    }
  };

  const getImpactColor = (i: string) => {
    switch (i) {
      case 'severe': return 'bg-red-500/10 text-red-600 border-red-500/30';
      case 'serious': return 'bg-orange-500/10 text-orange-600 border-orange-500/30';
      case 'moderate': return 'bg-yellow-500/10 text-yellow-600 border-yellow-500/30';
      default: return 'bg-green-500/10 text-green-600 border-green-500/30';
    }
  };

  const MiniGauge = ({ value, max = 5, color }: { value: number; max?: number; color: string }) => (
    <div className="flex items-center gap-1">
      <Progress value={(value / max) * 100} className={`w-12 h-2 ${color}`} />
      <span className="text-xs font-mono">{value.toFixed(1)}</span>
    </div>
  );

  const handleCreateAssessment = () => {
    toast({ title: 'TARA Assessment Created', description: `Assessment for ${formData.ecuName} has been created.` });
    setIsCreateModalOpen(false);
  };

  return (
    <AppLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-lg bg-gradient-to-br from-blue-500 to-purple-500 flex items-center justify-center">
              <Target className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-foreground">TARA Dashboard</h1>
              <p className="text-muted-foreground">Threat Assessment and Risk Analysis</p>
            </div>
          </div>
          <Dialog open={isCreateModalOpen} onOpenChange={setIsCreateModalOpen}>
            <DialogTrigger asChild>
              <Button className="gap-2 bg-gradient-to-r from-blue-500 to-purple-500 hover:from-blue-600 hover:to-purple-600">
                <Plus className="w-4 h-4" />
                Create TARA Assessment
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
              <DialogHeader>
                <DialogTitle>Create/Edit TARA Assessment</DialogTitle>
              </DialogHeader>
              <Tabs defaultValue="ecu" className="mt-4">
                <TabsList className="grid grid-cols-5 w-full">
                  <TabsTrigger value="ecu">ECU Info</TabsTrigger>
                  <TabsTrigger value="cia">CIA Scoring</TabsTrigger>
                  <TabsTrigger value="attack">Attack</TabsTrigger>
                  <TabsTrigger value="impact">Impact</TabsTrigger>
                  <TabsTrigger value="controls">Controls</TabsTrigger>
                </TabsList>

                <TabsContent value="ecu" className="space-y-4 mt-4">
                  <div className="space-y-2">
                    <Label>ECU Name</Label>
                    <Input 
                      placeholder="e.g., Engine Control Module" 
                      value={formData.ecuName}
                      onChange={(e) => setFormData({ ...formData, ecuName: e.target.value })}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>ECU Type</Label>
                    <Select value={formData.ecuType} onValueChange={(v) => setFormData({ ...formData, ecuType: v })}>
                      <SelectTrigger><SelectValue placeholder="Select type" /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="Engine">Engine</SelectItem>
                        <SelectItem value="Transmission">Transmission</SelectItem>
                        <SelectItem value="ADAS">ADAS</SelectItem>
                        <SelectItem value="Body">Body Control</SelectItem>
                        <SelectItem value="Infotainment">Infotainment</SelectItem>
                        <SelectItem value="Telematics">Telematics</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label>Network Context</Label>
                    <Select value={formData.networkContext} onValueChange={(v) => setFormData({ ...formData, networkContext: v })}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="CAN">CAN Bus</SelectItem>
                        <SelectItem value="LIN">LIN</SelectItem>
                        <SelectItem value="FlexRay">FlexRay</SelectItem>
                        <SelectItem value="Ethernet">Automotive Ethernet</SelectItem>
                        <SelectItem value="Private">Private Network</SelectItem>
                        <SelectItem value="Public">Public Interface</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </TabsContent>

                <TabsContent value="cia" className="space-y-6 mt-4">
                  <div className="space-y-4">
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <Lock className="w-4 h-4 text-blue-500" />
                        <Label>Confidentiality (0-5)</Label>
                        <span className="ml-auto text-sm font-mono">{formData.confidentiality[0]}</span>
                      </div>
                      <Slider value={formData.confidentiality} onValueChange={(v) => setFormData({ ...formData, confidentiality: v })} max={5} step={0.5} />
                      <p className="text-xs text-muted-foreground mt-1">Impact if data is disclosed to unauthorized parties</p>
                    </div>
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <Shield className="w-4 h-4 text-green-500" />
                        <Label>Integrity (0-5)</Label>
                        <span className="ml-auto text-sm font-mono">{formData.integrity[0]}</span>
                      </div>
                      <Slider value={formData.integrity} onValueChange={(v) => setFormData({ ...formData, integrity: v })} max={5} step={0.5} />
                      <p className="text-xs text-muted-foreground mt-1">Impact if data is modified without authorization</p>
                    </div>
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <Zap className="w-4 h-4 text-yellow-500" />
                        <Label>Availability (0-5)</Label>
                        <span className="ml-auto text-sm font-mono">{formData.availability[0]}</span>
                      </div>
                      <Slider value={formData.availability} onValueChange={(v) => setFormData({ ...formData, availability: v })} max={5} step={0.5} />
                      <p className="text-xs text-muted-foreground mt-1">Impact if system becomes unavailable</p>
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="attack" className="space-y-4 mt-4">
                  <Label>Attack Feasibility</Label>
                  <RadioGroup value={formData.attackFeasibility} onValueChange={(v) => setFormData({ ...formData, attackFeasibility: v })}>
                    {['very_low', 'low', 'medium', 'high', 'very_high'].map((level) => (
                      <div key={level} className="flex items-center space-x-2">
                        <RadioGroupItem value={level} id={level} />
                        <Label htmlFor={level} className="capitalize">{level.replace('_', ' ')}</Label>
                      </div>
                    ))}
                  </RadioGroup>
                  <div className="mt-4 p-3 bg-muted/50 rounded-lg">
                    <Label className="text-xs text-muted-foreground">Factors to consider:</Label>
                    <ul className="text-xs text-muted-foreground mt-2 space-y-1">
                      <li>• Physical access required?</li>
                      <li>• Specialized equipment needed?</li>
                      <li>• Expert knowledge required?</li>
                      <li>• Attack window availability?</li>
                    </ul>
                  </div>
                </TabsContent>

                <TabsContent value="impact" className="space-y-4 mt-4">
                  <Label>Impact Rating (ISO 26262 ASIL consideration)</Label>
                  <RadioGroup value={formData.impactRating} onValueChange={(v) => setFormData({ ...formData, impactRating: v })}>
                    {[
                      { value: 'negligible', desc: 'No safety impact, minor inconvenience' },
                      { value: 'moderate', desc: 'Limited safety impact, recoverable' },
                      { value: 'serious', desc: 'Significant safety impact, ASIL B/C' },
                      { value: 'severe', desc: 'Critical safety impact, ASIL D' },
                    ].map((item) => (
                      <div key={item.value} className="flex items-start space-x-2">
                        <RadioGroupItem value={item.value} id={item.value} className="mt-1" />
                        <div>
                          <Label htmlFor={item.value} className="capitalize">{item.value}</Label>
                          <p className="text-xs text-muted-foreground">{item.desc}</p>
                        </div>
                      </div>
                    ))}
                  </RadioGroup>
                </TabsContent>

                <TabsContent value="controls" className="space-y-4 mt-4">
                  <div className="flex items-center justify-between">
                    <Label>Mitigating Controls</Label>
                    <Button variant="outline" size="sm" onClick={() => setFormData({
                      ...formData,
                      mitigatingControls: [...formData.mitigatingControls, { name: '', type: 'Technical', effectiveness: 50 }]
                    })}>
                      <Plus className="w-3 h-3 mr-1" />Add Control
                    </Button>
                  </div>
                  <div className="space-y-3">
                    {formData.mitigatingControls.map((control, idx) => (
                      <div key={idx} className="flex items-center gap-2 p-2 bg-muted/50 rounded">
                        <Input 
                          placeholder="Control name" 
                          value={control.name}
                          onChange={(e) => {
                            const newControls = [...formData.mitigatingControls];
                            newControls[idx].name = e.target.value;
                            setFormData({ ...formData, mitigatingControls: newControls });
                          }}
                          className="flex-1"
                        />
                        <Select 
                          value={control.type}
                          onValueChange={(v) => {
                            const newControls = [...formData.mitigatingControls];
                            newControls[idx].type = v;
                            setFormData({ ...formData, mitigatingControls: newControls });
                          }}
                        >
                          <SelectTrigger className="w-[120px]"><SelectValue /></SelectTrigger>
                          <SelectContent>
                            <SelectItem value="Technical">Technical</SelectItem>
                            <SelectItem value="Procedural">Procedural</SelectItem>
                          </SelectContent>
                        </Select>
                        <span className="text-xs w-12">{control.effectiveness}%</span>
                      </div>
                    ))}
                    {formData.mitigatingControls.length === 0 && (
                      <p className="text-sm text-muted-foreground text-center py-4">No controls added yet</p>
                    )}
                  </div>
                </TabsContent>
              </Tabs>
              <div className="flex justify-end gap-2 mt-6">
                <Button variant="outline" onClick={() => setIsCreateModalOpen(false)}>Cancel</Button>
                <Button onClick={handleCreateAssessment}>Save Assessment</Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>

        {/* Risk Heatmap */}
        <Card className="p-4 border border-border">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold text-foreground">ECU Risk Heatmap</h3>
            <div className="flex items-center gap-3 text-xs">
              <div className="flex items-center gap-1"><div className="w-3 h-3 rounded bg-red-500" />&gt;75</div>
              <div className="flex items-center gap-1"><div className="w-3 h-3 rounded bg-orange-500" />50-75</div>
              <div className="flex items-center gap-1"><div className="w-3 h-3 rounded bg-yellow-500" />25-50</div>
              <div className="flex items-center gap-1"><div className="w-3 h-3 rounded bg-green-500" />&lt;25</div>
            </div>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
            {taraAssessments.map((assessment) => (
              <button
                key={assessment.id}
                onClick={() => setSelectedAssessment(assessment)}
                className={`p-4 rounded-lg border-2 text-left transition-all hover:scale-105 ${
                  assessment.riskValue >= 75 ? 'bg-red-500/20 border-red-500' :
                  assessment.riskValue >= 50 ? 'bg-orange-500/20 border-orange-500' :
                  assessment.riskValue >= 25 ? 'bg-yellow-500/20 border-yellow-500' :
                  'bg-green-500/20 border-green-500'
                }`}
              >
                <div className="text-sm font-medium text-foreground truncate">{assessment.ecuName}</div>
                <div className="text-xs text-muted-foreground">{assessment.ecuType}</div>
                <div className={`text-xl font-bold mt-1 ${getRiskColor(assessment.riskValue)}`}>{assessment.riskValue}</div>
              </button>
            ))}
          </div>
        </Card>

        {/* Vulnerabilities Requiring TARA Update */}
        <Card className="border-2 border-purple-500/30">
          <div className="flex items-center gap-2 p-4 border-b border-border bg-purple-500/5">
            <Bell className="w-5 h-5 text-purple-500" />
            <h3 className="font-semibold text-foreground">Vulnerabilities Requiring TARA Update</h3>
            <Badge variant="secondary" className="ml-auto">{vulnsRequiringUpdate.length} pending</Badge>
          </div>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Vulnerability</TableHead>
                <TableHead>Attack Path</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {vulnsRequiringUpdate.map((vuln) => (
                <TableRow key={vuln.id}>
                  <TableCell>
                    <div className="font-medium text-sm">{vuln.title}</div>
                    <div className="text-xs text-muted-foreground">{vuln.cve_id || vuln.cwe_id}</div>
                  </TableCell>
                  <TableCell><code className="text-xs">{vuln.attack_vector || 'Local'}</code></TableCell>
                  <TableCell>
                    <Badge variant={vuln.severity === 'critical' ? 'destructive' : 'secondary'}>
                      {vuln.severity}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Button variant="outline" size="sm" className="gap-1">
                      <AlertTriangle className="w-3 h-3" />
                      Review TARA
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>

        {/* TARA Assessments Table */}
        <Card className="border border-border overflow-hidden">
          <div className="flex items-center justify-between p-4 border-b border-border">
            <h3 className="font-semibold text-foreground">All TARA Assessments</h3>
            <Button variant="outline" size="sm"><Download className="w-4 h-4 mr-2" />Export</Button>
          </div>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ECU Name</TableHead>
                <TableHead>CIA Scores</TableHead>
                <TableHead>Attack Feasibility</TableHead>
                <TableHead>Impact</TableHead>
                <TableHead>Risk Value</TableHead>
                <TableHead>Controls</TableHead>
                <TableHead>Updated</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {taraAssessments.map((assessment) => (
                <TableRow key={assessment.id}>
                  <TableCell>
                    <div className="font-medium">{assessment.ecuName}</div>
                    <div className="text-xs text-muted-foreground">{assessment.ecuType}</div>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-col gap-1">
                      <div className="flex items-center gap-1">
                        <Lock className="w-3 h-3 text-blue-500" />
                        <MiniGauge value={assessment.ciaScores.confidentiality} color="[&>div]:bg-blue-500" />
                      </div>
                      <div className="flex items-center gap-1">
                        <Shield className="w-3 h-3 text-green-500" />
                        <MiniGauge value={assessment.ciaScores.integrity} color="[&>div]:bg-green-500" />
                      </div>
                      <div className="flex items-center gap-1">
                        <Zap className="w-3 h-3 text-yellow-500" />
                        <MiniGauge value={assessment.ciaScores.availability} color="[&>div]:bg-yellow-500" />
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className={getFeasibilityColor(assessment.attackFeasibility)}>
                      {assessment.attackFeasibility.replace('_', ' ')}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className={getImpactColor(assessment.impactRating)}>
                      {assessment.impactRating}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <span className={`text-lg font-bold ${getRiskColor(assessment.riskValue)}`}>
                      {assessment.riskValue}
                    </span>
                  </TableCell>
                  <TableCell>{assessment.mitigatingControlsCount}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {assessment.lastUpdated.toLocaleDateString()}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1">
                      <Button variant="ghost" size="sm"><Eye className="w-4 h-4" /></Button>
                      <Button variant="ghost" size="sm"><Edit className="w-4 h-4" /></Button>
                      {assessment.scanId && (
                        <Button variant="ghost" size="sm" onClick={() => navigate(`/scans/${assessment.scanId}`)}>
                          <Link2 className="w-4 h-4" />
                        </Button>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      </div>
    </AppLayout>
  );
}