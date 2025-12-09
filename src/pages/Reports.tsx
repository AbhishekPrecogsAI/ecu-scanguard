import { useState } from 'react';
import { FileBarChart, Download, Calendar, Filter, FileText, Shield, Database, Clock, CheckCircle, AlertTriangle } from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useScans, useVulnerabilities } from '@/hooks/useScans';
import { format } from 'date-fns';

const reportTypes = [
    {
        id: 'executive',
        title: 'Executive Summary',
        description: 'High-level security overview for leadership',
        icon: FileBarChart,
        format: 'PDF'
    },
    {
        id: 'vulnerability',
        title: 'Vulnerability Report',
        description: 'Detailed findings with remediation guidance',
        icon: Shield,
        format: 'PDF/HTML'
    },
    {
        id: 'compliance',
        title: 'Compliance Report',
        description: 'ISO 21434, MISRA C, UNECE R155 compliance',
        icon: FileText,
        format: 'PDF'
    },
    {
        id: 'sbom',
        title: 'SBOM Report',
        description: 'Software Bill of Materials in CycloneDX',
        icon: Database,
        format: 'JSON/XML'
    },
    {
        id: 'sarif',
        title: 'SARIF Export',
        description: 'Static Analysis Results Interchange Format',
        icon: FileText,
        format: 'SARIF'
    },
    {
        id: 'audit',
        title: 'Audit Trail',
        description: 'Complete scan history and changes',
        icon: Clock,
        format: 'CSV'
    },
];

interface GeneratedReport {
    id: string;
    type: string;
    title: string;
    generatedAt: Date;
    status: 'generating' | 'ready' | 'failed';
    downloadUrl?: string;
}

export default function Reports() {
    const [selectedScan, setSelectedScan] = useState<string>('all');
    const [generatedReports, setGeneratedReports] = useState<GeneratedReport[]>([]);
    const { data: scans = [] } = useScans();
    const { data: vulnerabilities = [] } = useVulnerabilities();

    const completedScans = scans.filter(s => s.status === 'complete');

    const handleGenerateReport = (reportTypeId: string) => {
        const reportType = reportTypes.find(r => r.id === reportTypeId);
        if (!reportType) return;

        const newReport: GeneratedReport = {
            id: Date.now().toString(),
            type: reportTypeId,
            title: reportType.title,
            generatedAt: new Date(),
            status: 'generating',
        };

        setGeneratedReports(prev => [newReport, ...prev]);

        // Simulate generation
        setTimeout(() => {
            setGeneratedReports(prev => prev.map(r =>
                r.id === newReport.id
                    ? { ...r, status: 'ready' as const, downloadUrl: '#' }
                    : r
            ));
        }, 2000);
    };

    return (
        <AppLayout>
            <div className="space-y-6">
                {/* Header */}
                <div className="flex items-center justify-between">
                    <div>
                        <h1 className="text-2xl font-bold text-foreground">Reports</h1>
                        <p className="text-muted-foreground">Generate and download security reports</p>
                    </div>
                    <div className="flex gap-3">
                        <Select value={selectedScan} onValueChange={setSelectedScan}>
                            <SelectTrigger className="w-64">
                                <SelectValue placeholder="Select scan" />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectItem value="all">All Scans</SelectItem>
                                {completedScans.map(scan => (
                                    <SelectItem key={scan.id} value={scan.id}>
                                        {scan.ecu_name || scan.file_name}
                                    </SelectItem>
                                ))}
                            </SelectContent>
                        </Select>
                    </div>
                </div>

                {/* Stats */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <div className="bg-card border border-border rounded-xl p-4">
                        <div className="text-2xl font-bold text-foreground">{completedScans.length}</div>
                        <div className="text-sm text-muted-foreground">Completed Scans</div>
                    </div>
                    <div className="bg-card border border-border rounded-xl p-4">
                        <div className="text-2xl font-bold text-foreground">{vulnerabilities.length}</div>
                        <div className="text-sm text-muted-foreground">Total Findings</div>
                    </div>
                    <div className="bg-card border border-border rounded-xl p-4">
                        <div className="text-2xl font-bold text-destructive">
                            {vulnerabilities.filter(v => v.severity === 'critical').length}
                        </div>
                        <div className="text-sm text-muted-foreground">Critical Issues</div>
                    </div>
                    <div className="bg-card border border-border rounded-xl p-4">
                        <div className="text-2xl font-bold text-foreground">{generatedReports.length}</div>
                        <div className="text-sm text-muted-foreground">Reports Generated</div>
                    </div>
                </div>

                {/* Report Types Grid */}
                <div>
                    <h2 className="text-lg font-semibold text-foreground mb-4">Available Report Types</h2>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        {reportTypes.map((report) => (
                            <div
                                key={report.id}
                                className="bg-card border border-border rounded-xl p-5 hover:border-primary/30 transition-colors"
                            >
                                <div className="flex items-start gap-4">
                                    <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
                                        <report.icon className="w-5 h-5 text-primary" />
                                    </div>
                                    <div className="flex-1">
                                        <h3 className="font-medium text-foreground">{report.title}</h3>
                                        <p className="text-sm text-muted-foreground mb-3">{report.description}</p>
                                        <div className="flex items-center justify-between">
                                            <span className="text-xs text-muted-foreground bg-muted px-2 py-1 rounded">
                                                {report.format}
                                            </span>
                                            <Button
                                                size="sm"
                                                onClick={() => handleGenerateReport(report.id)}
                                            >
                                                Generate
                                            </Button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Generated Reports */}
                {generatedReports.length > 0 && (
                    <div>
                        <h2 className="text-lg font-semibold text-foreground mb-4">Generated Reports</h2>
                        <div className="bg-card border border-border rounded-xl overflow-hidden">
                            <table className="w-full">
                                <thead className="bg-muted/30 border-b border-border">
                                    <tr>
                                        <th className="text-left px-6 py-3 text-sm font-medium text-muted-foreground">Report</th>
                                        <th className="text-left px-6 py-3 text-sm font-medium text-muted-foreground">Generated</th>
                                        <th className="text-left px-6 py-3 text-sm font-medium text-muted-foreground">Status</th>
                                        <th className="text-right px-6 py-3 text-sm font-medium text-muted-foreground">Actions</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-border">
                                    {generatedReports.map((report) => (
                                        <tr key={report.id} className="hover:bg-muted/20">
                                            <td className="px-6 py-4">
                                                <div className="font-medium text-foreground">{report.title}</div>
                                            </td>
                                            <td className="px-6 py-4 text-sm text-muted-foreground">
                                                {format(report.generatedAt, 'MMM d, yyyy HH:mm')}
                                            </td>
                                            <td className="px-6 py-4">
                                                {report.status === 'generating' && (
                                                    <span className="flex items-center gap-1 text-sm text-warning">
                                                        <Clock className="w-4 h-4 animate-spin" />
                                                        Generating...
                                                    </span>
                                                )}
                                                {report.status === 'ready' && (
                                                    <span className="flex items-center gap-1 text-sm text-success">
                                                        <CheckCircle className="w-4 h-4" />
                                                        Ready
                                                    </span>
                                                )}
                                                {report.status === 'failed' && (
                                                    <span className="flex items-center gap-1 text-sm text-destructive">
                                                        <AlertTriangle className="w-4 h-4" />
                                                        Failed
                                                    </span>
                                                )}
                                            </td>
                                            <td className="px-6 py-4 text-right">
                                                <Button
                                                    variant="outline"
                                                    size="sm"
                                                    disabled={report.status !== 'ready'}
                                                >
                                                    <Download className="w-4 h-4 mr-1" />
                                                    Download
                                                </Button>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                )}
            </div>
        </AppLayout>
    );
}
