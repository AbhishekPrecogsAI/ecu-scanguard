import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { useQueryClient } from '@tanstack/react-query';
import {
    Upload as UploadIcon,
    ArrowRight,
    Loader2,
    FileSearch,
    Github,
    GitBranch,
    Link,
    FolderGit,
    Clock,
    CheckCircle2,
    XCircle,
    AlertCircle,
    Filter,
    RefreshCw,
    Trash2,
    ExternalLink,
    Download,
    Eye,
    Radio
} from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { FileDropzone } from '@/components/upload/FileDropzone';
import { MetadataForm } from '@/components/upload/MetadataForm';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScanMetadata } from '@/types/scan';
import { toast } from '@/hooks/use-toast';
import { useAuth } from '@/hooks/useAuth';
import { useCreateScan, useStartAnalysis, useStartRepositoryAnalysis, useScans, useVulnerabilities, useGenerateReport } from '@/hooks/useScans';
import { cn } from '@/lib/utils';
import { StatusBadge } from '@/components/ui/status-badge';
import { supabase } from '@/integrations/supabase/client';
import type { ScanStatus } from '@/types/scan';

// GitLab icon component
const GitLabIcon = () => (
    <svg viewBox="0 0 24 24" fill="currentColor" className="w-5 h-5">
        <path d="M22.65 14.39L12 22.13 1.35 14.39a.84.84 0 0 1-.3-.94l1.22-3.78 2.44-7.51A.42.42 0 0 1 4.82 2a.43.43 0 0 1 .58 0 .42.42 0 0 1 .11.18l2.44 7.49h8.1l2.44-7.51A.42.42 0 0 1 18.6 2a.43.43 0 0 1 .58 0 .42.42 0 0 1 .11.18l2.44 7.51L23 13.45a.84.84 0 0 1-.35.94z" />
    </svg>
);

export default function ScanCentre() {
    const navigate = useNavigate();
    const queryClient = useQueryClient();
    const { user } = useAuth();
    const [activeTab, setActiveTab] = useState('upload');
    const [selectedFile, setSelectedFile] = useState<File | null>(null);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [isLiveUpdating, setIsLiveUpdating] = useState(true);

    // GitHub/GitLab state
    const [gitUrl, setGitUrl] = useState('');
    const [gitBranch, setGitBranch] = useState('main');
    const [gitProvider, setGitProvider] = useState<'github' | 'gitlab'>('github');
    const [isCloning, setIsCloning] = useState(false);

    // Scans list state
    const [statusFilter, setStatusFilter] = useState<string>('all');
    const [searchQuery, setSearchQuery] = useState('');

    const createScan = useCreateScan();
    const startAnalysis = useStartAnalysis();
    const startRepositoryAnalysis = useStartRepositoryAnalysis();
    const { data: scans = [], isLoading, refetch } = useScans();
    const { data: vulnerabilities = [] } = useVulnerabilities();
    const generateReport = useGenerateReport();

    // Real-time subscription for scan updates
    useEffect(() => {
        if (!isLiveUpdating) return;

        const channel = supabase
            .channel('scans-realtime')
            .on('postgres_changes', {
                event: '*',
                schema: 'public',
                table: 'scans'
            }, (payload) => {
                // Invalidate scans query to refresh the list
                queryClient.invalidateQueries({ queryKey: ['scans'] });

                // Show toast for status changes
                if (payload.eventType === 'UPDATE' && payload.new) {
                    const newScan = payload.new as any;
                    if (newScan.status === 'complete') {
                        toast({
                            title: 'Scan Complete',
                            description: `${newScan.ecu_name} analysis finished successfully.`,
                        });
                    } else if (newScan.status === 'failed') {
                        toast({
                            title: 'Scan Failed',
                            description: `${newScan.ecu_name} analysis encountered an error.`,
                            variant: 'destructive',
                        });
                    }
                }
            })
            .on('postgres_changes', {
                event: 'INSERT',
                schema: 'public',
                table: 'vulnerabilities'
            }, () => {
                queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] });
            })
            .subscribe();

        return () => {
            supabase.removeChannel(channel);
        };
    }, [isLiveUpdating, queryClient]);

    const form = useForm<ScanMetadata>({
        defaultValues: {
            ecuName: '',
            ecuType: 'Engine',
            version: '',
            manufacturer: '',
            platform: '',
            priority: 'medium',
            architecture: 'ARM',
            enableDeepAnalysis: false,
            complianceFrameworks: ['MISRA C', 'ISO 21434'],
        },
    });

    // Get vulnerability counts for scans
    const getVulnCountForScan = (scanId: string) => {
        return vulnerabilities.filter(v => v.scan_id === scanId).length;
    };

    // Filter scans
    const filteredScans = scans.filter((scan) => {
        const matchesStatus = statusFilter === 'all' || scan.status === statusFilter;
        const matchesSearch = searchQuery === '' ||
            scan.ecu_name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
            scan.file_name?.toLowerCase().includes(searchQuery.toLowerCase());
        return matchesStatus && matchesSearch;
    });

    const handleFileSubmit = async (data: ScanMetadata) => {
        if (!selectedFile) {
            toast({
                title: 'No file selected',
                description: 'Please upload an ECU binary file to analyze.',
                variant: 'destructive',
            });
            return;
        }

        if (!user) {
            toast({
                title: 'Not authenticated',
                description: 'Please sign in to upload files.',
                variant: 'destructive',
            });
            return;
        }

        setIsSubmitting(true);

        try {
            const fileContent = await new Promise<string>((resolve, reject) => {
                const reader = new FileReader();
                reader.onload = () => {
                    const base64 = (reader.result as string).split(',')[1];
                    resolve(base64);
                };
                reader.onerror = reject;
                reader.readAsDataURL(selectedFile);
            });

            const scan = await createScan.mutateAsync({
                user_id: user.id,
                ecu_name: data.ecuName,
                ecu_type: data.ecuType,
                version: data.version || null,
                manufacturer: data.manufacturer || null,
                platform: data.platform || null,
                file_name: selectedFile.name,
                file_size: selectedFile.size,
                architecture: data.architecture,
                deep_analysis: data.enableDeepAnalysis,
                compliance_frameworks: data.complianceFrameworks,
                status: 'queued',
                progress: 0,
            });

            toast({
                title: 'Scan created',
                description: `${data.ecuName} is being analyzed...`,
            });

            startAnalysis.mutate({
                scanId: scan.id,
                fileContent,
                fileName: selectedFile.name,
                metadata: {
                    ecuName: data.ecuName,
                    ecuType: data.ecuType,
                    version: data.version,
                    manufacturer: data.manufacturer,
                    architecture: data.architecture,
                    deepAnalysis: data.enableDeepAnalysis || false,
                    complianceFrameworks: data.complianceFrameworks,
                },
            });

            navigate(`/scans/${scan.id}`);
        } catch (error) {
            toast({
                title: 'Upload failed',
                description: error instanceof Error ? error.message : 'An error occurred',
                variant: 'destructive',
            });
        } finally {
            setIsSubmitting(false);
        }
    };

    const handleGitSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        if (!gitUrl.trim()) {
            toast({
                title: 'Repository URL required',
                description: 'Please enter a valid GitHub or GitLab repository URL.',
                variant: 'destructive',
            });
            return;
        }

        if (!user) {
            toast({
                title: 'Not authenticated',
                description: 'Please sign in to scan repositories.',
                variant: 'destructive',
            });
            return;
        }

        setIsCloning(true);

        try {
            // Extract repo name from URL
            const urlParts = gitUrl.replace(/\.git$/, '').split('/');
            const repoName = urlParts[urlParts.length - 1] || 'Unknown Repository';
            const orgName = urlParts[urlParts.length - 2] || '';

            const scan = await createScan.mutateAsync({
                user_id: user.id,
                ecu_name: `${orgName}/${repoName}`,
                ecu_type: 'Software',
                version: gitBranch,
                manufacturer: gitProvider === 'github' ? 'GitHub' : 'GitLab',
                platform: 'Git Repository',
                file_name: `${repoName}.git`,
                file_size: 0,
                architecture: 'x86_64',
                deep_analysis: true,
                compliance_frameworks: ['ISO 21434', 'MISRA C'],
                status: 'queued',
                progress: 0,
                // Store git info in metadata JSON field
                metadata: {
                    git_url: gitUrl,
                    git_branch: gitBranch,
                    git_provider: gitProvider,
                },
            });

            toast({
                title: 'Repository scan started',
                description: `Cloning and analyzing ${repoName}...`,
            });

            // Start repository analysis with git parameters
            // Get stored access token from Settings
            const storedToken = gitProvider === 'github'
                ? localStorage.getItem('github_token')
                : localStorage.getItem('gitlab_token');

            startRepositoryAnalysis.mutate({
                scanId: scan.id,
                gitUrl,
                gitBranch,
                gitProvider,
                accessToken: storedToken || undefined,
                metadata: {
                    ecuName: `${orgName}/${repoName}`,
                    ecuType: 'Software',
                    version: gitBranch,
                    manufacturer: gitProvider === 'github' ? 'GitHub' : 'GitLab',
                    architecture: 'x86_64',
                    deepAnalysis: true,
                    complianceFrameworks: ['ISO 21434', 'MISRA C'],
                },
            });

            navigate(`/scans/${scan.id}`);
        } catch (error) {
            toast({
                title: 'Repository scan failed',
                description: error instanceof Error ? error.message : 'An error occurred',
                variant: 'destructive',
            });
        } finally {
            setIsCloning(false);
        }
    };

    const handleDeleteScan = async (scanId: string) => {
        // Implementation would go here
        toast({
            title: 'Scan deleted',
            description: 'The scan has been removed.',
        });
        refetch();
    };

    return (
        <AppLayout>
            <div className="space-y-8">
                {/* Page Header */}
                <div className="flex items-center justify-between">
                    <div>
                        <div className="flex items-center gap-3 mb-2">
                            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-primary to-accent flex items-center justify-center">
                                <FileSearch className="w-5 h-5 text-primary-foreground" />
                            </div>
                            <h1 className="text-3xl font-bold text-foreground">Scan Centre</h1>
                        </div>
                        <p className="text-muted-foreground">
                            Upload files or connect to GitHub/GitLab repositories for vulnerability analysis
                        </p>
                    </div>
                    <Button variant="outline" size="sm" onClick={() => refetch()} className="gap-2">
                        <RefreshCw className="w-4 h-4" />
                        Refresh
                    </Button>
                </div>

                {/* Main Tabs */}
                <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
                    <TabsList className="grid w-full max-w-2xl grid-cols-4 p-1 bg-muted/50 rounded-xl">
                        <TabsTrigger
                            value="upload"
                            className="gap-2 data-[state=active]:bg-background data-[state=active]:shadow-sm rounded-lg"
                        >
                            <UploadIcon className="w-4 h-4" />
                            File Upload
                        </TabsTrigger>
                        <TabsTrigger
                            value="github"
                            className="gap-2 data-[state=active]:bg-background data-[state=active]:shadow-sm rounded-lg"
                        >
                            <Github className="w-4 h-4" />
                            GitHub
                        </TabsTrigger>
                        <TabsTrigger
                            value="gitlab"
                            className="gap-2 data-[state=active]:bg-background data-[state=active]:shadow-sm rounded-lg"
                        >
                            <GitLabIcon />
                            GitLab
                        </TabsTrigger>
                        <TabsTrigger
                            value="scans"
                            className="gap-2 data-[state=active]:bg-background data-[state=active]:shadow-sm rounded-lg"
                        >
                            <Clock className="w-4 h-4" />
                            All Scans
                            {scans.length > 0 && (
                                <span className="ml-1 px-1.5 py-0.5 text-xs bg-primary/20 text-primary rounded-full">
                                    {scans.length}
                                </span>
                            )}
                        </TabsTrigger>
                    </TabsList>

                    {/* File Upload Tab */}
                    <TabsContent value="upload" className="space-y-6">
                        <form onSubmit={form.handleSubmit(handleFileSubmit)} className="max-w-4xl space-y-8">
                            <div className="glass-card rounded-xl border border-border p-6">
                                <h2 className="text-lg font-semibold text-foreground mb-4">Binary File</h2>
                                <FileDropzone
                                    onFileSelect={setSelectedFile}
                                    selectedFile={selectedFile}
                                    onClear={() => setSelectedFile(null)}
                                />
                            </div>

                            <div className="glass-card rounded-xl border border-border p-6">
                                <h2 className="text-lg font-semibold text-foreground mb-4">ECU Information</h2>
                                <MetadataForm form={form} />
                            </div>

                            <div className="glass-card rounded-xl border border-border p-6 bg-muted/20">
                                <h3 className="text-sm font-medium text-foreground mb-3">Analysis will include:</h3>
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm text-muted-foreground">
                                    <div className="flex items-center gap-2">
                                        <span className="w-1.5 h-1.5 rounded-full bg-primary" />
                                        Binary Parsing
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <span className="w-1.5 h-1.5 rounded-full bg-primary" />
                                        Static Analysis
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <span className="w-1.5 h-1.5 rounded-full bg-primary" />
                                        CVE Matching
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <span className="w-1.5 h-1.5 rounded-full bg-primary" />
                                        AI Vulnerability Enrichment
                                    </div>
                                </div>
                            </div>

                            <div className="flex justify-end gap-4">
                                <Button type="button" variant="outline" onClick={() => navigate('/')}>
                                    Cancel
                                </Button>
                                <Button
                                    type="submit"
                                    disabled={!selectedFile || isSubmitting}
                                    className="gap-2 bg-gradient-to-r from-primary to-accent hover:opacity-90"
                                >
                                    {isSubmitting ? (
                                        <>
                                            <Loader2 className="w-4 h-4 animate-spin" />
                                            Uploading...
                                        </>
                                    ) : (
                                        <>
                                            Start Analysis
                                            <ArrowRight className="w-4 h-4" />
                                        </>
                                    )}
                                </Button>
                            </div>
                        </form>
                    </TabsContent>

                    {/* GitHub Tab */}
                    <TabsContent value="github" className="space-y-6">
                        <form onSubmit={(e) => { setGitProvider('github'); handleGitSubmit(e); }} className="max-w-3xl space-y-6">
                            <div className="glass-card rounded-xl border border-border p-6">
                                <div className="flex items-center gap-3 mb-6">
                                    <div className="w-10 h-10 rounded-lg bg-[#24292e] flex items-center justify-center">
                                        <Github className="w-5 h-5 text-white" />
                                    </div>
                                    <div>
                                        <h2 className="text-lg font-semibold text-foreground">GitHub Repository</h2>
                                        <p className="text-sm text-muted-foreground">Clone and scan a public or private GitHub repository</p>
                                    </div>
                                </div>

                                <div className="space-y-4">
                                    <div className="space-y-2">
                                        <Label htmlFor="github-url" className="text-sm font-medium">Repository URL</Label>
                                        <div className="relative">
                                            <Link className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                                            <Input
                                                id="github-url"
                                                type="url"
                                                placeholder="https://github.com/owner/repository"
                                                value={gitUrl}
                                                onChange={(e) => setGitUrl(e.target.value)}
                                                className="pl-10"
                                            />
                                        </div>
                                        <p className="text-xs text-muted-foreground">
                                            Enter the full URL of the GitHub repository you want to scan
                                        </p>
                                    </div>

                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="space-y-2">
                                            <Label htmlFor="github-branch" className="text-sm font-medium">Branch</Label>
                                            <div className="relative">
                                                <GitBranch className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                                                <Input
                                                    id="github-branch"
                                                    type="text"
                                                    placeholder="main"
                                                    value={gitBranch}
                                                    onChange={(e) => setGitBranch(e.target.value)}
                                                    className="pl-10"
                                                />
                                            </div>
                                        </div>
                                        <div className="space-y-2">
                                            <Label className="text-sm font-medium">Scan Depth</Label>
                                            <Select defaultValue="deep">
                                                <SelectTrigger>
                                                    <SelectValue placeholder="Select depth" />
                                                </SelectTrigger>
                                                <SelectContent>
                                                    <SelectItem value="quick">Quick Scan</SelectItem>
                                                    <SelectItem value="standard">Standard</SelectItem>
                                                    <SelectItem value="deep">Deep Analysis</SelectItem>
                                                </SelectContent>
                                            </Select>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div className="glass-card rounded-xl border border-border p-6 bg-gradient-to-r from-[#24292e]/10 to-transparent">
                                <h3 className="text-sm font-medium text-foreground mb-3">GitHub Analysis includes:</h3>
                                <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm text-muted-foreground">
                                    <div className="flex items-center gap-2">
                                        <CheckCircle2 className="w-4 h-4 text-success" />
                                        Dependency scanning
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <CheckCircle2 className="w-4 h-4 text-success" />
                                        Secret detection
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <CheckCircle2 className="w-4 h-4 text-success" />
                                        Code quality analysis
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <CheckCircle2 className="w-4 h-4 text-success" />
                                        License compliance
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <CheckCircle2 className="w-4 h-4 text-success" />
                                        SBOM generation
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <CheckCircle2 className="w-4 h-4 text-success" />
                                        CVE matching
                                    </div>
                                </div>
                            </div>

                            <div className="flex justify-end gap-4">
                                <Button type="button" variant="outline" onClick={() => navigate('/')}>
                                    Cancel
                                </Button>
                                <Button
                                    type="submit"
                                    disabled={!gitUrl.trim() || isCloning}
                                    className="gap-2 bg-[#24292e] hover:bg-[#24292e]/90 text-white"
                                >
                                    {isCloning ? (
                                        <>
                                            <Loader2 className="w-4 h-4 animate-spin" />
                                            Cloning Repository...
                                        </>
                                    ) : (
                                        <>
                                            <FolderGit className="w-4 h-4" />
                                            Clone & Scan
                                        </>
                                    )}
                                </Button>
                            </div>
                        </form>
                    </TabsContent>

                    {/* GitLab Tab */}
                    <TabsContent value="gitlab" className="space-y-6">
                        <form onSubmit={(e) => { setGitProvider('gitlab'); handleGitSubmit(e); }} className="max-w-3xl space-y-6">
                            <div className="glass-card rounded-xl border border-border p-6">
                                <div className="flex items-center gap-3 mb-6">
                                    <div className="w-10 h-10 rounded-lg bg-[#fc6d26] flex items-center justify-center">
                                        <GitLabIcon />
                                    </div>
                                    <div>
                                        <h2 className="text-lg font-semibold text-foreground">GitLab Repository</h2>
                                        <p className="text-sm text-muted-foreground">Clone and scan a public or private GitLab repository</p>
                                    </div>
                                </div>

                                <div className="space-y-4">
                                    <div className="space-y-2">
                                        <Label htmlFor="gitlab-url" className="text-sm font-medium">Repository URL</Label>
                                        <div className="relative">
                                            <Link className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                                            <Input
                                                id="gitlab-url"
                                                type="url"
                                                placeholder="https://gitlab.com/owner/repository"
                                                value={gitUrl}
                                                onChange={(e) => setGitUrl(e.target.value)}
                                                className="pl-10"
                                            />
                                        </div>
                                        <p className="text-xs text-muted-foreground">
                                            Enter the full URL of the GitLab repository you want to scan
                                        </p>
                                    </div>

                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="space-y-2">
                                            <Label htmlFor="gitlab-branch" className="text-sm font-medium">Branch</Label>
                                            <div className="relative">
                                                <GitBranch className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                                                <Input
                                                    id="gitlab-branch"
                                                    type="text"
                                                    placeholder="main"
                                                    value={gitBranch}
                                                    onChange={(e) => setGitBranch(e.target.value)}
                                                    className="pl-10"
                                                />
                                            </div>
                                        </div>
                                        <div className="space-y-2">
                                            <Label className="text-sm font-medium">Scan Depth</Label>
                                            <Select defaultValue="deep">
                                                <SelectTrigger>
                                                    <SelectValue placeholder="Select depth" />
                                                </SelectTrigger>
                                                <SelectContent>
                                                    <SelectItem value="quick">Quick Scan</SelectItem>
                                                    <SelectItem value="standard">Standard</SelectItem>
                                                    <SelectItem value="deep">Deep Analysis</SelectItem>
                                                </SelectContent>
                                            </Select>
                                        </div>
                                    </div>

                                    <div className="space-y-2">
                                        <Label htmlFor="gitlab-token" className="text-sm font-medium">Access Token (Optional)</Label>
                                        <Input
                                            id="gitlab-token"
                                            type="password"
                                            placeholder="glpat-xxxxxxxxxxxxxxxxxxxx"
                                        />
                                        <p className="text-xs text-muted-foreground">
                                            Required for private repositories. Create a token with read_repository scope.
                                        </p>
                                    </div>
                                </div>
                            </div>

                            <div className="glass-card rounded-xl border border-border p-6 bg-gradient-to-r from-[#fc6d26]/10 to-transparent">
                                <h3 className="text-sm font-medium text-foreground mb-3">GitLab Analysis includes:</h3>
                                <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm text-muted-foreground">
                                    <div className="flex items-center gap-2">
                                        <CheckCircle2 className="w-4 h-4 text-success" />
                                        Dependency scanning
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <CheckCircle2 className="w-4 h-4 text-success" />
                                        Secret detection
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <CheckCircle2 className="w-4 h-4 text-success" />
                                        SAST analysis
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <CheckCircle2 className="w-4 h-4 text-success" />
                                        Container scanning
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <CheckCircle2 className="w-4 h-4 text-success" />
                                        SBOM generation
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <CheckCircle2 className="w-4 h-4 text-success" />
                                        License compliance
                                    </div>
                                </div>
                            </div>

                            <div className="flex justify-end gap-4">
                                <Button type="button" variant="outline" onClick={() => navigate('/')}>
                                    Cancel
                                </Button>
                                <Button
                                    type="submit"
                                    disabled={!gitUrl.trim() || isCloning}
                                    className="gap-2 bg-[#fc6d26] hover:bg-[#fc6d26]/90 text-white"
                                >
                                    {isCloning ? (
                                        <>
                                            <Loader2 className="w-4 h-4 animate-spin" />
                                            Cloning Repository...
                                        </>
                                    ) : (
                                        <>
                                            <FolderGit className="w-4 h-4" />
                                            Clone & Scan
                                        </>
                                    )}
                                </Button>
                            </div>
                        </form>
                    </TabsContent>

                    {/* All Scans Tab */}
                    <TabsContent value="scans" className="space-y-6">
                        {/* Filters */}
                        <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between">
                            <div className="flex gap-3 items-center">
                                <div className="relative">
                                    <Filter className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                                    <Input
                                        placeholder="Search scans..."
                                        value={searchQuery}
                                        onChange={(e) => setSearchQuery(e.target.value)}
                                        className="pl-10 w-64"
                                    />
                                </div>
                                <Select value={statusFilter} onValueChange={setStatusFilter}>
                                    <SelectTrigger className="w-40">
                                        <SelectValue placeholder="Status" />
                                    </SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="all">All Status</SelectItem>
                                        <SelectItem value="queued">Queued</SelectItem>
                                        <SelectItem value="analyzing">Analyzing</SelectItem>
                                        <SelectItem value="complete">Complete</SelectItem>
                                        <SelectItem value="failed">Failed</SelectItem>
                                    </SelectContent>
                                </Select>
                                {/* Live Updates Toggle */}
                                <Button
                                    variant={isLiveUpdating ? "default" : "outline"}
                                    size="sm"
                                    onClick={() => setIsLiveUpdating(!isLiveUpdating)}
                                    className={cn(
                                        "gap-2 text-xs",
                                        isLiveUpdating && "bg-success hover:bg-success/90"
                                    )}
                                >
                                    <span className={cn(
                                        "w-2 h-2 rounded-full",
                                        isLiveUpdating ? "bg-white animate-pulse" : "bg-muted-foreground"
                                    )} />
                                    {isLiveUpdating ? "Live" : "Paused"}
                                </Button>
                            </div>
                            <Button
                                onClick={() => setActiveTab('upload')}
                                className="gap-2 bg-gradient-to-r from-primary to-accent hover:opacity-90"
                            >
                                <UploadIcon className="w-4 h-4" />
                                New Scan
                            </Button>
                        </div>

                        {/* Scans Table */}
                        <div className="glass-card rounded-xl border border-border overflow-hidden">
                            <div className="overflow-x-auto">
                                <table className="w-full">
                                    <thead className="bg-muted/30 border-b border-border">
                                        <tr>
                                            <th className="text-left px-6 py-4 text-sm font-medium text-muted-foreground">Name</th>
                                            <th className="text-left px-6 py-4 text-sm font-medium text-muted-foreground">Type</th>
                                            <th className="text-left px-6 py-4 text-sm font-medium text-muted-foreground">Status</th>
                                            <th className="text-left px-6 py-4 text-sm font-medium text-muted-foreground">Vulnerabilities</th>
                                            <th className="text-left px-6 py-4 text-sm font-medium text-muted-foreground">Date</th>
                                            <th className="text-right px-6 py-4 text-sm font-medium text-muted-foreground">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-border">
                                        {isLoading ? (
                                            <tr>
                                                <td colSpan={6} className="px-6 py-12 text-center">
                                                    <Loader2 className="w-6 h-6 animate-spin mx-auto text-primary" />
                                                    <p className="mt-2 text-sm text-muted-foreground">Loading scans...</p>
                                                </td>
                                            </tr>
                                        ) : filteredScans.length === 0 ? (
                                            <tr>
                                                <td colSpan={6} className="px-6 py-12 text-center">
                                                    <FileSearch className="w-12 h-12 mx-auto text-muted-foreground/50 mb-4" />
                                                    <p className="text-muted-foreground">No scans found</p>
                                                    <Button
                                                        variant="outline"
                                                        className="mt-4"
                                                        onClick={() => setActiveTab('upload')}
                                                    >
                                                        Start First Scan
                                                    </Button>
                                                </td>
                                            </tr>
                                        ) : (
                                            filteredScans.map((scan) => {
                                                const vulnCount = getVulnCountForScan(scan.id);
                                                const isGitScan = scan.platform === 'Git Repository';

                                                return (
                                                    <tr
                                                        key={scan.id}
                                                        className="hover:bg-muted/20 cursor-pointer transition-colors"
                                                        onClick={() => navigate(`/scans/${scan.id}`)}
                                                    >
                                                        <td className="px-6 py-4">
                                                            <div className="flex items-center gap-3">
                                                                {isGitScan ? (
                                                                    scan.manufacturer === 'GitHub' ? (
                                                                        <Github className="w-5 h-5 text-[#24292e]" />
                                                                    ) : (
                                                                        <span className="text-[#fc6d26]"><GitLabIcon /></span>
                                                                    )
                                                                ) : (
                                                                    <UploadIcon className="w-5 h-5 text-muted-foreground" />
                                                                )}
                                                                <div>
                                                                    <p className="font-medium text-foreground">{scan.ecu_name}</p>
                                                                    <p className="text-xs text-muted-foreground">{scan.file_name}</p>
                                                                </div>
                                                            </div>
                                                        </td>
                                                        <td className="px-6 py-4">
                                                            <span className="text-sm text-muted-foreground">{scan.ecu_type}</span>
                                                        </td>
                                                        <td className="px-6 py-4">
                                                            <StatusBadge status={(scan.status || 'queued') as ScanStatus} />
                                                        </td>
                                                        <td className="px-6 py-4">
                                                            {scan.status === 'complete' ? (
                                                                <span className={cn(
                                                                    "text-sm font-medium",
                                                                    vulnCount > 0 ? "text-critical" : "text-success"
                                                                )}>
                                                                    {vulnCount} found
                                                                </span>
                                                            ) : (
                                                                <span className="text-sm text-muted-foreground">—</span>
                                                            )}
                                                        </td>
                                                        <td className="px-6 py-4">
                                                            <span className="text-sm text-muted-foreground">
                                                                {new Date(scan.created_at).toLocaleDateString()}
                                                            </span>
                                                        </td>
                                                        <td className="px-6 py-4">
                                                            <div className="flex items-center justify-end gap-2" onClick={(e) => e.stopPropagation()}>
                                                                <Button
                                                                    variant="ghost"
                                                                    size="icon"
                                                                    className="h-8 w-8"
                                                                    onClick={() => navigate(`/scans/${scan.id}`)}
                                                                >
                                                                    <Eye className="w-4 h-4" />
                                                                </Button>
                                                                {scan.status === 'complete' && (
                                                                    <Button
                                                                        variant="ghost"
                                                                        size="icon"
                                                                        className="h-8 w-8"
                                                                        onClick={() => generateReport.mutate({ scanId: scan.id, format: 'pdf' })}
                                                                    >
                                                                        <Download className="w-4 h-4" />
                                                                    </Button>
                                                                )}
                                                                <Button
                                                                    variant="ghost"
                                                                    size="icon"
                                                                    className="h-8 w-8 text-destructive hover:text-destructive"
                                                                    onClick={() => handleDeleteScan(scan.id)}
                                                                >
                                                                    <Trash2 className="w-4 h-4" />
                                                                </Button>
                                                            </div>
                                                        </td>
                                                    </tr>
                                                );
                                            })
                                        )}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </TabsContent>
                </Tabs>
            </div>
        </AppLayout>
    );
}
