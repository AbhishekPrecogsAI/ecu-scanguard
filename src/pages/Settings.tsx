import { useState } from 'react';
import { Settings as SettingsIcon, Key, Bell, Shield, Database, Users, Github, CheckCircle2, XCircle, Loader2, ExternalLink, Eye, EyeOff } from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Separator } from '@/components/ui/separator';
import { useToast } from '@/hooks/use-toast';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';

// GitLab icon component
const GitLabIcon = ({ className }: { className?: string }) => (
  <svg viewBox="0 0 24 24" fill="currentColor" className={className || "w-5 h-5"}>
    <path d="M22.65 14.39L12 22.13 1.35 14.39a.84.84 0 0 1-.3-.94l1.22-3.78 2.44-7.51A.42.42 0 0 1 4.82 2a.43.43 0 0 1 .58 0 .42.42 0 0 1 .11.18l2.44 7.49h8.1l2.44-7.51A.42.42 0 0 1 18.6 2a.43.43 0 0 1 .58 0 .42.42 0 0 1 .11.18l2.44 7.51L23 13.45a.84.84 0 0 1-.35.94z" />
  </svg>
);

export default function Settings() {
  const { toast } = useToast();

  // Git token state
  const [githubToken, setGithubToken] = useState('');
  const [gitlabToken, setGitlabToken] = useState('');
  const [showGithubToken, setShowGithubToken] = useState(false);
  const [showGitlabToken, setShowGitlabToken] = useState(false);
  const [githubStatus, setGithubStatus] = useState<'idle' | 'validating' | 'valid' | 'invalid'>('idle');
  const [gitlabStatus, setGitlabStatus] = useState<'idle' | 'validating' | 'valid' | 'invalid'>('idle');
  const [githubUser, setGithubUser] = useState<string | null>(null);
  const [gitlabUser, setGitlabUser] = useState<string | null>(null);

  // Validate GitHub token
  const validateGithubToken = async () => {
    if (!githubToken.trim()) {
      toast({ title: 'Enter a token', description: 'Please enter your GitHub personal access token.', variant: 'destructive' });
      return;
    }

    setGithubStatus('validating');
    try {
      const response = await fetch('https://api.github.com/user', {
        headers: { 'Authorization': `token ${githubToken}` }
      });

      if (response.ok) {
        const user = await response.json();
        setGithubUser(user.login);
        setGithubStatus('valid');
        // Store token in localStorage (in production, use secure storage)
        localStorage.setItem('github_token', githubToken);
        toast({ title: 'GitHub Connected', description: `Authenticated as ${user.login}` });
      } else {
        setGithubStatus('invalid');
        setGithubUser(null);
        toast({ title: 'Invalid Token', description: 'GitHub token is invalid or expired.', variant: 'destructive' });
      }
    } catch (error) {
      setGithubStatus('invalid');
      toast({ title: 'Connection Error', description: 'Failed to connect to GitHub.', variant: 'destructive' });
    }
  };

  // Validate GitLab token
  const validateGitlabToken = async () => {
    if (!gitlabToken.trim()) {
      toast({ title: 'Enter a token', description: 'Please enter your GitLab personal access token.', variant: 'destructive' });
      return;
    }

    setGitlabStatus('validating');
    try {
      const response = await fetch('https://gitlab.com/api/v4/user', {
        headers: { 'PRIVATE-TOKEN': gitlabToken }
      });

      if (response.ok) {
        const user = await response.json();
        setGitlabUser(user.username);
        setGitlabStatus('valid');
        localStorage.setItem('gitlab_token', gitlabToken);
        toast({ title: 'GitLab Connected', description: `Authenticated as ${user.username}` });
      } else {
        setGitlabStatus('invalid');
        setGitlabUser(null);
        toast({ title: 'Invalid Token', description: 'GitLab token is invalid or expired.', variant: 'destructive' });
      }
    } catch (error) {
      setGitlabStatus('invalid');
      toast({ title: 'Connection Error', description: 'Failed to connect to GitLab.', variant: 'destructive' });
    }
  };

  // Load tokens on mount
  useState(() => {
    const storedGithub = localStorage.getItem('github_token');
    const storedGitlab = localStorage.getItem('gitlab_token');
    if (storedGithub) {
      setGithubToken(storedGithub);
      setGithubStatus('valid');
    }
    if (storedGitlab) {
      setGitlabToken(storedGitlab);
      setGitlabStatus('valid');
    }
  });

  // Disconnect tokens
  const disconnectGithub = () => {
    setGithubToken('');
    setGithubStatus('idle');
    setGithubUser(null);
    localStorage.removeItem('github_token');
    toast({ title: 'GitHub Disconnected', description: 'GitHub token has been removed.' });
  };

  const disconnectGitlab = () => {
    setGitlabToken('');
    setGitlabStatus('idle');
    setGitlabUser(null);
    localStorage.removeItem('gitlab_token');
    toast({ title: 'GitLab Disconnected', description: 'GitLab token has been removed.' });
  };

  return (
    <AppLayout>
      <div className="max-w-4xl mx-auto space-y-6">
        {/* Page Header */}
        <div className="flex items-center gap-3 mb-8">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-muted to-muted/50 flex items-center justify-center">
            <SettingsIcon className="w-5 h-5 text-muted-foreground" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-foreground">Settings</h1>
            <p className="text-muted-foreground">Configure your ECU Scanner preferences</p>
          </div>
        </div>

        {/* Source Control Integration - NEW */}
        <Card className="glass-card border-border">
          <CardHeader>
            <div className="flex items-center gap-2">
              <Github className="w-5 h-5 text-primary" />
              <CardTitle>Source Control Integration</CardTitle>
            </div>
            <CardDescription>
              Connect GitHub and GitLab to scan private repositories
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* GitHub */}
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <Github className="w-5 h-5" />
                <Label className="text-base font-medium">GitHub</Label>
                {githubStatus === 'valid' && (
                  <span className="flex items-center gap-1 text-xs text-success bg-success/10 px-2 py-0.5 rounded-full">
                    <CheckCircle2 className="w-3 h-3" />
                    Connected{githubUser && ` as ${githubUser}`}
                  </span>
                )}
                {githubStatus === 'invalid' && (
                  <span className="flex items-center gap-1 text-xs text-destructive bg-destructive/10 px-2 py-0.5 rounded-full">
                    <XCircle className="w-3 h-3" />
                    Invalid Token
                  </span>
                )}
              </div>
              <div className="flex gap-2">
                <div className="relative flex-1">
                  <Input
                    type={showGithubToken ? 'text' : 'password'}
                    placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                    value={githubToken}
                    onChange={(e) => setGithubToken(e.target.value)}
                    className="bg-muted/50 font-mono pr-10"
                  />
                  <button
                    type="button"
                    onClick={() => setShowGithubToken(!showGithubToken)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  >
                    {showGithubToken ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                {githubStatus === 'valid' ? (
                  <Button variant="outline" onClick={disconnectGithub} className="text-destructive hover:text-destructive">
                    Disconnect
                  </Button>
                ) : (
                  <Button onClick={validateGithubToken} disabled={githubStatus === 'validating'}>
                    {githubStatus === 'validating' ? (
                      <><Loader2 className="w-4 h-4 animate-spin mr-2" />Validating</>
                    ) : (
                      'Connect'
                    )}
                  </Button>
                )}
              </div>
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <a
                  href="https://github.com/settings/tokens/new?scopes=repo,read:user"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 text-primary hover:underline"
                >
                  Create a token with 'repo' scope <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            </div>

            <Separator />

            {/* GitLab */}
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <GitLabIcon className="w-5 h-5 text-[#fc6d26]" />
                <Label className="text-base font-medium">GitLab</Label>
                {gitlabStatus === 'valid' && (
                  <span className="flex items-center gap-1 text-xs text-success bg-success/10 px-2 py-0.5 rounded-full">
                    <CheckCircle2 className="w-3 h-3" />
                    Connected{gitlabUser && ` as ${gitlabUser}`}
                  </span>
                )}
                {gitlabStatus === 'invalid' && (
                  <span className="flex items-center gap-1 text-xs text-destructive bg-destructive/10 px-2 py-0.5 rounded-full">
                    <XCircle className="w-3 h-3" />
                    Invalid Token
                  </span>
                )}
              </div>
              <div className="flex gap-2">
                <div className="relative flex-1">
                  <Input
                    type={showGitlabToken ? 'text' : 'password'}
                    placeholder="glpat-xxxxxxxxxxxxxxxxxxxx"
                    value={gitlabToken}
                    onChange={(e) => setGitlabToken(e.target.value)}
                    className="bg-muted/50 font-mono pr-10"
                  />
                  <button
                    type="button"
                    onClick={() => setShowGitlabToken(!showGitlabToken)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  >
                    {showGitlabToken ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                {gitlabStatus === 'valid' ? (
                  <Button variant="outline" onClick={disconnectGitlab} className="text-destructive hover:text-destructive">
                    Disconnect
                  </Button>
                ) : (
                  <Button onClick={validateGitlabToken} disabled={gitlabStatus === 'validating'} className="bg-[#fc6d26] hover:bg-[#fc6d26]/90">
                    {gitlabStatus === 'validating' ? (
                      <><Loader2 className="w-4 h-4 animate-spin mr-2" />Validating</>
                    ) : (
                      'Connect'
                    )}
                  </Button>
                )}
              </div>
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <a
                  href="https://gitlab.com/-/user_settings/personal_access_tokens?scopes=read_repository,read_api"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 text-[#fc6d26] hover:underline"
                >
                  Create a token with 'read_repository' scope <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Webhooks & CI/CD */}
        <Card className="glass-card border-border">
          <CardHeader>
            <div className="flex items-center gap-2">
              <ExternalLink className="w-5 h-5 text-primary" />
              <CardTitle>Webhooks & CI/CD</CardTitle>
            </div>
            <CardDescription>
              Configure webhooks to automatically scan repositories on push events
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Webhook URL */}
            <div className="space-y-3">
              <Label className="text-base font-medium">Webhook URL</Label>
              <div className="flex gap-2">
                <div className="relative flex-1">
                  <Input
                    type="text"
                    value={`${window.location.origin}/api/webhook`}
                    readOnly
                    className="bg-muted/50 font-mono text-sm pr-20"
                  />
                  <Button
                    variant="ghost"
                    size="sm"
                    className="absolute right-1 top-1/2 -translate-y-1/2 h-7 text-xs"
                    onClick={() => {
                      navigator.clipboard.writeText(`${window.location.origin}/api/webhook`);
                      toast({ title: 'Copied!', description: 'Webhook URL copied to clipboard.' });
                    }}
                  >
                    Copy
                  </Button>
                </div>
              </div>
              <p className="text-xs text-muted-foreground">
                Add this URL to your GitHub or GitLab repository webhook settings
              </p>
            </div>

            <Separator />

            {/* GitHub Webhook Setup */}
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <Github className="w-4 h-4" />
                <Label className="text-sm font-medium">GitHub Setup</Label>
              </div>
              <div className="p-4 rounded-lg bg-muted/30 space-y-2 text-sm text-muted-foreground">
                <ol className="list-decimal list-inside space-y-1">
                  <li>Go to your repository → Settings → Webhooks</li>
                  <li>Click "Add webhook"</li>
                  <li>Paste the Webhook URL above</li>
                  <li>Set Content type to <code className="text-xs bg-muted px-1 rounded">application/json</code></li>
                  <li>Select events: Push, Pull requests</li>
                  <li>Click "Add webhook"</li>
                </ol>
              </div>
            </div>

            {/* GitLab Webhook Setup */}
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <GitLabIcon className="w-4 h-4 text-[#fc6d26]" />
                <Label className="text-sm font-medium">GitLab Setup</Label>
              </div>
              <div className="p-4 rounded-lg bg-muted/30 space-y-2 text-sm text-muted-foreground">
                <ol className="list-decimal list-inside space-y-1">
                  <li>Go to your project → Settings → Webhooks</li>
                  <li>Paste the Webhook URL above</li>
                  <li>Check triggers: Push events, Merge request events</li>
                  <li>Click "Add webhook"</li>
                </ol>
              </div>
            </div>

            {/* Webhook Events */}
            <div className="space-y-3">
              <Label className="text-sm font-medium">Trigger on events:</Label>
              <div className="grid grid-cols-2 gap-4">
                <div className="flex items-center justify-between p-3 rounded-lg bg-muted/20">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-success" />
                    <span className="text-sm">Push to branch</span>
                  </div>
                  <Switch defaultChecked />
                </div>
                <div className="flex items-center justify-between p-3 rounded-lg bg-muted/20">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-success" />
                    <span className="text-sm">Pull/Merge Request</span>
                  </div>
                  <Switch defaultChecked />
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* API Keys */}
        <Card className="glass-card border-border">
          <CardHeader>
            <div className="flex items-center gap-2">
              <Key className="w-5 h-5 text-primary" />
              <CardTitle>API Configuration</CardTitle>
            </div>
            <CardDescription>
              Configure API keys for external integrations
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="anthropic">Anthropic API Key (Claude)</Label>
              <Input
                id="anthropic"
                type="password"
                placeholder="sk-ant-..."
                className="bg-muted/50 font-mono"
              />
              <p className="text-xs text-muted-foreground">
                Used for AI-powered vulnerability enrichment and remediation suggestions
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="nvd">NVD API Key</Label>
              <Input
                id="nvd"
                type="password"
                placeholder="Enter your NVD API key"
                className="bg-muted/50 font-mono"
              />
              <p className="text-xs text-muted-foreground">
                For enhanced CVE database queries (optional but recommended)
              </p>
            </div>
            <Button className="mt-4">Save API Keys</Button>
          </CardContent>
        </Card>

        {/* Notifications */}
        <Card className="glass-card border-border">
          <CardHeader>
            <div className="flex items-center gap-2">
              <Bell className="w-5 h-5 text-primary" />
              <CardTitle>Notifications</CardTitle>
            </div>
            <CardDescription>
              Configure how you receive alerts and updates
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <Label>Critical Vulnerability Alerts</Label>
                <p className="text-sm text-muted-foreground">
                  Get notified immediately when critical vulnerabilities are found
                </p>
              </div>
              <Switch defaultChecked />
            </div>
            <Separator />
            <div className="flex items-center justify-between">
              <div>
                <Label>Scan Completion Notifications</Label>
                <p className="text-sm text-muted-foreground">
                  Receive a notification when a scan completes
                </p>
              </div>
              <Switch defaultChecked />
            </div>
            <Separator />
            <div className="flex items-center justify-between">
              <div>
                <Label>Weekly Summary Report</Label>
                <p className="text-sm text-muted-foreground">
                  Receive a weekly email summary of all security findings
                </p>
              </div>
              <Switch />
            </div>
          </CardContent>
        </Card>

        {/* Analysis Settings */}
        <Card className="glass-card border-border">
          <CardHeader>
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-primary" />
              <CardTitle>Analysis Settings</CardTitle>
            </div>
            <CardDescription>
              Configure default analysis parameters
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <Label>Enable Deep Analysis by Default</Label>
                <p className="text-sm text-muted-foreground">
                  Perform symbolic execution and taint analysis on all scans
                </p>
              </div>
              <Switch />
            </div>
            <Separator />
            <div className="flex items-center justify-between">
              <div>
                <Label>Auto-generate SBOM</Label>
                <p className="text-sm text-muted-foreground">
                  Automatically extract Software Bill of Materials
                </p>
              </div>
              <Switch defaultChecked />
            </div>
            <Separator />
            <div className="flex items-center justify-between">
              <div>
                <Label>AI Remediation Suggestions</Label>
                <p className="text-sm text-muted-foreground">
                  Use AI to generate remediation guidance for findings
                </p>
              </div>
              <Switch defaultChecked />
            </div>
          </CardContent>
        </Card>

        {/* Database Settings */}
        <Card className="glass-card border-border">
          <CardHeader>
            <div className="flex items-center gap-2">
              <Database className="w-5 h-5 text-primary" />
              <CardTitle>Database & Storage</CardTitle>
            </div>
            <CardDescription>
              Manage data retention and storage settings
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4 p-4 rounded-lg bg-muted/30">
              <div>
                <div className="text-2xl font-bold text-foreground font-mono">24</div>
                <div className="text-sm text-muted-foreground">Total Scans</div>
              </div>
              <div>
                <div className="text-2xl font-bold text-foreground font-mono">1.2 GB</div>
                <div className="text-sm text-muted-foreground">Storage Used</div>
              </div>
            </div>
            <div className="flex gap-3">
              <Button variant="outline">Export All Data</Button>
              <Button variant="outline" className="text-destructive hover:text-destructive">
                Clear Old Scans
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Team Settings */}
        <Card className="glass-card border-border">
          <CardHeader>
            <div className="flex items-center gap-2">
              <Users className="w-5 h-5 text-primary" />
              <CardTitle>Team & Access</CardTitle>
            </div>
            <CardDescription>
              Manage team members and permissions
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex items-center justify-between p-3 rounded-lg bg-muted/30">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-full bg-gradient-to-br from-primary to-accent flex items-center justify-center">
                    <span className="text-xs font-medium text-primary-foreground">SA</span>
                  </div>
                  <div>
                    <div className="font-medium text-foreground">Security Analyst</div>
                    <div className="text-xs text-muted-foreground">admin@example.com</div>
                  </div>
                </div>
                <span className="text-xs bg-primary/20 text-primary px-2 py-1 rounded">Admin</span>
              </div>
              <Button variant="outline" className="w-full">Invite Team Member</Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </AppLayout>
  );
}
