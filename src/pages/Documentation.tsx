import { BookOpen, ExternalLink, FileText, Code, Shield, Database, Target, AlertTriangle, ChevronRight, Search, Zap, Terminal, Settings, Users, Lock, Sparkles, GitBranch, FileBarChart } from 'lucide-react';
import { useState } from 'react';
import { AppLayout } from '@/components/layout/AppLayout';
import { Input } from '@/components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

// Documentation content with detailed explanations
const gettingStartedContent = {
    'quick-start': {
        title: 'Quick Start Guide',
        content: `
## Quick Start Guide

Welcome to Precogs AI Product Security Platform. This guide will help you get started with your first security scan in just a few minutes.

### Prerequisites

- A Precogs AI account (sign up at [precogs.ai](https://precogs.ai))
- ECU firmware binary or source code repository access
- Modern web browser (Chrome, Firefox, Safari, Edge)

### Step 1: Sign In

1. Navigate to the Precogs AI platform
2. Enter your email and password
3. Click "Sign In" to access the dashboard

### Step 2: Upload Your First Binary

1. Click **"Scan Centre"** in the sidebar navigation
2. Select the **"File Upload"** tab
3. Fill in the ECU details:
   - **ECU Name**: A descriptive name for your component
   - **ECU Type**: Select from Body Control, Powertrain, Infotainment, etc.
   - **Architecture**: ARM, x86, or other supported architectures
4. Drag and drop your binary file or click to browse
5. Click **"Start Scan"** to begin analysis

### Step 3: Review Results

Once the scan completes (typically 2-5 minutes):
1. View the **Risk Score** on the scan details page
2. Review **Vulnerabilities** sorted by severity
3. Check **Compliance** status for selected frameworks
4. Download the **SBOM** for your records

### Next Steps

- Configure [GitHub/GitLab integration](/settings) for repository scanning
- Set up [webhooks](/settings) for automated CI/CD scanning
- Explore the [AI Copilot](/copilot) for intelligent remediation guidance
`
    },
    'overview': {
        title: 'Platform Overview',
        content: `
## Platform Overview

Precogs AI is an AI-powered Product Security Platform designed specifically for automotive and embedded systems. Our platform provides comprehensive security analysis including SAST, DAST, SBOM generation, and compliance checking.

### Core Capabilities

#### 🔍 Static Application Security Testing (SAST)
- Binary and source code analysis
- Memory safety vulnerability detection
- Cryptographic weakness identification
- Secret and credential detection

#### 📦 Software Bill of Materials (SBOM)
- Automatic dependency extraction
- CycloneDX and SPDX format export
- Known vulnerability correlation (CVE matching)
- License compliance tracking

#### ✅ Compliance Checking
- ISO 21434 (Automotive Cybersecurity)
- MISRA C/C++ coding standards
- UNECE R155/R156 regulations
- AUTOSAR security requirements

#### 🎯 Threat Analysis & Risk Assessment (TARA)
- ISO 21434 compliant TARA methodology
- Attack tree visualization
- Risk scoring with CVSS integration
- Mitigation recommendation engine

### Architecture

\`\`\`
┌─────────────────────────────────────────────────────────────┐
│                    Precogs AI Platform                       │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐        │
│  │ Upload  │  │  GitHub │  │ GitLab  │  │ Webhook │        │
│  │ Binary  │  │  Clone  │  │  Clone  │  │  CI/CD  │        │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘        │
│       │            │            │            │              │
│       └────────────┴────────────┴────────────┘              │
│                          │                                   │
│              ┌───────────▼───────────┐                      │
│              │   Analysis Engine     │                      │
│              │  ┌────┐ ┌────┐ ┌────┐│                      │
│              │  │SAST│ │SBOM│ │COMP││                      │
│              │  └────┘ └────┘ └────┘│                      │
│              └───────────┬───────────┘                      │
│                          │                                   │
│              ┌───────────▼───────────┐                      │
│              │     AI Engine         │                      │
│              │  Vulnerability        │                      │
│              │  Prioritization       │                      │
│              └───────────────────────┘                      │
└─────────────────────────────────────────────────────────────┘
\`\`\`

### Security Model

All data is encrypted in transit (TLS 1.3) and at rest (AES-256). Binary files are processed in isolated containers and deleted after analysis. We do not retain your source code or binaries beyond the analysis window.
`
    },
    'first-scan': {
        title: 'Your First Scan Walkthrough',
        content: `
## Your First Scan Walkthrough

This detailed walkthrough covers the complete process of performing your first security scan.

### Understanding Scan Types

**Binary Scan**: Upload compiled firmware for reverse engineering and vulnerability detection.

**Repository Scan**: Connect to GitHub or GitLab to analyze source code directly.

### Preparing Your Binary

Before uploading, ensure your binary:
- Is in a supported format (ELF, PE, Mach-O, Intel HEX, S-Record)
- Does not exceed 500MB (contact support for larger files)
- Is stripped of non-essential debug symbols (optional but recommended)

### Configuring Analysis Options

#### ECU Type Selection
Choose the appropriate ECU type for targeted analysis:
| Type | Focus Areas |
|------|-------------|
| **Body Control** | CAN security, input validation |
| **Powertrain** | Safety-critical, timing analysis |
| **Infotainment** | Network security, privacy |
| **ADAS** | Real-time constraints, safety |
| **Gateway** | Protocol security, firewall rules |

#### Compliance Frameworks
Select frameworks relevant to your requirements:
- **ISO 21434**: Mandatory for OEM compliance
- **MISRA C**: Recommended for all C/C++ code
- **UNECE R155**: Required for European markets
- **AUTOSAR**: For AUTOSAR-based systems

### Reading Scan Results

#### Risk Score (0-100)
- **0-30**: Low risk, minor issues only
- **31-60**: Medium risk, address before release
- **61-100**: High risk, immediate attention required

#### Severity Levels
- **Critical**: Exploitable remotely, high impact
- **High**: Significant security weakness
- **Medium**: Defense-in-depth concerns
- **Low**: Best practice violations
`
    }
};

const scanCentreContent = {
    'binary-upload': {
        title: 'Binary Upload Guide',
        content: `
## Binary Upload Guide

The binary upload feature allows you to analyze compiled ECU firmware for security vulnerabilities.

### Supported File Formats

| Format | Extension | Description |
|--------|-----------|-------------|
| ELF | .elf, .so, .o | Linux/embedded binaries |
| PE | .exe, .dll | Windows executables |
| Mach-O | .dylib | macOS binaries |
| Intel HEX | .hex, .ihex | Firmware images |
| S-Record | .srec, .s19 | Motorola format |
| Raw Binary | .bin | Generic binary |

### Upload Process

1. **Navigate** to Scan Centre → File Upload tab
2. **Configure** ECU metadata:
   - **ECU Name**: Unique identifier for tracking
   - **ECU Type**: Category for targeted rules
   - **Version**: Firmware version being analyzed
   - **Manufacturer**: OEM or supplier name
   - **Architecture**: Target processor architecture
3. **Select** compliance frameworks (optional)
4. **Enable** deep analysis for thorough scanning (slower)
5. **Upload** your binary file
6. **Monitor** progress in real-time

### Analysis Stages

\`\`\`
Initialization → Parsing → SAST → Secrets → SBOM → Compliance → Complete
     │             │         │       │        │         │          │
     └─ 5%         └─ 15%    └─ 50%  └─ 65%   └─ 80%    └─ 95%     └─ 100%
\`\`\`

### Best Practices

- **Include symbols** when possible for better function identification
- **Use original binary** rather than compressed/encrypted versions
- **Specify correct architecture** to ensure proper disassembly
- **Enable deep analysis** for production release validation
`
    },
    'github': {
        title: 'GitHub Integration',
        content: `
## GitHub Integration

Connect your GitHub repositories for seamless source code security analysis.

### Setting Up GitHub Access

1. Navigate to **Settings** → **Source Control Integration**
2. Click **Configure** next to GitHub
3. Enter your **Personal Access Token** (PAT)

### Creating a GitHub PAT

1. Go to [github.com/settings/tokens](https://github.com/settings/tokens)
2. Click **Generate new token (classic)**
3. Select scopes:
   - \`repo\` - Full control over private repositories
   - \`read:user\` - Read user profile data
4. Click **Generate token**
5. Copy and paste into Precogs AI settings

### Repository Scanning

**Manual Scan:**
1. Go to **Scan Centre** → **GitHub** tab
2. Enter repository URL: \`https://github.com/owner/repo\`
3. Specify branch (default: main)
4. Configure ECU metadata
5. Click **Scan Repository**

**Automated Scan via Webhook:**
See the [Webhooks & CI/CD](#webhooks) section for automated scanning on every push.

### What Gets Analyzed

- **Source files**: .c, .cpp, .h, .py, .java, .js, .ts
- **Configuration**: Dockerfiles, CI configs, makefiles
- **Dependencies**: package.json, requirements.txt, CMakeLists.txt
- **Secrets scan**: All text files for credentials
`
    },
    'webhooks': {
        title: 'Webhooks & CI/CD Integration',
        content: `
## Webhooks & CI/CD Integration

Automate security scanning as part of your development workflow.

### Webhook Configuration

**Step 1: Get Your Webhook URL**
1. Navigate to **Settings** → **Webhooks & CI/CD**
2. Copy your unique webhook URL

**Step 2: Configure GitHub Webhook**
1. Go to your repository **Settings** → **Webhooks**
2. Click **Add webhook**
3. Configure:
   - **Payload URL**: Your Precogs webhook URL
   - **Content type**: \`application/json\`
   - **Secret**: Generate a secure secret
   - **Events**: Select "Just the push event" or customize
4. Click **Add webhook**

**Step 3: Configure GitLab Webhook**
1. Go to **Settings** → **Webhooks**
2. Add URL and secret token
3. Select trigger events: Push events, Merge request events

### CI/CD Integration Examples

**GitHub Actions:**
\`\`\`yaml
name: Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Trigger Precogs Scan
        run: |
          curl -X POST \\\\
            -H "Content-Type: application/json" \\\\
            -d '{"repository":"REPO_NAME","branch":"BRANCH_NAME"}' \\\\
            https://your-webhook-url
\`\`\`

**GitLab CI:**
\`\`\`yaml
security_scan:
  stage: test
  script:
    - curl -X POST -H "X-Gitlab-Token: $PRECOGS_TOKEN" $PRECOGS_WEBHOOK_URL
  only:
    - main
    - merge_requests
\`\`\`
`
    }
};

const vulnerabilityContent = {
    'severity': {
        title: 'Understanding Severity Levels',
        content: `
## Understanding Severity Levels

Precogs AI uses a four-tier severity classification aligned with industry standards.

### Severity Definitions

#### 🔴 Critical (CVSS 9.0-10.0)
- **Impact**: Complete system compromise
- **Exploitability**: Remotely exploitable without authentication
- **Examples**:
  - Remote code execution
  - Authentication bypass
  - Hardcoded credentials with remote access
- **Response Time**: Immediate (within 24 hours)

#### 🟠 High (CVSS 7.0-8.9)
- **Impact**: Significant security degradation
- **Exploitability**: Exploitable with some conditions
- **Examples**:
  - Buffer overflow (local)
  - SQL injection
  - Privilege escalation
- **Response Time**: Within 7 days

#### 🟡 Medium (CVSS 4.0-6.9)
- **Impact**: Partial compromise or information disclosure
- **Exploitability**: Requires specific conditions
- **Examples**:
  - Information disclosure
  - Denial of service
  - Incomplete input validation
- **Response Time**: Within 30 days

#### 🟢 Low (CVSS 0.1-3.9)
- **Impact**: Minimal or defense-in-depth concerns
- **Exploitability**: Theoretical or requires extensive access
- **Examples**:
  - Missing security headers
  - Verbose error messages
  - Non-critical configuration issues
- **Response Time**: Next release cycle

### Prioritization Matrix

| Severity | Exploitability | Priority |
|----------|----------------|----------|
| Critical | Easy | P0 - Immediate |
| Critical | Hard | P1 - This sprint |
| High | Easy | P1 - This sprint |
| High | Hard | P2 - Next sprint |
| Medium | Any | P3 - Backlog |
| Low | Any | P4 - Future |
`
    },
    'cwe': {
        title: 'CWE Classifications',
        content: `
## CWE Classifications

Common Weakness Enumeration (CWE) provides standardized vulnerability taxonomy.

### Most Common CWEs in Automotive

#### Memory Safety
| CWE | Name | Description |
|-----|------|-------------|
| CWE-119 | Buffer Overflow | Improper restriction of operations within memory bounds |
| CWE-120 | Buffer Copy | Classic buffer overflow |
| CWE-125 | Out-of-bounds Read | Reading beyond buffer boundaries |
| CWE-787 | Out-of-bounds Write | Writing beyond buffer boundaries |
| CWE-416 | Use After Free | Accessing freed memory |

#### Authentication & Access
| CWE | Name | Description |
|-----|------|-------------|
| CWE-287 | Improper Authentication | Missing or weak authentication |
| CWE-306 | Missing Authentication | No authentication for critical function |
| CWE-798 | Hardcoded Credentials | Embedded passwords or keys |
| CWE-862 | Missing Authorization | No permission checks |

#### Cryptography
| CWE | Name | Description |
|-----|------|-------------|
| CWE-327 | Broken Crypto | Use of weak algorithms |
| CWE-330 | Insufficient Randomness | Predictable random values |
| CWE-338 | Weak PRNG | Cryptographically weak RNG |

### Remediation Resources

Each detected CWE includes:
- Detailed description
- Affected code location
- Remediation guidance
- Example secure code
- MITRE reference link
`
    },
    'remediation': {
        title: 'Remediation Guidance',
        content: `
## AI-Powered Remediation Guidance

Precogs AI provides intelligent remediation suggestions powered by our security AI.

### Using the AI Copilot

1. Navigate to the **AI Copilot** page
2. Ask about specific vulnerabilities:
   - "How do I fix CWE-119 buffer overflow?"
   - "Generate secure code for input validation"
   - "What's the best way to handle CAN message authentication?"
3. Review the AI-generated guidance
4. Apply fixes to your codebase

### Example Remediation

**Vulnerability:** Buffer Overflow (CWE-119)

**Before (Vulnerable):**
\`\`\`c
void process_message(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // VULNERABLE
    // ...
}
\`\`\`

**After (Secure):**
\`\`\`c
void process_message(const char *input) {
    char buffer[64];
    size_t len = strlen(input);
    
    if (len >= sizeof(buffer)) {
        log_error("Input too large");
        return;
    }
    
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\\0';
    // ...
}
\`\`\`

### Verification Steps

After applying fixes:
1. Re-run the scan to verify remediation
2. Check that the vulnerability status changes to "Fixed"
3. Document the fix in your issue tracker
4. Update your coding guidelines if applicable
`
    }
};

// Combine all content
const allContent = { ...gettingStartedContent, ...scanCentreContent, ...vulnerabilityContent };

const documentationSections = [
    {
        title: 'Getting Started',
        icon: BookOpen,
        color: 'text-blue-500',
        items: [
            { id: 'quick-start', title: 'Quick Start Guide', description: 'Get up and running in 5 minutes' },
            { id: 'overview', title: 'Platform Overview', description: 'Understanding the Precogs AI platform' },
            { id: 'first-scan', title: 'First Scan Walkthrough', description: 'Upload and analyze your first ECU binary' },
        ]
    },
    {
        title: 'Scan Centre',
        icon: FileText,
        color: 'text-green-500',
        items: [
            { id: 'binary-upload', title: 'Binary Upload', description: 'Uploading ECU firmware for analysis' },
            { id: 'github', title: 'GitHub Integration', description: 'Scanning repositories from GitHub' },
            { id: 'webhooks', title: 'Webhooks & CI/CD', description: 'Automated scanning with webhooks' },
        ]
    },
    {
        title: 'Vulnerability Analysis',
        icon: Shield,
        color: 'text-red-500',
        items: [
            { id: 'severity', title: 'Understanding Severity Levels', description: 'Critical, High, Medium, Low classifications' },
            { id: 'cwe', title: 'CWE Classifications', description: 'Common Weakness Enumeration mapping' },
            { id: 'remediation', title: 'Remediation Guidance', description: 'AI-powered fix recommendations' },
        ]
    },
];

export default function Documentation() {
    const [searchQuery, setSearchQuery] = useState('');
    const [activeDoc, setActiveDoc] = useState<string | null>(null);

    const filteredSections = documentationSections.map(section => ({
        ...section,
        items: section.items.filter(item =>
            item.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
            item.description.toLowerCase().includes(searchQuery.toLowerCase())
        )
    })).filter(section => section.items.length > 0);

    const renderContent = (content: string) => {
        // Simple markdown-like rendering
        return content.split('\n').map((line, i) => {
            if (line.startsWith('## ')) {
                return <h2 key={i} className="text-xl font-bold mt-6 mb-3 text-foreground">{line.replace('## ', '')}</h2>;
            }
            if (line.startsWith('### ')) {
                return <h3 key={i} className="text-lg font-semibold mt-4 mb-2 text-foreground">{line.replace('### ', '')}</h3>;
            }
            if (line.startsWith('#### ')) {
                return <h4 key={i} className="text-base font-medium mt-3 mb-1 text-foreground">{line.replace('#### ', '')}</h4>;
            }
            if (line.startsWith('```')) {
                return null; // Skip code fence markers
            }
            if (line.startsWith('|')) {
                return <p key={i} className="font-mono text-xs bg-muted px-2 py-1 my-0.5">{line}</p>;
            }
            if (line.startsWith('- ')) {
                return <li key={i} className="ml-4 text-muted-foreground">{line.replace('- ', '')}</li>;
            }
            if (line.match(/^\d+\.\s/)) {
                return <li key={i} className="ml-4 text-muted-foreground list-decimal">{line.replace(/^\d+\.\s/, '')}</li>;
            }
            if (line.trim() === '') {
                return <br key={i} />;
            }
            return <p key={i} className="text-muted-foreground my-1">{line}</p>;
        });
    };

    return (
        <AppLayout>
            <div className="max-w-6xl mx-auto">
                {activeDoc ? (
                    // Document viewer
                    <div className="space-y-4">
                        <button
                            onClick={() => setActiveDoc(null)}
                            className="flex items-center gap-2 text-primary hover:underline text-sm"
                        >
                            ← Back to Documentation
                        </button>
                        <div className="bg-card border border-border rounded-xl p-8 prose prose-slate dark:prose-invert max-w-none">
                            <h1 className="text-2xl font-bold text-foreground mb-4">
                                {allContent[activeDoc as keyof typeof allContent]?.title}
                            </h1>
                            {renderContent(allContent[activeDoc as keyof typeof allContent]?.content || '')}
                        </div>
                    </div>
                ) : (
                    // Documentation index
                    <div className="space-y-8">
                        {/* Header */}
                        <div className="text-center space-y-4">
                            <div className="inline-flex items-center gap-2 px-4 py-2 bg-primary/10 text-primary rounded-full text-sm font-medium">
                                <BookOpen className="w-4 h-4" />
                                Documentation
                            </div>
                            <h1 className="text-4xl font-bold text-foreground">Precogs AI Documentation</h1>
                            <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                                Comprehensive guides, tutorials, and reference documentation for the Precogs AI Product Security Platform
                            </p>
                        </div>

                        {/* Search */}
                        <div className="max-w-xl mx-auto">
                            <div className="relative">
                                <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                                <Input
                                    placeholder="Search documentation..."
                                    value={searchQuery}
                                    onChange={(e) => setSearchQuery(e.target.value)}
                                    className="pl-12 py-6 text-lg"
                                />
                            </div>
                        </div>

                        {/* Quick Links */}
                        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                            <button
                                onClick={() => setActiveDoc('quick-start')}
                                className="flex items-center gap-3 p-4 bg-card border border-border rounded-xl hover:border-primary/30 transition-colors group text-left"
                            >
                                <div className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center">
                                    <Zap className="w-5 h-5 text-blue-500" />
                                </div>
                                <div>
                                    <div className="font-medium text-foreground">Quick Start</div>
                                    <div className="text-sm text-muted-foreground">5 min guide</div>
                                </div>
                            </button>
                            <button
                                onClick={() => setActiveDoc('github')}
                                className="flex items-center gap-3 p-4 bg-card border border-border rounded-xl hover:border-primary/30 transition-colors group text-left"
                            >
                                <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center">
                                    <GitBranch className="w-5 h-5 text-green-500" />
                                </div>
                                <div>
                                    <div className="font-medium text-foreground">Git Integration</div>
                                    <div className="text-sm text-muted-foreground">Connect repos</div>
                                </div>
                            </button>
                            <button
                                onClick={() => setActiveDoc('severity')}
                                className="flex items-center gap-3 p-4 bg-card border border-border rounded-xl hover:border-primary/30 transition-colors group text-left"
                            >
                                <div className="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center">
                                    <AlertTriangle className="w-5 h-5 text-red-500" />
                                </div>
                                <div>
                                    <div className="font-medium text-foreground">Severity Levels</div>
                                    <div className="text-sm text-muted-foreground">Understand risk</div>
                                </div>
                            </button>
                            <button
                                onClick={() => setActiveDoc('webhooks')}
                                className="flex items-center gap-3 p-4 bg-card border border-border rounded-xl hover:border-primary/30 transition-colors group text-left"
                            >
                                <div className="w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center">
                                    <Terminal className="w-5 h-5 text-purple-500" />
                                </div>
                                <div>
                                    <div className="font-medium text-foreground">CI/CD Setup</div>
                                    <div className="text-sm text-muted-foreground">Automate scans</div>
                                </div>
                            </button>
                        </div>

                        {/* Documentation Sections */}
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                            {filteredSections.map((section) => (
                                <div key={section.title} className="bg-card border border-border rounded-xl overflow-hidden">
                                    <div className="px-5 py-4 border-b border-border flex items-center gap-3 bg-muted/30">
                                        <div className={`w-8 h-8 rounded-lg bg-muted flex items-center justify-center`}>
                                            <section.icon className={`w-4 h-4 ${section.color}`} />
                                        </div>
                                        <h2 className="font-semibold text-foreground">{section.title}</h2>
                                    </div>
                                    <div className="divide-y divide-border">
                                        {section.items.map((item) => (
                                            <button
                                                key={item.id}
                                                onClick={() => setActiveDoc(item.id)}
                                                className="w-full flex items-center gap-3 px-5 py-3 hover:bg-muted/50 transition-colors group text-left"
                                            >
                                                <div className="flex-1">
                                                    <div className="font-medium text-foreground group-hover:text-primary transition-colors">{item.title}</div>
                                                    <div className="text-sm text-muted-foreground">{item.description}</div>
                                                </div>
                                                <ChevronRight className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors" />
                                            </button>
                                        ))}
                                    </div>
                                </div>
                            ))}
                        </div>

                        {/* Additional Resources */}
                        <div className="mt-8 p-6 bg-gradient-to-r from-primary/5 to-accent/5 rounded-xl border border-primary/10">
                            <h3 className="font-semibold text-foreground mb-3">Need More Help?</h3>
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                                <a href="mailto:support@precogs.ai" className="flex items-center gap-2 text-muted-foreground hover:text-primary">
                                    <Users className="w-4 h-4" />
                                    Contact Support
                                </a>
                                <a href="https://github.com/precogs-ai" target="_blank" rel="noopener" className="flex items-center gap-2 text-muted-foreground hover:text-primary">
                                    <Code className="w-4 h-4" />
                                    GitHub Examples
                                </a>
                                <a href="/copilot" className="flex items-center gap-2 text-muted-foreground hover:text-primary">
                                    <Sparkles className="w-4 h-4" />
                                    Ask AI Copilot
                                </a>
                            </div>
                        </div>
                    </div>
                )}
            </div>
        </AppLayout>
    );
}
