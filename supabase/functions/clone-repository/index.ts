import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

interface CloneRequest {
    scanId: string;
    gitUrl: string;
    gitBranch: string;
    gitProvider: 'github' | 'gitlab';
    accessToken?: string;
    metadata: {
        ecuName: string;
        ecuType: string;
        version?: string;
        manufacturer?: string;
        architecture: string;
        deepAnalysis: boolean;
        complianceFrameworks: string[];
    };
}

interface RepoFile {
    path: string;
    content: string;
    size: number;
}

async function updateScanStatus(supabase: any, scanId: string, status: string, progress: number, message?: string) {
    await supabase.from('scans').update({ status, progress }).eq('id', scanId);
    if (message) {
        await supabase.from('analysis_logs').insert({
            scan_id: scanId,
            stage: status,
            log_level: 'info',
            message,
        });
    }
}

// Fetch repository contents using GitHub/GitLab API
async function fetchRepositoryContents(
    gitUrl: string,
    branch: string,
    provider: 'github' | 'gitlab',
    accessToken?: string
): Promise<RepoFile[]> {
    const files: RepoFile[] = [];

    // Parse repository URL
    const urlParts = gitUrl.replace(/\.git$/, '').replace(/\/$/, '').split('/');
    const repoName = urlParts[urlParts.length - 1];
    const owner = urlParts[urlParts.length - 2];

    console.log(`Fetching repository: ${owner}/${repoName} branch: ${branch} provider: ${provider}`);

    // Relevant file extensions for security scanning
    const relevantExtensions = [
        '.c', '.h', '.cpp', '.hpp', '.cc', '.cxx',  // C/C++
        '.py', '.pyw',                               // Python
        '.js', '.ts', '.jsx', '.tsx',                // JavaScript/TypeScript
        '.java', '.kt', '.kts',                      // Java/Kotlin
        '.go',                                       // Go
        '.rs',                                       // Rust
        '.rb',                                       // Ruby
        '.php',                                      // PHP
        '.cs',                                       // C#
        '.swift',                                    // Swift
        '.m', '.mm',                                 // Objective-C
        '.xml', '.arxml',                            // AUTOSAR XML
        '.json', '.yaml', '.yml',                    // Config files
        '.toml', '.ini', '.cfg', '.conf',           // Config files
        '.sh', '.bash', '.zsh',                     // Shell scripts
        '.sql',                                      // SQL
        '.dockerfile', 'Dockerfile',                 // Docker
        '.env', '.env.example',                     // Environment files
        'requirements.txt', 'package.json',         // Dependencies
        'Cargo.toml', 'go.mod', 'pom.xml',         // Build files
        '.gitignore', '.npmrc',                     // Dotfiles with potential secrets
    ];

    try {
        if (provider === 'github') {
            // GitHub API - Get repository tree
            const headers: Record<string, string> = {
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'ECU-ScanGuard/1.0',
            };
            if (accessToken) {
                headers['Authorization'] = `token ${accessToken}`;
            }

            // Get the default branch SHA
            const repoResponse = await fetch(
                `https://api.github.com/repos/${owner}/${repoName}`,
                { headers }
            );

            if (!repoResponse.ok) {
                const errorText = await repoResponse.text();
                console.error('GitHub API error:', repoResponse.status, errorText);
                throw new Error(`Failed to access repository: ${repoResponse.status}`);
            }

            const repoData = await repoResponse.json();
            const defaultBranch = branch || repoData.default_branch;

            // Get the tree recursively
            const treeResponse = await fetch(
                `https://api.github.com/repos/${owner}/${repoName}/git/trees/${defaultBranch}?recursive=1`,
                { headers }
            );

            if (!treeResponse.ok) {
                throw new Error(`Failed to fetch repository tree: ${treeResponse.status}`);
            }

            const treeData = await treeResponse.json();

            // Filter for relevant files and limit to prevent timeout
            const relevantFiles = treeData.tree
                .filter((item: any) => {
                    if (item.type !== 'blob') return false;
                    const fileName = item.path.toLowerCase();
                    return relevantExtensions.some(ext =>
                        fileName.endsWith(ext.toLowerCase()) || fileName === ext.toLowerCase()
                    );
                })
                .slice(0, 50); // Limit to 50 files to prevent timeout

            console.log(`Found ${relevantFiles.length} relevant files in repository`);

            // Fetch content of each file
            for (const file of relevantFiles) {
                try {
                    const contentResponse = await fetch(
                        `https://api.github.com/repos/${owner}/${repoName}/contents/${file.path}?ref=${defaultBranch}`,
                        { headers }
                    );

                    if (contentResponse.ok) {
                        const contentData = await contentResponse.json();
                        if (contentData.encoding === 'base64' && contentData.content) {
                            files.push({
                                path: file.path,
                                content: contentData.content.replace(/\n/g, ''), // Remove newlines from base64
                                size: file.size || 0,
                            });
                        }
                    }
                } catch (e) {
                    console.warn(`Failed to fetch ${file.path}:`, e);
                }

                // Small delay to avoid rate limiting
                await new Promise(r => setTimeout(r, 100));
            }

        } else if (provider === 'gitlab') {
            // GitLab API
            const headers: Record<string, string> = {
                'Accept': 'application/json',
            };
            if (accessToken) {
                headers['PRIVATE-TOKEN'] = accessToken;
            }

            // URL encode the project path
            const projectPath = encodeURIComponent(`${owner}/${repoName}`);

            // Get project info
            const projectResponse = await fetch(
                `https://gitlab.com/api/v4/projects/${projectPath}`,
                { headers }
            );

            if (!projectResponse.ok) {
                throw new Error(`Failed to access GitLab repository: ${projectResponse.status}`);
            }

            const projectData = await projectResponse.json();
            const defaultBranch = branch || projectData.default_branch;

            // Get repository tree
            const treeResponse = await fetch(
                `https://gitlab.com/api/v4/projects/${projectPath}/repository/tree?ref=${defaultBranch}&recursive=true&per_page=100`,
                { headers }
            );

            if (!treeResponse.ok) {
                throw new Error(`Failed to fetch repository tree: ${treeResponse.status}`);
            }

            const treeData = await treeResponse.json();

            // Filter for relevant files
            const relevantFiles = treeData
                .filter((item: any) => {
                    if (item.type !== 'blob') return false;
                    const fileName = item.path.toLowerCase();
                    return relevantExtensions.some(ext =>
                        fileName.endsWith(ext.toLowerCase()) || fileName === ext.toLowerCase()
                    );
                })
                .slice(0, 50);

            console.log(`Found ${relevantFiles.length} relevant files in GitLab repository`);

            // Fetch content of each file
            for (const file of relevantFiles) {
                try {
                    const filePath = encodeURIComponent(file.path);
                    const contentResponse = await fetch(
                        `https://gitlab.com/api/v4/projects/${projectPath}/repository/files/${filePath}?ref=${defaultBranch}`,
                        { headers }
                    );

                    if (contentResponse.ok) {
                        const contentData = await contentResponse.json();
                        if (contentData.encoding === 'base64' && contentData.content) {
                            files.push({
                                path: file.path,
                                content: contentData.content.replace(/\n/g, ''),
                                size: contentData.size || 0,
                            });
                        }
                    }
                } catch (e) {
                    console.warn(`Failed to fetch ${file.path}:`, e);
                }

                await new Promise(r => setTimeout(r, 100));
            }
        }
    } catch (error) {
        console.error('Error fetching repository:', error);
        throw error;
    }

    return files;
}

// Analyze repository files with LLM
async function analyzeRepositoryWithLLM(
    files: RepoFile[],
    metadata: CloneRequest['metadata'],
    apiKey: string
): Promise<{
    vulnerabilities: any[];
    complianceResults: any[];
    sbomComponents: any[];
    piiFindings: any[];
    secretFindings: any[];
    executiveSummary: string;
    riskScore: number;
}> {
    // Create a summary of files for analysis
    const filesSummary = files.map(f => {
        let content: string;
        try {
            content = atob(f.content).slice(0, 2000);
        } catch {
            content = f.content.slice(0, 1000);
        }
        return `--- ${f.path} ---\n${content}\n`;
    }).join('\n\n');

    const systemPrompt = `You are an expert security analyst specializing in:
- Source code vulnerability detection (OWASP Top 10, CWE Top 25)
- Secret detection (API keys, passwords, tokens, private keys)
- PII detection (emails, phone numbers, personal data)
- Dependency vulnerability analysis
- Compliance checking (MISRA C, ISO 21434, ISO 26262)
- SBOM generation from source code

Analyze the provided source files for security issues.
Respond ONLY with valid JSON, no markdown or explanations.`;

    const analysisPrompt = `Analyze this repository for security vulnerabilities:

Repository: ${metadata.ecuName}
Type: ${metadata.ecuType}
Architecture: ${metadata.architecture}
Compliance Frameworks: ${metadata.complianceFrameworks.join(', ')}

SOURCE FILES:
${filesSummary.slice(0, 30000)}

INSTRUCTIONS:
1. Identify ALL security vulnerabilities with exact file paths and line numbers
2. Detect hardcoded secrets, API keys, passwords, tokens
3. Find PII exposure (emails, phone numbers, personal data in code)
4. Generate SBOM from imports, dependencies, and package files
5. Check compliance with ${metadata.complianceFrameworks.join(', ')}

Return JSON:
{
  "vulnerabilities": [
    {
      "cve_id": "CVE-XXX or null",
      "cwe_id": "CWE-XXX",
      "severity": "critical|high|medium|low",
      "cvss_score": 0.0-10.0,
      "title": "string",
      "description": "detailed description",
      "affected_component": "file/path.ext",
      "affected_function": "function_name()",
      "code_snippet": "vulnerable code",
      "line_number": number,
      "detection_method": "sast|secrets|dependency",
      "remediation": "how to fix",
      "attack_vector": "exploitation method",
      "impact": "potential damage"
    }
  ],
  "compliance_results": [
    {
      "framework": "framework name",
      "rule_id": "rule ID",
      "rule_description": "description",
      "status": "pass|fail|warning",
      "details": "specific finding"
    }
  ],
  "sbom_components": [
    {
      "component_name": "library name",
      "version": "version",
      "license": "license type",
      "source_file": "where detected",
      "vulnerabilities": ["CVE-XXX"],
      "purl": "pkg:type/name@version"
    }
  ],
  "pii_findings": [
    {
      "type": "email|phone|ip_address|name|device_id",
      "value": "masked value",
      "location": "file:line",
      "severity": "high|medium|low",
      "context": "code context",
      "remediation": "fix suggestion"
    }
  ],
  "secret_findings": [
    {
      "type": "api_key|password|token|private_key|aws_key",
      "value": "first 4 chars + ***",
      "location": "file:line",
      "severity": "critical|high|medium",
      "context": "usage context",
      "remediation": "use secrets manager"
    }
  ],
  "executive_summary": "2-3 paragraph security assessment",
  "risk_score": 0-100
}`;

    const response = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            model: 'google/gemini-2.5-flash',
            messages: [
                { role: 'system', content: systemPrompt },
                { role: 'user', content: analysisPrompt }
            ],
        }),
    });

    if (!response.ok) {
        const errorText = await response.text();
        console.error('LLM API error:', response.status, errorText);
        throw new Error(`LLM API error: ${response.status}`);
    }

    const data = await response.json();
    const content = data.choices?.[0]?.message?.content;

    if (!content) {
        throw new Error('No content in LLM response');
    }

    // Parse JSON from response
    let jsonContent = content;
    if (content.includes('```json')) {
        jsonContent = content.replace(/```json\n?/g, '').replace(/```\n?/g, '');
    } else if (content.includes('```')) {
        jsonContent = content.replace(/```\n?/g, '');
    }

    try {
        return JSON.parse(jsonContent.trim());
    } catch (e) {
        console.error('Failed to parse LLM response:', jsonContent.slice(0, 500));
        throw new Error('Failed to parse LLM response as JSON');
    }
}

serve(async (req) => {
    if (req.method === 'OPTIONS') {
        return new Response(null, { headers: corsHeaders });
    }

    try {
        const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
        const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
        const lovableApiKey = Deno.env.get('LOVABLE_API_KEY')!;

        const supabase = createClient(supabaseUrl, supabaseKey);

        const { scanId, gitUrl, gitBranch, gitProvider, accessToken, metadata } = await req.json() as CloneRequest;

        console.log(`Starting repository analysis for scan ${scanId}, URL: ${gitUrl}`);

        // Stage 1: Cloning
        await updateScanStatus(supabase, scanId, 'parsing', 10, `Connecting to ${gitProvider === 'github' ? 'GitHub' : 'GitLab'} repository...`);

        await supabase.from('analysis_logs').insert({
            scan_id: scanId,
            stage: 'parsing',
            log_level: 'info',
            message: `Repository URL: ${gitUrl}, Branch: ${gitBranch}`,
        });

        // Stage 2: Fetching files
        await updateScanStatus(supabase, scanId, 'decompiling', 25, 'Fetching repository files...');

        let files: RepoFile[];
        try {
            files = await fetchRepositoryContents(gitUrl, gitBranch, gitProvider, accessToken);
        } catch (error) {
            await supabase.from('analysis_logs').insert({
                scan_id: scanId,
                stage: 'decompiling',
                log_level: 'error',
                message: `Failed to fetch repository: ${error instanceof Error ? error.message : 'Unknown error'}`,
            });

            await supabase.from('scans').update({
                status: 'failed',
                progress: 0,
            }).eq('id', scanId);

            throw error;
        }

        await supabase.from('analysis_logs').insert({
            scan_id: scanId,
            stage: 'decompiling',
            log_level: 'info',
            message: `Fetched ${files.length} files for analysis`,
        });

        if (files.length === 0) {
            await supabase.from('analysis_logs').insert({
                scan_id: scanId,
                stage: 'decompiling',
                log_level: 'warning',
                message: 'No relevant source files found in repository',
            });
        }

        // Stage 3: Analyzing
        await updateScanStatus(supabase, scanId, 'analyzing', 50, 'Running security analysis...');

        const rawResult = await analyzeRepositoryWithLLM(files, metadata, lovableApiKey);

        // Normalize response
        const analysisResult = {
            vulnerabilities: rawResult.vulnerabilities || [],
            complianceResults: rawResult.complianceResults || rawResult.compliance_results || [],
            sbomComponents: rawResult.sbomComponents || rawResult.sbom_components || [],
            piiFindings: rawResult.piiFindings || rawResult.pii_findings || [],
            secretFindings: rawResult.secretFindings || rawResult.secret_findings || [],
            executiveSummary: rawResult.executiveSummary || rawResult.executive_summary || '',
            riskScore: rawResult.riskScore || rawResult.risk_score || 50,
        };

        console.log(`Analysis returned: ${analysisResult.vulnerabilities.length} vulns, ${analysisResult.secretFindings.length} secrets`);

        // Stage 4: Enriching and storing results
        await updateScanStatus(supabase, scanId, 'enriching', 75, 'Processing findings...');

        // Insert vulnerabilities
        for (const vuln of analysisResult.vulnerabilities) {
            await supabase.from('vulnerabilities').insert({
                scan_id: scanId,
                cve_id: vuln.cve_id,
                cwe_id: vuln.cwe_id,
                severity: vuln.severity,
                cvss_score: vuln.cvss_score,
                title: vuln.title,
                description: vuln.description,
                affected_component: vuln.affected_component,
                affected_function: vuln.affected_function,
                code_snippet: vuln.code_snippet,
                line_number: vuln.line_number,
                detection_method: vuln.detection_method || 'sast',
                remediation: vuln.remediation,
                attack_vector: vuln.attack_vector,
                impact: vuln.impact,
                status: 'new',
            });
        }

        // Insert PII findings as vulnerabilities
        for (const pii of analysisResult.piiFindings) {
            await supabase.from('vulnerabilities').insert({
                scan_id: scanId,
                cwe_id: 'CWE-359',
                severity: pii.severity || 'medium',
                title: `PII Exposure: ${pii.type}`,
                description: `Personal data (${pii.type}) detected. Value: ${pii.value}`,
                affected_component: pii.location?.split(':')[0] || 'unknown',
                line_number: parseInt(pii.location?.split(':')[1]) || null,
                code_snippet: pii.context,
                detection_method: 'pii_scanner',
                remediation: pii.remediation,
                status: 'new',
            });
        }

        // Insert secret findings as vulnerabilities
        for (const secret of analysisResult.secretFindings) {
            await supabase.from('vulnerabilities').insert({
                scan_id: scanId,
                cwe_id: 'CWE-798',
                severity: secret.severity || 'critical',
                title: `Hardcoded Secret: ${secret.type}`,
                description: `Hardcoded ${secret.type} detected. Masked: ${secret.value}`,
                affected_component: secret.location?.split(':')[0] || 'unknown',
                line_number: parseInt(secret.location?.split(':')[1]) || null,
                code_snippet: secret.context,
                detection_method: 'secret_scanner',
                remediation: secret.remediation,
                status: 'new',
            });
        }

        // Insert compliance results
        for (const result of analysisResult.complianceResults) {
            await supabase.from('compliance_results').insert({
                scan_id: scanId,
                framework: result.framework,
                rule_id: result.rule_id,
                rule_description: result.rule_description,
                status: result.status,
                details: result.details,
            });
        }

        // Insert SBOM components
        for (const component of analysisResult.sbomComponents) {
            await supabase.from('sbom_components').insert({
                scan_id: scanId,
                component_name: component.component_name,
                version: component.version,
                license: component.license,
                source_file: component.source_file,
                vulnerabilities: component.vulnerabilities || [],
            });
        }

        // Stage 5: Complete
        const totalFindings = analysisResult.vulnerabilities.length +
            analysisResult.piiFindings.length +
            analysisResult.secretFindings.length;

        await supabase.from('scans').update({
            status: 'complete',
            progress: 100,
            completed_at: new Date().toISOString(),
            executive_summary: analysisResult.executiveSummary,
            risk_score: analysisResult.riskScore,
        }).eq('id', scanId);

        await supabase.from('analysis_logs').insert({
            scan_id: scanId,
            stage: 'complete',
            log_level: 'info',
            message: `Repository analysis complete - ${totalFindings} findings, ${analysisResult.sbomComponents.length} components, Risk Score: ${analysisResult.riskScore}`,
        });

        console.log(`Repository analysis complete for scan ${scanId}`);

        return new Response(JSON.stringify({
            success: true,
            scanId,
            filesAnalyzed: files.length,
            vulnerabilityCount: analysisResult.vulnerabilities.length,
            piiCount: analysisResult.piiFindings.length,
            secretCount: analysisResult.secretFindings.length,
            sbomCount: analysisResult.sbomComponents.length,
            riskScore: analysisResult.riskScore,
        }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });

    } catch (error) {
        console.error('Repository analysis error:', error);
        return new Response(JSON.stringify({
            error: error instanceof Error ? error.message : 'Unknown error'
        }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
    }
});
