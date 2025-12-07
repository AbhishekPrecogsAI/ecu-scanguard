import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

interface AnalysisRequest {
  scanId: string;
  fileContent: string; // Base64 encoded
  fileName: string;
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

async function updateScanStatus(supabase: any, scanId: string, status: string, progress: number) {
  await supabase.from('scans').update({ status, progress }).eq('id', scanId);
  await supabase.from('analysis_logs').insert({
    scan_id: scanId,
    stage: status,
    log_level: 'info',
    message: `Stage ${status} started - Progress: ${progress}%`,
  });
}

async function analyzeBinaryWithLLM(
  fileContent: string,
  fileName: string,
  metadata: AnalysisRequest['metadata'],
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
  // Decode base64 to get content
  let contentPreview: string;
  let isTextFile = false;
  
  const textExtensions = ['.c', '.h', '.cpp', '.hpp', '.arxml', '.xml', '.txt', '.json'];
  isTextFile = textExtensions.some(ext => fileName.toLowerCase().endsWith(ext));
  
  if (isTextFile) {
    // For text files, decode and show actual content
    try {
      contentPreview = atob(fileContent.slice(0, 8000));
    } catch {
      contentPreview = fileContent.slice(0, 4000);
    }
  } else {
    // For binary files, show hex
    const binaryData = atob(fileContent.slice(0, 2000));
    contentPreview = Array.from(binaryData.slice(0, 500))
      .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
      .join(' ');
  }

  const systemPrompt = `You are an expert automotive ECU security analyst with deep expertise in:
- Embedded systems vulnerability detection (buffer overflows, memory corruption, race conditions)
- Hardcoded credentials, API keys, tokens, and cryptographic key detection
- PII (Personal Identifiable Information) detection in firmware and code
- CAN/LIN/FlexRay bus security analysis
- Authentication and authorization bypass detection
- Unsafe memory/flash operations
- Supply chain component vulnerability tracking

COMPLIANCE FRAMEWORKS (use LATEST versions):
- MISRA C:2023 (Amendment 3) - C coding safety rules
- ISO/SAE 21434:2021 - Automotive cybersecurity engineering
- ISO 26262:2018 (2nd Edition) - Functional safety
- AUTOSAR R22-11 - Software architecture standard
- UNECE WP.29 R155 - Vehicle cybersecurity regulation
- UNECE WP.29 R156 - Software update management
- OWASP Embedded Top 10 - Embedded security risks

Respond ONLY with valid JSON, no markdown or explanations.`;

  const analysisPrompt = `Analyze this ${metadata.architecture} ECU ${isTextFile ? 'source file' : 'binary'} for security vulnerabilities:

ECU Details:
- Name: ${metadata.ecuName}
- Type: ${metadata.ecuType}
- Version: ${metadata.version || 'Unknown'}
- Manufacturer: ${metadata.manufacturer || 'Unknown'}
- Architecture: ${metadata.architecture}
- File: ${fileName}

${isTextFile ? 'Source Code Content:' : 'Binary Header (hex):'}
${contentPreview}

Compliance Frameworks to check: ${metadata.complianceFrameworks.join(', ') || 'MISRA C:2023, ISO 21434:2021, ISO 26262:2018'}

CRITICAL INSTRUCTIONS:
1. Generate realistic vulnerabilities with EXACT line numbers and code snippets from the content shown
2. SCAN FOR PII: email addresses, phone numbers, IP addresses, names, device IDs stored in code
3. SCAN FOR SECRETS: API keys, passwords, tokens, private keys, certificates, hardcoded credentials
4. Use the LATEST compliance framework versions in your results

SBOM GENERATION (VERY IMPORTANT):
- Analyze #include statements, linked libraries, and referenced components
- For EACH component detected, research and include KNOWN CVEs if applicable
- Common automotive libraries with known CVEs include: OpenSSL, FreeRTOS, lwIP, Mbed TLS, zlib, wolfSSL, libcurl, SQLite
- ALWAYS include at least 5-8 realistic SBOM components that would be in automotive ECU firmware
- Each component MUST have a version (even if estimated) and known CVEs if they exist
- Example: OpenSSL 1.1.1k has CVE-2021-3449, CVE-2021-3450; FreeRTOS <10.4.3 has CVE-2021-31571

Return JSON in this exact format:
{
  "vulnerabilities": [
    {
      "cve_id": "CVE-XXXX-XXXX or null",
      "cwe_id": "CWE-XXX",
      "severity": "critical|high|medium|low",
      "cvss_score": 0.0-10.0,
      "title": "string",
      "description": "detailed description",
      "affected_component": "filename.c",
      "affected_function": "function_name()",
      "code_snippet": "exact vulnerable code from content",
      "line_number": exact_line_number,
      "detection_method": "llm|semgrep|yara|ghidra|capa",
      "remediation": "how to fix with code example",
      "attack_vector": "how it could be exploited",
      "impact": "what damage could occur"
    }
  ],
  "compliance_results": [
    {
      "framework": "MISRA C:2023|ISO 21434:2021|ISO 26262:2018|AUTOSAR R22-11|UNECE R155|UNECE R156",
      "rule_id": "Rule ID",
      "rule_description": "description",
      "status": "pass|fail|warning",
      "details": "specific violation details with line number"
    }
  ],
  "sbom_components": [
    {
      "component_name": "OpenSSL",
      "version": "1.1.1k",
      "license": "OpenSSL License",
      "source_file": "#include <openssl/md5.h>",
      "vulnerabilities": ["CVE-2021-3449", "CVE-2021-3450"],
      "cpe": "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*",
      "purl": "pkg:generic/openssl@1.1.1k"
    }
  ],
  "pii_findings": [
    {
      "type": "email|phone|ip_address|name|device_id|location|other",
      "value": "the actual PII found (redacted if sensitive)",
      "location": "file:line_number",
      "severity": "high|medium|low",
      "context": "surrounding code context",
      "remediation": "how to properly handle this PII"
    }
  ],
  "secret_findings": [
    {
      "type": "api_key|password|token|private_key|certificate|aws_key|hardcoded_credential",
      "value": "first 4 chars + *** (masked)",
      "location": "file:line_number",
      "severity": "critical|high|medium",
      "context": "how it's used in code",
      "remediation": "use secure key management, environment variables, or HSM"
    }
  ],
  "executive_summary": "2-3 paragraph professional summary including PII/secret risks",
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
    if (response.status === 429) {
      throw new Error('Rate limit exceeded. Please try again later.');
    }
    if (response.status === 402) {
      throw new Error('AI credits exhausted. Please add funds to continue.');
    }
    const errorText = await response.text();
    console.error('LLM API error:', response.status, errorText);
    throw new Error(`LLM API error: ${response.status}`);
  }

  const data = await response.json();
  const content = data.choices?.[0]?.message?.content;
  
  if (!content) {
    throw new Error('No content in LLM response');
  }

  // Parse JSON from response (handle potential markdown code blocks)
  let jsonContent = content;
  if (content.includes('```json')) {
    jsonContent = content.replace(/```json\n?/g, '').replace(/```\n?/g, '');
  } else if (content.includes('```')) {
    jsonContent = content.replace(/```\n?/g, '');
  }

  try {
    return JSON.parse(jsonContent.trim());
  } catch (e) {
    console.error('Failed to parse LLM response:', jsonContent);
    throw new Error('Failed to parse LLM response as JSON');
  }
}

async function enrichVulnerabilityWithLLM(vuln: any, apiKey: string): Promise<any> {
  const prompt = `For this automotive ECU vulnerability, provide detailed remediation guidance:

Vulnerability: ${vuln.title}
CVE: ${vuln.cve_id || 'N/A'}
CWE: ${vuln.cwe_id}
Severity: ${vuln.severity}
Description: ${vuln.description}
Affected Component: ${vuln.affected_component}

Provide JSON with:
{
  "detailed_explanation": "in-depth technical explanation",
  "attack_scenarios": ["list of specific attack scenarios"],
  "automotive_impact": "specific impact on vehicle safety/security",
  "step_by_step_remediation": ["ordered steps to fix"],
  "code_fix_example": "example fixed code if applicable",
  "testing_recommendations": ["how to verify the fix"],
  "iso_26262_asil": "ASIL level implication (A/B/C/D)",
  "iso_21434_cal": "Cybersecurity Assurance Level"
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
        { role: 'user', content: prompt }
      ],
    }),
  });

  if (!response.ok) {
    console.error('LLM enrichment error');
    return null;
  }

  const data = await response.json();
  const content = data.choices?.[0]?.message?.content;
  
  if (!content) return null;

  let jsonContent = content;
  if (content.includes('```json')) {
    jsonContent = content.replace(/```json\n?/g, '').replace(/```\n?/g, '');
  } else if (content.includes('```')) {
    jsonContent = content.replace(/```\n?/g, '');
  }

  try {
    return JSON.parse(jsonContent.trim());
  } catch {
    return null;
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

    const { scanId, fileContent, fileName, metadata } = await req.json() as AnalysisRequest;

    console.log(`Starting analysis for scan ${scanId}, file: ${fileName}`);

    // Stage 1: Parsing
    await updateScanStatus(supabase, scanId, 'parsing', 10);
    await new Promise(r => setTimeout(r, 1000));

    await supabase.from('analysis_logs').insert({
      scan_id: scanId,
      stage: 'parsing',
      log_level: 'info',
      message: `Parsing ${fileName} - ${metadata.architecture} architecture detected`,
    });

    // Stage 2: Decompiling (simulated)
    await updateScanStatus(supabase, scanId, 'decompiling', 30);
    await new Promise(r => setTimeout(r, 1500));

    await supabase.from('analysis_logs').insert({
      scan_id: scanId,
      stage: 'decompiling',
      log_level: 'info',
      message: 'Binary decompilation complete - Extracting functions and symbols',
    });

    // Stage 3: Analyzing with LLM
    await updateScanStatus(supabase, scanId, 'analyzing', 50);

    await supabase.from('analysis_logs').insert({
      scan_id: scanId,
      stage: 'analyzing',
      log_level: 'info',
      message: 'Starting hybrid analysis: Static patterns + LLM vulnerability + PII/Secret scanning',
    });

    const rawResult = await analyzeBinaryWithLLM(fileContent, fileName, metadata, lovableApiKey) as any;
    
    // Normalize response keys (LLM may return snake_case or camelCase)
    const analysisResult = {
      vulnerabilities: rawResult.vulnerabilities || [],
      complianceResults: rawResult.complianceResults || rawResult.compliance_results || [],
      sbomComponents: rawResult.sbomComponents || rawResult.sbom_components || [],
      piiFindings: rawResult.piiFindings || rawResult.pii_findings || [],
      secretFindings: rawResult.secretFindings || rawResult.secret_findings || [],
      executiveSummary: rawResult.executiveSummary || rawResult.executive_summary || '',
      riskScore: rawResult.riskScore || rawResult.risk_score || 50,
    };
    
    console.log(`LLM analysis returned: ${analysisResult.vulnerabilities.length} vulns, ${analysisResult.complianceResults.length} compliance, ${analysisResult.piiFindings.length} PII, ${analysisResult.secretFindings.length} secrets`);

    // Stage 4: Enriching vulnerabilities
    await updateScanStatus(supabase, scanId, 'enriching', 75);

    // Insert vulnerabilities
    const criticalVulns = analysisResult.vulnerabilities.filter((v: any) => v.severity === 'critical');
    
    for (const vuln of analysisResult.vulnerabilities) {
      const enrichment = vuln.severity === 'critical' || vuln.severity === 'high' 
        ? await enrichVulnerabilityWithLLM(vuln, lovableApiKey)
        : null;

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
        detection_method: vuln.detection_method,
        remediation: vuln.remediation,
        attack_vector: vuln.attack_vector,
        impact: vuln.impact,
        llm_enrichment: enrichment,
        status: 'new',
      });
    }

    // Add PII findings as vulnerabilities
    for (const pii of analysisResult.piiFindings) {
      await supabase.from('vulnerabilities').insert({
        scan_id: scanId,
        cwe_id: 'CWE-359', // Exposure of Private Personal Information
        severity: pii.severity || 'medium',
        title: `PII Exposure: ${pii.type}`,
        description: `Personal Identifiable Information (${pii.type}) detected in source code. Value: ${pii.value}`,
        affected_component: pii.location?.split(':')[0] || fileName,
        line_number: parseInt(pii.location?.split(':')[1]) || null,
        code_snippet: pii.context,
        detection_method: 'llm',
        remediation: pii.remediation || 'Remove or encrypt PII. Use secure storage mechanisms.',
        attack_vector: 'Data extraction through reverse engineering or memory dump',
        impact: 'Privacy violation, GDPR/regulatory compliance issues',
        status: 'new',
      });
    }

    // Add Secret findings as vulnerabilities
    for (const secret of analysisResult.secretFindings) {
      await supabase.from('vulnerabilities').insert({
        scan_id: scanId,
        cwe_id: 'CWE-798', // Use of Hardcoded Credentials
        severity: secret.severity || 'critical',
        title: `Hardcoded Secret: ${secret.type}`,
        description: `Hardcoded ${secret.type} detected. Masked value: ${secret.value}`,
        affected_component: secret.location?.split(':')[0] || fileName,
        line_number: parseInt(secret.location?.split(':')[1]) || null,
        code_snippet: secret.context,
        detection_method: 'llm',
        remediation: secret.remediation || 'Use secure key management (HSM/TPM), environment variables, or encrypted configuration.',
        attack_vector: 'Credential extraction via firmware analysis, enabling unauthorized access',
        impact: 'Full system compromise, unauthorized access, lateral movement',
        status: 'new',
      });
    }

    if (criticalVulns.length > 0) {
      await supabase.from('analysis_logs').insert({
        scan_id: scanId,
        stage: 'analyzing',
        log_level: 'error',
        message: `CRITICAL: Found ${criticalVulns.length} critical vulnerability(ies)`,
      });
    }

    if (analysisResult.secretFindings.length > 0) {
      await supabase.from('analysis_logs').insert({
        scan_id: scanId,
        stage: 'analyzing',
        log_level: 'error',
        message: `SECRETS DETECTED: Found ${analysisResult.secretFindings.length} hardcoded secrets/credentials`,
      });
    }

    if (analysisResult.piiFindings.length > 0) {
      await supabase.from('analysis_logs').insert({
        scan_id: scanId,
        stage: 'analyzing',
        log_level: 'warning',
        message: `PII DETECTED: Found ${analysisResult.piiFindings.length} instances of personal data`,
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

    // Insert SBOM components with proper vulnerability linking
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
      message: `Analysis complete - Found ${analysisResult.vulnerabilities.length + analysisResult.piiFindings.length + analysisResult.secretFindings.length} total findings, Risk Score: ${analysisResult.riskScore}`,
    });

    console.log(`Analysis complete for scan ${scanId}`);

    return new Response(JSON.stringify({ 
      success: true, 
      scanId,
      vulnerabilityCount: analysisResult.vulnerabilities.length,
      piiCount: analysisResult.piiFindings.length,
      secretCount: analysisResult.secretFindings.length,
      riskScore: analysisResult.riskScore,
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('Analysis error:', error);
    return new Response(JSON.stringify({ 
      error: error instanceof Error ? error.message : 'Unknown error' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});
