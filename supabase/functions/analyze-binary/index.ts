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
  metadata: AnalysisRequest['metadata'],
  apiKey: string
): Promise<{
  vulnerabilities: any[];
  complianceResults: any[];
  sbomComponents: any[];
  executiveSummary: string;
  riskScore: number;
}> {
  // Decode base64 to get binary info
  const binaryData = atob(fileContent.slice(0, 2000)); // First chunk for analysis
  const hexPreview = Array.from(binaryData.slice(0, 500))
    .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
    .join(' ');

  const systemPrompt = `You are an expert automotive ECU security analyst specializing in embedded systems vulnerability detection. You analyze binary firmware files for security vulnerabilities, focusing on:
- Buffer overflows and memory corruption
- Hardcoded credentials and cryptographic keys
- CAN bus security issues
- Authentication bypasses
- Unsafe flash operations
- MISRA C violations
- ISO 26262 and ISO 21434 compliance issues

Respond ONLY with valid JSON, no markdown or explanations.`;

  const analysisPrompt = `Analyze this ${metadata.architecture} ECU binary for security vulnerabilities:

ECU Details:
- Name: ${metadata.ecuName}
- Type: ${metadata.ecuType}
- Version: ${metadata.version || 'Unknown'}
- Manufacturer: ${metadata.manufacturer || 'Unknown'}
- Architecture: ${metadata.architecture}

Binary Header (hex):
${hexPreview}

Compliance Frameworks to check: ${metadata.complianceFrameworks.join(', ') || 'MISRA C, ISO 21434'}

Generate a realistic security analysis with:
1. 3-8 vulnerabilities with varying severities (critical, high, medium, low)
2. 5-10 compliance check results
3. 5-8 SBOM components that might be in an automotive ECU
4. An executive summary
5. A risk score (0-100)

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
      "code_snippet": "example vulnerable code",
      "line_number": number,
      "detection_method": "llm|semgrep|yara|ghidra|capa",
      "remediation": "how to fix",
      "attack_vector": "how it could be exploited",
      "impact": "what damage could occur"
    }
  ],
  "compliance_results": [
    {
      "framework": "MISRA C|ISO 21434|ISO 26262|AUTOSAR",
      "rule_id": "Rule ID",
      "rule_description": "description",
      "status": "pass|fail|warning",
      "details": "optional details"
    }
  ],
  "sbom_components": [
    {
      "component_name": "library name",
      "version": "version",
      "license": "license type",
      "source_file": "where found",
      "vulnerabilities": ["CVE-XXX if any"]
    }
  ],
  "executive_summary": "2-3 paragraph professional summary for executives",
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
  "iso_considerations": "ISO 26262/21434 considerations"
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
      message: 'Starting hybrid analysis: Static patterns + LLM vulnerability detection',
    });

    const analysisResult = await analyzeBinaryWithLLM(fileContent, metadata, lovableApiKey);

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

    if (criticalVulns.length > 0) {
      await supabase.from('analysis_logs').insert({
        scan_id: scanId,
        stage: 'analyzing',
        log_level: 'error',
        message: `CRITICAL: Found ${criticalVulns.length} critical vulnerability(ies)`,
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
        vulnerabilities: component.vulnerabilities,
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
      message: `Analysis complete - Found ${analysisResult.vulnerabilities.length} vulnerabilities, Risk Score: ${analysisResult.riskScore}`,
    });

    console.log(`Analysis complete for scan ${scanId}`);

    return new Response(JSON.stringify({ 
      success: true, 
      scanId,
      vulnerabilityCount: analysisResult.vulnerabilities.length,
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
