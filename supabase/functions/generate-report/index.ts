import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { scanId, format = 'json' } = await req.json();

    if (!scanId) {
      return new Response(JSON.stringify({ error: 'Scan ID required' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseKey);

    // Fetch all scan data
    const { data: scan, error: scanError } = await supabase
      .from('scans')
      .select('*')
      .eq('id', scanId)
      .single();

    if (scanError || !scan) {
      return new Response(JSON.stringify({ error: 'Scan not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const { data: vulnerabilities } = await supabase
      .from('vulnerabilities')
      .select('*')
      .eq('scan_id', scanId)
      .order('severity', { ascending: true });

    const { data: complianceResults } = await supabase
      .from('compliance_results')
      .select('*')
      .eq('scan_id', scanId);

    const { data: sbomComponents } = await supabase
      .from('sbom_components')
      .select('*')
      .eq('scan_id', scanId);

    const { data: analysisLogs } = await supabase
      .from('analysis_logs')
      .select('*')
      .eq('scan_id', scanId)
      .order('created_at', { ascending: true });

    // Calculate summary stats
    const vulnStats = {
      critical: vulnerabilities?.filter(v => v.severity === 'critical').length || 0,
      high: vulnerabilities?.filter(v => v.severity === 'high').length || 0,
      medium: vulnerabilities?.filter(v => v.severity === 'medium').length || 0,
      low: vulnerabilities?.filter(v => v.severity === 'low').length || 0,
      info: vulnerabilities?.filter(v => v.severity === 'info').length || 0,
    };

    const complianceStats = {
      pass: complianceResults?.filter(c => c.status === 'pass').length || 0,
      fail: complianceResults?.filter(c => c.status === 'fail').length || 0,
      warning: complianceResults?.filter(c => c.status === 'warning').length || 0,
    };

    const report = {
      generated_at: new Date().toISOString(),
      scan: {
        id: scan.id,
        ecu_name: scan.ecu_name,
        ecu_type: scan.ecu_type,
        version: scan.version,
        manufacturer: scan.manufacturer,
        architecture: scan.architecture,
        file_name: scan.file_name,
        file_hash: scan.file_hash,
        file_size: scan.file_size,
        status: scan.status,
        created_at: scan.created_at,
        completed_at: scan.completed_at,
        risk_score: scan.risk_score,
        executive_summary: scan.executive_summary,
      },
      summary: {
        total_vulnerabilities: (vulnerabilities?.length || 0),
        vulnerability_breakdown: vulnStats,
        compliance_breakdown: complianceStats,
        compliance_score: complianceStats.pass + complianceStats.fail + complianceStats.warning > 0
          ? Math.round((complianceStats.pass / (complianceStats.pass + complianceStats.fail + complianceStats.warning)) * 100)
          : 0,
        sbom_components_count: sbomComponents?.length || 0,
      },
      vulnerabilities: vulnerabilities?.map(v => ({
        id: v.id,
        cve_id: v.cve_id,
        cwe_id: v.cwe_id,
        severity: v.severity,
        cvss_score: v.cvss_score,
        title: v.title,
        description: v.description,
        affected_component: v.affected_component,
        affected_function: v.affected_function,
        code_snippet: v.code_snippet,
        line_number: v.line_number,
        detection_method: v.detection_method,
        status: v.status,
        remediation: v.remediation,
        attack_vector: v.attack_vector,
        impact: v.impact,
      })),
      compliance_results: complianceResults?.map(c => ({
        framework: c.framework,
        rule_id: c.rule_id,
        rule_description: c.rule_description,
        status: c.status,
        details: c.details,
      })),
      sbom: sbomComponents?.map(s => ({
        component_name: s.component_name,
        version: s.version,
        license: s.license,
        source_file: s.source_file,
        vulnerabilities: s.vulnerabilities,
      })),
      analysis_timeline: analysisLogs?.map(l => ({
        stage: l.stage,
        level: l.log_level,
        message: l.message,
        timestamp: l.created_at,
      })),
    };

    if (format === 'json') {
      return new Response(JSON.stringify(report, null, 2), {
        headers: { 
          ...corsHeaders, 
          'Content-Type': 'application/json',
          'Content-Disposition': `attachment; filename="scan-report-${scanId}.json"`,
        },
      });
    }

    // Generate text/markdown format for PDF conversion
    const textReport = `
# ECU Vulnerability Scan Report

Generated: ${new Date().toLocaleString()}

## Scan Information

- **ECU Name:** ${scan.ecu_name}
- **ECU Type:** ${scan.ecu_type}
- **Version:** ${scan.version || 'N/A'}
- **Manufacturer:** ${scan.manufacturer || 'N/A'}
- **Architecture:** ${scan.architecture}
- **File:** ${scan.file_name}
- **Risk Score:** ${scan.risk_score || 'N/A'}/100

## Executive Summary

${scan.executive_summary || 'No executive summary available.'}

## Vulnerability Summary

| Severity | Count |
|----------|-------|
| Critical | ${vulnStats.critical} |
| High | ${vulnStats.high} |
| Medium | ${vulnStats.medium} |
| Low | ${vulnStats.low} |
| Info | ${vulnStats.info} |
| **Total** | **${vulnerabilities?.length || 0}** |

## Compliance Summary

| Status | Count |
|--------|-------|
| Pass | ${complianceStats.pass} |
| Fail | ${complianceStats.fail} |
| Warning | ${complianceStats.warning} |
| **Score** | **${report.summary.compliance_score}%** |

## Detailed Vulnerabilities

${vulnerabilities?.map((v, i) => `
### ${i + 1}. ${v.title}

- **Severity:** ${v.severity.toUpperCase()}
- **CVE:** ${v.cve_id || 'N/A'}
- **CWE:** ${v.cwe_id || 'N/A'}
- **CVSS Score:** ${v.cvss_score || 'N/A'}
- **Component:** ${v.affected_component || 'N/A'}
- **Function:** ${v.affected_function || 'N/A'}
- **Detection Method:** ${v.detection_method || 'N/A'}

**Description:**
${v.description || 'No description available.'}

**Remediation:**
${v.remediation || 'No remediation guidance available.'}

${v.code_snippet ? `**Code Snippet:**\n\`\`\`c\n${v.code_snippet}\n\`\`\`` : ''}
`).join('\n') || 'No vulnerabilities found.'}

## SBOM (Software Bill of Materials)

| Component | Version | License |
|-----------|---------|---------|
${sbomComponents?.map(s => `| ${s.component_name} | ${s.version || 'N/A'} | ${s.license || 'N/A'} |`).join('\n') || '| No components detected | | |'}

---
*Report generated by JLR ECU Vulnerability Scanner*
`;

    return new Response(textReport, {
      headers: { 
        ...corsHeaders, 
        'Content-Type': 'text/markdown',
        'Content-Disposition': `attachment; filename="scan-report-${scanId}.md"`,
      },
    });

  } catch (error) {
    console.error('Generate report error:', error);
    return new Response(JSON.stringify({ 
      error: error instanceof Error ? error.message : 'Unknown error' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});
