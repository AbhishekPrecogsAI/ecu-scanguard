import { supabase } from '@/integrations/supabase/client';
import type { TablesInsert } from '@/integrations/supabase/types';

// Mock vulnerability data for development
const mockVulnerabilities = [
    {
        title: 'Buffer Overflow in CAN Message Handler',
        description: 'A stack-based buffer overflow vulnerability was detected in the CAN message processing routine. An attacker could send a specially crafted CAN message to trigger arbitrary code execution.',
        severity: 'critical' as const,
        cwe_id: 'CWE-119',
        cvss_score: 9.8,
        affected_component: 'can_handler.c',
        line_number: 142,
        remediation: 'Use bounded string functions and validate message length before processing.',
    },
    {
        title: 'Hardcoded API Key Detected',
        description: 'A hardcoded API key was found in the source code. This could allow attackers to access external services.',
        severity: 'high' as const,
        cwe_id: 'CWE-798',
        cvss_score: 7.5,
        affected_component: 'config.h',
        line_number: 23,
        remediation: 'Move API keys to secure environment variables or encrypted configuration.',
    },
    {
        title: 'Integer Overflow in Sensor Data Processing',
        description: 'An integer overflow vulnerability was found when processing sensor data that could lead to incorrect calculations.',
        severity: 'medium' as const,
        cwe_id: 'CWE-190',
        cvss_score: 5.3,
        affected_component: 'sensor_proc.c',
        line_number: 87,
        remediation: 'Add bounds checking before arithmetic operations.',
    },
    {
        title: 'Debug Interface Enabled in Production',
        description: 'The JTAG debug interface appears to be enabled, which could allow physical access attacks.',
        severity: 'high' as const,
        cwe_id: 'CWE-489',
        cvss_score: 6.8,
        affected_component: 'boot_config.bin',
        line_number: null,
        remediation: 'Disable debug interfaces in production firmware builds.',
    },
    {
        title: 'Weak Random Number Generator',
        description: 'The pseudo-random number generator used for cryptographic operations is not cryptographically secure.',
        severity: 'medium' as const,
        cwe_id: 'CWE-338',
        cvss_score: 5.9,
        affected_component: 'crypto_utils.c',
        line_number: 56,
        remediation: 'Replace with a CSPRNG like /dev/urandom or hardware RNG.',
    },
];

const mockComplianceResults = [
    {
        framework: 'ISO 21434',
        rule_id: 'CAL-1',
        rule_description: 'Risk Assessment - Cybersecurity Engineering',
        status: 'pass' as const,
        details: 'Threat analysis documentation found and valid.',
    },
    {
        framework: 'MISRA C',
        rule_id: 'Rule-11.5',
        rule_description: 'No cast from pointer to void to pointer to object',
        status: 'fail' as const,
        details: 'Found 3 violations in sensor_proc.c',
    },
    {
        framework: 'ISO 21434',
        rule_id: 'SEC-2',
        rule_description: 'Secure Coding Standards',
        status: 'warning' as const,
        details: 'Some coding standards violations detected.',
    },
];

const mockSbomComponents = [
    { component_name: 'FreeRTOS', version: '10.5.1', license: 'MIT' },
    { component_name: 'lwIP', version: '2.1.3', license: 'BSD-3-Clause' },
    { component_name: 'mbed TLS', version: '3.4.0', license: 'Apache-2.0' },
    { component_name: 'CAN driver', version: '2.0.0', license: 'Proprietary' },
    { component_name: 'STM32 HAL', version: '1.8.0', license: 'BSD-3-Clause' },
];

async function addLogEntry(scanId: string, stage: string, message: string) {
    await supabase.from('analysis_logs').insert({
        scan_id: scanId,
        stage,
        message,
    });
}

export async function runMockAnalysis(
    scanId: string,
    fileName: string,
    metadata: {
        ecuName: string;
        ecuType: string;
        deepAnalysis: boolean;
        complianceFrameworks: string[];
    }
): Promise<void> {
    try {
        // Update status to analyzing
        await supabase
            .from('scans')
            .update({ status: 'analyzing', started_at: new Date().toISOString() })
            .eq('id', scanId);

        await addLogEntry(scanId, 'initialization', `Starting analysis of ${fileName}...`);

        // Stage 1: File parsing (simulated delay)
        await new Promise(resolve => setTimeout(resolve, 1500));
        await addLogEntry(scanId, 'parsing', 'Binary file parsed successfully. Detected ARM Cortex-M4 architecture.');

        // Stage 2: SAST Analysis
        await new Promise(resolve => setTimeout(resolve, 2000));
        await addLogEntry(scanId, 'sast', 'Static analysis complete. Found potential vulnerabilities.');

        // Stage 3: Insert vulnerabilities
        const vulnsToInsert = mockVulnerabilities.slice(0, Math.floor(Math.random() * 3) + 2).map(v => ({
            scan_id: scanId,
            ...v,
        }));

        await supabase.from('vulnerabilities').insert(vulnsToInsert);
        await addLogEntry(scanId, 'vulnerabilities', `Identified ${vulnsToInsert.length} security findings.`);

        // Stage 4: Compliance checking
        if (metadata.complianceFrameworks.length > 0) {
            await new Promise(resolve => setTimeout(resolve, 1500));

            const complianceToInsert = mockComplianceResults
                .filter(c => metadata.complianceFrameworks.some(f => c.framework.includes(f.split(' ')[0])))
                .map(c => ({
                    scan_id: scanId,
                    ...c,
                }));

            if (complianceToInsert.length > 0) {
                await supabase.from('compliance_results').insert(complianceToInsert);
            }
            await addLogEntry(scanId, 'compliance', `Compliance check complete for ${metadata.complianceFrameworks.join(', ')}.`);
        }

        // Stage 5: SBOM generation
        await new Promise(resolve => setTimeout(resolve, 1000));
        const sbomToInsert = mockSbomComponents.map(c => ({
            scan_id: scanId,
            ...c,
        }));
        await supabase.from('sbom_components').insert(sbomToInsert);
        await addLogEntry(scanId, 'sbom', `SBOM generated with ${sbomToInsert.length} components.`);

        // Calculate risk score
        const criticalCount = vulnsToInsert.filter(v => v.severity === 'critical').length;
        const highCount = vulnsToInsert.filter(v => v.severity === 'high').length;
        const riskScore = Math.min(100, criticalCount * 25 + highCount * 15 + 20);

        // Complete the scan
        await supabase
            .from('scans')
            .update({
                status: 'complete',
                completed_at: new Date().toISOString(),
                risk_score: riskScore,
            })
            .eq('id', scanId);

        await addLogEntry(scanId, 'complete', `Analysis complete. Risk score: ${riskScore}/100`);

    } catch (error) {
        console.error('Mock analysis error:', error);

        await supabase
            .from('scans')
            .update({ status: 'failed' })
            .eq('id', scanId);

        await addLogEntry(scanId, 'error', `Analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
}

export async function runMockRepositoryAnalysis(
    scanId: string,
    gitUrl: string,
    gitBranch: string,
    gitProvider: 'github' | 'gitlab',
    metadata: {
        ecuName: string;
        ecuType: string;
        deepAnalysis: boolean;
        complianceFrameworks: string[];
    }
): Promise<void> {
    try {
        // Update status to analyzing
        await supabase
            .from('scans')
            .update({ status: 'analyzing', started_at: new Date().toISOString() })
            .eq('id', scanId);

        await addLogEntry(scanId, 'initialization', `Cloning ${gitProvider} repository...`);

        // Stage 1: Clone repository (simulated)
        await new Promise(resolve => setTimeout(resolve, 2000));

        // Extract repo name from URL
        const repoMatch = gitUrl.match(/github\.com\/([^\/]+\/[^\/]+)|gitlab\.com\/([^\/]+\/[^\/]+)/);
        const repoName = repoMatch ? (repoMatch[1] || repoMatch[2]).replace('.git', '') : 'unknown';

        await addLogEntry(scanId, 'cloning', `Repository ${repoName} (${gitBranch}) cloned successfully.`);

        // Stage 2: File discovery
        await new Promise(resolve => setTimeout(resolve, 1500));
        await addLogEntry(scanId, 'discovery', 'Found 47 source files for analysis (C, C++, Python).');

        // Stage 3: SAST Analysis
        await new Promise(resolve => setTimeout(resolve, 2500));
        await addLogEntry(scanId, 'sast', 'Static analysis of source code complete.');

        // Stage 4: Secret detection
        await new Promise(resolve => setTimeout(resolve, 1000));
        await addLogEntry(scanId, 'secrets', 'Secret detection scan complete.');

        // Insert vulnerabilities
        const repoVulns = [
            {
                scan_id: scanId,
                title: 'Potential Command Injection',
                description: 'User input is passed to system() without sanitization.',
                severity: 'critical' as const,
                cwe_id: 'CWE-78',
                cvss_score: 9.1,
                affected_component: 'src/controls.c',
                line_number: 234,
                remediation: 'Sanitize all user inputs before passing to system commands.',
            },
            {
                scan_id: scanId,
                title: 'Insecure CAN Message Handling',
                description: 'CAN messages are processed without authentication or validation.',
                severity: 'high' as const,
                cwe_id: 'CWE-306',
                cvss_score: 7.8,
                affected_component: 'src/can_interface.c',
                line_number: 89,
                remediation: 'Implement message authentication codes (MAC) for CAN messages.',
            },
            {
                scan_id: scanId,
                title: 'Memory Leak in Socket Handler',
                description: 'Socket connections are not properly closed, leading to resource exhaustion.',
                severity: 'medium' as const,
                cwe_id: 'CWE-401',
                cvss_score: 5.3,
                affected_component: 'src/icsim.c',
                line_number: 156,
                remediation: 'Ensure all allocated resources are freed on connection close.',
            },
        ];

        await supabase.from('vulnerabilities').insert(repoVulns);
        await addLogEntry(scanId, 'vulnerabilities', `Identified ${repoVulns.length} security findings.`);

        // Stage 5: SBOM
        await new Promise(resolve => setTimeout(resolve, 1000));
        const sbom = [
            { scan_id: scanId, component_name: 'SDL2', version: '2.0.20', license: 'Zlib' },
            { scan_id: scanId, component_name: 'can-utils', version: '2021.08.0', license: 'GPL-2.0' },
            { scan_id: scanId, component_name: 'vcan', version: 'kernel', license: 'GPL-2.0' },
        ];
        await supabase.from('sbom_components').insert(sbom);
        await addLogEntry(scanId, 'sbom', 'SBOM generated from source dependencies.');

        // Calculate risk score
        const riskScore = 65;

        // Complete
        await supabase
            .from('scans')
            .update({
                status: 'complete',
                completed_at: new Date().toISOString(),
                risk_score: riskScore,
            })
            .eq('id', scanId);

        await addLogEntry(scanId, 'complete', `Repository analysis complete. Risk score: ${riskScore}/100`);

    } catch (error) {
        console.error('Mock repository analysis error:', error);

        await supabase
            .from('scans')
            .update({ status: 'failed' })
            .eq('id', scanId);

        await addLogEntry(scanId, 'error', `Repository analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
}
