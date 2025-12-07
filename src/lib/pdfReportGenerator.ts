import { jsPDF } from 'jspdf';

export interface ReportBranding {
  companyName: string;
  logoDataUrl?: string;
  primaryColor: string;
  secondaryColor: string;
  footerText: string;
}

export interface ReportData {
  scan: {
    id: string;
    ecu_name: string;
    ecu_type: string;
    version?: string;
    manufacturer?: string;
    architecture?: string;
    file_name: string;
    file_hash?: string;
    risk_score?: number;
    executive_summary?: string;
    created_at?: string;
    completed_at?: string;
  };
  vulnerabilities: Array<{
    title: string;
    severity: string;
    cve_id?: string;
    cwe_id?: string;
    cvss_score?: number;
    description?: string;
    affected_component?: string;
    remediation?: string;
  }>;
  complianceResults: Array<{
    framework: string;
    rule_id: string;
    status: string;
    rule_description?: string;
  }>;
  sbomComponents: Array<{
    component_name: string;
    version?: string;
    license?: string;
  }>;
  options: {
    includeExecutiveSummary: boolean;
    includeTechnicalDetails: boolean;
    includeRemediation: boolean;
    includeSBOM: boolean;
    frameworks: string[];
  };
}

const defaultBranding: ReportBranding = {
  companyName: 'ECU Security Scanner',
  primaryColor: '#3b82f6',
  secondaryColor: '#1e40af',
  footerText: 'Confidential - For Internal Use Only',
};

function hexToRgb(hex: string): [number, number, number] {
  const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  return result
    ? [parseInt(result[1], 16), parseInt(result[2], 16), parseInt(result[3], 16)]
    : [59, 130, 246];
}

export function generatePDFReport(
  data: ReportData,
  branding: Partial<ReportBranding> = {}
): jsPDF {
  const brand = { ...defaultBranding, ...branding };
  const doc = new jsPDF();
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 20;
  let yPos = margin;

  const primaryRgb = hexToRgb(brand.primaryColor);
  const secondaryRgb = hexToRgb(brand.secondaryColor);

  // Helper functions
  const addHeader = () => {
    doc.setFillColor(...primaryRgb);
    doc.rect(0, 0, pageWidth, 35, 'F');
    
    if (brand.logoDataUrl) {
      try {
        doc.addImage(brand.logoDataUrl, 'PNG', margin, 8, 20, 20);
      } catch (e) {
        console.error('Failed to add logo:', e);
      }
    }
    
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(18);
    doc.setFont('helvetica', 'bold');
    doc.text(brand.companyName, brand.logoDataUrl ? margin + 25 : margin, 20);
    
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    doc.text('ECU Vulnerability Assessment Report', brand.logoDataUrl ? margin + 25 : margin, 28);
    
    doc.setTextColor(0, 0, 0);
    yPos = 45;
  };

  const addFooter = (pageNum: number, totalPages: number) => {
    doc.setFillColor(245, 245, 245);
    doc.rect(0, pageHeight - 15, pageWidth, 15, 'F');
    
    doc.setFontSize(8);
    doc.setTextColor(100, 100, 100);
    doc.text(brand.footerText, margin, pageHeight - 6);
    doc.text(`Page ${pageNum} of ${totalPages}`, pageWidth - margin - 20, pageHeight - 6);
    doc.text(new Date().toLocaleDateString(), pageWidth / 2 - 10, pageHeight - 6);
  };

  const checkNewPage = (requiredSpace: number = 30) => {
    if (yPos + requiredSpace > pageHeight - 25) {
      doc.addPage();
      addHeader();
      return true;
    }
    return false;
  };

  const addSectionTitle = (title: string) => {
    checkNewPage(25);
    doc.setFillColor(...secondaryRgb);
    doc.rect(margin - 5, yPos - 5, pageWidth - 2 * margin + 10, 10, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.text(title, margin, yPos + 2);
    doc.setTextColor(0, 0, 0);
    yPos += 15;
  };

  const addKeyValue = (key: string, value: string, indent: number = 0) => {
    checkNewPage();
    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    doc.text(`${key}:`, margin + indent, yPos);
    doc.setFont('helvetica', 'normal');
    const keyWidth = doc.getTextWidth(`${key}: `);
    doc.text(value || 'N/A', margin + indent + keyWidth, yPos);
    yPos += 6;
  };

  const addParagraph = (text: string, maxWidth: number = pageWidth - 2 * margin) => {
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    const lines = doc.splitTextToSize(text, maxWidth);
    lines.forEach((line: string) => {
      checkNewPage();
      doc.text(line, margin, yPos);
      yPos += 5;
    });
    yPos += 3;
  };

  // Start generating report
  addHeader();

  // Title Section
  doc.setFontSize(22);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(...primaryRgb);
  doc.text('Security Assessment Report', margin, yPos);
  yPos += 10;

  doc.setFontSize(14);
  doc.setTextColor(100, 100, 100);
  doc.text(data.scan.ecu_name, margin, yPos);
  yPos += 15;

  // Scan Information
  addSectionTitle('Scan Information');
  addKeyValue('ECU Name', data.scan.ecu_name);
  addKeyValue('ECU Type', data.scan.ecu_type);
  addKeyValue('Version', data.scan.version || 'N/A');
  addKeyValue('Manufacturer', data.scan.manufacturer || 'N/A');
  addKeyValue('Architecture', data.scan.architecture || 'N/A');
  addKeyValue('File Name', data.scan.file_name);
  addKeyValue('File Hash', data.scan.file_hash?.substring(0, 32) + '...' || 'N/A');
  addKeyValue('Scan Date', data.scan.completed_at ? new Date(data.scan.completed_at).toLocaleString() : 'N/A');
  yPos += 5;

  // Risk Score
  if (data.scan.risk_score !== undefined) {
    checkNewPage(30);
    doc.setFillColor(245, 245, 245);
    doc.roundedRect(margin, yPos, pageWidth - 2 * margin, 25, 3, 3, 'F');
    
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.text('Risk Score', margin + 10, yPos + 10);
    
    const score = data.scan.risk_score;
    const scoreColor: [number, number, number] = score >= 70 ? [239, 68, 68] : score >= 40 ? [245, 158, 11] : [34, 197, 94];
    doc.setTextColor(...scoreColor);
    doc.setFontSize(24);
    doc.text(`${score}/100`, margin + 10, yPos + 22);
    
    // Risk bar
    doc.setFillColor(229, 231, 235);
    doc.roundedRect(margin + 60, yPos + 12, 100, 8, 2, 2, 'F');
    doc.setFillColor(...scoreColor);
    doc.roundedRect(margin + 60, yPos + 12, score, 8, 2, 2, 'F');
    
    doc.setTextColor(0, 0, 0);
    yPos += 35;
  }

  // Executive Summary
  if (data.options.includeExecutiveSummary && data.scan.executive_summary) {
    addSectionTitle('Executive Summary');
    addParagraph(data.scan.executive_summary);
    yPos += 5;
  }

  // Vulnerability Summary
  const vulnStats = {
    critical: data.vulnerabilities.filter(v => v.severity === 'critical').length,
    high: data.vulnerabilities.filter(v => v.severity === 'high').length,
    medium: data.vulnerabilities.filter(v => v.severity === 'medium').length,
    low: data.vulnerabilities.filter(v => v.severity === 'low').length,
    info: data.vulnerabilities.filter(v => v.severity === 'info').length,
  };

  addSectionTitle('Vulnerability Summary');
  
  checkNewPage(40);
  const severities = [
    { name: 'Critical', count: vulnStats.critical, color: [239, 68, 68] as [number, number, number] },
    { name: 'High', count: vulnStats.high, color: [249, 115, 22] as [number, number, number] },
    { name: 'Medium', count: vulnStats.medium, color: [245, 158, 11] as [number, number, number] },
    { name: 'Low', count: vulnStats.low, color: [34, 197, 94] as [number, number, number] },
    { name: 'Info', count: vulnStats.info, color: [59, 130, 246] as [number, number, number] },
  ];

  let xOffset = margin;
  severities.forEach(sev => {
    doc.setFillColor(...sev.color);
    doc.roundedRect(xOffset, yPos, 30, 25, 2, 2, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.text(String(sev.count), xOffset + 12, yPos + 12);
    doc.setFontSize(8);
    doc.text(sev.name, xOffset + 5, yPos + 21);
    xOffset += 35;
  });
  
  doc.setTextColor(0, 0, 0);
  yPos += 35;

  // Detailed Vulnerabilities
  if (data.options.includeTechnicalDetails && data.vulnerabilities.length > 0) {
    addSectionTitle('Vulnerability Details');
    
    data.vulnerabilities.slice(0, 20).forEach((vuln, index) => {
      checkNewPage(50);
      
      const sevColors: Record<string, [number, number, number]> = {
        critical: [239, 68, 68],
        high: [249, 115, 22],
        medium: [245, 158, 11],
        low: [34, 197, 94],
        info: [59, 130, 246],
      };
      
      doc.setFillColor(...(sevColors[vuln.severity] || [100, 100, 100]));
      doc.roundedRect(margin, yPos, 4, 30, 1, 1, 'F');
      
      doc.setFontSize(11);
      doc.setFont('helvetica', 'bold');
      doc.text(`${index + 1}. ${vuln.title}`, margin + 8, yPos + 5);
      
      doc.setFontSize(9);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(100, 100, 100);
      const meta = [
        vuln.severity.toUpperCase(),
        vuln.cve_id,
        vuln.cwe_id,
        vuln.cvss_score ? `CVSS: ${vuln.cvss_score}` : null,
      ].filter(Boolean).join(' | ');
      doc.text(meta, margin + 8, yPos + 12);
      
      doc.setTextColor(0, 0, 0);
      if (vuln.description) {
        const descLines = doc.splitTextToSize(vuln.description.substring(0, 200) + '...', pageWidth - 2 * margin - 10);
        descLines.slice(0, 2).forEach((line: string, i: number) => {
          doc.text(line, margin + 8, yPos + 18 + i * 5);
        });
      }
      
      if (data.options.includeRemediation && vuln.remediation) {
        yPos += 28;
        doc.setFillColor(240, 253, 244);
        doc.roundedRect(margin + 8, yPos, pageWidth - 2 * margin - 10, 15, 2, 2, 'F');
        doc.setFontSize(8);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(22, 163, 74);
        doc.text('Remediation:', margin + 10, yPos + 5);
        doc.setFont('helvetica', 'normal');
        const remLines = doc.splitTextToSize(vuln.remediation, pageWidth - 2 * margin - 20);
        doc.text(remLines[0], margin + 10, yPos + 11);
        yPos += 20;
      } else {
        yPos += 35;
      }
      
      yPos += 5;
    });

    if (data.vulnerabilities.length > 20) {
      doc.setFontSize(10);
      doc.setTextColor(100, 100, 100);
      doc.text(`... and ${data.vulnerabilities.length - 20} more vulnerabilities`, margin, yPos);
      doc.setTextColor(0, 0, 0);
      yPos += 10;
    }
  }

  // Compliance Results
  const relevantCompliance = data.complianceResults.filter(c => 
    data.options.frameworks.length === 0 || 
    data.options.frameworks.some(f => c.framework.toLowerCase().includes(f.toLowerCase()))
  );

  if (relevantCompliance.length > 0) {
    addSectionTitle('Compliance Results');
    
    const compStats = {
      pass: relevantCompliance.filter(c => c.status === 'pass').length,
      fail: relevantCompliance.filter(c => c.status === 'fail').length,
      warning: relevantCompliance.filter(c => c.status === 'warning').length,
    };

    checkNewPage(20);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    doc.text(`Pass: ${compStats.pass} | Fail: ${compStats.fail} | Warning: ${compStats.warning}`, margin, yPos);
    yPos += 10;

    // Group by framework
    const byFramework = relevantCompliance.reduce((acc, c) => {
      if (!acc[c.framework]) acc[c.framework] = [];
      acc[c.framework].push(c);
      return acc;
    }, {} as Record<string, typeof relevantCompliance>);

    Object.entries(byFramework).slice(0, 5).forEach(([framework, results]) => {
      checkNewPage(25);
      doc.setFontSize(10);
      doc.setFont('helvetica', 'bold');
      doc.text(framework, margin, yPos);
      yPos += 6;

      results.slice(0, 5).forEach(result => {
        checkNewPage();
        const statusIcon = result.status === 'pass' ? '✓' : result.status === 'fail' ? '✗' : '!';
        const statusColor: [number, number, number] = result.status === 'pass' ? [34, 197, 94] : result.status === 'fail' ? [239, 68, 68] : [245, 158, 11];
        doc.setTextColor(...statusColor);
        doc.text(statusIcon, margin + 5, yPos);
        doc.setTextColor(0, 0, 0);
        doc.setFont('helvetica', 'normal');
        doc.text(`${result.rule_id}: ${result.rule_description?.substring(0, 60) || 'N/A'}...`, margin + 12, yPos);
        yPos += 5;
      });
      yPos += 5;
    });
  }

  // SBOM
  if (data.options.includeSBOM && data.sbomComponents.length > 0) {
    addSectionTitle('Software Bill of Materials (SBOM)');
    
    checkNewPage(30);
    
    // Table header
    doc.setFillColor(245, 245, 245);
    doc.rect(margin, yPos, pageWidth - 2 * margin, 8, 'F');
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold');
    doc.text('Component', margin + 2, yPos + 5);
    doc.text('Version', margin + 80, yPos + 5);
    doc.text('License', margin + 120, yPos + 5);
    yPos += 10;

    doc.setFont('helvetica', 'normal');
    data.sbomComponents.slice(0, 30).forEach((comp, i) => {
      checkNewPage();
      if (i % 2 === 0) {
        doc.setFillColor(250, 250, 250);
        doc.rect(margin, yPos - 4, pageWidth - 2 * margin, 6, 'F');
      }
      doc.text(comp.component_name.substring(0, 35), margin + 2, yPos);
      doc.text(comp.version || 'N/A', margin + 80, yPos);
      doc.text(comp.license || 'N/A', margin + 120, yPos);
      yPos += 6;
    });

    if (data.sbomComponents.length > 30) {
      doc.setTextColor(100, 100, 100);
      doc.text(`... and ${data.sbomComponents.length - 30} more components`, margin, yPos);
      doc.setTextColor(0, 0, 0);
      yPos += 10;
    }
  }

  // Add page numbers
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    addFooter(i, totalPages);
  }

  return doc;
}

export function downloadPDF(doc: jsPDF, filename: string) {
  doc.save(filename);
}
