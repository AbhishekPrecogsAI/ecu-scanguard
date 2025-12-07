import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

interface ExportRequest {
  scanId: string;
  format: 'cyclonedx' | 'spdx' | 'swid';
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseKey);

    const { scanId, format } = await req.json() as ExportRequest;

    // Fetch scan and SBOM data
    const { data: scan } = await supabase
      .from('scans')
      .select('*')
      .eq('id', scanId)
      .single();

    const { data: components } = await supabase
      .from('sbom_components')
      .select('*')
      .eq('scan_id', scanId);

    if (!scan || !components) {
      return new Response(JSON.stringify({ error: 'Scan or components not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    let exportData: string;
    let contentType: string;
    let filename: string;

    switch (format) {
      case 'cyclonedx':
        exportData = generateCycloneDX(scan, components);
        contentType = 'application/json';
        filename = `${scan.ecu_name}-sbom-cyclonedx.json`;
        break;
      
      case 'spdx':
        exportData = generateSPDX(scan, components);
        contentType = 'application/json';
        filename = `${scan.ecu_name}-sbom-spdx.json`;
        break;
      
      case 'swid':
        exportData = generateSWID(scan, components);
        contentType = 'application/xml';
        filename = `${scan.ecu_name}-sbom-swid.xml`;
        break;
      
      default:
        return new Response(JSON.stringify({ error: 'Invalid format. Use: cyclonedx, spdx, or swid' }), {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
    }

    return new Response(JSON.stringify({ 
      data: exportData, 
      filename,
      contentType 
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('SBOM export error:', error);
    return new Response(JSON.stringify({ 
      error: error instanceof Error ? error.message : 'Unknown error' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});

function generateCycloneDX(scan: any, components: any[]): string {
  const cyclonedx = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${scan.id}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{
        vendor: "ECU Security Scanner",
        name: "Automotive Firmware Analyzer",
        version: "1.0.0"
      }],
      component: {
        type: "firmware",
        name: scan.ecu_name,
        version: scan.version || "unknown",
        description: `${scan.ecu_type} ECU from ${scan.manufacturer || 'Unknown'}`,
        properties: [
          { name: "architecture", value: scan.architecture },
          { name: "manufacturer", value: scan.manufacturer || "Unknown" }
        ]
      }
    },
    components: components.map((comp, index) => ({
      type: "library",
      "bom-ref": `component-${index}`,
      name: comp.component_name,
      version: comp.version || "unknown",
      licenses: comp.license ? [{ license: { id: comp.license } }] : [],
      purl: `pkg:generic/${comp.component_name}@${comp.version || 'unknown'}`,
      properties: [
        { name: "source_file", value: comp.source_file || "unknown" }
      ]
    })),
    vulnerabilities: components.flatMap((comp, compIndex) => {
      const vulns = comp.vulnerabilities as string[] || [];
      return vulns.map((cve, vulnIndex) => ({
        id: cve,
        source: { name: "NVD", url: `https://nvd.nist.gov/vuln/detail/${cve}` },
        affects: [{ ref: `component-${compIndex}` }]
      }));
    })
  };

  return JSON.stringify(cyclonedx, null, 2);
}

function generateSPDX(scan: any, components: any[]): string {
  const spdx = {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: `SBOM for ${scan.ecu_name}`,
    documentNamespace: `https://spdx.org/spdxdocs/${scan.id}`,
    creationInfo: {
      created: new Date().toISOString(),
      creators: ["Tool: ECU Security Scanner-1.0.0"],
      licenseListVersion: "3.19"
    },
    packages: [
      {
        SPDXID: "SPDXRef-RootPackage",
        name: scan.ecu_name,
        versionInfo: scan.version || "unknown",
        packageFileName: scan.file_name,
        downloadLocation: "NOASSERTION",
        filesAnalyzed: false,
        supplier: scan.manufacturer ? `Organization: ${scan.manufacturer}` : "NOASSERTION",
        primaryPackagePurpose: "FIRMWARE"
      },
      ...components.map((comp, index) => ({
        SPDXID: `SPDXRef-Package-${index}`,
        name: comp.component_name,
        versionInfo: comp.version || "NOASSERTION",
        downloadLocation: "NOASSERTION",
        filesAnalyzed: false,
        licenseConcluded: comp.license || "NOASSERTION",
        licenseDeclared: comp.license || "NOASSERTION",
        copyrightText: "NOASSERTION",
        externalRefs: (comp.vulnerabilities as string[] || []).map(cve => ({
          referenceCategory: "SECURITY",
          referenceType: "cpe23Type",
          referenceLocator: cve
        }))
      }))
    ],
    relationships: components.map((_, index) => ({
      spdxElementId: "SPDXRef-RootPackage",
      relationshipType: "CONTAINS",
      relatedSpdxElement: `SPDXRef-Package-${index}`
    }))
  };

  return JSON.stringify(spdx, null, 2);
}

function generateSWID(scan: any, components: any[]): string {
  const entities = components.map(comp => 
    `    <Entity name="${escapeXml(comp.component_name)}" role="softwareCreator" />`
  ).join('\n');

  const payloads = components.map((comp, index) => `
    <Payload>
      <File name="${escapeXml(comp.source_file || comp.component_name)}" 
            version="${escapeXml(comp.version || 'unknown')}"
            size="0" />
    </Payload>`
  ).join('');

  const swid = `<?xml version="1.0" encoding="UTF-8"?>
<SoftwareIdentity
    xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd"
    name="${escapeXml(scan.ecu_name)}"
    tagId="${scan.id}"
    version="${escapeXml(scan.version || '1.0.0')}"
    versionScheme="semver">
  
  <Entity name="${escapeXml(scan.manufacturer || 'Unknown')}" role="tagCreator" />
  <Entity name="ECU Security Scanner" role="tagCreator" />
  
  <Meta 
    product="${escapeXml(scan.ecu_name)}"
    colloquialVersion="${escapeXml(scan.version || 'unknown')}"
    revision="${scan.architecture || 'unknown'}"
    edition="${escapeXml(scan.ecu_type)}" />

  <Payload>
    <Directory name="components">
${components.map((comp, i) => `      <File name="${escapeXml(comp.component_name)}" version="${escapeXml(comp.version || 'unknown')}" />`).join('\n')}
    </Directory>
  </Payload>

</SoftwareIdentity>`;

  return swid;
}

function escapeXml(str: string): string {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}
