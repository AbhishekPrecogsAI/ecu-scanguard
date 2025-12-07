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
    const { cveId } = await req.json();

    if (!cveId) {
      return new Response(JSON.stringify({ error: 'CVE ID required' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseKey);

    // Check cache first
    const { data: cached } = await supabase
      .from('cve_cache')
      .select('*')
      .eq('cve_id', cveId)
      .maybeSingle();

    if (cached) {
      const cacheAge = Date.now() - new Date(cached.fetched_at).getTime();
      const oneDayMs = 24 * 60 * 60 * 1000;
      
      if (cacheAge < oneDayMs) {
        console.log(`Returning cached CVE data for ${cveId}`);
        return new Response(JSON.stringify(cached), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
    }

    // Fetch from NVD API
    console.log(`Fetching CVE ${cveId} from NVD...`);
    
    const nvdResponse = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`,
      {
        headers: {
          'Accept': 'application/json',
        },
      }
    );

    if (!nvdResponse.ok) {
      console.error(`NVD API error: ${nvdResponse.status}`);
      
      // Return cached data if available, even if stale
      if (cached) {
        return new Response(JSON.stringify(cached), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      return new Response(JSON.stringify({ error: 'Failed to fetch from NVD' }), {
        status: 502,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const nvdData = await nvdResponse.json();
    const cve = nvdData.vulnerabilities?.[0]?.cve;

    if (!cve) {
      return new Response(JSON.stringify({ error: 'CVE not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Extract CVSS score
    let cvssScore = null;
    let severity = null;

    if (cve.metrics?.cvssMetricV31?.[0]) {
      cvssScore = cve.metrics.cvssMetricV31[0].cvssData.baseScore;
      severity = cve.metrics.cvssMetricV31[0].cvssData.baseSeverity;
    } else if (cve.metrics?.cvssMetricV2?.[0]) {
      cvssScore = cve.metrics.cvssMetricV2[0].cvssData.baseScore;
      severity = cve.metrics.cvssMetricV2[0].baseSeverity;
    }

    // Extract CWE IDs
    const cweIds = cve.weaknesses?.flatMap((w: any) => 
      w.description?.map((d: any) => d.value)
    ).filter(Boolean) || [];

    // Extract references
    const referenceLinks = cve.references?.map((ref: any) => ({
      url: ref.url,
      source: ref.source,
      tags: ref.tags,
    })) || [];

    const cveData = {
      cve_id: cveId,
      description: cve.descriptions?.find((d: any) => d.lang === 'en')?.value || '',
      cvss_score: cvssScore,
      severity: severity?.toLowerCase(),
      published_date: cve.published,
      modified_date: cve.lastModified,
      reference_links: referenceLinks,
      cwe_ids: cweIds,
      affected_products: cve.configurations || [],
      fetched_at: new Date().toISOString(),
    };

    // Upsert to cache
    await supabase.from('cve_cache').upsert(cveData, { onConflict: 'cve_id' });

    console.log(`Cached CVE data for ${cveId}`);

    return new Response(JSON.stringify(cveData), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('Fetch CVE error:', error);
    return new Response(JSON.stringify({ 
      error: error instanceof Error ? error.message : 'Unknown error' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});
