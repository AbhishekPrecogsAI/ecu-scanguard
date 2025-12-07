import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';
import type { Tables, TablesInsert } from '@/integrations/supabase/types';

export type Scan = Tables<'scans'>;
export type Vulnerability = Tables<'vulnerabilities'>;
export type ComplianceResult = Tables<'compliance_results'>;
export type SBOMComponent = Tables<'sbom_components'>;
export type AnalysisLog = Tables<'analysis_logs'>;

export function useScans() {
  return useQuery({
    queryKey: ['scans'],
    queryFn: async () => {
      const { data, error } = await supabase
        .from('scans')
        .select('*')
        .order('created_at', { ascending: false });
      
      if (error) throw error;
      return data as Scan[];
    },
  });
}

export function useScan(scanId: string | undefined) {
  return useQuery({
    queryKey: ['scan', scanId],
    queryFn: async () => {
      if (!scanId) return null;
      
      const { data, error } = await supabase
        .from('scans')
        .select('*')
        .eq('id', scanId)
        .maybeSingle();
      
      if (error) throw error;
      return data as Scan | null;
    },
    enabled: !!scanId,
  });
}

export function useVulnerabilities(scanId?: string) {
  return useQuery({
    queryKey: ['vulnerabilities', scanId],
    queryFn: async () => {
      let query = supabase
        .from('vulnerabilities')
        .select('*')
        .order('created_at', { ascending: false });
      
      if (scanId) {
        query = query.eq('scan_id', scanId);
      }
      
      const { data, error } = await query;
      if (error) throw error;
      return data as Vulnerability[];
    },
  });
}

export function useComplianceResults(scanId: string | undefined) {
  return useQuery({
    queryKey: ['compliance', scanId],
    queryFn: async () => {
      if (!scanId) return [];
      
      const { data, error } = await supabase
        .from('compliance_results')
        .select('*')
        .eq('scan_id', scanId);
      
      if (error) throw error;
      return data as ComplianceResult[];
    },
    enabled: !!scanId,
  });
}

export function useSBOMComponents(scanId?: string) {
  return useQuery({
    queryKey: ['sbom', scanId],
    queryFn: async () => {
      let query = supabase
        .from('sbom_components')
        .select('*')
        .order('component_name');
      
      if (scanId) {
        query = query.eq('scan_id', scanId);
      }
      
      const { data, error } = await query;
      if (error) throw error;
      return data as SBOMComponent[];
    },
  });
}

export function useAnalysisLogs(scanId: string | undefined) {
  return useQuery({
    queryKey: ['logs', scanId],
    queryFn: async () => {
      if (!scanId) return [];
      
      const { data, error } = await supabase
        .from('analysis_logs')
        .select('*')
        .eq('scan_id', scanId)
        .order('created_at', { ascending: true });
      
      if (error) throw error;
      return data as AnalysisLog[];
    },
    enabled: !!scanId,
  });
}

export function useCreateScan() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (scanData: TablesInsert<'scans'>) => {
      const { data, error } = await supabase
        .from('scans')
        .insert(scanData)
        .select()
        .single();
      
      if (error) throw error;
      return data as Scan;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
    },
    onError: (error) => {
      toast({
        title: 'Error creating scan',
        description: error.message,
        variant: 'destructive',
      });
    },
  });
}

export function useStartAnalysis() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: async ({ 
      scanId, 
      fileContent, 
      fileName, 
      metadata 
    }: { 
      scanId: string; 
      fileContent: string; 
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
    }) => {
      const { data, error } = await supabase.functions.invoke('analyze-binary', {
        body: { scanId, fileContent, fileName, metadata },
      });
      
      if (error) throw error;
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      toast({
        title: 'Analysis started',
        description: 'Binary analysis is now in progress.',
      });
    },
    onError: (error) => {
      toast({
        title: 'Analysis failed',
        description: error.message,
        variant: 'destructive',
      });
    },
  });
}

export function useUpdateVulnerabilityStatus() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: async ({ 
      id, 
      status 
    }: { 
      id: string; 
      status: 'new' | 'reopened' | 'fixed' | 'false_positive' | 'risk_accepted';
    }) => {
      const { data, error } = await supabase
        .from('vulnerabilities')
        .update({ status })
        .eq('id', id)
        .select()
        .single();
      
      if (error) throw error;
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] });
      toast({
        title: 'Status updated',
        description: 'Vulnerability status has been updated.',
      });
    },
    onError: (error) => {
      toast({
        title: 'Update failed',
        description: error.message,
        variant: 'destructive',
      });
    },
  });
}

export function useGenerateReport() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async ({ scanId, format = 'json' }: { scanId: string; format?: 'json' | 'markdown' }) => {
      const { data, error } = await supabase.functions.invoke('generate-report', {
        body: { scanId, format },
      });
      
      if (error) throw error;
      return data;
    },
    onError: (error) => {
      toast({
        title: 'Report generation failed',
        description: error.message,
        variant: 'destructive',
      });
    },
  });
}

export function useFetchCVE() {
  return useMutation({
    mutationFn: async (cveId: string) => {
      const { data, error } = await supabase.functions.invoke('fetch-cve', {
        body: { cveId },
      });
      
      if (error) throw error;
      return data;
    },
  });
}

// Real-time subscription hook
export function useScanRealtime(scanId: string | undefined) {
  const queryClient = useQueryClient();

  return useQuery({
    queryKey: ['scan-realtime', scanId],
    queryFn: () => null,
    enabled: false,
  });
}
