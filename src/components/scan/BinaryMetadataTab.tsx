import { useMemo } from 'react';
import { Hash, HardDrive, Cpu, Wrench, FileCode, BarChart3, Layers, Info } from 'lucide-react';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Progress } from '@/components/ui/progress';
import type { Scan } from '@/hooks/useScans';

interface BinaryMetadataTabProps {
  scan: Scan;
}

export function BinaryMetadataTab({ scan }: BinaryMetadataTabProps) {
  const formatFileSize = (bytes: number | null) => {
    if (!bytes) return 'N/A';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  // Simulated entropy analysis (in real implementation, this would come from backend)
  const entropyData = useMemo(() => [
    { section: '.text', entropy: 6.2, size: '45%', description: 'Code section' },
    { section: '.data', entropy: 4.8, size: '15%', description: 'Initialized data' },
    { section: '.rodata', entropy: 5.5, size: '20%', description: 'Read-only data' },
    { section: '.bss', entropy: 0.1, size: '10%', description: 'Uninitialized data' },
    { section: '.plt', entropy: 5.9, size: '5%', description: 'Procedure linkage' },
    { section: 'other', entropy: 3.2, size: '5%', description: 'Other sections' },
  ], []);

  // Simulated section analysis
  const sectionAnalysis = useMemo(() => [
    { name: '.text', type: 'PROGBITS', flags: 'AX', address: '0x00001000', size: '0x45000', align: '16' },
    { name: '.rodata', type: 'PROGBITS', flags: 'A', address: '0x00046000', size: '0x12000', align: '32' },
    { name: '.data', type: 'PROGBITS', flags: 'WA', address: '0x00058000', size: '0x8000', align: '32' },
    { name: '.bss', type: 'NOBITS', flags: 'WA', address: '0x00060000', size: '0x5000', align: '32' },
    { name: '.plt', type: 'PROGBITS', flags: 'AX', address: '0x00065000', size: '0x2000', align: '16' },
    { name: '.got', type: 'PROGBITS', flags: 'WA', address: '0x00067000', size: '0x1000', align: '8' },
  ], []);

  // Simulated compiler detection
  const compilerInfo = {
    name: 'ARM GCC',
    version: '11.2.0',
    flags: '-O2 -fstack-protector-strong -fPIC',
    target: scan.architecture || 'ARM Cortex-M4',
  };

  // Simulated symbol table summary
  const symbolSummary = {
    total: 2847,
    functions: 892,
    globalVariables: 234,
    localSymbols: 1721,
    undefinedSymbols: 45,
  };

  const MetadataCard = ({ title, icon: Icon, children }: { title: string; icon: any; children: React.ReactNode }) => (
    <Card className="p-4 border border-border">
      <div className="flex items-center gap-2 mb-4">
        <Icon className="w-5 h-5 text-primary" />
        <h4 className="font-medium text-foreground">{title}</h4>
      </div>
      {children}
    </Card>
  );

  const MetadataItem = ({ label, value, mono = false }: { label: string; value: string | number; mono?: boolean }) => (
    <div className="flex justify-between py-2 border-b border-border last:border-0">
      <span className="text-sm text-muted-foreground">{label}</span>
      <span className={`text-sm font-medium ${mono ? 'font-mono' : ''}`}>{value}</span>
    </div>
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
          <Info className="w-5 h-5 text-primary" />
        </div>
        <div>
          <h3 className="font-semibold text-foreground">Binary Metadata</h3>
          <p className="text-sm text-muted-foreground">Detailed analysis of {scan.file_name}</p>
        </div>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* File Information */}
        <MetadataCard title="File Information" icon={Hash}>
          <MetadataItem label="File Name" value={scan.file_name} />
          <MetadataItem label="File Size" value={formatFileSize(scan.file_size)} />
          <MetadataItem label="SHA-256 Hash" value={scan.file_hash?.substring(0, 16) + '...' || 'N/A'} mono />
          <MetadataItem label="File Format" value={scan.file_name.split('.').pop()?.toUpperCase() || 'Binary'} />
        </MetadataCard>

        {/* Architecture Details */}
        <MetadataCard title="Architecture Details" icon={Cpu}>
          <MetadataItem label="Architecture" value={scan.architecture || 'Unknown'} />
          <MetadataItem label="Platform" value={scan.platform || 'Automotive ECU'} />
          <MetadataItem label="Endianness" value="Little Endian" />
          <MetadataItem label="Word Size" value="32-bit" />
        </MetadataCard>

        {/* Compiler Information */}
        <MetadataCard title="Compiler Detected" icon={Wrench}>
          <MetadataItem label="Compiler" value={compilerInfo.name} />
          <MetadataItem label="Version" value={compilerInfo.version} />
          <MetadataItem label="Target" value={compilerInfo.target} />
          <MetadataItem label="Flags" value={compilerInfo.flags} mono />
        </MetadataCard>

        {/* Symbol Table Summary */}
        <MetadataCard title="Symbol Table Summary" icon={FileCode}>
          <MetadataItem label="Total Symbols" value={symbolSummary.total.toLocaleString()} />
          <MetadataItem label="Functions" value={symbolSummary.functions.toLocaleString()} />
          <MetadataItem label="Global Variables" value={symbolSummary.globalVariables.toLocaleString()} />
          <MetadataItem label="Undefined Symbols" value={symbolSummary.undefinedSymbols.toLocaleString()} />
        </MetadataCard>
      </div>

      {/* Entropy Analysis */}
      <Card className="p-4 border border-border">
        <div className="flex items-center gap-2 mb-4">
          <BarChart3 className="w-5 h-5 text-primary" />
          <h4 className="font-medium text-foreground">Entropy Analysis</h4>
          <Badge variant="outline" className="ml-auto">Max Entropy: 8.0</Badge>
        </div>
        <div className="space-y-3">
          {entropyData.map((section) => (
            <div key={section.section} className="flex items-center gap-4">
              <code className="w-20 text-xs font-mono text-muted-foreground">{section.section}</code>
              <div className="flex-1">
                <Progress value={(section.entropy / 8) * 100} className="h-2" />
              </div>
              <span className={`w-12 text-sm font-medium text-right ${
                section.entropy > 7 ? 'text-red-500' : section.entropy > 5 ? 'text-yellow-500' : 'text-green-500'
              }`}>
                {section.entropy.toFixed(1)}
              </span>
              <span className="w-16 text-xs text-muted-foreground text-right">{section.size}</span>
            </div>
          ))}
        </div>
        <p className="text-xs text-muted-foreground mt-3">
          High entropy (&gt;7.0) may indicate packed/encrypted content. Normal code typically has entropy of 5.0-6.5.
        </p>
      </Card>

      {/* Section Analysis */}
      <Card className="border border-border overflow-hidden">
        <div className="flex items-center gap-2 p-4 border-b border-border">
          <Layers className="w-5 h-5 text-primary" />
          <h4 className="font-medium text-foreground">Section Analysis</h4>
        </div>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Section</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Flags</TableHead>
              <TableHead>Address</TableHead>
              <TableHead>Size</TableHead>
              <TableHead>Alignment</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {sectionAnalysis.map((section) => (
              <TableRow key={section.name}>
                <TableCell>
                  <code className="text-xs font-mono">{section.name}</code>
                </TableCell>
                <TableCell>
                  <Badge variant="outline" className="text-xs">{section.type}</Badge>
                </TableCell>
                <TableCell>
                  <code className="text-xs font-mono text-muted-foreground">{section.flags}</code>
                </TableCell>
                <TableCell>
                  <code className="text-xs font-mono">{section.address}</code>
                </TableCell>
                <TableCell>
                  <code className="text-xs font-mono">{section.size}</code>
                </TableCell>
                <TableCell>
                  <span className="text-xs text-muted-foreground">{section.align}</span>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Card>
    </div>
  );
}