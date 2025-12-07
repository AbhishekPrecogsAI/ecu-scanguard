import { useState, useMemo } from 'react';
import { Key, User, AlertTriangle, Eye, EyeOff, Shield, MapPin, Phone, Mail, Fingerprint } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { SeverityBadge } from '@/components/ui/severity-badge';
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible';
import { cn } from '@/lib/utils';

interface Vulnerability {
  id: string;
  cwe_id: string | null;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string | null;
  affected_component: string | null;
  line_number: number | null;
  code_snippet: string | null;
  remediation: string | null;
  attack_vector: string | null;
  impact: string | null;
  llm_enrichment: any;
}

interface SecretsFindingsProps {
  vulnerabilities: Vulnerability[];
}

// Patterns for additional regex-based detection
const SECRET_PATTERNS = [
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/gi, type: 'aws_key', severity: 'critical' },
  { name: 'AWS Secret Key', regex: /[A-Za-z0-9/+=]{40}/gi, type: 'aws_secret', severity: 'critical' },
  { name: 'API Key', regex: /api[_-]?key['":\s]*[=:]\s*['"]?[A-Za-z0-9_\-]{20,}/gi, type: 'api_key', severity: 'high' },
  { name: 'Password', regex: /password['":\s]*[=:]\s*['"]?[^\s'"]{8,}/gi, type: 'password', severity: 'critical' },
  { name: 'Private Key', regex: /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/gi, type: 'private_key', severity: 'critical' },
  { name: 'JWT Token', regex: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/gi, type: 'jwt', severity: 'high' },
  { name: 'Bearer Token', regex: /bearer\s+[A-Za-z0-9_\-\.]+/gi, type: 'bearer', severity: 'high' },
  { name: 'GitHub Token', regex: /gh[pousr]_[A-Za-z0-9_]{36,}/gi, type: 'github_token', severity: 'critical' },
];

const PII_PATTERNS = [
  { name: 'Email Address', regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi, type: 'email', severity: 'medium' },
  { name: 'Phone Number', regex: /(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/gi, type: 'phone', severity: 'medium' },
  { name: 'IP Address', regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/gi, type: 'ip_address', severity: 'low' },
  { name: 'MAC Address', regex: /([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})/gi, type: 'mac_address', severity: 'low' },
  { name: 'Credit Card', regex: /\b(?:\d{4}[-\s]?){3}\d{4}\b/gi, type: 'credit_card', severity: 'critical' },
  { name: 'SSN', regex: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/gi, type: 'ssn', severity: 'critical' },
];

const getTypeIcon = (type: string) => {
  switch (type) {
    case 'email':
      return <Mail className="w-4 h-4" />;
    case 'phone':
      return <Phone className="w-4 h-4" />;
    case 'ip_address':
    case 'location':
      return <MapPin className="w-4 h-4" />;
    case 'device_id':
    case 'mac_address':
      return <Fingerprint className="w-4 h-4" />;
    case 'api_key':
    case 'password':
    case 'private_key':
    case 'aws_key':
    case 'jwt':
    case 'bearer':
    case 'github_token':
      return <Key className="w-4 h-4" />;
    default:
      return <User className="w-4 h-4" />;
  }
};

export function SecretsFindings({ vulnerabilities }: SecretsFindingsProps) {
  const [expandedItems, setExpandedItems] = useState<string[]>([]);
  const [showValues, setShowValues] = useState<Record<string, boolean>>({});

  // Filter vulnerabilities that are secrets (CWE-798) or PII (CWE-359)
  const secretsAndPII = useMemo(() => {
    return vulnerabilities.filter(v => 
      v.cwe_id === 'CWE-798' || v.cwe_id === 'CWE-359'
    );
  }, [vulnerabilities]);

  const secrets = secretsAndPII.filter(v => v.cwe_id === 'CWE-798');
  const piiFindings = secretsAndPII.filter(v => v.cwe_id === 'CWE-359');

  // Additionally scan code snippets with regex for any missed items
  const regexFindings = useMemo(() => {
    const findings: { type: string; name: string; value: string; location: string; severity: string; source: string }[] = [];
    
    vulnerabilities.forEach(v => {
      if (v.code_snippet) {
        // Check for secrets
        SECRET_PATTERNS.forEach(pattern => {
          const matches = v.code_snippet?.match(pattern.regex) || [];
          matches.forEach(match => {
            findings.push({
              type: pattern.type,
              name: pattern.name,
              value: match,
              location: `${v.affected_component}:${v.line_number || '?'}`,
              severity: pattern.severity,
              source: 'regex',
            });
          });
        });
        
        // Check for PII
        PII_PATTERNS.forEach(pattern => {
          const matches = v.code_snippet?.match(pattern.regex) || [];
          matches.forEach(match => {
            findings.push({
              type: pattern.type,
              name: pattern.name,
              value: match,
              location: `${v.affected_component}:${v.line_number || '?'}`,
              severity: pattern.severity,
              source: 'regex',
            });
          });
        });
      }
    });
    
    // Deduplicate
    return findings.filter((f, i, arr) => 
      arr.findIndex(x => x.value === f.value && x.location === f.location) === i
    );
  }, [vulnerabilities]);

  const toggleExpand = (id: string) => {
    setExpandedItems(prev => 
      prev.includes(id) ? prev.filter(i => i !== id) : [...prev, id]
    );
  };

  const toggleShowValue = (id: string) => {
    setShowValues(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const maskValue = (value: string) => {
    if (value.length <= 8) return '••••••••';
    return value.slice(0, 4) + '••••' + value.slice(-4);
  };

  const totalFindings = secrets.length + piiFindings.length + regexFindings.length;

  if (totalFindings === 0) {
    return (
      <Card className="glass-card border-border">
        <CardHeader>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-success/20 flex items-center justify-center">
              <Shield className="w-5 h-5 text-success" />
            </div>
            <div>
              <CardTitle>Secrets & PII Scanner</CardTitle>
              <CardDescription>No sensitive data detected</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="text-center py-8 text-muted-foreground">
            <Shield className="w-12 h-12 mx-auto mb-4 text-success/50" />
            <p>No hardcoded secrets, API keys, or personal information found.</p>
            <p className="text-sm mt-2">Your code appears clean of sensitive data exposure.</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="glass-card border-border">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-destructive/20 flex items-center justify-center">
              <Key className="w-5 h-5 text-destructive" />
            </div>
            <div>
              <CardTitle>Secrets & PII Scanner</CardTitle>
              <CardDescription>
                {totalFindings} sensitive data finding{totalFindings !== 1 ? 's' : ''} detected
              </CardDescription>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="destructive" className="gap-1">
              <Key className="w-3 h-3" />
              {secrets.length} Secrets
            </Badge>
            <Badge variant="outline" className="gap-1 border-warning/50 text-warning">
              <User className="w-3 h-3" />
              {piiFindings.length} PII
            </Badge>
            {regexFindings.length > 0 && (
              <Badge variant="outline" className="gap-1">
                +{regexFindings.length} Regex
              </Badge>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Summary Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
          <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/20">
            <div className="text-xl font-bold text-destructive font-mono">
              {secrets.filter(s => s.severity === 'critical').length}
            </div>
            <div className="text-xs text-muted-foreground">Critical Secrets</div>
          </div>
          <div className="p-3 rounded-lg bg-warning/10 border border-warning/20">
            <div className="text-xl font-bold text-warning font-mono">
              {secrets.filter(s => s.severity === 'high').length}
            </div>
            <div className="text-xs text-muted-foreground">High Risk</div>
          </div>
          <div className="p-3 rounded-lg bg-primary/10 border border-primary/20">
            <div className="text-xl font-bold text-primary font-mono">{piiFindings.length}</div>
            <div className="text-xs text-muted-foreground">PII Exposures</div>
          </div>
          <div className="p-3 rounded-lg bg-muted border border-border">
            <div className="text-xl font-bold text-foreground font-mono">{regexFindings.length}</div>
            <div className="text-xs text-muted-foreground">Regex Matches</div>
          </div>
        </div>

        {/* Secrets Section */}
        {secrets.length > 0 && (
          <div className="space-y-2">
            <h4 className="text-sm font-semibold text-destructive flex items-center gap-2">
              <Key className="w-4 h-4" />
              Hardcoded Secrets ({secrets.length})
            </h4>
            <div className="space-y-2">
              {secrets.map((secret) => (
                <Collapsible
                  key={secret.id}
                  open={expandedItems.includes(secret.id)}
                  onOpenChange={() => toggleExpand(secret.id)}
                >
                  <CollapsibleTrigger asChild>
                    <div className="flex items-center justify-between p-3 rounded-lg bg-destructive/5 border border-destructive/20 hover:bg-destructive/10 cursor-pointer transition-colors">
                      <div className="flex items-center gap-3">
                        <Key className="w-4 h-4 text-destructive" />
                        <div>
                          <span className="font-medium text-foreground">{secret.title}</span>
                          <div className="text-xs text-muted-foreground">
                            {secret.affected_component}
                            {secret.line_number && `:${secret.line_number}`}
                          </div>
                        </div>
                      </div>
                      <SeverityBadge severity={secret.severity} />
                    </div>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="px-3 pb-3">
                    <div className="mt-3 space-y-3 pl-7">
                      <p className="text-sm text-muted-foreground">{secret.description}</p>
                      
                      {secret.code_snippet && (
                        <div className="relative">
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-xs text-muted-foreground">Code Snippet</span>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-6 text-xs"
                              onClick={(e) => {
                                e.stopPropagation();
                                toggleShowValue(secret.id);
                              }}
                            >
                              {showValues[secret.id] ? (
                                <><EyeOff className="w-3 h-3 mr-1" /> Hide</>
                              ) : (
                                <><Eye className="w-3 h-3 mr-1" /> Show</>
                              )}
                            </Button>
                          </div>
                          <pre className="text-xs bg-muted/50 p-3 rounded overflow-x-auto font-mono">
                            {showValues[secret.id] ? secret.code_snippet : maskValue(secret.code_snippet)}
                          </pre>
                        </div>
                      )}
                      
                      {secret.remediation && (
                        <div className="p-3 rounded-lg bg-success/10 border border-success/20">
                          <div className="text-xs font-medium text-success mb-1">Remediation</div>
                          <p className="text-sm text-muted-foreground">{secret.remediation}</p>
                        </div>
                      )}
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              ))}
            </div>
          </div>
        )}

        {/* PII Section */}
        {piiFindings.length > 0 && (
          <div className="space-y-2">
            <h4 className="text-sm font-semibold text-warning flex items-center gap-2">
              <User className="w-4 h-4" />
              Personal Information ({piiFindings.length})
            </h4>
            <div className="space-y-2">
              {piiFindings.map((pii) => (
                <Collapsible
                  key={pii.id}
                  open={expandedItems.includes(pii.id)}
                  onOpenChange={() => toggleExpand(pii.id)}
                >
                  <CollapsibleTrigger asChild>
                    <div className="flex items-center justify-between p-3 rounded-lg bg-warning/5 border border-warning/20 hover:bg-warning/10 cursor-pointer transition-colors">
                      <div className="flex items-center gap-3">
                        <User className="w-4 h-4 text-warning" />
                        <div>
                          <span className="font-medium text-foreground">{pii.title}</span>
                          <div className="text-xs text-muted-foreground">
                            {pii.affected_component}
                            {pii.line_number && `:${pii.line_number}`}
                          </div>
                        </div>
                      </div>
                      <SeverityBadge severity={pii.severity} />
                    </div>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="px-3 pb-3">
                    <div className="mt-3 space-y-3 pl-7">
                      <p className="text-sm text-muted-foreground">{pii.description}</p>
                      
                      {pii.impact && (
                        <div className="p-3 rounded-lg bg-muted/50 border border-border">
                          <div className="text-xs font-medium text-foreground mb-1">Privacy Impact</div>
                          <p className="text-sm text-muted-foreground">{pii.impact}</p>
                        </div>
                      )}
                      
                      {pii.remediation && (
                        <div className="p-3 rounded-lg bg-success/10 border border-success/20">
                          <div className="text-xs font-medium text-success mb-1">Remediation</div>
                          <p className="text-sm text-muted-foreground">{pii.remediation}</p>
                        </div>
                      )}
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              ))}
            </div>
          </div>
        )}

        {/* Regex Findings Section */}
        {regexFindings.length > 0 && (
          <div className="space-y-2">
            <h4 className="text-sm font-semibold text-muted-foreground flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" />
              Additional Regex Detections ({regexFindings.length})
            </h4>
            <div className="grid gap-2">
              {regexFindings.map((finding, index) => (
                <div 
                  key={`regex-${index}`}
                  className="flex items-center justify-between p-3 rounded-lg bg-muted/30 border border-border"
                >
                  <div className="flex items-center gap-3">
                    {getTypeIcon(finding.type)}
                    <div>
                      <span className="font-medium text-foreground">{finding.name}</span>
                      <div className="text-xs text-muted-foreground font-mono">{finding.location}</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <code className="text-xs bg-muted px-2 py-1 rounded font-mono">
                      {maskValue(finding.value)}
                    </code>
                    <SeverityBadge severity={finding.severity as any} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Compliance Warning */}
        <div className="p-4 rounded-lg bg-warning/10 border border-warning/20 mt-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-warning mt-0.5" />
            <div>
              <div className="font-medium text-foreground">Compliance Warning</div>
              <p className="text-sm text-muted-foreground mt-1">
                Hardcoded secrets and PII in firmware violate GDPR, ISO 21434 (automotive cybersecurity), 
                and UNECE WP.29 R155 regulations. Remediate immediately to ensure compliance.
              </p>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
