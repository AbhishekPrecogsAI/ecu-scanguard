import { useState, useRef, useEffect } from 'react';
import { Send, Sparkles, Bot, User, Loader2, Copy, Check, Lightbulb, Shield, FileSearch, Code, AlertTriangle } from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useScans, useVulnerabilities } from '@/hooks/useScans';
import { cn } from '@/lib/utils';

interface Message {
    id: string;
    role: 'user' | 'assistant';
    content: string;
    timestamp: Date;
}

const suggestedQuestions = [
    { icon: Shield, text: "What are the critical vulnerabilities in my latest scan?" },
    { icon: FileSearch, text: "Summarize the security posture of my ECU firmware" },
    { icon: Code, text: "Generate remediation code for CWE-119 buffer overflow" },
    { icon: AlertTriangle, text: "Which scans have the highest risk scores?" },
];

export default function Copilot() {
    const [messages, setMessages] = useState<Message[]>([
        {
            id: '1',
            role: 'assistant',
            content: "Hello! I'm your AI Security Copilot. I can help you analyze vulnerabilities, understand security findings, generate remediation code, and provide insights about your ECU security posture. How can I assist you today?",
            timestamp: new Date(),
        }
    ]);
    const [input, setInput] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [copiedId, setCopiedId] = useState<string | null>(null);
    const messagesEndRef = useRef<HTMLDivElement>(null);

    const { data: scans = [] } = useScans();
    const { data: vulnerabilities = [] } = useVulnerabilities();

    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages]);

    const generateResponse = async (userMessage: string): Promise<string> => {
        // Simulate AI response based on context
        const lowerMessage = userMessage.toLowerCase();

        const criticalVulns = vulnerabilities.filter(v => v.severity === 'critical');
        const highVulns = vulnerabilities.filter(v => v.severity === 'high');
        const completedScans = scans.filter(s => s.status === 'complete');
        const avgRisk = completedScans.length > 0
            ? Math.round(completedScans.reduce((acc, s) => acc + (s.risk_score || 0), 0) / completedScans.length)
            : 0;

        if (lowerMessage.includes('critical') || lowerMessage.includes('vulnerability')) {
            return `Based on your scan data, I found **${criticalVulns.length} critical** and **${highVulns.length} high severity** vulnerabilities across ${completedScans.length} completed scans.

${criticalVulns.length > 0 ? `### Critical Findings:
${criticalVulns.slice(0, 3).map((v, i) => `${i + 1}. **${v.title}** (${v.cwe_id || 'No CWE'}) - Found in scan targeting ${v.affected_component || 'unknown component'}`).join('\n')}

**Recommended Actions:**
1. Prioritize fixing buffer overflow vulnerabilities (CWE-119, CWE-120)
2. Review and rotate any exposed credentials
3. Update third-party libraries with known CVEs` : 'No critical vulnerabilities found. Great job maintaining security!'}`;
        }

        if (lowerMessage.includes('security posture') || lowerMessage.includes('summarize')) {
            return `## Security Posture Summary

**Overall Risk Score:** ${avgRisk}/100 (${avgRisk < 30 ? 'Low' : avgRisk < 60 ? 'Medium' : 'High'} Risk)

### Scan Statistics
- **Total Scans:** ${scans.length}
- **Completed:** ${completedScans.length}
- **Active:** ${scans.filter(s => s.status === 'analyzing').length}

### Vulnerability Breakdown
| Severity | Count |
|----------|-------|
| Critical | ${criticalVulns.length} |
| High | ${highVulns.length} |
| Medium | ${vulnerabilities.filter(v => v.severity === 'medium').length} |
| Low | ${vulnerabilities.filter(v => v.severity === 'low').length} |

### Recommendations
1. Address all critical vulnerabilities within 24 hours
2. Schedule remediation for high-severity issues
3. Review compliance status for ISO 21434`;
        }

        if (lowerMessage.includes('remediation') || lowerMessage.includes('code') || lowerMessage.includes('fix')) {
            return `## Remediation Code Example

For **CWE-119: Buffer Overflow** vulnerabilities, here's a secure implementation:

\`\`\`c
// BEFORE (Vulnerable)
char buffer[64];
strcpy(buffer, user_input); // Unsafe!

// AFTER (Secure)
char buffer[64];
size_t input_len = strlen(user_input);
if (input_len >= sizeof(buffer)) {
    // Handle error - input too large
    log_error("Input exceeds buffer size");
    return ERROR_BUFFER_OVERFLOW;
}
strncpy(buffer, user_input, sizeof(buffer) - 1);
buffer[sizeof(buffer) - 1] = '\\0'; // Ensure null termination
\`\`\`

**Key Points:**
1. Always validate input length before copying
2. Use bounded string functions (strncpy, snprintf)
3. Ensure null termination
4. Log security-relevant events`;
        }

        if (lowerMessage.includes('risk') || lowerMessage.includes('score')) {
            const highRiskScans = completedScans.filter(s => (s.risk_score || 0) > 60);
            return `## High Risk Scans Analysis

Found **${highRiskScans.length}** scans with risk scores above 60:

${highRiskScans.slice(0, 5).map((s, i) => `${i + 1}. **${s.ecu_name}** - Risk Score: ${s.risk_score}/100
   - Type: ${s.ecu_type}
   - Version: ${s.version || 'N/A'}`).join('\n\n')}

**Recommendations:**
- Prioritize these ECUs for immediate security review
- Consider isolating high-risk components
- Schedule penetration testing for critical systems`;
        }

        return `I understand you're asking about "${userMessage}". Based on your current security data:

- **Total Scans:** ${scans.length}
- **Total Vulnerabilities:** ${vulnerabilities.length}
- **Average Risk Score:** ${avgRisk}/100

How can I provide more specific insights? You can ask me about:
- Critical vulnerabilities and their remediation
- Security posture summaries
- Code fixes for specific CWEs
- Risk analysis and prioritization`;
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!input.trim() || isLoading) return;

        const userMessage: Message = {
            id: Date.now().toString(),
            role: 'user',
            content: input,
            timestamp: new Date(),
        };

        setMessages(prev => [...prev, userMessage]);
        setInput('');
        setIsLoading(true);

        // Simulate API delay
        await new Promise(resolve => setTimeout(resolve, 1500));

        const response = await generateResponse(input);

        const assistantMessage: Message = {
            id: (Date.now() + 1).toString(),
            role: 'assistant',
            content: response,
            timestamp: new Date(),
        };

        setMessages(prev => [...prev, assistantMessage]);
        setIsLoading(false);
    };

    const handleSuggestedQuestion = (question: string) => {
        setInput(question);
    };

    const copyToClipboard = (content: string, id: string) => {
        navigator.clipboard.writeText(content);
        setCopiedId(id);
        setTimeout(() => setCopiedId(null), 2000);
    };

    return (
        <AppLayout>
            <div className="flex flex-col h-[calc(100vh-2rem)] max-w-4xl mx-auto">
                {/* Header */}
                <div className="flex items-center gap-3 mb-6">
                    <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-primary to-accent flex items-center justify-center">
                        <Sparkles className="w-6 h-6 text-white" />
                    </div>
                    <div>
                        <h1 className="text-2xl font-bold text-foreground">AI Security Copilot</h1>
                        <p className="text-sm text-muted-foreground">Powered by Precogs AI • Analyze, Remediate, Secure</p>
                    </div>
                    <span className="ml-auto px-3 py-1 text-xs font-semibold bg-primary/10 text-primary rounded-full">BETA</span>
                </div>

                {/* Chat Container */}
                <div className="flex-1 overflow-hidden flex flex-col bg-card rounded-xl border border-border">
                    {/* Messages */}
                    <div className="flex-1 overflow-y-auto p-4 space-y-4">
                        {messages.map((message) => (
                            <div
                                key={message.id}
                                className={cn(
                                    "flex gap-3",
                                    message.role === 'user' && "flex-row-reverse"
                                )}
                            >
                                <div className={cn(
                                    "w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0",
                                    message.role === 'assistant'
                                        ? "bg-gradient-to-br from-primary to-accent"
                                        : "bg-muted"
                                )}>
                                    {message.role === 'assistant' ? (
                                        <Bot className="w-4 h-4 text-white" />
                                    ) : (
                                        <User className="w-4 h-4 text-muted-foreground" />
                                    )}
                                </div>
                                <div className={cn(
                                    "flex-1 max-w-[80%]",
                                    message.role === 'user' && "flex justify-end"
                                )}>
                                    <div className={cn(
                                        "rounded-xl px-4 py-3 text-sm",
                                        message.role === 'assistant'
                                            ? "bg-muted/50 text-foreground"
                                            : "bg-primary text-primary-foreground"
                                    )}>
                                        <div className="prose prose-sm dark:prose-invert max-w-none">
                                            {message.content.split('\n').map((line, i) => {
                                                if (line.startsWith('```')) {
                                                    return <code key={i} className="block bg-muted p-2 rounded text-xs font-mono mt-2">{line.replace(/```\w*/, '').replace('```', '')}</code>;
                                                }
                                                if (line.startsWith('##')) {
                                                    return <h3 key={i} className="font-semibold mt-3 mb-2">{line.replace('## ', '')}</h3>;
                                                }
                                                if (line.startsWith('###')) {
                                                    return <h4 key={i} className="font-medium mt-2 mb-1">{line.replace('### ', '')}</h4>;
                                                }
                                                if (line.startsWith('|')) {
                                                    return <p key={i} className="font-mono text-xs">{line}</p>;
                                                }
                                                return <p key={i} className={line.startsWith('-') || line.startsWith('1.') ? 'ml-4' : ''}>{line}</p>;
                                            })}
                                        </div>
                                    </div>
                                    {message.role === 'assistant' && (
                                        <button
                                            onClick={() => copyToClipboard(message.content, message.id)}
                                            className="mt-1 text-xs text-muted-foreground hover:text-foreground flex items-center gap-1"
                                        >
                                            {copiedId === message.id ? (
                                                <><Check className="w-3 h-3" /> Copied</>
                                            ) : (
                                                <><Copy className="w-3 h-3" /> Copy</>
                                            )}
                                        </button>
                                    )}
                                </div>
                            </div>
                        ))}

                        {isLoading && (
                            <div className="flex gap-3">
                                <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-primary to-accent flex items-center justify-center">
                                    <Bot className="w-4 h-4 text-white" />
                                </div>
                                <div className="bg-muted/50 rounded-xl px-4 py-3">
                                    <Loader2 className="w-4 h-4 animate-spin text-primary" />
                                </div>
                            </div>
                        )}
                        <div ref={messagesEndRef} />
                    </div>

                    {/* Suggested Questions */}
                    {messages.length === 1 && (
                        <div className="px-4 pb-4">
                            <p className="text-xs text-muted-foreground mb-2 flex items-center gap-1">
                                <Lightbulb className="w-3 h-3" /> Suggested questions
                            </p>
                            <div className="grid grid-cols-2 gap-2">
                                {suggestedQuestions.map((q, i) => (
                                    <button
                                        key={i}
                                        onClick={() => handleSuggestedQuestion(q.text)}
                                        className="flex items-center gap-2 p-3 text-left text-sm bg-muted/30 hover:bg-muted/50 rounded-lg transition-colors border border-border/50"
                                    >
                                        <q.icon className="w-4 h-4 text-primary flex-shrink-0" />
                                        <span className="text-muted-foreground">{q.text}</span>
                                    </button>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Input */}
                    <form onSubmit={handleSubmit} className="p-4 border-t border-border">
                        <div className="flex gap-2">
                            <Input
                                value={input}
                                onChange={(e) => setInput(e.target.value)}
                                placeholder="Ask about vulnerabilities, get remediation code, analyze security..."
                                className="flex-1"
                                disabled={isLoading}
                            />
                            <Button type="submit" disabled={isLoading || !input.trim()}>
                                {isLoading ? (
                                    <Loader2 className="w-4 h-4 animate-spin" />
                                ) : (
                                    <Send className="w-4 h-4" />
                                )}
                            </Button>
                        </div>
                    </form>
                </div>
            </div>
        </AppLayout>
    );
}
