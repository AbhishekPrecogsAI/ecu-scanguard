import { useState, useRef, useEffect } from 'react';
import { Sparkles, X, Send, Loader2, Copy, Check, Minimize2, Maximize2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { cn } from '@/lib/utils';
import { useScans, useVulnerabilities } from '@/hooks/useScans';
import { supabase } from '@/integrations/supabase/client';

interface Message {
    id: string;
    role: 'user' | 'assistant';
    content: string;
    timestamp: Date;
}

// AI API configuration
const AI_ENDPOINT = 'https://ai.gateway.lovable.dev/v1/chat/completions';

export function FloatingCopilot() {
    const [isOpen, setIsOpen] = useState(false);
    const [isMinimized, setIsMinimized] = useState(false);
    const [messages, setMessages] = useState<Message[]>([]);
    const [input, setInput] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [copiedId, setCopiedId] = useState<string | null>(null);
    const messagesEndRef = useRef<HTMLDivElement>(null);

    const { data: scans = [] } = useScans();
    const { data: vulnerabilities = [] } = useVulnerabilities();

    // Auto-scroll to bottom when new messages arrive
    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages]);

    // Build context from scan data for the AI
    const buildSecurityContext = () => {
        const recentScans = scans.slice(0, 5);
        const criticalVulns = vulnerabilities.filter(v => v.severity === 'critical');
        const highVulns = vulnerabilities.filter(v => v.severity === 'high');

        return `
You are Precogs AI Security Copilot, an expert automotive cybersecurity assistant.

Current Security Context:
- Total Scans: ${scans.length}
- Recent Scans: ${recentScans.map(s => `${s.ecu_name} (${s.status})`).join(', ') || 'None'}
- Total Vulnerabilities: ${vulnerabilities.length}
- Critical: ${criticalVulns.length}, High: ${highVulns.length}
- Top CWEs: ${[...new Set(vulnerabilities.map(v => v.cwe_id).filter(Boolean))].slice(0, 5).join(', ') || 'None detected'}

You specialize in:
- Automotive ECU security (ISO 21434, UNECE R155)
- MISRA C/C++ compliance
- Memory safety vulnerabilities (buffer overflows, use-after-free)
- CAN bus security
- Cryptographic best practices
- SBOM analysis

Provide concise, actionable security advice. When discussing vulnerabilities, include:
1. Brief explanation of the issue
2. Potential impact in automotive context
3. Remediation code example when applicable
4. Relevant CWE/CVE references
`;
    };

    const sendMessage = async () => {
        if (!input.trim() || isLoading) return;

        const userMessage: Message = {
            id: Date.now().toString(),
            role: 'user',
            content: input.trim(),
            timestamp: new Date(),
        };

        setMessages(prev => [...prev, userMessage]);
        setInput('');
        setIsLoading(true);

        try {
            // Build conversation history for context
            const conversationHistory = messages.slice(-10).map(m => ({
                role: m.role,
                content: m.content,
            }));

            const response = await fetch(AI_ENDPOINT, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    model: 'gpt-4o-mini',
                    messages: [
                        { role: 'system', content: buildSecurityContext() },
                        ...conversationHistory,
                        { role: 'user', content: input.trim() },
                    ],
                    max_tokens: 1000,
                    temperature: 0.7,
                }),
            });

            if (!response.ok) {
                throw new Error('AI service unavailable');
            }

            const data = await response.json();
            const aiContent = data.choices?.[0]?.message?.content || 'I apologize, but I could not generate a response. Please try again.';

            const assistantMessage: Message = {
                id: (Date.now() + 1).toString(),
                role: 'assistant',
                content: aiContent,
                timestamp: new Date(),
            };

            setMessages(prev => [...prev, assistantMessage]);
        } catch (error) {
            console.error('AI Copilot error:', error);

            // Fallback response
            const fallbackMessage: Message = {
                id: (Date.now() + 1).toString(),
                role: 'assistant',
                content: `I'm having trouble connecting to the AI service. Here's what I can tell you based on your current data:

**Security Summary:**
- ${scans.length} total scans performed
- ${vulnerabilities.length} vulnerabilities detected
- ${vulnerabilities.filter(v => v.severity === 'critical').length} critical issues need immediate attention

For specific security questions, please try again in a moment or check the Documentation page for common remediation guidance.`,
                timestamp: new Date(),
            };
            setMessages(prev => [...prev, fallbackMessage]);
        } finally {
            setIsLoading(false);
        }
    };

    const copyToClipboard = async (text: string, id: string) => {
        await navigator.clipboard.writeText(text);
        setCopiedId(id);
        setTimeout(() => setCopiedId(null), 2000);
    };

    const handleKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    };

    const suggestedQuestions = [
        "How do I fix a buffer overflow?",
        "Explain CWE-119 remediation",
        "Best practices for CAN security",
        "What is ISO 21434?",
    ];

    if (!isOpen) {
        return (
            <button
                onClick={() => setIsOpen(true)}
                className="fixed bottom-6 right-6 z-50 w-14 h-14 rounded-full bg-gradient-to-br from-violet-600 to-cyan-500 shadow-lg hover:shadow-xl transition-all duration-300 flex items-center justify-center group hover:scale-110"
                aria-label="Open AI Copilot"
            >
                <Sparkles className="w-6 h-6 text-white" />
                <span className="absolute -top-1 -right-1 w-4 h-4 bg-green-500 rounded-full border-2 border-white animate-pulse" />
                <span className="absolute inset-0 rounded-full bg-gradient-to-br from-violet-600 to-cyan-500 animate-ping opacity-20" />
            </button>
        );
    }

    return (
        <div
            className={cn(
                "fixed z-50 bg-card border border-border rounded-2xl shadow-2xl transition-all duration-300 flex flex-col overflow-hidden",
                isMinimized
                    ? "bottom-6 right-6 w-80 h-14"
                    : "bottom-6 right-6 w-96 h-[600px] max-h-[80vh]"
            )}
        >
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-3 bg-gradient-to-r from-violet-600 to-cyan-500 text-white">
                <div className="flex items-center gap-2">
                    <Sparkles className="w-5 h-5" />
                    <span className="font-semibold">AI Security Copilot</span>
                    <span className="text-xs bg-white/20 px-2 py-0.5 rounded-full">LIVE</span>
                </div>
                <div className="flex items-center gap-1">
                    <button
                        onClick={() => setIsMinimized(!isMinimized)}
                        className="p-1.5 hover:bg-white/20 rounded-lg transition-colors"
                    >
                        {isMinimized ? <Maximize2 className="w-4 h-4" /> : <Minimize2 className="w-4 h-4" />}
                    </button>
                    <button
                        onClick={() => setIsOpen(false)}
                        className="p-1.5 hover:bg-white/20 rounded-lg transition-colors"
                    >
                        <X className="w-4 h-4" />
                    </button>
                </div>
            </div>

            {!isMinimized && (
                <>
                    {/* Messages */}
                    <div className="flex-1 overflow-y-auto p-4 space-y-4">
                        {messages.length === 0 ? (
                            <div className="text-center py-8">
                                <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-gradient-to-br from-violet-500/20 to-cyan-500/20 flex items-center justify-center">
                                    <Sparkles className="w-8 h-8 text-violet-500" />
                                </div>
                                <h3 className="font-semibold text-foreground mb-2">AI Security Assistant</h3>
                                <p className="text-sm text-muted-foreground mb-4">
                                    Ask me about vulnerabilities, remediation, or security best practices.
                                </p>
                                <div className="flex flex-wrap gap-2 justify-center">
                                    {suggestedQuestions.map((q, i) => (
                                        <button
                                            key={i}
                                            onClick={() => setInput(q)}
                                            className="text-xs px-3 py-1.5 bg-muted hover:bg-muted/80 rounded-full text-muted-foreground hover:text-foreground transition-colors"
                                        >
                                            {q}
                                        </button>
                                    ))}
                                </div>
                            </div>
                        ) : (
                            messages.map((message) => (
                                <div
                                    key={message.id}
                                    className={cn(
                                        "flex",
                                        message.role === 'user' ? 'justify-end' : 'justify-start'
                                    )}
                                >
                                    <div
                                        className={cn(
                                            "max-w-[85%] rounded-2xl px-4 py-2.5 text-sm",
                                            message.role === 'user'
                                                ? 'bg-gradient-to-r from-violet-600 to-cyan-500 text-white rounded-br-md'
                                                : 'bg-muted text-foreground rounded-bl-md'
                                        )}
                                    >
                                        <div className="whitespace-pre-wrap">{message.content}</div>
                                        {message.role === 'assistant' && (
                                            <button
                                                onClick={() => copyToClipboard(message.content, message.id)}
                                                className="mt-2 text-xs text-muted-foreground hover:text-foreground flex items-center gap-1"
                                            >
                                                {copiedId === message.id ? (
                                                    <>
                                                        <Check className="w-3 h-3" />
                                                        Copied
                                                    </>
                                                ) : (
                                                    <>
                                                        <Copy className="w-3 h-3" />
                                                        Copy
                                                    </>
                                                )}
                                            </button>
                                        )}
                                    </div>
                                </div>
                            ))
                        )}
                        {isLoading && (
                            <div className="flex justify-start">
                                <div className="bg-muted rounded-2xl rounded-bl-md px-4 py-3">
                                    <Loader2 className="w-5 h-5 animate-spin text-violet-500" />
                                </div>
                            </div>
                        )}
                        <div ref={messagesEndRef} />
                    </div>

                    {/* Input */}
                    <div className="p-3 border-t border-border">
                        <div className="flex gap-2">
                            <Textarea
                                value={input}
                                onChange={(e) => setInput(e.target.value)}
                                onKeyDown={handleKeyDown}
                                placeholder="Ask about security, vulnerabilities..."
                                className="min-h-[44px] max-h-32 resize-none text-sm"
                                rows={1}
                            />
                            <Button
                                onClick={sendMessage}
                                disabled={!input.trim() || isLoading}
                                size="icon"
                                className="shrink-0 bg-gradient-to-r from-violet-600 to-cyan-500 hover:opacity-90"
                            >
                                <Send className="w-4 h-4" />
                            </Button>
                        </div>
                        <p className="text-xs text-muted-foreground mt-2 text-center">
                            Powered by Precogs AI • Context-aware security assistance
                        </p>
                    </div>
                </>
            )}
        </div>
    );
}
