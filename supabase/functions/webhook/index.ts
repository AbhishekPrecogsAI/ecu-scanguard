import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { createHmac } from "https://deno.land/std@0.168.0/crypto/mod.ts";

const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-hub-signature-256, x-gitlab-token, x-github-event, x-gitlab-event',
};

interface WebhookPayload {
    provider: 'github' | 'gitlab';
    event: string;
    repository: {
        name: string;
        full_name: string;
        clone_url: string;
        default_branch: string;
    };
    ref?: string;
    sender?: {
        login: string;
    };
    commits?: any[];
}

// Verify GitHub webhook signature
async function verifyGitHubSignature(payload: string, signature: string, secret: string): Promise<boolean> {
    if (!signature) return false;

    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );

    const signatureBuffer = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
    const expectedSignature = 'sha256=' + Array.from(new Uint8Array(signatureBuffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

    return signature === expectedSignature;
}

// Parse GitHub webhook
function parseGitHubPayload(body: any, event: string): WebhookPayload | null {
    if (event === 'push') {
        return {
            provider: 'github',
            event: 'push',
            repository: {
                name: body.repository?.name,
                full_name: body.repository?.full_name,
                clone_url: body.repository?.clone_url,
                default_branch: body.repository?.default_branch || 'main',
            },
            ref: body.ref?.replace('refs/heads/', ''),
            sender: body.sender,
            commits: body.commits,
        };
    } else if (event === 'pull_request') {
        return {
            provider: 'github',
            event: 'pull_request',
            repository: {
                name: body.repository?.name,
                full_name: body.repository?.full_name,
                clone_url: body.repository?.clone_url,
                default_branch: body.repository?.default_branch || 'main',
            },
            ref: body.pull_request?.head?.ref,
            sender: body.sender,
        };
    }
    return null;
}

// Parse GitLab webhook
function parseGitLabPayload(body: any, event: string): WebhookPayload | null {
    if (event === 'Push Hook') {
        return {
            provider: 'gitlab',
            event: 'push',
            repository: {
                name: body.project?.name,
                full_name: body.project?.path_with_namespace,
                clone_url: body.project?.git_http_url,
                default_branch: body.project?.default_branch || 'main',
            },
            ref: body.ref?.replace('refs/heads/', ''),
            sender: { login: body.user_username },
            commits: body.commits,
        };
    } else if (event === 'Merge Request Hook') {
        return {
            provider: 'gitlab',
            event: 'merge_request',
            repository: {
                name: body.project?.name,
                full_name: body.project?.path_with_namespace,
                clone_url: body.project?.git_http_url,
                default_branch: body.project?.default_branch || 'main',
            },
            ref: body.object_attributes?.source_branch,
            sender: { login: body.user?.username },
        };
    }
    return null;
}

serve(async (req) => {
    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
        return new Response(null, { headers: corsHeaders });
    }

    try {
        const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
        const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
        const webhookSecret = Deno.env.get('WEBHOOK_SECRET') || 'ecu-scanguard-webhook';

        const supabase = createClient(supabaseUrl, supabaseKey);

        // Get raw body for signature verification
        const rawBody = await req.text();
        const body = JSON.parse(rawBody);

        // Detect provider from headers
        const githubEvent = req.headers.get('x-github-event');
        const gitlabEvent = req.headers.get('x-gitlab-event');
        const githubSignature = req.headers.get('x-hub-signature-256');
        const gitlabToken = req.headers.get('x-gitlab-token');

        let payload: WebhookPayload | null = null;
        let provider: 'github' | 'gitlab';

        if (githubEvent) {
            // GitHub webhook
            provider = 'github';

            // Verify signature if secret is configured
            if (webhookSecret && githubSignature) {
                const isValid = await verifyGitHubSignature(rawBody, githubSignature, webhookSecret);
                if (!isValid) {
                    console.error('Invalid GitHub webhook signature');
                    return new Response(JSON.stringify({ error: 'Invalid signature' }), {
                        status: 401,
                        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
                    });
                }
            }

            payload = parseGitHubPayload(body, githubEvent);

        } else if (gitlabEvent) {
            // GitLab webhook
            provider = 'gitlab';

            // Verify token if configured
            if (webhookSecret && gitlabToken !== webhookSecret) {
                console.error('Invalid GitLab webhook token');
                return new Response(JSON.stringify({ error: 'Invalid token' }), {
                    status: 401,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
                });
            }

            payload = parseGitLabPayload(body, gitlabEvent);

        } else {
            // Manual trigger via API
            if (body.gitUrl && body.gitBranch) {
                const urlParts = body.gitUrl.replace(/\.git$/, '').split('/');
                payload = {
                    provider: body.gitProvider || 'github',
                    event: 'manual',
                    repository: {
                        name: urlParts[urlParts.length - 1],
                        full_name: `${urlParts[urlParts.length - 2]}/${urlParts[urlParts.length - 1]}`,
                        clone_url: body.gitUrl,
                        default_branch: body.gitBranch,
                    },
                    ref: body.gitBranch,
                };
                provider = body.gitProvider || 'github';
            } else {
                return new Response(JSON.stringify({ error: 'Unknown webhook source' }), {
                    status: 400,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
                });
            }
        }

        if (!payload) {
            console.log('Ignoring unsupported event type');
            return new Response(JSON.stringify({ message: 'Event ignored' }), {
                status: 200,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            });
        }

        console.log(`Processing ${payload.provider} ${payload.event} for ${payload.repository.full_name}`);

        // Check if this repository has webhook scanning enabled
        const { data: webhookConfig } = await supabase
            .from('webhook_configs')
            .select('*')
            .eq('repository_url', payload.repository.clone_url)
            .eq('enabled', true)
            .maybeSingle();

        // Get the user ID from webhook config or use a system user
        const userId = webhookConfig?.user_id || body.userId;

        if (!userId) {
            console.log('No user associated with this webhook');
            return new Response(JSON.stringify({
                message: 'Webhook received but no user configured',
                repository: payload.repository.full_name
            }), {
                status: 200,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            });
        }

        // Create a new scan record
        const { data: scan, error: scanError } = await supabase
            .from('scans')
            .insert({
                user_id: userId,
                ecu_name: payload.repository.full_name,
                ecu_type: 'Software',
                version: payload.ref || payload.repository.default_branch,
                manufacturer: payload.provider === 'github' ? 'GitHub' : 'GitLab',
                platform: 'Git Repository',
                file_name: `${payload.repository.name}.git`,
                file_size: 0,
                architecture: 'x86_64',
                deep_analysis: true,
                compliance_frameworks: ['ISO 21434', 'MISRA C'],
                status: 'queued',
                progress: 0,
            })
            .select()
            .single();

        if (scanError) {
            console.error('Failed to create scan:', scanError);
            throw new Error('Failed to create scan record');
        }

        // Log the webhook event
        await supabase.from('analysis_logs').insert({
            scan_id: scan.id,
            stage: 'queued',
            log_level: 'info',
            message: `Webhook triggered by ${payload.event} event from ${payload.sender?.login || 'unknown'}`,
        });

        // Trigger the clone-repository function
        const { error: invokeError } = await supabase.functions.invoke('clone-repository', {
            body: {
                scanId: scan.id,
                gitUrl: payload.repository.clone_url,
                gitBranch: payload.ref || payload.repository.default_branch,
                gitProvider: payload.provider,
                accessToken: webhookConfig?.access_token,
                metadata: {
                    ecuName: payload.repository.full_name,
                    ecuType: 'Software',
                    version: payload.ref || payload.repository.default_branch,
                    manufacturer: payload.provider === 'github' ? 'GitHub' : 'GitLab',
                    architecture: 'x86_64',
                    deepAnalysis: true,
                    complianceFrameworks: ['ISO 21434', 'MISRA C'],
                },
            },
        });

        if (invokeError) {
            console.error('Failed to invoke clone-repository:', invokeError);
            // Update scan status to failed
            await supabase.from('scans').update({ status: 'failed' }).eq('id', scan.id);
            throw invokeError;
        }

        console.log(`Scan ${scan.id} triggered successfully`);

        return new Response(JSON.stringify({
            success: true,
            message: 'Scan triggered',
            scanId: scan.id,
            repository: payload.repository.full_name,
            branch: payload.ref || payload.repository.default_branch,
            event: payload.event,
        }), {
            status: 200,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });

    } catch (error) {
        console.error('Webhook error:', error);
        return new Response(JSON.stringify({
            error: error instanceof Error ? error.message : 'Unknown error'
        }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
    }
});
