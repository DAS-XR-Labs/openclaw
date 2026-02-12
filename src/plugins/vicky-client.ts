import { type AgentMessage } from "@mariozechner/pi-agent-core";

/**
 * Start of Selection
 */
export type RiskTier = "LOW" | "MED" | "HIGH";

export type PolicyDecision =
    | { action: "ALLOW"; tier: RiskTier }
    | { action: "BLOCK"; tier: RiskTier; blockReason: string }
    | { action: "REQUIRE_APPROVAL"; tier: RiskTier; approvalId: string; blockReason: string };

export class PolicyDeniedError extends Error {
    public override readonly name = "PolicyDeniedError";
    constructor(
        public readonly reason: string,
        public readonly approvalId?: string,
    ) {
        super(reason);
    }
}

export type ToolRequest = {
    toolName: string;
    arguments: Record<string, unknown>;
    metadata?: {
        agentId?: string;
        sessionKey?: string;
        clientIp?: string;
    };
};

// Startup Check: Warn if secret token is missing to prevent silent failures.
if (!process.env.VICKY_SECRET_TOKEN) {
    console.warn("⚠️ [VickyClient] VICKY_SECRET_TOKEN is not set. All Anonymization/Gatekeeper calls will fail (401).");
}

export class VickyClient {
    private static readonly baseUrl: string = "http://127.0.0.1:3000";
    private static readonly timeoutMs: number = 300;
    private static readonly maxRetries: number = 2;

    /**
     * Check if a tool execution is allowed.
     * Implements strict PRP contract:
     * - 300ms timeout
     * - Max 2 retries on timeout/network (5xx)
     * - Fail-closed on other errors
     */
    static async checkPermission(request: ToolRequest): Promise<PolicyDecision> {
        let attempt = 0;
        let lastError: unknown;

        const secretToken = process.env.VICKY_SECRET_TOKEN || "";

        while (attempt <= this.maxRetries) {
            attempt++;
            try {
                const controller = new AbortController();
                const id = setTimeout(() => controller.abort(), this.timeoutMs);

                const response = await fetch(`${this.baseUrl}/api/check-permission`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "x-vicky-token": secretToken
                    },
                    body: JSON.stringify(request),
                    signal: controller.signal,
                });

                clearTimeout(id);

                if (response.ok) {
                    const data = (await response.json()) as PolicyDecision;
                    return data;
                }

                if (response.status >= 500) {
                    throw new Error(`Vicky API Server Error: ${response.status}`);
                }

                // 4xx errors are client/policy confusion, treated as failure but likely not retried if it was protocol error.
                // But for safety, we treat known 4xx as non-retriable fatal.
                throw new Error(`Vicky API Client Error: ${response.status}`);
            } catch (err: unknown) {
                lastError = err;
                const isTimeout = err instanceof Error && err.name === "AbortError";
                // Retry only on Timeout or 5xx-like fetch errors (network)
                // If it's a fetch error (TypeError typically for network), we retry.
                const isNetworkError =
                    err instanceof TypeError || (err instanceof Error && err.message.includes("fetch"));
                const isServerError = err instanceof Error && err.message.includes("Vicky API Server Error");

                if (!isTimeout && !isNetworkError && !isServerError) {
                    // Break immediately on non-transient errors
                    break;
                }

                // If we have retries left, loop
                if (attempt <= this.maxRetries) {
                    // optionally small backoff? PRP says "retry", doesn't specify backoff.
                    // Immediate retry for tight 300ms budget is usually better.
                    continue;
                }
            }
        }

        // Fallback Matrix
        // If we are here, we exhausted retries or hit a fatal error.
        // Default to Fail-Closed (BLOCK).
        // In a real scenario, we might want Fail-Open for LOW risk if mapped locally,
        // but without local policy cache, we must be safe.
        // PRP: "Apply fallback matrix by risk tier". Using stricter default for now.

        // Check if tool is obviously low risk? 
        // We don't have local risk map. We assume "HIGH".

        // Log failure
        console.error(`[VickyClient] Check permission failed after ${attempt} attempts:`, lastError);

        // Default Fail-Closed
        return {
            action: "BLOCK",
            tier: "HIGH",
            blockReason: `Security Gatekeeper Unreachable: ${lastError instanceof Error ? lastError.message : String(lastError)}`,
        };
    }

    /**
     * Anonymize text by calling Vicky API.
     */
    static async anonymize(text: string, sessionKey: string): Promise<string> {
        return this.handleTextRequest(text, sessionKey, "/api/anonymize", "sanitizedText");
    }

    /**
     * Restore original text by calling Vicky API.
     */
    static async restore(text: string, sessionKey: string): Promise<string> {
        try {
            return await this.handleTextRequest(text, sessionKey, "/api/deanonymize", "originalText");
        } catch (err) {
            // Fail-closed for restoration means we return the sanitized text?
            // User requested fail-closed for tool execution.
            // But for simple string restore, re-throwing ensures the caller handles the failure.
            throw err;
        }
    }

    /**
     * Recursively scan and restore strings within an object/array.
     */
    static async restoreRecursive(params: any, sessionKey: string): Promise<any> {
        if (typeof params === "string") {
            // Optimization: Only call API if it looks like a placeholder
            if (this.looksLikePlaceholder(params)) {
                return this.restore(params, sessionKey);
            }
            return params;
        }

        if (Array.isArray(params)) {
            return Promise.all(params.map(item => this.restoreRecursive(item, sessionKey)));
        }

        if (params && typeof params === "object") {
            const result: any = {};
            for (const key of Object.keys(params)) {
                result[key] = await this.restoreRecursive(params[key], sessionKey);
            }
            return result;
        }

        return params;
    }


    private static looksLikePlaceholder(text: string): boolean {
        // Simple heuristic to avoid API calls for obviously safe strings
        // Placeholders usually look like EMAIL_01, PHONE_01, etc.
        // User requested STRICT regex: /^[A-Z]+_\d+$/
        return /^[A-Z]+_\d+$/.test(text);
    }


    private static async handleTextRequest(text: string, sessionKey: string, endpoint: string, resultKey: string): Promise<string> {
        if (!text) return text;

        let attempt = 0;
        let lastError: unknown;
        const secretToken = process.env.VICKY_SECRET_TOKEN || "";

        while (attempt <= this.maxRetries) {
            attempt++;
            try {
                const controller = new AbortController();
                const id = setTimeout(() => controller.abort(), this.timeoutMs);

                const response = await fetch(`${this.baseUrl}${endpoint}`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "x-openclaw-session-id": sessionKey,
                        "x-vicky-token": secretToken
                    },
                    body: JSON.stringify({ text }),
                    signal: controller.signal,
                });

                clearTimeout(id);

                if (response.ok) {
                    const data = await response.json();
                    return data[resultKey] || text;
                }

                if (response.status >= 500) {
                    throw new Error(`Vicky API Server Error: ${response.status}`);
                }
                throw new Error(`Vicky API Client Error: ${response.status}`);

            } catch (err) {
                lastError = err;
                const isTimeout = err instanceof Error && err.name === "AbortError";
                const isNetworkError =
                    err instanceof TypeError || (err instanceof Error && err.message.includes("fetch"));
                const isServerError = err instanceof Error && err.message.includes("Vicky API Server Error");

                if (!isTimeout && !isNetworkError && !isServerError) {
                    break;
                }

                if (attempt <= this.maxRetries) {
                    continue;
                }
            }
        }
        throw lastError || new Error("Unknown error");
    }
}
