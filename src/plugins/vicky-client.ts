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
    private static get baseUrl(): string {
        return process.env.VICKY_BASE_URL || "http://127.0.0.1:3000";
    }
    private static readonly CHECKS_TIMEOUT = 300;
    private static readonly TEXT_TIMEOUT = 1500;
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
                const id = setTimeout(() => controller.abort(), this.CHECKS_TIMEOUT);

                const response = await fetch(`${this.baseUrl}/api/check-permission`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "x-openclaw-session-id": request.metadata?.sessionKey || "",
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
                throw new Error(`Vicky API Client Error: ${response.status}`);
            } catch (err: unknown) {
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

        console.error(`[VickyClient] Check permission failed after ${attempt} attempts:`, lastError);

        return {
            action: "BLOCK",
            tier: "HIGH",
            blockReason: `Security Gatekeeper Unreachable: ${lastError instanceof Error ? lastError.message : String(lastError)}`,
        };
    }

    /**
     * Anonymize text by calling Vicky API.
     * Fails-closed: throws error if Vicky is unreachable.
     */
    static async anonymize(text: string, sessionKey: string): Promise<string> {
        return this.handleTextRequest(text, sessionKey, "/api/anonymize", "sanitizedText");
    }

    /**
     * Restore original text by calling Vicky API.
     * Fails-closed: throws error if Vicky is unreachable.
     */
    static async restore(text: string, sessionKey: string): Promise<string> {
        return this.handleTextRequest(text, sessionKey, "/api/deanonymize", "originalText");
    }

    /**
     * Recursively scan and restore strings within an object/array.
     * - Idempotent
     * - Handles nested objects/arrays
     * - Leaves non-string primitives alone
     */
    static async restoreRecursive(params: any, sessionKey: string): Promise<any> {
        if (typeof params === "string") {
            // Optimization: Only call API if it contains a placeholder
            if (this.containsPlaceholder(params)) {
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


    public static containsPlaceholder(text: string): boolean {
        // Relaxed Regex: "Contains Placeholder" (e.g. "Call EMAIL_01 now")
        // Uses word boundaries to avoid partial matches on normal words.
        return /\b[A-Z]+_\d+\b/.test(text);
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
                const id = setTimeout(() => controller.abort(), this.TEXT_TIMEOUT);

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
        throw lastError || new Error(`Vicky Service Unreachable (${endpoint}): ${lastError}`);
    }
}
