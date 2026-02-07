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

export class VickyClient {
    private readonly baseUrl: string = "http://127.0.0.1:3000";
    private readonly timeoutMs: number = 300;
    private readonly maxRetries: number = 2;

    /**
     * Check if a tool execution is allowed.
     * Implements strict PRP contract:
     * - 300ms timeout
     * - Max 2 retries on timeout/network (5xx)
     * - Fail-closed on other errors
     */
    async checkPermission(request: ToolRequest): Promise<PolicyDecision> {
        let attempt = 0;
        let lastError: unknown;

        while (attempt <= this.maxRetries) {
            attempt++;
            try {
                const controller = new AbortController();
                const id = setTimeout(() => controller.abort(), this.timeoutMs);

                const response = await fetch(`${this.baseUrl}/api/check-permission`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
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
}
