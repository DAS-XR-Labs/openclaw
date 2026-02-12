
import type { OpenClawPluginDefinition } from "./types.js";
import { VickyClient, PolicyDeniedError } from "./vicky-client.js";


const VickyPlugin: OpenClawPluginDefinition = {
    id: "vicky-gatekeeper",
    name: "Vicky Gatekeeper",
    description: "Enforces security policies via external Vicky service",
    version: "1.0.0",
    configSchema: {
        jsonSchema: {
            type: "object",
            properties: {
                enabled: { type: "boolean", default: true },
                vickyUrl: { type: "string", default: "http://127.0.0.1:3000" },
            },
        },
        uiHints: {
            enabled: { label: "Enable Vicky Gatekeeper" },
            vickyUrl: { label: "Vicky API URL" },
        },
    },

    activate: (api) => {
        const logger = api.logger;
        const config = api.pluginConfig as { enabled?: boolean; vickyUrl?: string };

        if (config.enabled === false) {
            logger.info("[VickyPlugin] Disabled by configuration");
            return;
        }

        logger.info(`[VickyPlugin] Active. Gatekeeper URL: ${config.vickyUrl ?? "default"}`);

        api.on("before_tool_call", async (event, ctx) => {
            const toolName = event.toolName;
            const args = event.params;
            const sessionKey = ctx.sessionKey || ""; // Fix undefined sessionKey

            logger.debug(`[VickyPlugin] Checking permission for tool: ${toolName}`);

            try {
                // 1. JIT Restore: Restore PII in arguments so the tool receives real values.
                // We also check permission against the REAL values.
                const restoredArgs = await VickyClient.restoreRecursive(args || {}, sessionKey);

                const decision = await VickyClient.checkPermission({
                    toolName,
                    arguments: restoredArgs,
                    metadata: {
                        agentId: ctx.agentId,
                        sessionKey: sessionKey,
                    },
                });

                if (decision.action === "ALLOW") {
                    logger.debug(`[VickyPlugin] Allowed ${toolName} (${decision.tier})`);
                    // Return the restored arguments to the tool runner
                    return {
                        params: restoredArgs,
                    };
                }

                if (decision.action === "BLOCK") {
                    const reason = decision.blockReason || "Blocked by Policy";
                    logger.warn(`[VickyPlugin] BLOCKED ${toolName} (${decision.tier}): ${reason}`);
                    return {
                        block: true,
                        blockReason: reason,
                    };
                }

                if (decision.action === "REQUIRE_APPROVAL") {
                    const reason = decision.blockReason || "Approval Required";
                    const approvalId = decision.approvalId;
                    logger.warn(`[VickyPlugin] REQUIRE_APPROVAL ${toolName} (${decision.tier}): ${reason} (ID: ${approvalId})`);

                    // Return blocking result with structured reason/ID so agent can handle it
                    return {
                        block: true,
                        blockReason: `${reason} (Approval ID: ${approvalId})`,
                    };
                }

            } catch (err) {
                logger.error(`[VickyPlugin] Error checking permission for ${toolName}: ${err}`);
                // Fail-Closed on error
                return {
                    block: true,
                    blockReason: "Security Gatekeeper Error (Fail-Closed)",
                };
            }
        });
    },
};

export default VickyPlugin;
