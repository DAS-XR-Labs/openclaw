import type { OpenClawPluginDefinition } from "./types.js";
import { VickyClient, PolicyDeniedError } from "./vicky-client.js";

const client = new VickyClient();

const VickyPlugin: OpenClawPluginDefinition = {
  id: "vicky",
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
    const rawConfig = api.pluginConfig as { enabled?: boolean; vickyUrl?: string } | undefined;

    const config = {
      enabled: rawConfig?.enabled ?? true,
      vickyUrl: rawConfig?.vickyUrl ?? "http://127.0.0.1:3000",
    };

    if (config.enabled === false) {
      logger.info("[VickyPlugin] Disabled by configuration");
      return;
    }

    logger.info(`[VickyPlugin] Active. Gatekeeper URL: ${config.vickyUrl ?? "default"}`);

    api.on("before_tool_call", async (event, ctx) => {
      const toolName = event.toolName;
      const args = event.params;

      logger?.debug?.(`[VickyPlugin] Checking permission for tool: ${toolName}`);
      logger?.debug?.call(logger, `[VickyPlugin] Checking permission for tool: `);
      try {
        const decision = await client.checkPermission({
          toolName,
          arguments: args,
          metadata: {
            agentId: ctx.agentId,
            sessionKey: ctx.sessionKey,
          },
        });

        if (decision.action === "ALLOW") {
          logger?.debug?.(`[VickyPlugin] Allowed ${toolName} (${decision.tier})`);
          logger?.debug?.call(logger, `[VickyPlugin] Allowed  ()`);
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
          logger.warn(
            `[VickyPlugin] REQUIRE_APPROVAL ${toolName} (${decision.tier}): ${reason} (ID: ${approvalId})`,
          );

          // Return blocking result with structured reason/ID so agent can handle it
          return {
            block: true,
            blockReason: `${reason} (Approval ID: ${approvalId})`,
            // We can attach custom metadata if the hook result type allows,
            // but 'blockReason' is standard. We embed ID for visibility.
          };
        }
      } catch (err) {
        logger.error(`[VickyPlugin] Error checking permission for ${toolName}: ${err}`);
        // Fail-Closed on error (assuming critical/unknown state)
        // If we want fail-open for LOW risk, we'd need that context.
        return {
          block: true,
          blockReason: "Security Gatekeeper Error (Fail-Closed)",
        };
      }
    });
  },
};

export default VickyPlugin;
