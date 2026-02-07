
import type { AnyAgentTool } from "./pi-tools.types.js";
import type { HookRunner } from "../plugins/hooks.js";
import type { PluginHookToolContext } from "../plugins/types.js";

/**
 * Wraps an agent tool with hooks for `before_tool_call` and `after_tool_call`.
 * If `before_tool_call` returns a blocking result, execution is prevented and an error is thrown.
 */
export function wrapToolWithHooks(
    tool: AnyAgentTool,
    hookRunner: HookRunner | null,
    context: Omit<PluginHookToolContext, "toolName">
): AnyAgentTool {
    if (!hookRunner) {
        return tool;
    }

    const originalExecute = tool.execute;
    if (!originalExecute) {
        return tool;
    }

    return {
        ...tool,
        execute: async (toolCallId: string, params: any, signal?: AbortSignal, onUpdate?: (update: any) => void) => {
            // Run before_tool_call hook
            const hookResult = await hookRunner.runBeforeToolCall(
                {
                    toolName: tool.name,
                    params: params || {},
                },
                { ...context, toolName: tool.name }
            );

            if (hookResult?.block) {
                const reason = hookResult.blockReason || "Blocked by plugin hook";
                throw new Error(`Tool execution blocked: ${reason}`);
            }

            // If hook modified params, use them (optional feature, not strictly needed for Vicky but good practice)
            const effectiveParams = hookResult?.params || params;

            try {
                const result = await originalExecute(toolCallId, effectiveParams, signal, onUpdate);

                // Run after_tool_call hook (fire-and-forget)
                await hookRunner.runAfterToolCall(
                    {
                        toolName: tool.name,
                        params: effectiveParams || {},
                        result,
                    },
                    { ...context, toolName: tool.name }
                );

                return result;
            } catch (err) {
                // Run after_tool_call hook with error
                await hookRunner.runAfterToolCall(
                    {
                        toolName: tool.name,
                        params: effectiveParams || {},
                        error: String(err),
                    },
                    { ...context, toolName: tool.name }
                );
                throw err;
            }
        },
    };
}
