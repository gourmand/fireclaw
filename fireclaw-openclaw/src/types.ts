/** Minimal OpenClaw type stubs — no dependency on OpenClaw packages. */

export interface ToolCall {
  name: string;
  args: Record<string, unknown>;
}

export interface HookResponse {
  block: true;
  blockReason: string;
}

export type BeforeToolCallHandler = (
  call: ToolCall,
) => HookResponse | undefined;

export interface PluginAPI {
  on(event: "before_tool_call", handler: BeforeToolCallHandler): void;
  config: Record<string, unknown>;
}
