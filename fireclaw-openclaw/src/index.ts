/** Fireclaw plugin entry point for OpenClaw. */

import { DomainGuard } from "./domain-guard.js";
import { EmailGuard } from "./email-guard.js";
import type { PluginAPI } from "./types.js";

export { DomainGuard, extractHost, ancestorDomains } from "./domain-guard.js";
export { EmailGuard } from "./email-guard.js";

/** Register the fireclaw plugin with an OpenClaw plugin API. */
export function register(api: PluginAPI): void {
  const cfg = api.config ?? {};
  const blocklist = (cfg.blocklist as string[] | undefined) ?? [];
  const allowlist = (cfg.allowlist as string[] | undefined) ?? [];
  const domainGuard = new DomainGuard(blocklist, allowlist);
  const emailGuard = new EmailGuard();

  api.on("before_tool_call", (call) => {
    // Domain check
    const domainBlock = domainGuard.check(call.name, call.args);
    if (domainBlock) return { block: true, blockReason: domainBlock };

    // Email deletion check
    const emailBlock = emailGuard.check(call.name, call.args);
    if (emailBlock) return { block: true, blockReason: emailBlock };

    return undefined;
  });
}
