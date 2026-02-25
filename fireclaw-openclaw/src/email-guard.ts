/** Email deletion guard — blocks tool calls that would delete emails. */

/** Tool names that are hard-blocked when performing destructive actions. */
const EMAIL_DELETE_TOOLS = [
  "delete_email",
  "trash_email",
  "remove_email",
  "expunge",
  "delete_messages",
];

/** Patterns in bash/shell commands that indicate email deletion. */
const BASH_DELETE_PATTERNS: RegExp[] = [
  /himalaya\s+.*\bdelete\b/i,
  /himalaya\s+.*\bexpunge\b/i,
  /\bSTORE\b.*\+FLAGS.*\\Deleted/i,
  /\bEXPUNGE\b/i,
];

export class EmailGuard {
  /** Check a tool call. Returns a block reason string, or undefined if safe. */
  check(toolName: string, args: Record<string, unknown>): string | undefined {
    const name = toolName.toLowerCase();

    // Hard-block known email deletion tools
    if (EMAIL_DELETE_TOOLS.some((t) => name.includes(t))) {
      return `fireclaw: email deletion tool '${toolName}' is blocked`;
    }

    // Check bash/shell commands for email deletion patterns
    if (name === "bash" || name === "shell" || name === "execute_command") {
      const command = typeof args.command === "string" ? args.command : "";
      for (const pattern of BASH_DELETE_PATTERNS) {
        if (pattern.test(command)) {
          return `fireclaw: blocked bash command containing email deletion pattern`;
        }
      }
    }

    return undefined;
  }
}
