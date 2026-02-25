/** Domain blocklist guard — blocks requests to known malware domains. */

const BUILTIN_BLOCKLIST: readonly string[] = [
  // EICAR test / demonstration domains
  "eicar.org",
  "eicar.com",
  // Commonly abused free dynamic-DNS services used in malware C2
  "no-ip.com",
  "duckdns.org",
  "hopto.org",
  "zapto.org",
  "sytes.net",
  // Known malware test domains
  "malware.wicar.org",
  "testsafebrowsing.appspot.com",
];

/** URL-bearing tool names whose args should be domain-checked. */
const URL_BEARING_TOOLS = ["web_fetch", "browser", "http_request"];

/** JSON keys that typically hold a URL in tool arguments. */
const URL_KEYS = ["url", "uri", "href", "endpoint"];

export class DomainGuard {
  private readonly blocked: Set<string>;
  private readonly allowed: Set<string>;

  constructor(extraBlocked: string[] = [], allowlist: string[] = []) {
    this.blocked = new Set([
      ...BUILTIN_BLOCKLIST.map((d) => d.toLowerCase()),
      ...extraBlocked.map((d) => d.toLowerCase()),
    ]);
    this.allowed = new Set(allowlist.map((d) => d.toLowerCase()));
  }

  /** Check a tool call. Returns a block reason string, or undefined if safe. */
  check(toolName: string, args: Record<string, unknown>): string | undefined {
    const name = toolName.toLowerCase();
    if (!URL_BEARING_TOOLS.some((t) => name.includes(t))) return undefined;

    const url = this.extractUrl(args);
    if (!url) return undefined;

    const host = extractHost(url);
    if (!host) return undefined;

    if (this.isBlocked(host)) {
      return `fireclaw: blocked request to malware domain '${host}'`;
    }
    return undefined;
  }

  /** Returns true if the domain (or any ancestor) is blocked and not allowed. */
  isBlocked(domain: string): boolean {
    const ancestors = ancestorDomains(domain);
    if (ancestors.some((a) => this.allowed.has(a))) return false;
    return ancestors.some((a) => this.blocked.has(a));
  }

  private extractUrl(args: Record<string, unknown>): string | undefined {
    for (const key of URL_KEYS) {
      const val = args[key];
      if (typeof val === "string") return val;
    }
    return undefined;
  }
}

/** Extract hostname from a URL or bare domain. */
export function extractHost(url: string): string | undefined {
  const trimmed = url.trim();
  if (!trimmed) return undefined;

  let host: string;

  if (/^https?:\/\//i.test(trimmed)) {
    try {
      const parsed = new URL(trimmed);
      host = parsed.hostname;
    } catch {
      return undefined;
    }
  } else {
    // Bare domain or host:port
    host = trimmed.split(":")[0];
  }

  const normalized = host.toLowerCase().replace(/\.$/, "");
  return normalized || undefined;
}

/** Generate ancestor domains for hierarchical matching. */
export function ancestorDomains(domain: string): string[] {
  const parts = domain.split(".");
  return parts.map((_, i) => parts.slice(i).join("."));
}
