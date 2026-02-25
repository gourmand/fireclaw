//! Fireclaw safety-net addon for ZeroClaw.
//!
//! Implements ZeroClaw's `HookHandler` trait to intercept tool calls and block:
//! - Requests to known malware domains
//! - Email deletion tools
//! - Any custom-blocked tool names
//!
//! # Usage
//!
//! Register `FireclawHook` with ZeroClaw's hook system:
//!
//! ```ignore
//! use fireclaw_zeroclaw::FireclawHook;
//!
//! let hook = FireclawHook::from_config(&config);
//! runtime.register_hook(Box::new(hook));
//! ```

pub mod blocklist;
pub mod config;

use blocklist::{extract_host, is_blocked_domain, BUILTIN_BLOCKLIST};
use config::FireclawConfig;

/// Result of a hook invocation. Mirrors ZeroClaw's `HookResult` enum.
#[derive(Debug, Clone, PartialEq)]
pub enum HookResult {
    /// Allow the tool call to proceed (possibly with modified args).
    Continue(String, serde_json::Value),
    /// Block the tool call with a reason.
    Cancel(String),
}

/// Tools that interact with URLs and should have their arguments checked.
const URL_BEARING_TOOLS: &[&str] = &["http_request", "web_fetch", "browser"];

/// JSON keys that typically contain URLs in tool arguments.
const URL_KEYS: &[&str] = &["url", "uri", "href", "endpoint"];

/// The Fireclaw hook for ZeroClaw's `HookHandler` trait.
///
/// Checks every tool call against a domain blocklist and a set of hard-blocked
/// tool names. Runs at priority 100 (before most other hooks).
#[derive(Debug, Clone)]
pub struct FireclawHook {
    blocked_domains: Vec<String>,
    allowed_domains: Vec<String>,
    blocked_tools: Vec<String>,
}

impl FireclawHook {
    /// Create a new hook from a `FireclawConfig`.
    pub fn from_config(config: &FireclawConfig) -> Self {
        let mut blocked: Vec<String> = BUILTIN_BLOCKLIST
            .iter()
            .map(|s| s.to_string())
            .collect();
        blocked.extend(config.extra_blocked_domains.iter().map(|s| s.to_lowercase()));

        Self {
            blocked_domains: blocked,
            allowed_domains: config.allow_list.iter().map(|s| s.to_lowercase()).collect(),
            blocked_tools: config.blocked_tools.iter().map(|s| s.to_lowercase()).collect(),
        }
    }

    /// Create a hook with default configuration (built-in blocklist only).
    pub fn default_config() -> Self {
        Self::from_config(&FireclawConfig::default())
    }

    /// The hook priority. Higher values run first. Fireclaw uses 100.
    pub fn priority(&self) -> u32 {
        100
    }

    /// Evaluate a tool call and decide whether to allow or block it.
    ///
    /// This is the core method that would be called by ZeroClaw's
    /// `HookHandler::before_tool_call`.
    pub fn before_tool_call(
        &self,
        tool_name: &str,
        args: serde_json::Value,
    ) -> HookResult {
        let name_lower = tool_name.to_lowercase();

        // Check hard-blocked tool names
        if self.blocked_tools.iter().any(|bt| name_lower.contains(bt)) {
            return HookResult::Cancel(format!(
                "fireclaw: tool '{}' is blocked by policy",
                tool_name
            ));
        }

        // For URL-bearing tools, extract and check the domain
        if URL_BEARING_TOOLS.iter().any(|t| name_lower.contains(t)) {
            if let Some(url) = self.extract_url_from_args(&args) {
                if let Some(host) = extract_host(&url) {
                    if is_blocked_domain(&host, &self.blocked_domains, &self.allowed_domains) {
                        return HookResult::Cancel(format!(
                            "fireclaw: blocked request to malware domain '{}'",
                            host
                        ));
                    }
                }
            }
        }

        HookResult::Continue(tool_name.to_string(), args)
    }

    /// Try to extract a URL from tool call arguments by checking common keys.
    fn extract_url_from_args(&self, args: &serde_json::Value) -> Option<String> {
        if let serde_json::Value::Object(map) = args {
            for key in URL_KEYS {
                if let Some(serde_json::Value::String(url)) = map.get(*key) {
                    return Some(url.clone());
                }
            }
        }
        None
    }
}

// The actual ZeroClaw trait impl would look like this (commented out since
// we don't depend on the zeroclaw crate directly):
//
// #[async_trait::async_trait]
// impl zeroclaw::hooks::HookHandler for FireclawHook {
//     fn priority(&self) -> u32 { self.priority() }
//
//     async fn before_tool_call(
//         &self,
//         name: &str,
//         args: serde_json::Value,
//     ) -> zeroclaw::hooks::HookResult {
//         match self.before_tool_call(name, args) {
//             HookResult::Continue(n, a) => zeroclaw::hooks::HookResult::Continue((n, a)),
//             HookResult::Cancel(reason) => zeroclaw::hooks::HookResult::Cancel(reason),
//         }
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn default_hook() -> FireclawHook {
        FireclawHook::default_config()
    }

    fn hook_with_config(
        extra_blocked: &[&str],
        allow: &[&str],
        blocked_tools: &[&str],
    ) -> FireclawHook {
        FireclawHook::from_config(&FireclawConfig {
            extra_blocked_domains: extra_blocked.iter().map(|s| s.to_string()).collect(),
            allow_list: allow.iter().map(|s| s.to_string()).collect(),
            blocked_tools: blocked_tools.iter().map(|s| s.to_string()).collect(),
        })
    }

    // -- Tool blocking --

    #[test]
    fn blocked_tool_is_cancelled() {
        let hook = hook_with_config(&[], &[], &["composio"]);
        let result = hook.before_tool_call("composio_delete_email", json!({}));
        assert!(matches!(result, HookResult::Cancel(_)));
    }

    #[test]
    fn non_blocked_tool_continues() {
        let hook = default_hook();
        let result = hook.before_tool_call("read_file", json!({"path": "/tmp/test"}));
        assert!(matches!(result, HookResult::Continue(_, _)));
    }

    // -- Domain blocking via URL-bearing tools --

    #[test]
    fn malware_domain_in_http_request_is_blocked() {
        let hook = default_hook();
        let result = hook.before_tool_call(
            "http_request",
            json!({"url": "https://evil.duckdns.org/payload"}),
        );
        assert!(matches!(result, HookResult::Cancel(_)));
    }

    #[test]
    fn malware_domain_in_web_fetch_is_blocked() {
        let hook = default_hook();
        let result = hook.before_tool_call(
            "web_fetch",
            json!({"url": "https://eicar.org/test"}),
        );
        assert!(matches!(result, HookResult::Cancel(_)));
    }

    #[test]
    fn safe_domain_in_http_request_passes() {
        let hook = default_hook();
        let result = hook.before_tool_call(
            "http_request",
            json!({"url": "https://api.github.com/repos"}),
        );
        assert!(matches!(result, HookResult::Continue(_, _)));
    }

    #[test]
    fn subdomain_of_blocked_domain_is_blocked() {
        let hook = default_hook();
        let result = hook.before_tool_call(
            "http_request",
            json!({"url": "https://payload.c2.no-ip.com/x"}),
        );
        assert!(matches!(result, HookResult::Cancel(_)));
    }

    #[test]
    fn allowed_domain_overrides_blocklist() {
        let hook = hook_with_config(&[], &["safe.duckdns.org"], &[]);
        let result = hook.before_tool_call(
            "http_request",
            json!({"url": "https://safe.duckdns.org/api"}),
        );
        assert!(matches!(result, HookResult::Continue(_, _)));
    }

    #[test]
    fn extra_blocked_domain_is_blocked() {
        let hook = hook_with_config(&["evil-custom.com"], &[], &[]);
        let result = hook.before_tool_call(
            "web_fetch",
            json!({"url": "https://evil-custom.com/mal"}),
        );
        assert!(matches!(result, HookResult::Cancel(_)));
    }

    // -- Non-URL tools pass through --

    #[test]
    fn non_url_tool_ignores_domain_check() {
        let hook = default_hook();
        let result = hook.before_tool_call(
            "write_file",
            json!({"url": "https://eicar.org/test", "path": "/tmp/x"}),
        );
        assert!(matches!(result, HookResult::Continue(_, _)));
    }

    // -- Edge cases --

    #[test]
    fn missing_url_in_args_continues() {
        let hook = default_hook();
        let result = hook.before_tool_call("http_request", json!({"method": "GET"}));
        assert!(matches!(result, HookResult::Continue(_, _)));
    }

    #[test]
    fn empty_args_continues() {
        let hook = default_hook();
        let result = hook.before_tool_call("http_request", json!({}));
        assert!(matches!(result, HookResult::Continue(_, _)));
    }

    #[test]
    fn priority_is_100() {
        let hook = default_hook();
        assert_eq!(hook.priority(), 100);
    }
}
