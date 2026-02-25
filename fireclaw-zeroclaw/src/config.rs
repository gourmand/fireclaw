/// Configuration for the Fireclaw hook, deserializable from ZeroClaw's config.toml.
use serde::Deserialize;

/// Top-level configuration section for `[fireclaw]` in config.toml.
///
/// ```toml
/// [fireclaw]
/// extra_blocked_domains = ["evil-custom.com"]
/// allow_list = ["safe.duckdns.org"]
/// blocked_tools = ["composio"]
/// ```
#[derive(Debug, Clone, Deserialize, Default)]
pub struct FireclawConfig {
    /// Additional domains to block beyond the built-in list.
    #[serde(default)]
    pub extra_blocked_domains: Vec<String>,

    /// Domains that should always be allowed, overriding the blocklist.
    #[serde(default)]
    pub allow_list: Vec<String>,

    /// Tool names to hard-block entirely (e.g. email deletion tools).
    #[serde(default)]
    pub blocked_tools: Vec<String>,
}
