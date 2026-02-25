/// Built-in malware domain blocklist and domain matching logic.

/// The default set of blocked domains, matching the Python fireclaw implementation.
pub const BUILTIN_BLOCKLIST: &[&str] = &[
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

/// Extract the hostname from a URL string, handling full URLs and bare domains.
pub fn extract_host(url: &str) -> Option<String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }

    let host = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        // Full URL — extract between :// and the next / or end
        let after_scheme = trimmed.split("://").nth(1)?;
        let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
        // Strip userinfo (user:pass@)
        let host_port = authority.rsplit('@').next().unwrap_or(authority);
        // Strip port
        // Handle IPv6 bracket notation [::1]:8080
        if host_port.starts_with('[') {
            host_port.split(']').next().map(|s| &s[1..]).unwrap_or(host_port)
        } else {
            host_port.split(':').next().unwrap_or(host_port)
        }
    } else {
        // Bare domain or host:port
        trimmed.split(':').next().unwrap_or(trimmed)
    };

    let normalized = host.to_lowercase().trim_end_matches('.').to_string();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

/// Generate ancestor domains for hierarchical matching.
/// e.g. "evil.sub.duckdns.org" → ["evil.sub.duckdns.org", "sub.duckdns.org", "duckdns.org", "org"]
pub fn ancestor_domains(domain: &str) -> Vec<String> {
    let parts: Vec<&str> = domain.split('.').collect();
    (0..parts.len())
        .map(|i| parts[i..].join("."))
        .collect()
}

/// Check whether a domain (or any of its ancestors) is in the given blocklist,
/// unless it (or an ancestor) is in the allow-list.
pub fn is_blocked_domain(
    domain: &str,
    blocked: &[String],
    allowed: &[String],
) -> bool {
    let ancestors = ancestor_domains(domain);

    // Allow-list wins: if any ancestor is allowed, pass through
    if ancestors.iter().any(|a| allowed.iter().any(|al| al == a)) {
        return false;
    }

    ancestors.iter().any(|a| blocked.iter().any(|bl| bl == a))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_host_full_url() {
        assert_eq!(extract_host("https://evil.example.com/path"), Some("evil.example.com".into()));
    }

    #[test]
    fn extract_host_bare_domain() {
        assert_eq!(extract_host("evil.example.com"), Some("evil.example.com".into()));
    }

    #[test]
    fn extract_host_with_port() {
        assert_eq!(extract_host("evil.example.com:8080"), Some("evil.example.com".into()));
    }

    #[test]
    fn extract_host_url_with_port() {
        assert_eq!(extract_host("https://evil.example.com:443/x"), Some("evil.example.com".into()));
    }

    #[test]
    fn extract_host_empty() {
        assert_eq!(extract_host(""), None);
    }

    #[test]
    fn extract_host_normalizes_case() {
        assert_eq!(extract_host("https://EVIL.Example.COM/"), Some("evil.example.com".into()));
    }

    #[test]
    fn extract_host_trailing_dot() {
        assert_eq!(extract_host("evil.example.com."), Some("evil.example.com".into()));
    }

    #[test]
    fn ancestor_domains_generates_all() {
        let ancestors = ancestor_domains("evil.sub.duckdns.org");
        assert_eq!(ancestors, vec![
            "evil.sub.duckdns.org",
            "sub.duckdns.org",
            "duckdns.org",
            "org",
        ]);
    }

    #[test]
    fn blocked_domain_exact() {
        let blocked = vec!["evil.com".to_string()];
        assert!(is_blocked_domain("evil.com", &blocked, &[]));
    }

    #[test]
    fn blocked_domain_subdomain() {
        let blocked = vec!["duckdns.org".to_string()];
        assert!(is_blocked_domain("payload.duckdns.org", &blocked, &[]));
    }

    #[test]
    fn safe_domain_passes() {
        let blocked = vec!["evil.com".to_string()];
        assert!(!is_blocked_domain("safe.com", &blocked, &[]));
    }

    #[test]
    fn allow_list_overrides_block() {
        let blocked = vec!["duckdns.org".to_string()];
        let allowed = vec!["safe.duckdns.org".to_string()];
        assert!(!is_blocked_domain("safe.duckdns.org", &blocked, &allowed));
    }

    #[test]
    fn allow_list_parent_overrides_child() {
        let blocked = vec!["sub.safe.com".to_string()];
        let allowed = vec!["safe.com".to_string()];
        assert!(!is_blocked_domain("sub.safe.com", &blocked, &allowed));
    }

    #[test]
    fn malformed_url_handled() {
        assert_eq!(extract_host("not-a-url"), Some("not-a-url".into()));
        assert_eq!(extract_host("://broken"), Some("://broken".into()));
    }
}
