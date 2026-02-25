# fireclaw

A firewall for your claw.
Stop your claw from deleting emails and calling malware domains. The safety net so you can sleep while your claw runs.

Website: https://fireclawlabs.com

## Addons

### fireclaw-zeroclaw (Rust)

Native addon for [ZeroClaw](https://github.com/zeroclaw). Implements ZeroClaw's `HookHandler` trait to intercept tool calls before they execute.

```toml
[fireclaw]
extra_blocked_domains = ["evil-custom.com"]
allow_list = ["safe.duckdns.org"]
blocked_tools = ["composio"]
```

```bash
cd fireclaw-zeroclaw && cargo test
```

### fireclaw-openclaw (TypeScript)

Plugin for [OpenClaw](https://github.com/openclaw). Hooks into `before_tool_call` to block malware domains and email deletion.

```json
{ "plugins": { "fireclaw": { "blocklist": [], "allowlist": [], "strict": true } } }
```

```bash
cd fireclaw-openclaw && npm install && npm run build && npm test
```

## What gets blocked

- **Malware domains**: eicar.org, duckdns.org, no-ip.com, hopto.org, zapto.org, sytes.net, and more — plus all subdomains
- **Email deletion**: Tools like `delete_email`, `expunge`, `delete_messages`, and bash commands containing `himalaya delete` or IMAP delete patterns
- **Custom tools**: Configure `blocked_tools` to hard-block any tool by name

Allow-lists override the blocklist for specific domains when you need exceptions.
