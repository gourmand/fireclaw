import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { DomainGuard, extractHost, ancestorDomains } from "../domain-guard.js";

describe("extractHost", () => {
  it("extracts host from full URL", () => {
    assert.equal(extractHost("https://evil.example.com/path"), "evil.example.com");
  });

  it("extracts host from bare domain", () => {
    assert.equal(extractHost("evil.example.com"), "evil.example.com");
  });

  it("extracts host from domain with port", () => {
    assert.equal(extractHost("evil.example.com:8080"), "evil.example.com");
  });

  it("extracts host from URL with port", () => {
    assert.equal(extractHost("https://evil.example.com:443/x"), "evil.example.com");
  });

  it("returns undefined for empty string", () => {
    assert.equal(extractHost(""), undefined);
  });

  it("normalizes case", () => {
    assert.equal(extractHost("https://EVIL.Example.COM/"), "evil.example.com");
  });

  it("strips trailing dot", () => {
    assert.equal(extractHost("evil.example.com."), "evil.example.com");
  });

  it("returns undefined for malformed URL", () => {
    assert.equal(extractHost("https://"), undefined);
  });
});

describe("ancestorDomains", () => {
  it("generates all ancestor domains", () => {
    assert.deepEqual(ancestorDomains("evil.sub.duckdns.org"), [
      "evil.sub.duckdns.org",
      "sub.duckdns.org",
      "duckdns.org",
      "org",
    ]);
  });
});

describe("DomainGuard", () => {
  describe("built-in blocklist", () => {
    const guard = new DomainGuard();

    it("blocks eicar.org", () => {
      assert.ok(guard.isBlocked("eicar.org"));
    });

    it("blocks duckdns.org subdomain", () => {
      assert.ok(guard.isBlocked("evil.duckdns.org"));
    });

    it("passes safe domain", () => {
      assert.ok(!guard.isBlocked("github.com"));
    });
  });

  describe("check() with tool calls", () => {
    const guard = new DomainGuard();

    it("blocks malware domain in http_request", () => {
      const reason = guard.check("http_request", { url: "https://eicar.org/test" });
      assert.ok(reason != null);
      assert.ok(reason!.includes("eicar.org"));
    });

    it("blocks malware domain in web_fetch", () => {
      const reason = guard.check("web_fetch", { url: "https://evil.duckdns.org/payload" });
      assert.ok(reason);
    });

    it("passes safe domain in http_request", () => {
      const reason = guard.check("http_request", { url: "https://api.github.com/repos" });
      assert.equal(reason, undefined);
    });

    it("ignores non-URL tools", () => {
      const reason = guard.check("write_file", { url: "https://eicar.org/test" });
      assert.equal(reason, undefined);
    });

    it("handles missing URL in args", () => {
      const reason = guard.check("http_request", { method: "GET" });
      assert.equal(reason, undefined);
    });
  });

  describe("extra blocklist", () => {
    const guard = new DomainGuard(["evil-custom.com"]);

    it("blocks extra domain", () => {
      assert.ok(guard.isBlocked("evil-custom.com"));
    });

    it("blocks subdomain of extra domain", () => {
      assert.ok(guard.isBlocked("sub.evil-custom.com"));
    });
  });

  describe("allowlist", () => {
    it("overrides blocklist for specific domain", () => {
      const guard = new DomainGuard([], ["safe.duckdns.org"]);
      assert.ok(!guard.isBlocked("safe.duckdns.org"));
    });

    it("parent allow overrides child block", () => {
      const guard = new DomainGuard(["sub.safe.com"], ["safe.com"]);
      assert.ok(!guard.isBlocked("sub.safe.com"));
    });

    it("still blocks non-allowed subdomains", () => {
      const guard = new DomainGuard([], ["safe.duckdns.org"]);
      assert.ok(guard.isBlocked("evil.duckdns.org"));
    });
  });
});
