import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { EmailGuard } from "../email-guard.js";

describe("EmailGuard", () => {
  const guard = new EmailGuard();

  describe("blocks email deletion tools", () => {
    it("blocks delete_email", () => {
      const reason = guard.check("delete_email", {});
      assert.ok(reason != null);
      assert.ok(reason!.includes("blocked"));
    });

    it("blocks trash_email", () => {
      assert.ok(guard.check("trash_email", {}));
    });

    it("blocks expunge", () => {
      assert.ok(guard.check("expunge", {}));
    });

    it("blocks delete_messages", () => {
      assert.ok(guard.check("delete_messages", {}));
    });
  });

  describe("blocks bash email deletion commands", () => {
    it("blocks himalaya delete", () => {
      const reason = guard.check("bash", { command: "himalaya -a work delete 123" });
      assert.ok(reason);
    });

    it("blocks himalaya expunge", () => {
      const reason = guard.check("bash", { command: "himalaya expunge INBOX" });
      assert.ok(reason);
    });

    it("blocks IMAP STORE +FLAGS \\Deleted", () => {
      const reason = guard.check("bash", {
        command: 'curl "imap://server" -X "STORE 1 +FLAGS (\\Deleted)"',
      });
      assert.ok(reason);
    });

    it("blocks EXPUNGE in commands", () => {
      const reason = guard.check("bash", { command: "echo EXPUNGE | nc imap.server 143" });
      assert.ok(reason);
    });
  });

  describe("passes non-destructive operations", () => {
    it("passes read_email", () => {
      assert.equal(guard.check("read_email", {}), undefined);
    });

    it("passes send_email", () => {
      assert.equal(guard.check("send_email", {}), undefined);
    });

    it("passes safe bash commands", () => {
      assert.equal(guard.check("bash", { command: "himalaya list INBOX" }), undefined);
    });

    it("passes bash with no command", () => {
      assert.equal(guard.check("bash", {}), undefined);
    });

    it("passes non-bash tools", () => {
      assert.equal(guard.check("write_file", { command: "himalaya delete 1" }), undefined);
    });
  });
});
