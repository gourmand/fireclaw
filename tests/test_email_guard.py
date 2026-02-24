"""Tests for fireclaw.email_guard."""

import pytest

from fireclaw.email_guard import EmailDeletionBlocked, EmailGuard


# ---------------------------------------------------------------------------
# Minimal IMAP stub – simulates imaplib.IMAP4 interface
# ---------------------------------------------------------------------------


class _FakeIMAP:
    """Minimal fake IMAP4 connection for testing."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def store(self, message_set, command, flags):
        self.calls.append(("store", message_set, command, flags))
        return ("OK", [b"1 (FLAGS (\\Seen))"])

    def expunge(self):
        self.calls.append(("expunge",))
        return ("OK", [b"1"])

    def uid(self, command, *args):
        self.calls.append(("uid", command, *args))
        return ("OK", [b""])

    def delete(self, *args, **kwargs):
        self.calls.append(("delete", args, kwargs))
        return ("OK", [b""])

    def delete_messages(self, *args, **kwargs):
        self.calls.append(("delete_messages", args, kwargs))
        return ("OK", [b""])

    def select(self, mailbox="INBOX"):
        self.calls.append(("select", mailbox))
        return ("OK", [b"5"])

    def search(self, charset, *criteria):
        self.calls.append(("search", charset, *criteria))
        return ("OK", [b"1 2 3"])


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def make_guard(strict: bool = True):
    conn = _FakeIMAP()
    guard = EmailGuard(conn, strict=strict)
    return guard, conn


# ---------------------------------------------------------------------------
# Blocking tests (strict mode)
# ---------------------------------------------------------------------------


class TestEmailGuardBlocks:
    def test_store_deleted_flag_is_blocked(self):
        guard, conn = make_guard()
        with pytest.raises(EmailDeletionBlocked):
            guard.store("1:*", "+FLAGS", "\\Deleted")
        assert conn.calls == [], "underlying connection must not be called"

    def test_store_deleted_flag_silent_is_blocked(self):
        guard, conn = make_guard()
        with pytest.raises(EmailDeletionBlocked):
            guard.store("1", "+FLAGS.SILENT", "\\Deleted")
        assert conn.calls == []

    def test_store_deleted_flag_with_parens_is_blocked(self):
        guard, conn = make_guard()
        with pytest.raises(EmailDeletionBlocked):
            guard.store("1", "+FLAGS", "(\\Deleted)")
        assert conn.calls == []

    def test_expunge_is_blocked(self):
        guard, conn = make_guard()
        with pytest.raises(EmailDeletionBlocked):
            guard.expunge()
        assert conn.calls == []

    def test_uid_expunge_is_blocked(self):
        guard, conn = make_guard()
        with pytest.raises(EmailDeletionBlocked):
            guard.uid("EXPUNGE")
        assert conn.calls == []

    def test_uid_store_deleted_is_blocked(self):
        guard, conn = make_guard()
        with pytest.raises(EmailDeletionBlocked):
            guard.uid("STORE", "1:*", "+FLAGS", "\\Deleted")
        assert conn.calls == []

    def test_delete_method_is_blocked(self):
        guard, conn = make_guard()
        with pytest.raises(EmailDeletionBlocked):
            guard.delete("INBOX")
        assert conn.calls == []

    def test_delete_messages_method_is_blocked(self):
        guard, conn = make_guard()
        with pytest.raises(EmailDeletionBlocked):
            guard.delete_messages([1, 2, 3])
        assert conn.calls == []


# ---------------------------------------------------------------------------
# Pass-through tests (operations that should NOT be blocked)
# ---------------------------------------------------------------------------


class TestEmailGuardPassthrough:
    def test_select_passes_through(self):
        guard, conn = make_guard()
        result = guard.select("INBOX")
        assert result == ("OK", [b"5"])
        assert conn.calls == [("select", "INBOX")]

    def test_search_passes_through(self):
        guard, conn = make_guard()
        result = guard.search(None, "ALL")
        assert result == ("OK", [b"1 2 3"])
        assert conn.calls == [("search", None, "ALL")]

    def test_store_remove_deleted_flag_passes_through(self):
        """Removing the Deleted flag (-FLAGS) must NOT be blocked."""
        guard, conn = make_guard()
        guard.store("1", "-FLAGS", "\\Deleted")
        assert conn.calls == [("store", "1", "-FLAGS", "\\Deleted")]

    def test_store_seen_flag_passes_through(self):
        guard, conn = make_guard()
        guard.store("1", "+FLAGS", "\\Seen")
        assert conn.calls == [("store", "1", "+FLAGS", "\\Seen")]

    def test_uid_fetch_passes_through(self):
        guard, conn = make_guard()
        guard.uid("FETCH", "1:*", "(RFC822)")
        assert conn.calls == [("uid", "FETCH", "1:*", "(RFC822)")]


# ---------------------------------------------------------------------------
# Non-strict mode (warning only, no raise)
# ---------------------------------------------------------------------------


class TestEmailGuardNonStrict:
    def test_store_deleted_logs_but_does_not_raise(self):
        guard, conn = make_guard(strict=False)
        # Should not raise
        guard.store("1:*", "+FLAGS", "\\Deleted")
        # But the underlying call should still go through in non-strict mode
        assert any(c[0] == "store" for c in conn.calls)

    def test_expunge_logs_but_does_not_raise(self):
        guard, conn = make_guard(strict=False)
        guard.expunge()
        assert any(c[0] == "expunge" for c in conn.calls)
