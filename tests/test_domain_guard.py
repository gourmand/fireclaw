"""Tests for fireclaw.domain_guard."""

from unittest.mock import MagicMock, patch

import pytest

from fireclaw.domain_guard import DomainGuard, MalwareDomainBlocked


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_guard(**kwargs) -> DomainGuard:
    return DomainGuard(**kwargs)


# ---------------------------------------------------------------------------
# is_blocked / check_url – built-in blocklist
# ---------------------------------------------------------------------------


class TestDomainGuardBuiltinBlocklist:
    def test_known_malware_domain_is_blocked(self):
        guard = make_guard()
        assert guard.is_blocked("evil.example.com") is True

    def test_known_malware_domain_url_is_blocked(self):
        guard = make_guard()
        assert guard.is_blocked("https://evil.example.com/some/path?q=1") is True

    def test_subdomain_of_blocked_domain_is_blocked(self):
        guard = make_guard()
        # "c2.example.com" is in the built-in list; any sub-domain should also match
        assert guard.is_blocked("payload.c2.example.com") is True
        assert guard.is_blocked("sub.malware.example.com") is True

    def test_safe_domain_is_not_blocked(self):
        guard = make_guard()
        assert guard.is_blocked("https://www.example.com") is False

    def test_check_url_raises_for_blocked(self):
        guard = make_guard()
        with pytest.raises(MalwareDomainBlocked):
            guard.check_url("https://evil.example.com/payload")

    def test_check_url_passes_for_safe(self):
        guard = make_guard()
        guard.check_url("https://www.github.com")  # must not raise

    def test_eicar_domain_blocked(self):
        guard = make_guard()
        assert guard.is_blocked("https://eicar.org/test") is True


# ---------------------------------------------------------------------------
# extra_blocklist
# ---------------------------------------------------------------------------


class TestDomainGuardExtraBlocklist:
    def test_extra_domain_is_blocked(self):
        guard = make_guard(extra_blocklist=["badactor.net"])
        assert guard.is_blocked("http://badactor.net/cmd") is True

    def test_subdomain_of_extra_domain_is_blocked(self):
        guard = make_guard(extra_blocklist=["badactor.net"])
        assert guard.is_blocked("sub.badactor.net") is True

    def test_unrelated_domain_not_blocked(self):
        guard = make_guard(extra_blocklist=["badactor.net"])
        assert guard.is_blocked("legit.net") is False


# ---------------------------------------------------------------------------
# allow_list overrides blocklist
# ---------------------------------------------------------------------------


class TestDomainGuardAllowList:
    def test_allowed_domain_overrides_blocklist(self):
        guard = make_guard(allow_list=["evil.example.com"])
        assert guard.is_blocked("evil.example.com") is False

    def test_allowed_parent_overrides_blocked_child(self):
        guard = make_guard(extra_blocklist=["sub.safe.com"], allow_list=["safe.com"])
        assert guard.is_blocked("sub.safe.com") is False


# ---------------------------------------------------------------------------
# Runtime add/remove
# ---------------------------------------------------------------------------


class TestDomainGuardMutability:
    def test_add_domains_blocks_new_domain(self):
        guard = make_guard(use_builtin_blocklist=False)
        assert guard.is_blocked("newbad.io") is False
        guard.add_domains("newbad.io")
        assert guard.is_blocked("newbad.io") is True

    def test_remove_domains_unblocks_domain(self):
        guard = make_guard(extra_blocklist=["removeme.com"])
        assert guard.is_blocked("removeme.com") is True
        guard.remove_domains("removeme.com")
        assert guard.is_blocked("removeme.com") is False

    def test_blocked_domains_property(self):
        guard = make_guard(use_builtin_blocklist=False, extra_blocklist=["only.com"])
        assert "only.com" in guard.blocked_domains


# ---------------------------------------------------------------------------
# Non-strict mode
# ---------------------------------------------------------------------------


class TestDomainGuardNonStrict:
    def test_non_strict_does_not_raise(self):
        guard = make_guard(strict=False)
        guard.check_url("https://evil.example.com/payload")  # must not raise


# ---------------------------------------------------------------------------
# wrap_urlopen
# ---------------------------------------------------------------------------


class TestDomainGuardWrapUrlopen:
    def test_blocked_url_raises(self):
        guard = make_guard()
        fake_urlopen = MagicMock()
        safe_open = guard.wrap_urlopen(fake_urlopen)
        with pytest.raises(MalwareDomainBlocked):
            safe_open("https://evil.example.com/x")
        fake_urlopen.assert_not_called()

    def test_safe_url_passes_through(self):
        guard = make_guard()
        fake_urlopen = MagicMock(return_value="response")
        safe_open = guard.wrap_urlopen(fake_urlopen)
        result = safe_open("https://safe.example.com/x")
        assert result == "response"
        fake_urlopen.assert_called_once()


# ---------------------------------------------------------------------------
# wrap_requests_session
# ---------------------------------------------------------------------------


class TestDomainGuardWrapRequestsSession:
    def _make_session(self):
        session = MagicMock()
        session.get = MagicMock(return_value="ok-get")
        session.post = MagicMock(return_value="ok-post")
        session.request = MagicMock(return_value="ok-request")
        return session

    def test_get_blocked_url_raises(self):
        guard = make_guard()
        session = self._make_session()
        safe = guard.wrap_requests_session(session)
        with pytest.raises(MalwareDomainBlocked):
            safe.get("https://malware.example.com/cmd")
        session.get.assert_not_called()

    def test_get_safe_url_passes_through(self):
        guard = make_guard()
        session = self._make_session()
        safe = guard.wrap_requests_session(session)
        result = safe.get("https://safe.example.com/page")
        assert result == "ok-get"

    def test_post_blocked_url_raises(self):
        guard = make_guard()
        session = self._make_session()
        safe = guard.wrap_requests_session(session)
        with pytest.raises(MalwareDomainBlocked):
            safe.post("https://c2.example.com/data", json={"x": 1})
        session.post.assert_not_called()

    def test_request_blocked_url_raises(self):
        guard = make_guard()
        session = self._make_session()
        safe = guard.wrap_requests_session(session)
        with pytest.raises(MalwareDomainBlocked):
            safe.request("GET", "https://evil.example.com/")
        session.request.assert_not_called()

    def test_non_http_attr_proxied_to_session(self):
        guard = make_guard()
        session = self._make_session()
        session.headers = {"User-Agent": "test"}
        safe = guard.wrap_requests_session(session)
        assert safe.headers == {"User-Agent": "test"}
