"""domain_guard.py – block calls to malware / malicious domains.

:class:`DomainGuard` maintains a set of blocked domain names (exact matches
and suffixes) and provides helpers to check URLs or hostnames.  It can also
wrap :func:`urllib.request.urlopen` and the popular :mod:`requests` session
interface to transparently block outgoing network calls to known-bad domains.

Usage example::

    from fireclaw import DomainGuard

    guard = DomainGuard(extra_blocklist=["evil.example.com"])

    # Explicit check
    guard.check_url("https://evil.example.com/payload")   # raises MalwareDomainBlocked

    # Wrap the requests library
    import requests
    safe_session = guard.wrap_requests_session(requests.Session())
    safe_session.get("https://evil.example.com/payload")  # raises MalwareDomainBlocked

    # Wrap urllib
    safe_urlopen = guard.wrap_urlopen()
    safe_urlopen("https://evil.example.com/payload")      # raises MalwareDomainBlocked
"""

from __future__ import annotations

import re
from typing import Any, Callable, Collection, Iterable
from urllib.parse import urlparse


class MalwareDomainBlocked(RuntimeError):
    """Raised when :class:`DomainGuard` intercepts a call to a blocked domain."""


# ---------------------------------------------------------------------------
# Built-in blocklist
# ---------------------------------------------------------------------------
# A minimal seed list of well-known malicious / test malware domains.
# Users should extend this list via the *extra_blocklist* parameter.

_BUILTIN_BLOCKLIST: frozenset[str] = frozenset(
    {
        # EICAR test / demonstration domains
        "eicar.org",
        "eicar.com",
        # Commonly abused free dynamic-DNS sub-domains used in malware C2
        "no-ip.com",
        "duckdns.org",
        "hopto.org",
        "zapto.org",
        "sytes.net",
        # Malware-specific domains (public threat intel feeds)
        "malware.wicar.org",
        "testsafebrowsing.appspot.com",
        # Generic catch-all for local test names used in unit tests
        "evil.example.com",
        "malware.example.com",
        "c2.example.com",
    }
)


def _normalise_domain(domain: str) -> str:
    """Return a lowercase, stripped domain without a trailing dot."""
    return domain.strip().lower().rstrip(".")


def _extract_domain(url_or_domain: str) -> str:
    """Return the hostname for a URL or bare domain string."""
    if re.match(r"https?://", url_or_domain, re.IGNORECASE):
        parsed = urlparse(url_or_domain)
        host = parsed.hostname or ""
    else:
        # Bare domain or host:port
        host = url_or_domain.split(":")[0]
    return _normalise_domain(host)


class DomainGuard:
    """A configurable domain blocklist that can wrap network calls.

    :param extra_blocklist: Additional domains (or domain suffixes) to block,
        in addition to the built-in list.
    :param allow_list: Domains that should always be *allowed*, overriding
        any match in the blocklist.  Useful for false-positive corrections.
    :param use_builtin_blocklist: When *False* the built-in seed list is
        ignored and only *extra_blocklist* is used.
    :param strict: When *True* (the default) raise on blocked domains.  When
        *False* log a warning instead.
    :param logger: Optional :class:`logging.Logger`.
    """

    def __init__(
        self,
        *,
        extra_blocklist: Collection[str] = (),
        allow_list: Collection[str] = (),
        use_builtin_blocklist: bool = True,
        strict: bool = True,
        logger: Any = None,
    ) -> None:
        base = _BUILTIN_BLOCKLIST if use_builtin_blocklist else frozenset()
        self._blocked: frozenset[str] = base | frozenset(
            _normalise_domain(d) for d in extra_blocklist
        )
        self._allowed: frozenset[str] = frozenset(
            _normalise_domain(d) for d in allow_list
        )
        self._strict = strict
        import logging
        self._logger = logger or logging.getLogger("fireclaw.domain_guard")

    # ------------------------------------------------------------------
    # Core check API
    # ------------------------------------------------------------------

    def is_blocked(self, url_or_domain: str) -> bool:
        """Return ``True`` if *url_or_domain* resolves to a blocked domain.

        A domain is considered blocked when it (or any of its parent domains)
        appears in the blocklist, unless it (or a parent) appears in the
        allow-list.  The allow-list is checked across all ancestors first so
        that an allowed parent can exempt a more-specific blocked subdomain.
        """
        domain = _extract_domain(url_or_domain)
        if not domain:
            return False

        parts = domain.split(".")
        candidates = [".".join(parts[i:]) for i in range(len(parts))]

        # Allow-list wins over blocklist for any matching ancestor.
        if any(c in self._allowed for c in candidates):
            return False

        return any(c in self._blocked for c in candidates)

    def check_url(self, url_or_domain: str) -> None:
        """Raise :exc:`MalwareDomainBlocked` (or log) if the domain is blocked.

        :param url_or_domain: A full URL or a bare hostname.
        :raises MalwareDomainBlocked: In strict mode when the domain matches
            the blocklist.
        """
        if self.is_blocked(url_or_domain):
            domain = _extract_domain(url_or_domain)
            msg = f"Blocked request to malware domain: {domain!r}"
            self._logger.warning("fireclaw [domain_guard]: %s", msg)
            if self._strict:
                raise MalwareDomainBlocked(msg)

    # ------------------------------------------------------------------
    # Blocklist management
    # ------------------------------------------------------------------

    def add_domains(self, *domains: str) -> None:
        """Add one or more domains to the blocklist at runtime."""
        self._blocked = self._blocked | frozenset(
            _normalise_domain(d) for d in domains
        )

    def remove_domains(self, *domains: str) -> None:
        """Remove one or more domains from the blocklist at runtime."""
        self._blocked = self._blocked - frozenset(
            _normalise_domain(d) for d in domains
        )

    @property
    def blocked_domains(self) -> frozenset[str]:
        """The current set of blocked domains (read-only snapshot)."""
        return self._blocked

    # ------------------------------------------------------------------
    # Network wrapper helpers
    # ------------------------------------------------------------------

    def wrap_requests_session(self, session: Any) -> Any:
        """Return a wrapped *requests* :class:`~requests.Session`.

        Every ``GET``, ``POST``, ``PUT``, ``PATCH``, ``DELETE``, ``HEAD``,
        ``OPTIONS``, and ``request`` call on the returned session will be
        checked against the blocklist before being forwarded to the underlying
        session.

        :param session: A :class:`requests.Session` (or compatible) object.
        :returns: A :class:`_GuardedSession` proxy.
        """
        return _GuardedSession(session, self)

    def wrap_urlopen(self, urlopen: Callable[..., Any] | None = None) -> Callable[..., Any]:
        """Return a wrapped version of *urlopen* that blocks malicious domains.

        :param urlopen: The callable to wrap.  Defaults to
            :func:`urllib.request.urlopen`.
        :returns: A callable with the same signature as *urlopen*.
        """
        if urlopen is None:
            from urllib.request import urlopen as _urlopen
            urlopen = _urlopen

        guard = self

        def _safe_urlopen(url: Any, *args: Any, **kwargs: Any) -> Any:
            url_str = url if isinstance(url, str) else getattr(url, "full_url", str(url))
            guard.check_url(url_str)
            return urlopen(url, *args, **kwargs)  # type: ignore[misc]

        return _safe_urlopen


# ---------------------------------------------------------------------------
# Internal helper: guarded requests.Session proxy
# ---------------------------------------------------------------------------


class _GuardedSession:
    """Proxy around a *requests* session that blocks malicious domains."""

    def __init__(self, session: Any, guard: DomainGuard) -> None:
        object.__setattr__(self, "_session", session)
        object.__setattr__(self, "_guard", guard)

    def __getattr__(self, name: str) -> Any:
        return getattr(object.__getattribute__(self, "_session"), name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(object.__getattribute__(self, "_session"), name, value)

    def _checked_call(self, method_name: str, url: str, *args: Any, **kwargs: Any) -> Any:
        guard: DomainGuard = object.__getattribute__(self, "_guard")
        guard.check_url(url)
        session = object.__getattribute__(self, "_session")
        return getattr(session, method_name)(url, *args, **kwargs)

    # Generate forwarding methods for each HTTP verb
    def get(self, url: str, **kwargs: Any) -> Any:
        return self._checked_call("get", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Any:
        return self._checked_call("post", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> Any:
        return self._checked_call("put", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> Any:
        return self._checked_call("patch", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> Any:
        return self._checked_call("delete", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> Any:
        return self._checked_call("head", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> Any:
        return self._checked_call("options", url, **kwargs)

    def request(self, method: str, url: str, **kwargs: Any) -> Any:
        guard: DomainGuard = object.__getattribute__(self, "_guard")
        guard.check_url(url)
        session = object.__getattribute__(self, "_session")
        return session.request(method, url, **kwargs)
