"""email_guard.py – prevent email deletion.

:class:`EmailGuard` wraps an :mod:`imaplib` IMAP4 connection (or any object
with a compatible interface) and intercepts methods that would permanently
delete messages:

* ``store`` – adding the ``\\Deleted`` flag
* ``expunge`` – removing messages flagged ``\\Deleted``
* ``uid`` – the UID-based variant of the above two
* ``delete`` / ``delete_messages`` – higher-level helpers used by some wrappers

When a deletion attempt is detected, :exc:`EmailDeletionBlocked` is raised
instead of forwarding the call to the underlying connection.

Usage example::

    import imaplib
    from fireclaw import EmailGuard

    raw = imaplib.IMAP4_SSL("imap.example.com")
    raw.login("user", "password")
    imap = EmailGuard(raw)

    # This would normally mark messages for deletion – fireclaw blocks it.
    imap.store("1:*", "+FLAGS", "\\Deleted")   # raises EmailDeletionBlocked

    # Safe operations pass through unchanged.
    imap.select("INBOX")
    imap.search(None, "ALL")
"""

from __future__ import annotations

import re
from typing import Any


class EmailDeletionBlocked(RuntimeError):
    """Raised when :class:`EmailGuard` intercepts a deletion attempt."""


# ---------------------------------------------------------------------------
# Patterns that indicate a deletion intent in IMAP STORE flag operations
# ---------------------------------------------------------------------------

# Matches "+FLAGS (\Deleted)" and "+FLAGS.SILENT (\Deleted)" (case-insensitive)
_FLAG_DELETED_RE = re.compile(r"\+FLAGS(?:\.SILENT)?\s*\(?\\Deleted\)?", re.IGNORECASE)


def _is_delete_store(flag_name: str, flag_list: str) -> bool:
    """Return ``True`` when a STORE operation would set the ``\\Deleted`` flag."""
    combined = f"{flag_name} {flag_list}"
    return bool(_FLAG_DELETED_RE.search(combined))


class EmailGuard:
    """A proxy for an IMAP connection that blocks any deletion operation.

    All attributes and method calls are forwarded to the wrapped *connection*
    object transparently, except for those that would delete messages.

    :param connection: An :class:`imaplib.IMAP4` (or compatible) instance.
    :param strict: When *True* (the default), raise on any attempt to add the
        ``\\Deleted`` flag *or* to expunge.  Set to *False* to only log a
        warning instead of raising (useful for gradual adoption).
    :param logger: Optional :class:`logging.Logger`.  If *None* a logger named
        ``fireclaw.email_guard`` is used.
    """

    def __init__(self, connection: Any, *, strict: bool = True, logger: Any = None) -> None:
        # Use object.__setattr__ to avoid triggering our __setattr__ override.
        object.__setattr__(self, "_conn", connection)
        object.__setattr__(self, "_strict", strict)
        import logging
        object.__setattr__(
            self,
            "_logger",
            logger or logging.getLogger("fireclaw.email_guard"),
        )

    # ------------------------------------------------------------------
    # Transparent attribute proxy
    # ------------------------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        return getattr(object.__getattribute__(self, "_conn"), name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(object.__getattribute__(self, "_conn"), name, value)

    # ------------------------------------------------------------------
    # Intercepted methods
    # ------------------------------------------------------------------

    def store(self, message_set: str, command: str, flags: str) -> Any:
        """Block ``+FLAGS (\\Deleted)`` STORE commands."""
        if _is_delete_store(command, flags):
            self._block(
                f"Blocked STORE {command!r} {flags!r} on message set {message_set!r}"
            )
        return object.__getattribute__(self, "_conn").store(message_set, command, flags)

    def expunge(self) -> Any:
        """Block EXPUNGE (permanently removes flagged messages)."""
        self._block("Blocked EXPUNGE – would permanently delete flagged messages")
        return object.__getattribute__(self, "_conn").expunge()

    def uid(self, command: str, *args: Any) -> Any:
        """Block UID STORE …\\Deleted and UID EXPUNGE."""
        cmd_upper = command.upper()
        if cmd_upper == "EXPUNGE":
            self._block("Blocked UID EXPUNGE – would permanently delete flagged messages")
        if cmd_upper == "STORE" and len(args) >= 2:
            if _is_delete_store(str(args[1]), str(args[2]) if len(args) > 2 else ""):
                self._block(
                    f"Blocked UID STORE {args[1]!r} {args[2] if len(args) > 2 else ''!r}"
                )
        return object.__getattribute__(self, "_conn").uid(command, *args)

    # Some higher-level libraries expose these names directly.
    def delete(self, *args: Any, **kwargs: Any) -> Any:
        """Block any method named ``delete``."""
        self._block(f"Blocked delete() call with args={args!r} kwargs={kwargs!r}")
        return object.__getattribute__(self, "_conn").delete(*args, **kwargs)

    def delete_messages(self, *args: Any, **kwargs: Any) -> Any:
        """Block any method named ``delete_messages``."""
        self._block(
            f"Blocked delete_messages() call with args={args!r} kwargs={kwargs!r}"
        )
        return object.__getattribute__(self, "_conn").delete_messages(*args, **kwargs)

    # ------------------------------------------------------------------
    # Internal helper
    # ------------------------------------------------------------------

    def _block(self, message: str) -> None:
        logger = object.__getattribute__(self, "_logger")
        strict = object.__getattribute__(self, "_strict")
        logger.warning("fireclaw [email_guard]: %s", message)
        if strict:
            raise EmailDeletionBlocked(message)
