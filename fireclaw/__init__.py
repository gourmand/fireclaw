"""fireclaw – A firewall for your claw.

Provides two safety guards:

* :class:`EmailGuard` – wraps an IMAP connection and blocks any attempt to
  delete or permanently expunge messages.
* :class:`DomainGuard` – checks URLs and domain names against a configurable
  blocklist and raises an error when a known-malicious domain is detected.
"""

from .domain_guard import DomainGuard
from .email_guard import EmailGuard

__all__ = ["DomainGuard", "EmailGuard"]
