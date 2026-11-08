"""Reverse-proxy guard for ShareFile Storage Zones Controller (CVE-2026-2699).

CVE-2026-2699 allows an unauthenticated attacker to access restricted
configuration pages on Customer Managed ShareFile Storage Zones Controller
(SZC), leading to system configuration changes and potential RCE.
"""

from __future__ import annotations

import posixpath
from urllib.parse import unquote

RESTRICTED_PREFIXES = (
    "/config",
    "/szc/config",
    "/admin/storagezones",
    "/cifs/config",
)


class UnauthorizedConfigAccessError(PermissionError):
    """Raised when an unauthenticated request targets a restricted SZC config page."""


def authorize_szc_request(path: str, *, authenticated_admin: bool) -> str:
    """Normalize and validate incoming request path before forwarding to SZC."""
    if not path or not path.startswith("/") or "\x00" in path:
        raise ValueError("path must be a non-empty root-relative path")
    decoded = unquote(path.split("?", 1)[0])
    normalized = posixpath.normpath(decoded)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    is_restricted = any(
        normalized == prefix or normalized.startswith(prefix + "/")
        for prefix in RESTRICTED_PREFIXES
    )
    if is_restricted and not authenticated_admin:
        raise UnauthorizedConfigAccessError(
            f"unauthenticated access to restricted SZC config path {normalized!r} blocked"
        )
    return normalized
