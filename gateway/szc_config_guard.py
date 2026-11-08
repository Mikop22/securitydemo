"""Reverse-proxy guard for ShareFile Storage Zones Controller (CVE-2026-2699).

CVE-2026-2699 allows an unauthenticated attacker to access restricted
configuration pages on Customer Managed ShareFile Storage Zones Controller
(SZC), leading to system configuration changes and potential RCE.
"""

from __future__ import annotations

RESTRICTED_PREFIXES = (
    "/config",
    "/szc/config",
    "/admin/storagezones",
    "/cifs/config",
)


class UnauthorizedConfigAccessError(PermissionError):
    """Raised when an unauthenticated request targets a restricted SZC config page."""


def authorize_szc_request(path: str, *, authenticated_admin: bool) -> str:
    """Validate incoming request path before forwarding to the SZC appliance.

    VULNERABLE on main: normalizes nothing and forwards restricted configuration
    paths even when ``authenticated_admin`` is False.
    """
    if not path or not path.startswith("/"):
        raise ValueError("path must start with '/'")
    # Intentionally missing authentication & path normalization check on main.
    return path
