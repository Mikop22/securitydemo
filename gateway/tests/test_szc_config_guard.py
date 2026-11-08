from __future__ import annotations

import pytest

from gateway.szc_config_guard import (
    UnauthorizedConfigAccessError,
    authorize_szc_request,
)


def test_public_healthcheck_allowed_without_admin() -> None:
    assert authorize_szc_request("/healthz", authenticated_admin=False) == "/healthz"


def test_unauthenticated_restricted_config_page_rejected() -> None:
    with pytest.raises(UnauthorizedConfigAccessError):
        authorize_szc_request("/config/zone-controller", authenticated_admin=False)


def test_unauthenticated_traversal_into_config_rejected() -> None:
    with pytest.raises(UnauthorizedConfigAccessError):
        authorize_szc_request("/public/../szc/config/keys", authenticated_admin=False)


def test_authenticated_admin_can_access_config_page() -> None:
    assert (
        authorize_szc_request("/config/zone-controller", authenticated_admin=True)
        == "/config/zone-controller"
    )
