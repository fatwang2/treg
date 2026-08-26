"""Compatibility checks for the identity-domain dependency extraction."""

from treg import api, timeutil
from treg.domain.identity import access
from treg.routers import auth_helpers


def test_api_reexports_shared_http_dependencies() -> None:
    names = (
        "Caller",
        "_membership_by_token",
        "_resolve_org",
        "_role_at_least",
        "_user_from_identity_token",
        "_user_from_session",
        "require_identity",
        "require_member",
        "require_superadmin",
    )
    for name in names:
        assert getattr(api, name) is getattr(access, name)
    assert api._is_https is auth_helpers._is_https


def test_api_reexports_shared_time_convention() -> None:
    assert api._utcnow_naive is timeutil.utcnow_naive
    assert api._as_naive is timeutil.as_naive
