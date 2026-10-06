"""Tokens without a refresh token must stay usable until their real expiry.

google-auth refreshes credentials REFRESH_THRESHOLD before expiry. When the
server holds no Google refresh token that refresh can only fail, which produced
an authentication error for every call in the final minutes of a token's life.
"""

import time
from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastmcp.server.auth import AccessToken
from google.auth import _helpers as google_auth_helpers

import auth.oauth21_session_store as session_store_module
from auth.oauth21_session_store import OAuth21SessionStore

EMAIL = "user@example.com"
SCOPES = ["https://www.googleapis.com/auth/admin.directory.customer.readonly"]


@pytest.fixture
def store(tmp_path, monkeypatch):
    fresh_store = OAuth21SessionStore(oauth_state_file=str(tmp_path / "states.json"))
    monkeypatch.setattr(
        session_store_module, "get_oauth21_session_store", lambda: fresh_store
    )
    monkeypatch.setattr(
        session_store_module, "is_external_oauth21_provider", lambda: False
    )
    return fresh_store


def _install_provider(monkeypatch, refresh_for=None):
    access_to_refresh = {}
    refresh_tokens = {}
    if refresh_for:
        access_to_refresh[refresh_for] = "refresh-handle"
        refresh_tokens["refresh-handle"] = SimpleNamespace(token="google-refresh")
    provider = SimpleNamespace(
        _access_tokens={},
        _access_to_refresh=access_to_refresh,
        _refresh_tokens=refresh_tokens,
        _upstream_client_id="client-id",
        _upstream_client_secret="client-secret",
    )
    monkeypatch.setattr(session_store_module, "_auth_provider", provider)


def _access_token(seconds_left):
    return AccessToken(
        token="google-access",
        client_id="client-id",
        scopes=SCOPES,
        expires_at=int(time.time()) + seconds_left,
        claims={"email": EMAIL},
    )


def _inside_refresh_window():
    # Comfortably inside google-auth's early-refresh window, still unexpired.
    return int(google_auth_helpers.REFRESH_THRESHOLD.total_seconds() / 2)


def test_provider_token_without_refresh_token_stays_valid_near_expiry(
    store, monkeypatch
):
    _install_provider(monkeypatch)
    credentials = session_store_module.ensure_session_from_access_token(
        _access_token(_inside_refresh_window()), EMAIL
    )

    assert credentials.refresh_token is None
    assert credentials.valid


def test_stored_session_is_not_shifted_twice(store, monkeypatch):
    _install_provider(monkeypatch)
    seconds_left = _inside_refresh_window()
    access_token = _access_token(seconds_left)
    session_store_module.ensure_session_from_access_token(access_token, EMAIL)

    stored = store.get_credentials(EMAIL)

    assert stored.valid
    expected = (
        session_store_module._normalize_expiry_to_naive_utc(
            session_store_module.datetime.fromtimestamp(
                access_token.expires_at, tz=session_store_module.timezone.utc
            )
        )
        + google_auth_helpers.REFRESH_THRESHOLD
    )
    assert abs(stored.expiry - expected) <= timedelta(seconds=1)


def test_expired_token_without_refresh_token_is_still_expired(store, monkeypatch):
    _install_provider(monkeypatch)
    credentials = session_store_module.ensure_session_from_access_token(
        _access_token(-5), EMAIL
    )

    assert credentials.expired


def test_refreshable_token_keeps_early_refresh(store, monkeypatch):
    _install_provider(monkeypatch, refresh_for="google-access")
    credentials = session_store_module.ensure_session_from_access_token(
        _access_token(_inside_refresh_window()), EMAIL
    )

    assert credentials.refresh_token == "google-refresh"
    assert credentials.expired
