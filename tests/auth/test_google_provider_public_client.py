"""Downstream public-client contract against the frozen FastMCP/SDK stack.

No Google traffic or real credentials: ASGI requests, in-memory state, and
synthetic upstream tokens only. These are protocol checks, not live acceptance.
"""

import base64
import hashlib
import socket
import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastmcp.server.auth.oauth_proxy.models import ClientCode
from fastmcp.server.auth.providers.google import (
    GoogleProvider as UpstreamGoogleProvider,
)
from key_value.aio.stores.memory import MemoryStore
from starlette.applications import Starlette

from core.server import GoogleProvider, well_known_cache_control_middleware

ORIGIN = "https://workspace.example.test"
CALLBACK = "http://127.0.0.1:54321/oauth/callback"
SCOPES = ["https://www.googleapis.com/auth/calendar.readonly", "openid"]
VERIFIER = "a" * 64
CHALLENGE = (
    base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest())
    .decode()
    .rstrip("=")
)
REGISTRATION = {
    "client_name": "Synthetic public canary",
    "redirect_uris": [CALLBACK],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
    "scope": " ".join(SCOPES),
}


@pytest.fixture(autouse=True)
def deny_network(monkeypatch):
    def denied(*args, **kwargs):
        pytest.fail("This protocol test must not open a network connection")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    monkeypatch.setattr(socket, "create_connection", denied)


def make_provider(provider_class=GoogleProvider, *, enable_cimd=True):
    return provider_class(
        client_id="synthetic-upstream-client",
        client_secret="synthetic-upstream-secret-not-a-credential",
        base_url=ORIGIN,
        redirect_path="/oauth2callback",
        required_scopes=["openid"],
        valid_scopes=SCOPES,
        client_storage=MemoryStore(),
        jwt_signing_key=b"synthetic-test-signing-material!!",
        allowed_client_redirect_uris=[CALLBACK],
        enable_cimd=enable_cimd,
    )


def asgi_client(provider):
    app = Starlette(
        routes=provider.get_routes(mcp_path="/mcp"),
        middleware=[well_known_cache_control_middleware],
    )
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN)


@pytest.mark.asyncio
@pytest.mark.parametrize("enable_cimd", [True, False])
async def test_discovery_advertises_public_clients_without_changing_other_metadata(
    enable_cimd,
):
    async with asgi_client(make_provider(enable_cimd=enable_cimd)) as client:
        response = await client.get("/.well-known/oauth-authorization-server")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store, must-revalidate"
        metadata = response.json()
        assert "none" in metadata["token_endpoint_auth_methods_supported"]
        assert metadata["token_endpoint_auth_methods_supported"].count("none") == 1
        assert metadata["issuer"].rstrip("/") == ORIGIN
        assert metadata["token_endpoint"] == ORIGIN + "/token"
        assert metadata["registration_endpoint"] == ORIGIN + "/register"
        assert metadata["code_challenge_methods_supported"] == ["S256"]
        assert metadata["scopes_supported"] == SCOPES
        resource = await client.get("/.well-known/oauth-protected-resource/mcp")
        assert resource.json()["resource"] == ORIGIN + "/mcp"
        assert resource.json()["scopes_supported"] == SCOPES
        cors = await client.options(
            "/.well-known/oauth-authorization-server",
            headers={
                "Origin": "https://client.example.test",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert cors.status_code == 200
        assert cors.headers["access-control-allow-origin"] == "*"

    # Characterize the pinned-stack mismatch: only the missing method changes.
    async with asgi_client(
        make_provider(UpstreamGoogleProvider, enable_cimd=enable_cimd)
    ) as client:
        previous = (await client.get("/.well-known/oauth-authorization-server")).json()
    assert metadata.pop("token_endpoint_auth_methods_supported") == [
        *previous.pop("token_endpoint_auth_methods_supported"),
        "none",
    ]
    assert metadata == previous


async def register(client):
    response = await client.post("/register", json=REGISTRATION)
    assert response.status_code == 201
    result = response.json()
    assert set(result) == set(REGISTRATION) | {"client_id", "client_id_issued_at"}
    assert isinstance(result["client_id"], str) and result["client_id"]
    assert type(result["client_id_issued_at"]) is int
    assert {key: result[key] for key in REGISTRATION} == REGISTRATION
    return result["client_id"]


async def seed_consented_code(provider, client_id):
    # The Google callback boundary is replaced with synthetic, already-consented
    # upstream material. Real downstream code/PKCE/token handlers remain intact.
    await provider._code_store.put(
        key="synthetic-code",
        value=ClientCode(
            code="synthetic-code",
            client_id=client_id,
            redirect_uri=CALLBACK,
            code_challenge=CHALLENGE,
            code_challenge_method="S256",
            scopes=SCOPES,
            idp_tokens={
                "access_token": "synthetic-upstream-access",
                "refresh_token": "synthetic-upstream-refresh",
                "expires_in": 3600,
                "token_type": "Bearer",
                "scope": " ".join(SCOPES),
            },
            created_at=time.time(),
            expires_at=time.time() + 300,
        ),
    )


def token_request(client_id):
    return {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": "synthetic-code",
        "code_verifier": VERIFIER,
        "redirect_uri": CALLBACK,
        "resource": ORIGIN + "/mcp",
    }


def assert_token_shape(response):
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    result = response.json()
    assert set(result) == {
        "access_token",
        "token_type",
        "expires_in",
        "refresh_token",
        "scope",
    }
    assert result["token_type"] == "Bearer"
    assert type(result["expires_in"]) is int and result["expires_in"] > 0
    assert result["scope"] == " ".join(SCOPES)
    assert result["access_token"] != "synthetic-upstream-access"
    assert result["refresh_token"] != "synthetic-upstream-refresh"
    assert all(
        isinstance(result[key], str) and result[key]
        for key in ("access_token", "refresh_token")
    )
    return result


@pytest.mark.asyncio
async def test_public_registration_still_requires_consent_before_google_redirect():
    async with asgi_client(make_provider()) as client:
        client_id = await register(client)
        response = await client.get(
            "/authorize",
            params={
                "client_id": client_id,
                "redirect_uri": CALLBACK,
                "response_type": "code",
                "state": "synthetic-state",
                "code_challenge": CHALLENGE,
                "code_challenge_method": "S256",
                "scope": " ".join(SCOPES),
                "resource": ORIGIN + "/mcp",
            },
        )
        assert response.status_code == 302
        location = urlparse(response.headers["location"])
        assert location.path == "/consent"
        assert location.netloc == "workspace.example.test"
        assert parse_qs(location.query)["txn_id"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change, error",
    [
        ({"code_verifier": "b" * 64}, "invalid_grant"),
        ({"redirect_uri": "http://127.0.0.1:54322/oauth/callback"}, "invalid_request"),
        ({"client_id": "unregistered-synthetic-client"}, "invalid_client"),
    ],
)
async def test_invalid_public_exchange_never_issues_tokens(change, error):
    provider = make_provider()
    async with asgi_client(provider) as client:
        client_id = await register(client)
        await seed_consented_code(provider, client_id)
        response = await client.post("/token", data=token_request(client_id) | change)
        assert response.status_code in (400, 401)
        assert response.json()["error"] == error
        assert "access_token" not in response.json()


@pytest.mark.asyncio
async def test_public_code_exchange_is_one_use_and_refresh_stays_client_bound(
    monkeypatch,
):
    provider = make_provider()
    async with asgi_client(provider) as client:
        client_id = await register(client)
        await seed_consented_code(provider, client_id)
        tokens = assert_token_shape(
            await client.post("/token", data=token_request(client_id))
        )
        replay = await client.post("/token", data=token_request(client_id))
        assert replay.status_code == 401
        assert replay.json()["error"] == "invalid_grant"
        other_id = await register(client)
        refresh = {
            "grant_type": "refresh_token",
            "client_id": other_id,
            "refresh_token": tokens["refresh_token"],
            "resource": ORIGIN + "/mcp",
        }
        wrong_client = await client.post("/token", data=refresh)
        assert wrong_client.status_code == 401
        assert wrong_client.json()["error"] == "invalid_grant"

        # Keep Authlib request construction; substitute only its external HTTP I/O.
        def upstream(request):
            assert str(request.url) == "https://oauth2.googleapis.com/token"
            assert request.method == "POST"
            form = parse_qs(request.content.decode())
            assert form["grant_type"] == ["refresh_token"]
            assert form["refresh_token"] == ["synthetic-upstream-refresh"]
            return httpx.Response(
                200,
                json={
                    "access_token": "synthetic-renewed-upstream-access",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                    "scope": " ".join(SCOPES),
                },
            )

        from authlib.integrations.httpx_client import AsyncOAuth2Client

        async with AsyncOAuth2Client(
            client_id="synthetic-upstream-client",
            client_secret="synthetic-upstream-secret-not-a-credential",
            transport=httpx.MockTransport(upstream),
        ) as upstream_client:
            monkeypatch.setattr(
                provider, "_create_upstream_oauth_client", lambda: upstream_client
            )
            refreshed = assert_token_shape(
                await client.post("/token", data=refresh | {"client_id": client_id})
            )
        assert refreshed["access_token"] != tokens["access_token"]
        assert refreshed["refresh_token"] != tokens["refresh_token"]
        old_refresh = await client.post(
            "/token", data=refresh | {"client_id": client_id}
        )
        assert old_refresh.status_code == 401
        assert old_refresh.json()["error"] == "invalid_grant"
