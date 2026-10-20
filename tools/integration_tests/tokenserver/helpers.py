# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Helper functions and constants for tokenserver integration tests.

These are plain module-level utilities — no pytest fixtures here.
Test files import directly from this module; conftest.py imports
whatever it needs to seed fixtures.
"""

import binascii
import functools
import json
import math
import os
import secrets
import time
import urllib.parse as urlparse
import uuid
from base64 import urlsafe_b64encode as b64encode

import requests
from sqlalchemy.sql import text as sqltext
from tokenlib.utils import decode_token_bytes
from webtest import TestApp

DEFAULT_OAUTH_SCOPE = "https://identity.mozilla.com/apps/oldsync"

NODE_ID = 800
NODE_URL = "https://example.com"
FXA_EMAIL_DOMAIN = "api-accounts.stage.mozaws.net"
TOKEN_SIGNING_SECRET = os.environ.get("SYNC_MASTER_SECRET", "secret0")
FXA_METRICS_HASH_SECRET = os.environ.get("SYNC_MASTER_SECRET", "secret0")


# ── DB-mode helpers ───────────────────────────────────────────────────────────


def get_db_mode() -> str:
    """Derive db_mode from the SYNC_TOKENSERVER__DATABASE_URL env var."""
    return os.environ["SYNC_TOKENSERVER__DATABASE_URL"].split(":")[0]


def get_expected_node_type() -> str:
    """Derive expected node_type from the SYNC_SYNCSTORAGE__DATABASE_URL env var."""
    syncstorage_url = os.environ.get("SYNC_SYNCSTORAGE__DATABASE_URL", "spanner://")
    node_type = syncstorage_url.split(":")[0]
    if node_type == "postgresql":
        return "postgres"
    if node_type.startswith("mysql"):
        return "mysql"
    return node_type


# ── Keycloak (OIDC) helpers ──────────────────────────────────────────────────
#
# When SYNC_TOKENSERVER__OAUTH_PROVIDER is "oidc", Tokenserver only accepts real
# access tokens signed by the OIDC provider, so the tests can't send the fake
# tokens the mock FxA server echoes back. Instead, the helpers below mint a real
# Keycloak token that carries the claims the test asks for:
#   sub             the Keycloak user ID; test users are created with ID == `user`
#   fxa-generation  the `generation`, from a user attribute via a protocol mapper
#   scope           the requested scope (the oldsync scope by default)
# Only how the credential is obtained differs; the requests and assertions are
# the same as with FxA.
# Settings:
#   SYNC_TOKENSERVER__OIDC_ISSUER_URL  e.g. http://localhost:7080/realms/sync
#   KEYCLOAK_ADMIN_USERNAME            a master realm admin (default "admin")
#   KEYCLOAK_ADMIN_PASSWORD            that admin's password (required)

KEYCLOAK_TEST_CLIENT_ID = "tokenserver-tests"
KEYCLOAK_BAD_SCOPE = "bad_scope"
KEYCLOAK_GENERATION_ATTRIBUTE = "fxa-generation"
# Test users only ever log in through these helpers, so one random password per
# session is enough. It is never printed.
_KEYCLOAK_USER_PASSWORD = secrets.token_urlsafe(24)
_keycloak_admin_token: dict = {}
_keycloak_users_ready: set = set()


def is_using_oidc() -> bool:
    """Return True when Tokenserver verifies tokens from an OIDC provider (Keycloak)."""
    return os.environ.get("SYNC_TOKENSERVER__OAUTH_PROVIDER", "fxa") == "oidc"


def _keycloak_issuer() -> tuple[str, str]:
    """Split the issuer URL into the Keycloak base URL and the realm name."""
    issuer = os.environ["SYNC_TOKENSERVER__OIDC_ISSUER_URL"].rstrip("/")
    base, realm = issuer.rsplit("/realms/", 1)
    return base, realm


def _keycloak_admin(method: str, path: str, **kwargs) -> requests.Response:
    """Call the Keycloak admin API for the test realm."""
    base, realm = _keycloak_issuer()
    if _keycloak_admin_token.get("expires_at", 0) < time.time() + 10:
        res = requests.post(
            f"{base}/realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": os.environ.get("KEYCLOAK_ADMIN_USERNAME", "admin"),
                "password": os.environ["KEYCLOAK_ADMIN_PASSWORD"],
            },
            timeout=10,
        )
        res.raise_for_status()
        body = res.json()
        _keycloak_admin_token["token"] = body["access_token"]
        _keycloak_admin_token["expires_at"] = time.time() + body["expires_in"]
    headers = {"Authorization": f"Bearer {_keycloak_admin_token['token']}"}
    return requests.request(
        method,
        f"{base}/admin/realms/{realm}{path}",
        headers=headers,
        timeout=10,
        **kwargs,
    )


@functools.lru_cache(maxsize=None)
def _setup_keycloak_realm() -> None:
    """Add what the tests need to the realm: a test client and attribute permissions.

    The test client is a public client with direct password grants, whose access
    tokens are RFC 9068 tokens (typ at+jwt) carrying the user's generation
    attribute as the fxa-generation claim. The oldsync scope (whose audience
    mapper adds Tokenserver's audience) and a bad scope with the same audience
    mapper are optional scopes, so a token only has the scope the test asks for.
    """
    # Let admins set the generation attribute, which isn't in the user profile
    profile = _keycloak_admin("GET", "/users/profile")
    profile.raise_for_status()
    config = profile.json()
    if config.get("unmanagedAttributePolicy") != "ADMIN_EDIT":
        config["unmanagedAttributePolicy"] = "ADMIN_EDIT"
        _keycloak_admin("PUT", "/users/profile", json=config).raise_for_status()

    res = _keycloak_admin(
        "POST",
        "/client-scopes",
        json={
            "name": KEYCLOAK_BAD_SCOPE,
            "protocol": "openid-connect",
            "attributes": {"include.in.token.scope": "true"},
            # Same audience as the oldsync scope, so a token with this scope
            # differs from a good one only in its scope
            "protocolMappers": [
                {
                    "name": "tokenserver audience",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-mapper",
                    "config": {
                        "included.custom.audience": "tokenserver",
                        "id.token.claim": "false",
                        "access.token.claim": "true",
                        "introspection.token.claim": "true",
                    },
                }
            ],
        },
    )
    if res.status_code != 409:
        res.raise_for_status()

    res = _keycloak_admin(
        "POST",
        "/clients",
        json={
            "clientId": KEYCLOAK_TEST_CLIENT_ID,
            "protocol": "openid-connect",
            "publicClient": True,
            "standardFlowEnabled": False,
            "directAccessGrantsEnabled": True,
            "fullScopeAllowed": False,
            "attributes": {"access.token.header.type.rfc9068": "true"},
            "defaultClientScopes": ["basic"],
            "optionalClientScopes": [DEFAULT_OAUTH_SCOPE, KEYCLOAK_BAD_SCOPE],
            "protocolMappers": [
                {
                    "name": KEYCLOAK_GENERATION_ATTRIBUTE,
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-usermodel-attribute-mapper",
                    "config": {
                        "user.attribute": KEYCLOAK_GENERATION_ATTRIBUTE,
                        "claim.name": KEYCLOAK_GENERATION_ATTRIBUTE,
                        "jsonType.label": "long",
                        "access.token.claim": "true",
                        "id.token.claim": "false",
                        "userinfo.token.claim": "false",
                        "introspection.token.claim": "true",
                    },
                }
            ],
        },
    )
    if res.status_code != 409:
        res.raise_for_status()


def _keycloak_user(user: str) -> dict:
    """Create (or reset) the Keycloak user whose ID, and so token subject, is `user`."""
    _setup_keycloak_realm()
    if user not in _keycloak_users_ready:
        # The admin API ignores the ID on create, but a partial import keeps it
        res = _keycloak_admin(
            "POST",
            "/partialImport",
            json={
                "ifResourceExists": "SKIP",
                "users": [
                    {
                        "id": user,
                        "username": user,
                        "email": f"{user}@example.com",
                        "emailVerified": True,
                        "firstName": "Sync",
                        "lastName": "Test",
                        "enabled": True,
                    }
                ],
            },
        )
        res.raise_for_status()
        _keycloak_admin(
            "PUT",
            f"/users/{user}/reset-password",
            json={
                "type": "password",
                "value": _KEYCLOAK_USER_PASSWORD,
                "temporary": False,
            },
        ).raise_for_status()
        _keycloak_users_ready.add(user)
    res = _keycloak_admin("GET", f"/users/{user}")
    res.raise_for_status()
    rep: dict = res.json()
    return rep


def get_keycloak_token(
    user: str = "test",
    generation: int | None = None,
    scope: str = DEFAULT_OAUTH_SCOPE,
) -> str:
    """Mint a real Keycloak access token for `user` with the given generation and scope."""
    rep = _keycloak_user(user)
    attributes = rep.get("attributes") or {}
    if generation is None:
        attributes.pop(KEYCLOAK_GENERATION_ATTRIBUTE, None)
    else:
        attributes[KEYCLOAK_GENERATION_ATTRIBUTE] = [str(generation)]
    rep["attributes"] = attributes
    _keycloak_admin("PUT", f"/users/{user}", json=rep).raise_for_status()

    base, realm = _keycloak_issuer()
    res = requests.post(
        f"{base}/realms/{realm}/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": KEYCLOAK_TEST_CLIENT_ID,
            "username": user,
            "password": _KEYCLOAK_USER_PASSWORD,
            "scope": scope,
        },
        timeout=10,
    )
    res.raise_for_status()
    token: str = res.json()["access_token"]
    return token


class KeycloakSession:
    """Stands in for a PyFxA session in test_e2e.py: a user with a `uid`."""

    def __init__(self, uid: str):
        """Wrap the Keycloak user ID."""
        self.uid = uid


class KeycloakOAuthClient:
    """Stands in for PyFxA's OAuth client in test_e2e.py."""

    def authorize_token(self, session: KeycloakSession, scope: str) -> str:
        """Mint a Keycloak access token for the session's user with only `scope`."""
        return get_keycloak_token(user=session.uid, scope=scope)


def keycloak_e2e_auth() -> dict:
    """Return the same keys test_e2e.py uses from the FxA account fixture."""
    session = KeycloakSession(str(uuid.uuid4()))
    oauth_client = KeycloakOAuthClient()
    return {
        "session": session,
        "oauth_client": oauth_client,
        "oauth_token": oauth_client.authorize_token(session, DEFAULT_OAUTH_SCOPE),
    }


# ── SQL helpers ───────────────────────────────────────────────────────────────


def execute_sql(conn, query, params=None):
    """Execute a SQL statement and return the cursor."""
    return conn.execute(query, params or {})


def clear_db(conn) -> None:
    """Delete all users and nodes.

    Services are intentionally not cleared: tokenserver may have cached
    its service_id and a DELETE would invalidate that cache mid-run.
    """
    execute_sql(conn, sqltext("DELETE FROM users"), {}).close()
    execute_sql(conn, sqltext("DELETE FROM nodes"), {}).close()


def get_service_id(conn, service: str):
    """Return the ID for the given service name, or None if not found."""
    cursor = execute_sql(
        conn,
        sqltext("select id from services where service = :service"),
        {"service": service},
    )
    row = cursor.fetchone()
    cursor.close()
    return None if row is None else row[0]


def add_service(conn, service: str, pattern: str) -> int:
    """Insert a services row and return its ID."""
    db_mode = get_db_mode()
    if db_mode == "postgres":
        sql = sqltext(
            "insert into services (service, pattern) values (:service, :pattern) RETURNING id"
        )
        cursor = execute_sql(conn, sql, {"service": service, "pattern": pattern})
        result: int = cursor.fetchone()[0]
    else:
        sql = sqltext(
            "insert into services (service, pattern) values (:service, :pattern)"
        )
        cursor = execute_sql(conn, sql, {"service": service, "pattern": pattern})
        result = cursor.lastrowid
    cursor.close()
    return result


def get_or_add_service(conn, service: str, pattern: str) -> int:
    """Return existing service ID, inserting a new row if it does not exist."""
    service_id = get_service_id(conn, service)
    if service_id is not None:
        return int(service_id)
    return add_service(conn, service, pattern)


def add_node(
    conn,
    service_id: int,
    capacity: int = 100,
    available: int = 100,
    node: str = NODE_URL,
    id: int | None = None,
    current_load: int = 0,
    backoff: int = 0,
    downed: int = 0,
) -> int:
    """Insert a nodes row and return its ID."""
    db_mode = get_db_mode()
    params = {
        "service": service_id,
        "node": node,
        "available": available,
        "capacity": capacity,
        "current_load": current_load,
        "backoff": backoff,
        "downed": downed,
    }
    if id is not None:
        params["id"] = id
        cols = "service, node, available, capacity, current_load, backoff, downed, id"
        vals = ":service, :node, :available, :capacity, :current_load, :backoff, :downed, :id"
    else:
        cols = "service, node, available, capacity, current_load, backoff, downed"
        vals = (
            ":service, :node, :available, :capacity, :current_load, :backoff, :downed"
        )

    result: int
    if db_mode == "postgres":
        sql = sqltext(f"insert into nodes ({cols}) values ({vals}) RETURNING id")  # nosec B608 - cols/vals are hardcoded literals, not user input
        cursor = execute_sql(conn, sql, params)
        result = cursor.fetchone()[0]
    else:
        sql = sqltext(f"insert into nodes ({cols}) values ({vals})")  # nosec B608
        cursor = execute_sql(conn, sql, params)
        result = cursor.lastrowid
    cursor.close()
    return result


def get_node(conn, node_id: int) -> dict:
    """Return a node dict by ID."""
    cursor = execute_sql(
        conn, sqltext("select * from nodes where id = :id"), {"id": node_id}
    )
    (id_, service, node, available, current_load, capacity, downed, backoff) = (
        cursor.fetchone()
    )
    cursor.close()
    return {
        "id": id_,
        "service": service,
        "node": node,
        "available": available,
        "current_load": current_load,
        "capacity": capacity,
        "downed": downed,
        "backoff": backoff,
    }


def add_user(
    conn,
    service_id: int,
    email: str | None = None,
    nodeid: int = NODE_ID,
    generation: int = 1234,
    keys_changed_at: int | None = 1234,
    client_state: str = "aaaa",
    created_at: int | None = None,
    replaced_at: int | None = None,
) -> int:
    """Insert a users row and return its uid."""
    db_mode = get_db_mode()
    created_at = created_at or math.trunc(time.time() * 1000)
    params = {
        "service": service_id,
        "email": email or f"test@{FXA_EMAIL_DOMAIN}",
        "nodeid": nodeid,
        "generation": generation,
        "keys_changed_at": keys_changed_at,
        "client_state": client_state,
        "created_at": created_at,
        "replaced_at": replaced_at,
    }
    result: int
    if db_mode == "postgres":
        sql = sqltext("""\
            insert into users
                (service, email, nodeid, generation, keys_changed_at,
                 client_state, created_at, replaced_at)
            values
                (:service, :email, :nodeid, :generation, :keys_changed_at,
                 :client_state, :created_at, :replaced_at)
            RETURNING uid
        """)
        cursor = execute_sql(conn, sql, params)
        result = cursor.fetchone()[0]
    else:
        sql = sqltext("""\
            insert into users
                (service, email, nodeid, generation, keys_changed_at,
                 client_state, created_at, replaced_at)
            values
                (:service, :email, :nodeid, :generation, :keys_changed_at,
                 :client_state, :created_at, :replaced_at)
        """)
        cursor = execute_sql(conn, sql, params)
        result = cursor.lastrowid
    cursor.close()
    return result


def get_user(conn, uid: int) -> dict:
    """Return a user dict by uid."""
    cursor = execute_sql(
        conn, sqltext("select * from users where uid = :uid"), {"uid": uid}
    )
    (
        uid,
        service,
        email,
        generation,
        client_state,
        created_at,
        replaced_at,
        nodeid,
        keys_changed_at,
    ) = cursor.fetchone()
    cursor.close()
    return {
        "uid": uid,
        "service": service,
        "email": email,
        "generation": generation,
        "client_state": client_state,
        "created_at": created_at,
        "replaced_at": replaced_at,
        "nodeid": nodeid,
        "keys_changed_at": keys_changed_at,
    }


def get_replaced_users(conn, service_id: int, email: str) -> list:
    """Return a list of user dicts for records with a non-null replaced_at."""
    cursor = execute_sql(
        conn,
        sqltext("""\
            select * from users
             where service = :service
               and email = :email
               and replaced_at is not null
        """),
        {"service": service_id, "email": email},
    )
    users = []
    for row in cursor.fetchall():
        (
            uid,
            service,
            email,
            generation,
            client_state,
            created_at,
            replaced_at,
            nodeid,
            keys_changed_at,
        ) = row
        users.append(
            {
                "uid": uid,
                "service": service,
                "email": email,
                "generation": generation,
                "client_state": client_state,
                "created_at": created_at,
                "replaced_at": replaced_at,
                "nodeid": nodeid,
                "keys_changed_at": keys_changed_at,
            }
        )
    cursor.close()
    return users


def count_users(conn) -> int:
    """Return the count of distinct user UIDs."""
    cursor = execute_sql(conn, sqltext("select COUNT(DISTINCT(uid)) from users"), {})
    (count,) = cursor.fetchone()
    cursor.close()
    return int(count)


# ── Auth helpers ──────────────────────────────────────────────────────────────


def build_oauth_headers(
    generation: int | None = None,
    user: str = "test",
    keys_changed_at: int | None = None,
    client_state: str | None = None,
    status: int = 200,
    **additional_headers: str,
) -> dict:
    """Build OAuth Bearer + X-KeyID headers for a test request."""
    if is_using_oidc():
        # A real token from Keycloak; see the Keycloak helpers above
        if status != 200:
            raise ValueError(
                "Keycloak can't be told to fail verification with a status"
            )
        token = get_keycloak_token(user=user, generation=generation)
        headers = {"Authorization": f"Bearer {token}"}
        client_state_bytes = binascii.unhexlify(client_state or "")
        client_state_b64 = b64encode(client_state_bytes).strip(b"=").decode("utf-8")
        headers["X-KeyID"] = f"{keys_changed_at}-{client_state_b64}"
        headers.update(additional_headers)
        return headers

    claims = {
        "user": user,
        "generation": generation,
        "client_id": "fake client id",
        "scope": [DEFAULT_OAUTH_SCOPE],
    }
    if generation is not None:
        claims["generation"] = generation
    body = {"body": claims, "status": status}
    headers = {}
    headers["Authorization"] = f"Bearer {json.dumps(body)}"
    client_state_bytes = binascii.unhexlify(client_state or "")
    client_state_b64 = b64encode(client_state_bytes).strip(b"=").decode("utf-8")
    headers["X-KeyID"] = f"{keys_changed_at}-{client_state_b64}"
    headers.update(additional_headers)
    return headers


def make_app(host: str) -> TestApp:
    """Build a WebTest TestApp pointing at the given host URL."""
    host_url = urlparse.urlparse(host)
    return TestApp(
        host,
        extra_environ={
            "HTTP_HOST": host_url.netloc,
            "wsgi.url_scheme": host_url.scheme or "http",
            "SERVER_NAME": host_url.hostname,
            "REMOTE_ADDR": "127.0.0.1",
            "SCRIPT_NAME": host_url.path,
        },
    )


def unsafe_parse_token(token: str) -> dict:
    """Parse a tokenlib token without verifying its HMAC signature."""
    return json.loads(decode_token_bytes(token)[:-32].decode("utf8"))  # type: ignore[no-any-return]
