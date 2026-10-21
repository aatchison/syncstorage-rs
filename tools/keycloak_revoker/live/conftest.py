# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Fixtures for the live revocation tests (run by keycloak/run-suite.sh).

They need a running Keycloak with keycloak/realm-export.json, its master admin,
the revoker's client secret, and a Tokenserver in OIDC mode that accepts tokens
from LIVE_CLIENT_ID. Settings, all required:

  SYNC_TOKENSERVER__OIDC_ISSUER_URL   e.g. http://localhost:7080/realms/sync
  KEYCLOAK_ADMIN_USERNAME, KEYCLOAK_ADMIN_PASSWORD
  REVOKER_CLIENT_ID, REVOKER_CLIENT_SECRET_FILE
  TOKENSERVER_HOST                    e.g. http://localhost:8000
  SYNC_TOKENSERVER__DATABASE_URL, SYNC_TOKENSERVER__FXA_EMAIL_DOMAIN

SYNC_TOKENSERVER__DATABASE_URL must be able to create MySQL accounts: the
revoker runs with its own account, which may only select and update `users`.
"""

import os

import pytest

from .helpers import (
    BROWSER_CLIENT_ID,
    BROWSER_REDIRECT_URI,
    DEFAULT_OAUTH_SCOPE,
    LIVE_CLIENT_ID,
    NODE_URL,
    Database,
    KeycloakAdmin,
    RevokerEnv,
    client_uuid,
    create_revoker_db_account,
    drop_revoker_db_account,
    run_revoker,
)


@pytest.fixture(scope="session")
def admin():
    """Return a KeycloakAdmin, after adding the Thunderbird stand-in client and
    the browser client.
    """
    admin = KeycloakAdmin()
    res = admin(
        "POST",
        "/clients",
        json={
            "clientId": LIVE_CLIENT_ID,
            "protocol": "openid-connect",
            "publicClient": True,
            "standardFlowEnabled": False,
            "directAccessGrantsEnabled": True,
            "fullScopeAllowed": False,
            # Tokenserver accepts only RFC 9068 access tokens
            "attributes": {"access.token.header.type.rfc9068": "true"},
            "defaultClientScopes": ["basic"],
            "optionalClientScopes": [DEFAULT_OAUTH_SCOPE, "offline_access"],
        },
    )
    if res.status_code != 409:
        res.raise_for_status()
    res = admin(
        "POST",
        "/clients",
        json={
            "clientId": BROWSER_CLIENT_ID,
            "protocol": "openid-connect",
            "publicClient": True,
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": False,
            "fullScopeAllowed": False,
            "redirectUris": [BROWSER_REDIRECT_URI],
            "defaultClientScopes": ["basic"],
        },
    )
    if res.status_code != 409:
        res.raise_for_status()
    return admin


@pytest.fixture(scope="session")
def live_client(admin):
    """Return the internal ID of the Thunderbird stand-in client."""
    return client_uuid(admin, LIVE_CLIENT_ID)


@pytest.fixture(scope="session")
def db():
    """Return tools/tokenserver's Database, with the sync service and a node."""
    database = Database()
    try:
        database._get_service_id("sync-1.5")
    except Exception:
        database.add_service("sync-1.5", r"{node}/1.5/{uid}")
    try:
        database.get_node_id(NODE_URL)
    except ValueError:
        database.add_node(NODE_URL, 1000, available=1000)
    yield database
    database.close()


@pytest.fixture(scope="session")
def revoker_db_url(db):
    """Return the URL of a MySQL account with only the revoker's grants."""
    url = create_revoker_db_account(db)
    yield url
    drop_revoker_db_account(db)


@pytest.fixture(scope="session")
def revoker_env(tmp_path_factory, revoker_db_url):
    """Return the environment the revoker runs with, its cursor in a temp dir."""
    issuer = os.environ["SYNC_TOKENSERVER__OIDC_ISSUER_URL"].rstrip("/")
    base, realm = issuer.rsplit("/realms/", 1)
    # The revoker's own settings only: not the tests' (the Keycloak admin
    # password, Tokenserver's database URL, proxies)
    return RevokerEnv(
        {
            "REVOKER_KEYCLOAK_URL": base,
            "REVOKER_REALM": realm,
            "REVOKER_CLIENT_ID": os.environ["REVOKER_CLIENT_ID"],
            "REVOKER_CLIENT_SECRET_FILE": os.environ["REVOKER_CLIENT_SECRET_FILE"],
            "REVOKER_OFFLINE_CLIENTS": LIVE_CLIENT_ID,
            "REVOKER_CURSOR_FILE": str(tmp_path_factory.mktemp("revoker") / "cursor"),
            "REVOKER_LOG_LEVEL": "DEBUG",
            "SYNC_TOKENSERVER__DATABASE_URL": revoker_db_url.value,
            "SYNC_TOKENSERVER__FXA_EMAIL_DOMAIN": os.environ[
                "SYNC_TOKENSERVER__FXA_EMAIL_DOMAIN"
            ],
            "SQLALCHEMY_SILENCE_UBER_WARNING": "1",
        }
    )


@pytest.fixture(scope="session")
def revoker(revoker_env, admin, db):
    """Return a function that runs the revoker, after starting its cursor."""
    # As on a first deployment: the first run creates the cursor at the
    # current time
    run_revoker(revoker_env, "--once", "--init-cursor")
    return lambda *args: run_revoker(revoker_env, *args)
