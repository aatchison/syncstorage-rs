# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Helpers and constants for the live revocation tests. No fixtures here."""

import base64
import html
import json
import os
import re
import subprocess
import sys
import time
from typing import Any, Mapping

import requests
from sqlalchemy.sql import text as sqltext

TOOLS = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REVOKER = os.path.join(TOOLS, "keycloak_revoker", "revoker.py")

# tools/tokenserver's modules import each other as top-level modules
try:
    from database import MAX_GENERATION, Database
except ImportError:
    sys.path.insert(0, os.path.join(TOOLS, "tokenserver"))
    from database import MAX_GENERATION, Database

__all__ = ["MAX_GENERATION", "Database"]

DEFAULT_OAUTH_SCOPE = "https://identity.mozilla.com/apps/oldsync"
# The Thunderbird stand-in: a public client like a desktop app's, which may ask
# for offline_access
LIVE_CLIENT_ID = "revoker-live-thunderbird"
# A browser client, for the user's own password change through Keycloak's pages
BROWSER_CLIENT_ID = "revoker-live-browser"
BROWSER_REDIRECT_URI = "http://127.0.0.1/revoker-live/callback"
NODE_URL = "https://revoker-live.example.com"


class KeycloakAdmin:
    """Calls the Keycloak admin API as the master realm's admin."""

    def __init__(self) -> None:
        issuer = os.environ["SYNC_TOKENSERVER__OIDC_ISSUER_URL"].rstrip("/")
        self.issuer = issuer
        self.base, self.realm = issuer.rsplit("/realms/", 1)
        self._token = None
        self._expires = 0.0

    def __call__(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        if self._expires < time.time() + 10:
            res = requests.post(
                f"{self.base}/realms/master/protocol/openid-connect/token",
                data={
                    "grant_type": "password",
                    "client_id": "admin-cli",
                    "username": os.environ["KEYCLOAK_ADMIN_USERNAME"],
                    "password": os.environ["KEYCLOAK_ADMIN_PASSWORD"],
                },
                timeout=10,
            )
            res.raise_for_status()
            self._token = res.json()["access_token"]
            self._expires = time.time() + res.json()["expires_in"]
        return requests.request(
            method,
            f"{self.base}/admin/realms/{self.realm}{path}",
            headers={"Authorization": f"Bearer {self._token}"},
            timeout=10,
            **kwargs,
        )


def run_revoker(env: Mapping[str, str], *args: str, status: int = 0) -> str:
    """Run revoker.py once with `args`; fail the test unless it exits `status`."""
    proc = subprocess.run(
        [sys.executable, REVOKER, *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    # The revoker logs Keycloak user IDs only, so its output can be shown
    sys.stderr.write(proc.stderr)
    assert proc.returncode == status, (
        f"revoker {' '.join(args)} exited {proc.returncode}"
    )
    return proc.stderr


def jwt_payload(token: str) -> dict:
    """Decode a JWT's payload without verifying it (to read typ in tests)."""
    payload = token.split(".")[1]
    claims: dict = json.loads(
        base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    )
    return claims


def create_user(admin: KeycloakAdmin, name: str, password: str) -> str:
    """Create an enabled Keycloak user with a password; return its ID (sub)."""
    res = admin(
        "POST",
        "/users",
        json={
            "username": name,
            "email": f"{name}@example.com",
            "emailVerified": True,
            "firstName": "Revoker",
            "lastName": "Test",
            "enabled": True,
            "credentials": [
                {"type": "password", "value": password, "temporary": False}
            ],
        },
    )
    assert res.status_code == 201, res.text
    user_id: str = res.headers["Location"].rstrip("/").rsplit("/", 1)[1]
    return user_id


def client_uuid(admin: KeycloakAdmin, client_id: str) -> str:
    """Return the internal ID of a client of the realm."""
    res = admin("GET", "/clients", params={"clientId": client_id})
    assert res.status_code == 200, res.status_code
    (client,) = [c for c in res.json() if c["clientId"] == client_id]
    uuid: str = client["id"]
    return uuid


def offline_sessions(admin: KeycloakAdmin, user_id: str, client: str) -> list:
    """Return the user's offline sessions of a client (by its internal ID)."""
    res = admin("GET", f"/users/{user_id}/offline-sessions/{client}")
    assert res.status_code == 200, res.status_code
    sessions: list = res.json()
    return sessions


def token_endpoint(admin: KeycloakAdmin) -> str:
    """Return the realm's token endpoint."""
    return f"{admin.issuer}/protocol/openid-connect/token"


def login(admin: KeycloakAdmin, name: str, password: str, offline: bool) -> dict:
    """Sign in as LIVE_CLIENT_ID; return the token response."""
    scope = DEFAULT_OAUTH_SCOPE + (" offline_access" if offline else "")
    res = requests.post(
        token_endpoint(admin),
        data={
            "grant_type": "password",
            "client_id": LIVE_CLIENT_ID,
            "username": name,
            "password": password,
            "scope": scope,
        },
        timeout=10,
    )
    assert res.status_code == 200, res.text
    tokens: dict = res.json()
    # The session really is of the kind the test case is about
    expected = "Offline" if offline else "Refresh"
    assert jwt_payload(tokens["refresh_token"])["typ"] == expected
    return tokens


def refresh(admin: KeycloakAdmin, refresh_token: str) -> requests.Response:
    """Refresh as LIVE_CLIENT_ID; return the response."""
    return requests.post(
        token_endpoint(admin),
        data={
            "grant_type": "refresh_token",
            "client_id": LIVE_CLIENT_ID,
            "refresh_token": refresh_token,
        },
        timeout=10,
    )


def introspect(admin: KeycloakAdmin, token: str) -> bool:
    """Return whether Keycloak reports the token as active (asked as the revoker)."""
    with open(os.environ["REVOKER_CLIENT_SECRET_FILE"]) as f:
        secret = f.read().strip()
    res = requests.post(
        f"{token_endpoint(admin)}/introspect",
        data={
            "client_id": os.environ["REVOKER_CLIENT_ID"],
            "client_secret": secret,
            "token": token,
        },
        timeout=10,
    )
    assert res.status_code == 200, res.status_code
    active: bool = res.json()["active"]
    return active


def _browse(session: requests.Session, method: str, url: str, **kwargs: Any) -> Any:
    """Send a request as a browser would, without following redirects.

    Keycloak marks its login cookies Secure. Browsers send those to
    http://localhost too, which requests doesn't, so they are unmarked here
    (the live tests reach Keycloak over plain HTTP on localhost only).
    """
    res = session.request(method, url, allow_redirects=False, timeout=10, **kwargs)
    for cookie in session.cookies:
        if cookie.domain in ("localhost.local", "127.0.0.1"):
            cookie.secure = False
    return res


def _form_action(page: requests.Response, form_id: str) -> str:
    """Return the action URL of a form on a Keycloak page."""
    match = re.search(rf'<form[^>]*\bid="{form_id}"[^>]*>', page.text)
    assert match, f"no form {form_id} on the page (HTTP {page.status_code})"
    action = re.search(r'\baction="([^"]+)"', match.group(0))
    assert action, f"form {form_id} has no action"
    return html.unescape(action.group(1))


def _follow(session: requests.Session, res: requests.Response) -> requests.Response:
    """Follow redirects within Keycloak, stopping at the browser client's redirect."""
    while res.is_redirect and not res.headers["Location"].startswith(
        BROWSER_REDIRECT_URI
    ):
        res = _browse(session, "GET", res.headers["Location"])
    return res


def change_password_as_user(
    admin: KeycloakAdmin, name: str, password: str, new_password: str
) -> None:
    """Change the user's password as the user would, in Keycloak's own pages.

    Signs in to BROWSER_CLIENT_ID with kc_action=UPDATE_PASSWORD (what the
    account console's "Update password" does), then fills in the new password,
    without ticking "Sign out from other devices".
    """
    session = requests.Session()
    page = _browse(
        session,
        "GET",
        f"{admin.issuer}/protocol/openid-connect/auth",
        params={
            "client_id": BROWSER_CLIENT_ID,
            "redirect_uri": BROWSER_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid",
            "kc_action": "UPDATE_PASSWORD",
        },
    )
    assert page.status_code == 200, page.status_code
    res = _browse(
        session,
        "POST",
        _form_action(page, "kc-form-login"),
        data={"username": name, "password": password, "credentialId": ""},
    )
    page = _follow(session, res)
    assert page.status_code == 200, page.status_code
    res = _browse(
        session,
        "POST",
        _form_action(page, "kc-passwd-update-form"),
        data={"password-new": new_password, "password-confirm": new_password},
    )
    res = _follow(session, res)
    assert res.is_redirect, res.status_code
    assert "kc_action_status=success" in res.headers["Location"]


def user_events(admin: KeycloakAdmin, user_id: str) -> list:
    """Return the types of the user's stored user events, newest first."""
    res = admin("GET", "/events", params={"user": user_id})
    assert res.status_code == 200, res.status_code
    return [event["type"] for event in res.json()]


def admin_events_on(admin: KeycloakAdmin, user_id: str) -> list:
    """Return the operation types of the stored admin events on a user."""
    res = admin("GET", "/admin-events", params={"resourcePath": f"users/{user_id}*"})
    assert res.status_code == 200, res.status_code
    return [event["operationType"] for event in res.json()]


def exchange(access_token: str) -> requests.Response:
    """Ask Tokenserver for a sync token with an access token; return the response."""
    client_state = base64.urlsafe_b64encode(bytes.fromhex("aaaa")).rstrip(b"=")
    return requests.get(
        f"{os.environ['TOKENSERVER_HOST']}/1.0/sync/1.5",
        headers={
            "Authorization": f"Bearer {access_token}",
            "X-KeyID": f"1234-{client_state.decode()}",
        },
        timeout=10,
    )


def tokenserver_email(user_id: str) -> str:
    """Return the Tokenserver email of a Keycloak user."""
    return f"{user_id}@{os.environ['SYNC_TOKENSERVER__FXA_EMAIL_DOMAIN']}"


def user_rows(db: Any, user_id: str) -> list[tuple]:
    """Return the (generation, replaced_at) of the user's Tokenserver records."""
    res = db._execute_sql(
        sqltext("select generation, replaced_at from users where email = :email"),
        email=tokenserver_email(user_id),
    )
    try:
        return [tuple(row) for row in res]
    finally:
        res.close()
