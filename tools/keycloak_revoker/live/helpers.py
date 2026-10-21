# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Helpers and constants for the live revocation tests. No fixtures here.

Tokens, passwords and the revoker's environment are held in Secret and
RevokerEnv, whose repr is masked. A Secret is unwrapped only inside a `try`
that turns any exception into one naming its type alone, raised `from None`:
HTTP calls go through `send`, SQL with a secret parameter through `_sql`. So a
failing test shows none of them: neither pytest's assertion details, nor the
arguments it prints for each frame of a traceback, nor an exception's message
(SQLAlchemy's lists the statement's parameters).
"""

import base64
import html
import json
import os
import re
import secrets
import subprocess
import sys
import time
from typing import Any, Optional
from urllib.parse import urlsplit

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
# The MySQL account the revoker runs with, with the README's grants only
REVOKER_DB_USER = "revoker_live"


class Secret:
    """A token, password or other secret value, masked in test output."""

    __slots__ = ("value",)

    def __init__(self, value: str) -> None:
        self.value = value

    def __repr__(self) -> str:
        return "Secret(***)"

    __str__ = __repr__


class RevokerEnv(dict):
    """The revoker's environment; its repr names the variables only."""

    def __repr__(self) -> str:
        return f"RevokerEnv({', '.join(sorted(self))})"

    def but(self, **changes: str) -> "RevokerEnv":
        """Return a copy with some variables changed."""
        return RevokerEnv({**self, **changes})


def reveal(value: Any) -> Any:
    """Return `value` with every Secret in it (in dicts and lists) unwrapped."""
    if isinstance(value, Secret):
        return value.value
    if isinstance(value, dict):
        return {k: reveal(v) for k, v in value.items()}
    if isinstance(value, list):
        return [reveal(v) for v in value]
    return value


def send(
    method: str,
    url: str,
    session: Optional[requests.Session] = None,
    **kwargs: Any,
) -> requests.Response:
    """Send an HTTP request whose data, json and headers may hold Secrets.

    Any failure raises AssertionError without the requests traceback, whose
    frames would show the unwrapped values, and without the exception's
    message: not only a RequestException, but also, for example, the
    ValueError of a header requests refuses.
    """
    try:
        return (session or requests.Session()).request(
            method, url, timeout=10, **reveal(kwargs)
        )
    except Exception as e:
        raise AssertionError(f"{method} {url}: {type(e).__name__}") from None


def why(res: requests.Response) -> str:
    """Describe a failed response for an assertion message, without any token.

    Only the status and the error fields of a Keycloak or Tokenserver error
    body are kept; a success body, which holds tokens or Hawk credentials,
    shows none of them.
    """
    try:
        body = res.json()
    except ValueError:
        body = None
    fields = ("error", "error_description", "status", "errors")
    errors = {k: body[k] for k in fields if k in body} if isinstance(body, dict) else {}
    return f"HTTP {res.status_code} {json.dumps(errors)}"


class KeycloakAdmin:
    """Calls the Keycloak admin API as the master realm's admin."""

    def __init__(self) -> None:
        issuer = os.environ["SYNC_TOKENSERVER__OIDC_ISSUER_URL"].rstrip("/")
        self.issuer = issuer
        self.base, self.realm = issuer.rsplit("/realms/", 1)
        self._token = Secret("")
        self._expires = 0.0

    def __repr__(self) -> str:
        return f"KeycloakAdmin({self.issuer})"

    def __call__(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """Call the realm's admin API; `json` and `params` may hold Secrets."""
        if self._expires < time.time() + 10:
            res = send(
                "POST",
                f"{self.base}/realms/master/protocol/openid-connect/token",
                data={
                    "grant_type": "password",
                    "client_id": "admin-cli",
                    "username": os.environ["KEYCLOAK_ADMIN_USERNAME"],
                    "password": Secret(os.environ["KEYCLOAK_ADMIN_PASSWORD"]),
                },
            )
            assert res.status_code == 200, why(res)
            self._token = Secret(res.json()["access_token"])
            self._expires = time.time() + res.json()["expires_in"]
        return send(
            method,
            f"{self.base}/admin/realms/{self.realm}{path}",
            headers={"Authorization": Secret(f"Bearer {self._token.value}")},
            **kwargs,
        )


def run_revoker(env: RevokerEnv, *args: str, status: int = 0) -> str:
    """Run revoker.py once with `args`; fail the test unless it exits `status`."""
    try:
        proc = subprocess.run(
            [sys.executable, REVOKER, *args],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except Exception as e:
        # The frames below would show the environment unwrapped
        raise AssertionError(f"revoker {' '.join(args)}: {type(e).__name__}") from None
    # The revoker logs Keycloak user IDs only, so its output can be shown
    sys.stderr.write(proc.stderr)
    assert proc.returncode == status, (
        f"revoker {' '.join(args)} exited {proc.returncode}"
    )
    return proc.stderr


def jwt_payload(token: Secret) -> dict:
    """Decode a JWT's payload without verifying it (to read typ in tests)."""
    try:
        payload = token.value.split(".")[1]
        claims: dict = json.loads(
            base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        )
    except Exception as e:
        raise AssertionError(f"not a JWT: {type(e).__name__}") from None
    return claims


def create_user(admin: KeycloakAdmin, name: str, password: Secret) -> str:
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
    assert res.status_code == 201, why(res)
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


def login(
    admin: KeycloakAdmin, name: str, password: Secret, offline: bool
) -> dict[str, Secret]:
    """Sign in as LIVE_CLIENT_ID; return the access and refresh tokens."""
    scope = DEFAULT_OAUTH_SCOPE + (" offline_access" if offline else "")
    res = send(
        "POST",
        token_endpoint(admin),
        data={
            "grant_type": "password",
            "client_id": LIVE_CLIENT_ID,
            "username": name,
            "password": password,
            "scope": scope,
        },
    )
    assert res.status_code == 200, why(res)
    body = res.json()
    tokens = {
        "access_token": Secret(body["access_token"]),
        "refresh_token": Secret(body["refresh_token"]),
    }
    # The session really is of the kind the test case is about
    typ = jwt_payload(tokens["refresh_token"])["typ"]
    expected = "Offline" if offline else "Refresh"
    assert typ == expected, f"refresh token of type {typ}"
    return tokens


def refresh(admin: KeycloakAdmin, refresh_token: Secret) -> requests.Response:
    """Refresh as LIVE_CLIENT_ID; return the response."""
    return send(
        "POST",
        token_endpoint(admin),
        data={
            "grant_type": "refresh_token",
            "client_id": LIVE_CLIENT_ID,
            "refresh_token": refresh_token,
        },
    )


def introspect(admin: KeycloakAdmin, token: Secret) -> bool:
    """Return whether Keycloak reports the token as active (asked as the revoker)."""
    with open(os.environ["REVOKER_CLIENT_SECRET_FILE"]) as f:
        secret = Secret(f.read().strip())
    res = send(
        "POST",
        f"{token_endpoint(admin)}/introspect",
        data={
            "client_id": os.environ["REVOKER_CLIENT_ID"],
            "client_secret": secret,
            "token": token,
        },
    )
    assert res.status_code == 200, why(res)
    active: bool = res.json()["active"]
    return active


def _browse(session: requests.Session, method: str, url: str, **kwargs: Any) -> Any:
    """Send a request as a browser would, without following redirects.

    Keycloak marks its login cookies Secure. Browsers send those to
    http://localhost too, which requests doesn't, so they are unmarked here
    (the live tests reach Keycloak over plain HTTP on localhost only).
    """
    res = send(method, url, session=session, allow_redirects=False, **kwargs)
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
    admin: KeycloakAdmin, name: str, password: Secret, new_password: Secret
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
    # The redirect holds an authorization code: kept out of the assertion
    succeeded = "kc_action_status=success" in res.headers["Location"]
    assert succeeded, "Keycloak didn't report the password update as done"


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


def exchange(access_token: Secret) -> requests.Response:
    """Ask Tokenserver for a sync token with an access token; return the response.

    A 200 response holds Hawk credentials: describe it with `why` only.
    """
    client_state = base64.urlsafe_b64encode(bytes.fromhex("aaaa")).rstrip(b"=")
    return send(
        "GET",
        f"{os.environ['TOKENSERVER_HOST']}/1.0/sync/1.5",
        headers={
            "Authorization": Secret(f"Bearer {access_token.value}"),
            "X-KeyID": f"1234-{client_state.decode()}",
        },
    )


def create_revoker_db_account(db: Any) -> Secret:
    """Create the revoker's MySQL account, as README.md says; return its URL.

    It may only select and update Tokenserver's `users` table.
    """
    url = urlsplit(os.environ["SYNC_TOKENSERVER__DATABASE_URL"])
    database = url.path.lstrip("/")
    password = Secret(secrets.token_hex(24))
    drop_revoker_db_account(db)
    _sql(
        db,
        f"creating {REVOKER_DB_USER}",
        f"CREATE USER '{REVOKER_DB_USER}'@'%' IDENTIFIED BY :password",
        password=password,
    )
    _sql(
        db,
        f"granting {REVOKER_DB_USER}",
        f"GRANT SELECT, UPDATE ON `{database}`.users TO '{REVOKER_DB_USER}'@'%'",
    )
    netloc = f"{REVOKER_DB_USER}:{password.value}@{url.hostname}:{url.port or 3306}"
    return Secret(url._replace(netloc=netloc).geturl())


def drop_revoker_db_account(db: Any) -> None:
    """Drop the revoker's MySQL account, if it exists."""
    _sql(
        db,
        f"dropping {REVOKER_DB_USER}",
        f"DROP USER IF EXISTS '{REVOKER_DB_USER}'@'%'",
    )


def _sql(db: Any, what: str, statement: str, **params: Any) -> None:
    """Run an SQL statement whose parameters may be Secrets.

    A failure raises AssertionError naming `what` and the exception's type
    only: SQLAlchemy's message lists the parameters, and the frames below this
    one would show them unwrapped.
    """
    try:
        db._execute_sql(sqltext(statement), **reveal(params)).close()
    except Exception as e:
        raise AssertionError(f"{what}: {type(e).__name__}") from None


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
