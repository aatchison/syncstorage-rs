# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Revoke Keycloak sessions and retire Tokenserver users from Keycloak events.

Keycloak has no webhook, so this polls the realm's stored user events and admin
events and acts on them through the Keycloak admin API and the Tokenserver
database:

  password change (user events UPDATE_PASSWORD, UPDATE_CREDENTIAL of a password,
  admin ACTION users/<id>/reset-password), and any admin UPDATE users/<id>,
  which may have set a password
      sign the user out of every session (POST users/<id>/logout), then revoke
      their offline sessions of each configured client
      (DELETE users/<id>/consents/<client>)
  admin sign-out (ACTION users/<id>/logout)
      revoke the offline sessions, which Keycloak's sign-out leaves alive
  user deleted (admin DELETE users/<id>, user event DELETE_ACCOUNT)
      retire the Tokenserver user "<id>@<FXA_EMAIL_DOMAIN>"

Any other event is ignored. With --reconcile it instead retires every
Tokenserver user whose Keycloak user no longer exists, which catches deletions
whose events were missed; it refuses when Keycloak's answers look wrong, or
(without --force) when that would retire too many users.

Settings come from the environment; see README.md. Logs name Keycloak user IDs
only, never emails or secrets.
"""

import argparse
import base64
import hashlib
import json
import logging
import os
import re
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional
from urllib.parse import quote

import requests
from sqlalchemy.sql import text as sqltext

# tools/tokenserver's modules import each other as top-level modules, as its
# scripts run with that directory on the path
try:
    from database import Database
except ImportError:
    sys.path.insert(
        0,
        os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tokenserver"
        ),
    )
    from database import Database

logger = logging.getLogger("keycloak_revoker")

# What to do for an event
REVOKE_ALL = "revoke-all-sessions"
REVOKE_OFFLINE = "revoke-offline-sessions"
RETIRE = "retire-tokenserver-user"

# UPDATE_CREDENTIAL counts only for a password: Keycloak also emits it when an
# OTP or WebAuthn credential is set up. A password change emits both events.
PASSWORD_USER_EVENTS = ("UPDATE_CREDENTIAL", "UPDATE_PASSWORD")
DELETE_USER_EVENTS = ("DELETE_ACCOUNT",)
# users/<id>, users/<id>/reset-password or users/<id>/logout, nothing deeper
ADMIN_USER_PATH = re.compile(r"^users/([^/]+)(?:/(reset-password|logout))?$")

PAGE_SIZE = 100
# Keycloak's body for a 404 on a user that doesn't exist. A 404 without it may
# come from a proxy or a wrong URL, and doesn't show that a user is gone.
USER_NOT_FOUND = "User not found"
# The 404s of DELETE users/<id>/consents/<client>: the user has no consent or
# offline session for the client (nothing to revoke), or no such client exists
CONSENT_NOT_FOUND = "Consent nor offline token not found"
CLIENT_NOT_FOUND = "Client not found"
# The cursor never moves past the revoker's own clock minus this
CLOCK_MARGIN_MS = 1000
# --reconcile retires at most this share of the active users without --force
RECONCILE_MAX_SHARE = 0.1

_ACTIVE_EMAILS = sqltext("""\
select distinct
    email
from
    users
where
    replaced_at is null
""")


class RevokerError(Exception):
    """A failure that stops this poll or reconcile; it is safe to log."""


@dataclass(frozen=True)
class Action:
    """An action to take for one Keycloak user."""

    kind: str
    user_id: str


def user_event_action(event: Mapping[str, Any]) -> Optional[Action]:
    """Return the action for a Keycloak user event, or None to ignore it."""
    user_id = event.get("userId")
    if not user_id or event.get("error"):
        return None
    details = event.get("details") or {}
    if event.get("type") == "UPDATE_PASSWORD" or (
        event.get("type") == "UPDATE_CREDENTIAL"
        and details.get("credential_type") == "password"
    ):
        # Whether or not the user ticked "Sign out from other devices"
        return Action(REVOKE_ALL, user_id)
    if event.get("type") in DELETE_USER_EVENTS:
        return Action(RETIRE, user_id)
    return None


def admin_event_action(event: Mapping[str, Any]) -> Optional[Action]:
    """Return the action for a Keycloak admin event, or None to ignore it."""
    if event.get("resourceType") != "USER" or event.get("error"):
        return None
    match = ADMIN_USER_PATH.match(event.get("resourcePath") or "")
    if not match:
        return None
    user_id, sub_resource = match.groups()
    operation = event.get("operationType")
    if operation == "ACTION" and sub_resource == "reset-password":
        return Action(REVOKE_ALL, user_id)
    if operation == "UPDATE" and sub_resource is None:
        # PUT users/<id> can set a password through its credentials array, and
        # the event doesn't say whether it did: every update counts as one, so
        # profile edits and disabling sign the user out too
        return Action(REVOKE_ALL, user_id)
    if operation == "ACTION" and sub_resource == "logout":
        return Action(REVOKE_OFFLINE, user_id)
    if operation == "DELETE" and sub_resource is None:
        return Action(RETIRE, user_id)
    return None


def keycloak_error(res: requests.Response) -> Optional[str]:
    """Return the `error` of a Keycloak JSON error body, or None if it has none."""
    try:
        body = res.json()
    except ValueError:
        return None
    error = body.get("error") if isinstance(body, dict) else None
    return error if isinstance(error, str) else None


def event_key(kind: str, event: Mapping[str, Any]) -> str:
    """Return a key that identifies an event, for de-duplication."""
    if event.get("id"):
        return f"{kind}:{event['id']}"
    digest = hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()
    return f"{kind}:{digest}"


def _env_int(env: Mapping[str, str], name: str, default: int) -> int:
    value = env.get(name)
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        raise RevokerError(f"{name} must be an integer") from None


@dataclass
class Config:
    """Settings, from environment variables (see from_env)."""

    keycloak_url: str
    realm: str
    client_id: str
    client_secret: str = field(repr=False)
    offline_clients: list[str]
    email_domain: str
    cursor_file: str
    interval: int = 15
    overlap: int = 60
    timeout: int = 10
    attempts: int = 4
    reconcile_max: int = 10

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "Config":
        """Read the settings, raising RevokerError for a missing or bad one."""

        def required(name: str) -> str:
            value = env.get(name, "").strip()
            if not value:
                raise RevokerError(f"{name} must be set")
            return value

        secret_file = env.get("REVOKER_CLIENT_SECRET_FILE", "").strip()
        if secret_file:
            try:
                with open(secret_file) as f:
                    secret = f.read().strip()
            except OSError as e:
                raise RevokerError(
                    f"can't read REVOKER_CLIENT_SECRET_FILE: {e.strerror}"
                ) from None
        else:
            secret = env.get("REVOKER_CLIENT_SECRET", "").strip()
        if not secret:
            raise RevokerError(
                "REVOKER_CLIENT_SECRET_FILE or REVOKER_CLIENT_SECRET must be set"
            )
        # The clients Thunderbird signs in with: by default the ones Tokenserver
        # accepts tokens from
        clients = env.get("REVOKER_OFFLINE_CLIENTS") or env.get(
            "SYNC_TOKENSERVER__OIDC_ALLOWED_CLIENTS", ""
        )
        offline_clients = [c.strip() for c in clients.split(",") if c.strip()]
        if not offline_clients:
            raise RevokerError(
                "REVOKER_OFFLINE_CLIENTS or SYNC_TOKENSERVER__OIDC_ALLOWED_CLIENTS "
                "must be set"
            )
        config = cls(
            keycloak_url=required("REVOKER_KEYCLOAK_URL").rstrip("/"),
            realm=required("REVOKER_REALM"),
            client_id=env.get("REVOKER_CLIENT_ID", "").strip() or "keycloak-revoker",
            client_secret=secret,
            offline_clients=offline_clients,
            email_domain=required("SYNC_TOKENSERVER__FXA_EMAIL_DOMAIN"),
            cursor_file=required("REVOKER_CURSOR_FILE"),
            interval=_env_int(env, "REVOKER_INTERVAL", 15),
            overlap=_env_int(env, "REVOKER_OVERLAP", 60),
            timeout=_env_int(env, "REVOKER_TIMEOUT", 10),
            attempts=_env_int(env, "REVOKER_ATTEMPTS", 4),
            reconcile_max=_env_int(env, "REVOKER_RECONCILE_MAX", 10),
        )
        # database.py reads the URL itself; check it here so a missing URL fails
        # at startup rather than at the first deletion
        required("SYNC_TOKENSERVER__DATABASE_URL")
        return config


class Keycloak:
    """The parts of the Keycloak admin API the revoker uses.

    Authenticates as the revoker client's service account. A 5xx response or a
    network error is retried with exponential backoff; when the attempts run
    out RevokerError is raised.
    """

    def __init__(
        self,
        config: Config,
        session: Optional[requests.Session] = None,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.config = config
        self.session = session or requests.Session()
        self.sleep = sleep
        self._token: Optional[str] = None
        self._token_expires = 0.0

    def _send(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        """Send a request, retrying 5xx responses and network errors."""
        what = f"{method} {url.removeprefix(self.config.keycloak_url)}"
        for attempt in range(self.config.attempts):
            if attempt:
                self.sleep(2 ** (attempt - 1))
            try:
                res = self.session.request(
                    method, url, timeout=self.config.timeout, **kwargs
                )
            except requests.RequestException as e:
                logger.warning(
                    "%s: %s (attempt %d)", what, type(e).__name__, attempt + 1
                )
                continue
            if res.status_code < 500:
                return res
            logger.warning(
                "%s: HTTP %d (attempt %d)", what, res.status_code, attempt + 1
            )
        raise RevokerError(f"{what}: Keycloak unavailable")

    def _get_token(self) -> str:
        if self._token and time.monotonic() < self._token_expires:
            return self._token
        res = self._send(
            "POST",
            f"{self.config.keycloak_url}/realms/{self.config.realm}"
            "/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
            },
        )
        if res.status_code != 200:
            raise RevokerError(
                f"can't get a token for client {self.config.client_id}: "
                f"HTTP {res.status_code}"
            )
        body = res.json()
        self._token = body["access_token"]
        self._token_expires = time.monotonic() + max(body.get("expires_in", 60) - 30, 0)
        return self._token

    def admin(
        self, method: str, path: str, params: Optional[Mapping[str, Any]] = None
    ) -> requests.Response:
        """Call the realm's admin API. 2xx and 404 are returned; other errors raise."""
        url = f"{self.config.keycloak_url}/admin/realms/{self.config.realm}{path}"
        for _ in range(2):
            headers = {"Authorization": f"Bearer {self._get_token()}"}
            res = self._send(method, url, params=params, headers=headers)
            if res.status_code == 401:
                # The token expired or was revoked: get a new one, once
                self._token = None
                continue
            break
        if res.status_code != 404 and not 200 <= res.status_code < 300:
            raise RevokerError(f"{method} {path}: HTTP {res.status_code}")
        return res

    def _events(self, path: str, params: Mapping[str, Any]) -> list[dict]:
        events: list[dict] = []
        while True:
            page = {**params, "first": len(events), "max": PAGE_SIZE}
            res = self.admin("GET", path, params=page)
            if res.status_code != 200:
                raise RevokerError(f"GET {path}: HTTP {res.status_code}")
            batch = res.json()
            events.extend(batch)
            if len(batch) < PAGE_SIZE:
                return events

    def user_events(self, since_ms: int) -> list[dict]:
        """Return the user events stored since `since_ms`, oldest first."""
        return self._events(
            "/events",
            {
                "type": [*PASSWORD_USER_EVENTS, *DELETE_USER_EVENTS],
                "dateFrom": str(since_ms),
                "direction": "asc",
            },
        )

    def admin_events(self, since_ms: int) -> list[dict]:
        """Return the admin events on users stored since `since_ms`, oldest first."""
        return self._events(
            "/admin-events",
            {
                "resourceTypes": ["USER"],
                "operationTypes": ["ACTION", "DELETE", "UPDATE"],
                "dateFrom": str(since_ms),
                "direction": "asc",
            },
        )

    def client_uuid(self, client_id: str) -> str:
        """Return the internal ID of a client, raising RevokerError if there is none."""
        res = self.admin("GET", "/clients", params={"clientId": client_id})
        try:
            clients = res.json() if res.status_code == 200 else None
        except ValueError:
            clients = None
        if not isinstance(clients, list):
            raise RevokerError(f"GET /clients: HTTP {res.status_code} without clients")
        for client in clients:
            if isinstance(client, dict) and client.get("clientId") == client_id:
                return str(client["id"])
        # Without view-clients Keycloak answers with an empty list as well
        raise RevokerError(
            f"offline client {client_id} not found in the realm (or the revoker's "
            "service account lacks view-clients)"
        )

    def logout(self, user_id: str) -> None:
        """Sign the user out of all their (online) sessions."""
        res = self.admin("POST", f"/users/{quote(user_id, safe='')}/logout")
        # A user who no longer exists has no sessions left
        if res.status_code == 404 and keycloak_error(res) != USER_NOT_FOUND:
            raise RevokerError("POST /users/{id}/logout: unexpected HTTP 404")

    def revoke_offline(self, user_id: str, client_id: str) -> None:
        """Revoke the user's offline sessions (and consent) for a client."""
        res = self.admin(
            "DELETE",
            f"/users/{quote(user_id, safe='')}/consents/{quote(client_id, safe='')}",
        )
        if res.status_code != 404:
            return
        error = keycloak_error(res)
        if error == CLIENT_NOT_FOUND:
            raise RevokerError(f"offline client {client_id} not found in the realm")
        # Nothing is left to revoke: the user has no consent or offline session
        # for the client, or no longer exists at all
        if error not in (CONSENT_NOT_FOUND, USER_NOT_FOUND):
            raise RevokerError(
                "DELETE /users/{id}/consents/{client}: unexpected HTTP 404"
            )

    def user_exists(self, user_id: str) -> bool:
        """Return whether the user exists.

        Only Keycloak's own "User not found" 404 counts as a missing user; any
        other answer raises RevokerError.
        """
        res = self.admin("GET", f"/users/{quote(user_id, safe='')}")
        if res.status_code == 200:
            return True
        if res.status_code == 404 and keycloak_error(res) == USER_NOT_FOUND:
            return False
        raise RevokerError(f"GET /users/{{id}}: unexpected HTTP {res.status_code}")

    def user_count(self) -> int:
        """Return the number of users in the realm."""
        res = self.admin("GET", "/users/count")
        try:
            count = res.json() if res.status_code == 200 else None
        except ValueError:
            count = None
        # bool is an int subclass, and JSON true is no count
        if not isinstance(count, int) or isinstance(count, bool):
            raise RevokerError(
                f"GET /users/count: HTTP {res.status_code} without a user count"
            )
        return count

    def own_user_id(self) -> str:
        """Return the ID of the revoker's service-account user (its token's sub)."""
        token = self._get_token()
        try:
            payload = token.split(".")[1]
            claims = json.loads(
                base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
            )
            sub = claims["sub"]
        except (IndexError, ValueError, KeyError, TypeError):
            raise RevokerError("the revoker's token has no sub") from None
        if not isinstance(sub, str) or not sub:
            raise RevokerError("the revoker's token has no sub")
        return sub


@dataclass
class Cursor:
    """Where the event polling has got to, persisted as JSON.

    `time` is the time of the newest event handled, but never later than the
    revoker's own clock (minus CLOCK_MARGIN_MS) at the poll. Each poll asks
    for events from `time - overlap`, so an event that Keycloak stored late, or
    stamped with a clock that runs behind, still turns up; `seen` holds the
    keys of the events handled in that window, so none is handled twice.
    `floor` is the revoker's first start minus the overlap: older events are
    never handled.
    """

    path: str
    time: int
    floor: int
    seen: dict[str, int]

    @classmethod
    def load(cls, path: str, start_ms: int) -> "Cursor":
        """Load the cursor, or start one at `start_ms` if there is none."""
        try:
            with open(path) as f:
                data = json.load(f)
        except FileNotFoundError:
            cursor = cls(path, start_ms, start_ms, {})
            cursor.save()
            logger.info("no cursor file; starting from now minus REVOKER_OVERLAP")
            return cursor
        except (OSError, ValueError) as e:
            raise RevokerError(f"can't read the cursor file: {e}") from None
        return cls(path, int(data["time"]), int(data["floor"]), dict(data["seen"]))

    def save(self) -> None:
        """Write the cursor atomically."""
        directory = os.path.dirname(os.path.abspath(self.path))
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".revoker-cursor-")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(
                    {"time": self.time, "floor": self.floor, "seen": self.seen}, f
                )
            os.replace(tmp, self.path)
        except BaseException:
            os.unlink(tmp)
            raise


class Revoker:
    """Applies the actions for Keycloak events, and the reconcile."""

    def __init__(
        self,
        config: Config,
        keycloak: Optional[Keycloak] = None,
        db_factory: Callable[[], Any] = Database,
        clock: Callable[[], float] = time.time,
    ):
        self.config = config
        self.keycloak = keycloak or Keycloak(config)
        self._db_factory = db_factory
        self._db: Any = None
        self.clock = clock
        self._checked = False

    @property
    def db(self) -> Any:
        """Return the Tokenserver database, connecting on first use."""
        if self._db is None:
            self._db = self._db_factory()
        return self._db

    def retire(self, user_id: str) -> None:
        """Retire the Tokenserver user of a Keycloak user."""
        self.db.retire_user(f"{user_id}@{self.config.email_domain}")

    def apply(self, action: Action) -> None:
        """Take an action."""
        if action.kind == REVOKE_ALL:
            self.keycloak.logout(action.user_id)
        if action.kind in (REVOKE_ALL, REVOKE_OFFLINE):
            for client_id in self.config.offline_clients:
                self.keycloak.revoke_offline(action.user_id, client_id)
        if action.kind == RETIRE:
            self.retire(action.user_id)
        logger.info("%s: keycloak user %s", action.kind, action.user_id)

    def check(self) -> None:
        """Check, before the first poll, that the revoker can do its work.

        Every offline client must exist: DELETE users/<id>/consents/<client> of
        a missing one revokes nothing.
        """
        for client_id in self.config.offline_clients:
            self.keycloak.client_uuid(client_id)
        self._checked = True

    def poll_once(self) -> int:
        """Handle the events stored since the cursor; return how many acted on.

        The cursor is saved only when every event got handled, so after a
        failure the next poll starts from the same place.
        """
        if not self._checked:
            self.check()
        now_ms = int(self.clock() * 1000)
        overlap_ms = self.config.overlap * 1000
        # A first start looks back by the overlap too, in case the revoker's
        # clock runs ahead of Keycloak's
        cursor = Cursor.load(self.config.cursor_file, now_ms - overlap_ms)
        since = max(cursor.time - overlap_ms, cursor.floor)
        events = [("user", e) for e in self.keycloak.user_events(since)]
        events += [("admin", e) for e in self.keycloak.admin_events(since)]
        events.sort(key=lambda item: item[1].get("time", 0))

        seen = dict(cursor.seen)
        newest = cursor.time
        acted = 0
        for kind, event in events:
            key = event_key(kind, event)
            event_time = int(event.get("time", 0))
            if key in seen or event_time < cursor.floor:
                continue
            if kind == "user":
                action = user_event_action(event)
            else:
                action = admin_event_action(event)
            if action:
                self.apply(action)
                acted += 1
            seen[key] = event_time
            newest = max(newest, event_time)

        # An event stamped by a Keycloak node whose clock runs ahead must not
        # carry the next poll's window past the events the other nodes have
        # yet to store
        cursor.time = min(newest, now_ms - CLOCK_MARGIN_MS)
        cursor.seen = {k: t for k, t in seen.items() if t >= cursor.time - overlap_ms}
        cursor.save()
        return acted

    def reconcile(self, force: bool = False) -> int:
        """Retire Tokenserver users whose Keycloak user is gone; return how many.

        Retirement can't be undone, so nothing is retired unless Keycloak
        answers as expected for a user that certainly exists, and, without
        `force`, not more than REVOKER_RECONCILE_MAX users or 10 % of the
        active ones.
        """
        # A Keycloak with no users at all is far more likely to be the wrong one
        # (or a broken one) than a realm whose every user was deleted
        if self.keycloak.user_count() == 0:
            raise RevokerError("the realm has no users; not reconciling")
        # The revoker's own service-account user exists for sure: if Keycloak
        # says otherwise, its answers about other users mean nothing either
        if not self.keycloak.user_exists(self.keycloak.own_user_id()):
            raise RevokerError(
                "Keycloak reports the revoker's own service-account user as "
                "missing; not reconciling"
            )
        suffix = f"@{self.config.email_domain}"
        res = self.db._execute_sql(_ACTIVE_EMAILS)
        try:
            emails = [row[0] for row in res]
        finally:
            res.close()
        user_ids = [
            email[: -len(suffix)]
            for email in emails
            if email.endswith(suffix) and len(email) > len(suffix)
        ]
        gone = [
            user_id for user_id in user_ids if not self.keycloak.user_exists(user_id)
        ]
        too_many = (
            len(gone) > self.config.reconcile_max
            or len(gone) > len(user_ids) * RECONCILE_MAX_SHARE
        )
        if too_many and not force:
            raise RevokerError(
                f"reconcile would retire {len(gone)} of {len(user_ids)} active "
                f"users, more than REVOKER_RECONCILE_MAX "
                f"({self.config.reconcile_max}) or 10 %; retired none. If "
                "Keycloak really lost these users, rerun with --force"
            )
        for user_id in gone:
            self.retire(user_id)
            logger.info("reconcile: retired keycloak user %s", user_id)
        return len(gone)


def main(argv: Optional[list[str]] = None) -> int:
    """Run the revoker; returns the exit status."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="poll once, then exit")
    mode.add_argument(
        "--reconcile",
        action="store_true",
        help="retire Tokenserver users whose Keycloak user is gone, then exit",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="with --reconcile: retire however many users are gone",
    )
    args = parser.parse_args(argv)
    if args.force and not args.reconcile:
        parser.error("--force needs --reconcile")
    logging.basicConfig(
        level=os.environ.get("REVOKER_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    def run(step: Callable[[], int]) -> bool:
        try:
            count = step()
        except RevokerError as e:
            logger.error("%s", e)
            return False
        except Exception as e:
            # Database errors can carry SQL parameters (emails), so only the
            # error's type is logged
            logger.error("failed: %s", type(e).__name__)
            return False
        # A poll that found nothing is the usual case; keep it out of INFO
        level = logging.INFO if count or step.__name__ == "reconcile" else logging.DEBUG
        logger.log(level, "%s done: %d", step.__name__, count)
        return True

    try:
        config = Config.from_env(os.environ)
    except RevokerError as e:
        logger.error("%s", e)
        return 2
    revoker = Revoker(config)

    def reconcile() -> int:
        return revoker.reconcile(force=args.force)

    if args.reconcile:
        return 0 if run(reconcile) else 1
    try:
        revoker.check()
    except RevokerError as e:
        logger.error("%s", e)
        return 1
    if args.once:
        return 0 if run(revoker.poll_once) else 1
    while True:
        run(revoker.poll_once)
        time.sleep(config.interval)


if __name__ == "__main__":
    sys.exit(main())
