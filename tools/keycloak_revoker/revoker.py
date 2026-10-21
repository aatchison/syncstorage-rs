# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Revoke Keycloak sessions and retire Tokenserver users from Keycloak events.

Keycloak has no webhook, so this polls the realm's stored user events and admin
events and acts on them through the Keycloak admin API and the Tokenserver
database:

  password change (user events UPDATE_PASSWORD, UPDATE_CREDENTIAL of a password,
  admin ACTION users/<id>/reset-password), and an admin UPDATE users/<id> after
  which the user's password credential is newer than the event (less
  REVOKER_OVERLAP)
      sign the user out of every session (POST users/<id>/logout), then revoke
      their offline sessions of each configured client
      (DELETE users/<id>/consents/<client>)
  admin sign-out (ACTION users/<id>/logout)
      revoke the offline sessions, which Keycloak's sign-out leaves in place
      (it makes their tokens stale, except those issued in the same second)
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
# REVOKE_ALL, but only if the user's password was set at or after the event
REVOKE_ALL_IF_NEW_PASSWORD = "revoke-all-sessions-if-new-password"
REVOKE_OFFLINE = "revoke-offline-sessions"
RETIRE = "retire-tokenserver-user"

# UPDATE_CREDENTIAL counts only for a password: Keycloak also emits it when an
# OTP or WebAuthn credential is set up. A password change emits both events.
PASSWORD_USER_EVENTS = ("UPDATE_CREDENTIAL", "UPDATE_PASSWORD")
DELETE_USER_EVENTS = ("DELETE_ACCOUNT",)
# users/<id>, users/<id>/reset-password or users/<id>/logout, nothing deeper
ADMIN_USER_PATH = re.compile(r"^users/([^/]+)(?:/(reset-password|logout))?$")

PAGE_SIZE = 100
# The user events the realm must store. Not UPDATE_PASSWORD, deprecated in
# Keycloak 26 (EventType): every password change also emits UPDATE_CREDENTIAL
# with credential_type password. It is still acted on when stored.
REQUIRED_EVENT_TYPES = ("UPDATE_CREDENTIAL", *DELETE_USER_EVENTS)
# Keycloak's body for a 404 on a user that doesn't exist. A 404 without it may
# come from a proxy or a wrong URL, and doesn't show that a user is gone.
USER_NOT_FOUND = "User not found"
# The 404s of DELETE users/<id>/consents/<client>: the user has no consent or
# offline session for the client (nothing to revoke), or no such client exists
CONSENT_NOT_FOUND = "Consent nor offline token not found"
CLIENT_NOT_FOUND = "Client not found"
# The cursor never moves past the revoker's own clock minus this
CLOCK_MARGIN_MS = 1000
# --reconcile retires at most this percentage of the active users without
# --force, but at least 1
RECONCILE_MAX_PERCENT = 10

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


class FatalRevokerError(RevokerError):
    """A failure that retrying can't fix: the revoker exits, even when looping."""


@dataclass(frozen=True)
class Action:
    """An action to take for one Keycloak user."""

    kind: str
    user_id: str
    # The event's time, for REVOKE_ALL_IF_NEW_PASSWORD
    event_time: int = 0


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
        # PUT users/<id> can set a password through its credentials array, but
        # the event doesn't say whether it did (its representation never holds
        # credentials): the password's createdDate does
        return Action(REVOKE_ALL_IF_NEW_PASSWORD, user_id, int(event.get("time", 0)))
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


def _env_flag(env: Mapping[str, str], name: str) -> bool:
    value = env.get(name, "").strip()
    if value not in ("", "0", "1"):
        raise RevokerError(f"{name} must be 1 or 0")
    return value == "1"


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
    max_failures: int = 5
    init_cursor: bool = False
    recheck_interval: int = 3600
    # The realm's adminEventsExpiration in seconds, which the revoker can't
    # read; None: admin events are kept at least as long as user events
    admin_events_expiration: Optional[int] = None

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
            max_failures=_env_int(env, "REVOKER_MAX_FAILURES", 5),
            init_cursor=_env_flag(env, "REVOKER_INIT_CURSOR"),
            recheck_interval=_env_int(env, "REVOKER_RECHECK_INTERVAL", 3600),
            admin_events_expiration=_env_int(env, "REVOKER_ADMIN_EVENTS_EXPIRATION", 0)
            or None,
        )
        if config.max_failures < 1:
            raise RevokerError("REVOKER_MAX_FAILURES must be at least 1")
        if config.recheck_interval < 1:
            raise RevokerError("REVOKER_RECHECK_INTERVAL must be at least 1")
        if (
            config.admin_events_expiration is not None
            and config.admin_events_expiration < 0
        ):
            raise RevokerError("REVOKER_ADMIN_EVENTS_EXPIRATION must not be negative")
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

    def events_config(self) -> dict:
        """Return the realm's events configuration."""
        res = self.admin("GET", "/events/config")
        try:
            config = res.json() if res.status_code == 200 else None
        except ValueError:
            config = None
        if not isinstance(config, dict):
            raise RevokerError(
                f"GET /events/config: HTTP {res.status_code} without a configuration"
            )
        return config

    def check_offline_client(self, client_id: str) -> None:
        """Raise RevokerError unless the realm has the client.

        Revokes the client's offline sessions of the revoker's own
        service-account user, which never has any, so nothing changes. Unlike
        GET /clients, which needs view-clients, this needs no role beyond
        manage-users: Keycloak answers 404 "Client not found" for a missing
        client, and 204 or 404 "Consent nor offline token not found" for one
        that exists.
        """
        own = quote(self.own_user_id(), safe="")
        res = self.admin("DELETE", f"/users/{own}/consents/{quote(client_id, safe='')}")
        if res.status_code != 404:
            return
        error = keycloak_error(res)
        if error == CLIENT_NOT_FOUND:
            raise RevokerError(f"offline client {client_id} not found in the realm")
        # Any other 404, such as "User not found" for the revoker's own user,
        # says nothing about the client
        if error != CONSENT_NOT_FOUND:
            raise RevokerError(
                f"checking offline client {client_id}: DELETE "
                "/users/{id}/consents/{client}: unexpected HTTP 404"
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

    def password_created(self, user_id: str) -> Optional[list[int]]:
        """Return the createdDate of each of the user's password credentials.

        None if the user no longer exists (Keycloak's "User not found").
        """
        res = self.admin("GET", f"/users/{quote(user_id, safe='')}/credentials")
        if res.status_code == 404:
            if keycloak_error(res) == USER_NOT_FOUND:
                return None
            raise RevokerError("GET /users/{id}/credentials: unexpected HTTP 404")
        try:
            credentials = res.json()
        except ValueError:
            credentials = None
        if not isinstance(credentials, list):
            raise RevokerError(
                f"GET /users/{{id}}/credentials: HTTP {res.status_code} without a list"
            )
        created = []
        for c in credentials:
            if not isinstance(c, dict) or c.get("type") != "password":
                continue
            date = c.get("createdDate")
            if not isinstance(date, int) or isinstance(date, bool):
                raise RevokerError(
                    "GET /users/{id}/credentials: a password without a createdDate"
                )
            created.append(date)
        return created

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
    `floor` is the revoker's first start (with --init-cursor) minus the overlap: older events are
    never handled. `polled` is the revoker's clock at the start of the last
    poll that handled every event (or at the first start): events stored
    before it have been seen, however quiet the realm.
    """

    path: str
    time: int
    floor: int
    seen: dict[str, int]
    polled: int

    @classmethod
    def load(cls, path: str) -> "Cursor":
        """Load the cursor; a missing file is fatal (see `create`)."""
        try:
            with open(path) as f:
                data = json.load(f)
        except FileNotFoundError:
            # Starting afresh would skip every event since the last poll
            raise FatalRevokerError(
                "no cursor file: first deployment? Run with --init-cursor (or "
                "REVOKER_INIT_CURSOR=1). If the revoker ran before, events since "
                "its last poll may be lost: see 'Lost events' in its README"
            ) from None
        except (OSError, ValueError) as e:
            raise RevokerError(f"can't read the cursor file: {e}") from None
        return cls(
            path,
            int(data["time"]),
            int(data["floor"]),
            dict(data["seen"]),
            # Cursor files from before `polled` existed
            int(data.get("polled", data["time"])),
        )

    @classmethod
    def create(cls, path: str, start_ms: int, now_ms: int) -> "Cursor":
        """Write a new cursor starting at `start_ms`; an existing file is fatal."""
        if os.path.exists(path):
            raise FatalRevokerError(
                "--init-cursor (REVOKER_INIT_CURSOR=1) given, but the cursor file "
                "exists; run without it"
            )
        cursor = cls(path, start_ms, start_ms, {}, now_ms)
        cursor.save()
        logger.info("new cursor file; starting from now minus REVOKER_OVERLAP")
        return cursor

    def save(self) -> None:
        """Write the cursor atomically."""
        directory = os.path.dirname(os.path.abspath(self.path))
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".revoker-cursor-")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(
                    {
                        "time": self.time,
                        "floor": self.floor,
                        "seen": self.seen,
                        "polled": self.polled,
                    },
                    f,
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
        # The revoker's clock at the last successful events-config check
        self._checked_at = 0.0
        # Create the cursor at the first poll, rather than load it
        self._init_cursor = config.init_cursor
        # How long the realm keeps both kinds of events, in ms; None: for ever
        self._events_expiration_ms: Optional[int] = None

    @property
    def db(self) -> Any:
        """Return the Tokenserver database, connecting on first use."""
        if self._db is None:
            self._db = self._db_factory()
        return self._db

    def retire(self, user_id: str) -> None:
        """Retire the Tokenserver user of a Keycloak user."""
        self.db.retire_user(f"{user_id}@{self.config.email_domain}")

    def apply(self, action: Action) -> bool:
        """Take an action; return False if it turned out to need nothing."""
        if action.kind == REVOKE_ALL_IF_NEW_PASSWORD:
            created = self.keycloak.password_created(action.user_id)
            # A deleted user's DELETE event retires them; a user whose password
            # is older than the update (less the overlap, for skew between
            # Keycloak's nodes) had their profile, attributes, required
            # actions or enabled flag changed, which needs no sign-out
            since = action.event_time - self.config.overlap * 1000
            if not created or max(created) < since:
                return False
            action = Action(REVOKE_ALL, action.user_id)
        if action.kind == REVOKE_ALL:
            self.keycloak.logout(action.user_id)
        if action.kind in (REVOKE_ALL, REVOKE_OFFLINE):
            for client_id in self.config.offline_clients:
                self.keycloak.revoke_offline(action.user_id, client_id)
        if action.kind == RETIRE:
            self.retire(action.user_id)
        return True

    def check_events_config(self) -> None:
        """Check that the realm stores the events the revoker acts on.

        Otherwise every poll finds nothing, for ever. Also reads how long the
        realm keeps them, for the gap check. A configuration that fails the
        check raises FatalRevokerError: retrying doesn't fix it. Not being able
        to read it raises RevokerError, as any Keycloak error.
        """
        events = self.keycloak.events_config()
        if events.get("eventsEnabled") is not True:
            raise FatalRevokerError(
                "the realm doesn't store user events (eventsEnabled)"
            )
        if events.get("adminEventsEnabled") is not True:
            raise FatalRevokerError(
                "the realm doesn't store admin events (adminEventsEnabled)"
            )
        # An empty list would store Keycloak's default types; the revoker
        # wants its types listed
        enabled = events.get("enabledEventTypes") or []
        missing = [t for t in REQUIRED_EVENT_TYPES if t not in enabled]
        if missing:
            raise FatalRevokerError(
                "the realm doesn't store these user events (enabledEventTypes): "
                + ", ".join(missing)
            )
        # Keycloak deletes admin events after the realm's adminEventsExpiration,
        # which the revoker can't read without view-realm: the setting stands
        # in for it. The shorter of the two bounds how long a gap may be.
        expirations = [
            e
            for e in (
                events.get("eventsExpiration"),
                self.config.admin_events_expiration,
            )
            if isinstance(e, int) and not isinstance(e, bool) and e > 0
        ]
        self._events_expiration_ms = min(expirations) * 1000 if expirations else None
        self._checked_at = self.clock()

    def check(self) -> None:
        """Check, before the first poll, that the revoker can do its work.

        The realm must store the events (check_events_config). Every offline
        client must exist: DELETE users/<id>/consents/<client> of a missing one
        revokes nothing. Each is checked with that same DELETE for the
        revoker's own service-account user, which has nothing to revoke.
        """
        self.check_events_config()
        for client_id in self.config.offline_clients:
            self.keycloak.check_offline_client(client_id)
        self._checked = True

    def recheck_events_config(self) -> None:
        """Check the events configuration again, if REVOKER_RECHECK_INTERVAL passed.

        An admin may turn events off or shorten their retention at any time,
        and the poller rarely restarts. A failed read is retried at the next
        poll, as the time of the last check moves only when one succeeds.
        """
        if self.clock() - self._checked_at >= self.config.recheck_interval:
            self.check_events_config()

    def poll_once(self) -> int:
        """Handle the events stored since the cursor; return how many acted on.

        The cursor is saved only when every event got handled, so after a
        failure the next poll starts from the same place.
        """
        if not self._checked:
            self.check()
        else:
            self.recheck_events_config()
        now_ms = int(self.clock() * 1000)
        overlap_ms = self.config.overlap * 1000
        # A first start looks back by the overlap too, in case the revoker's
        # clock runs ahead of Keycloak's
        if self._init_cursor:
            cursor = Cursor.create(self.config.cursor_file, now_ms - overlap_ms, now_ms)
            self._init_cursor = False
        else:
            cursor = Cursor.load(self.config.cursor_file)
        expiration_ms = self._events_expiration_ms
        # Less the overlap: an event stamped just before `polled` but stored
        # late, or a Keycloak cleanup whose clock runs ahead, needs the margin
        if (
            expiration_ms is not None
            and now_ms - cursor.polled > expiration_ms - overlap_ms
        ):
            raise FatalRevokerError(
                f"the last complete poll was {(now_ms - cursor.polled) / 3_600_000:.1f}"
                " h ago, longer than the realm keeps events "
                f"({expiration_ms / 3_600_000:.1f} h, the shorter of eventsExpiration "
                "and REVOKER_ADMIN_EVENTS_EXPIRATION) less REVOKER_OVERLAP: events "
                "may have been lost. Sign every user out (the realm's 'Sign out all "
                "active sessions'), run --reconcile, then delete the cursor file and "
                "start again with --init-cursor"
            )
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
                what = str(event.get("type"))
            else:
                action = admin_event_action(event)
                # The resource path names the user ID only
                what = f"{event.get('operationType')} {event.get('resourcePath')}"
            if action and self.apply(action):
                kind_done = (
                    REVOKE_ALL
                    if action.kind == REVOKE_ALL_IF_NEW_PASSWORD
                    else action.kind
                )
                logger.info(
                    "%s: keycloak user %s, for %s event %s",
                    kind_done,
                    action.user_id,
                    kind,
                    what,
                )
                acted += 1
            elif action:
                logger.debug(
                    "no new password: keycloak user %s, for %s event %s",
                    action.user_id,
                    kind,
                    what,
                )
            seen[key] = event_time
            newest = max(newest, event_time)

        # An event stamped by a Keycloak node whose clock runs ahead must not
        # carry the next poll's window past the events the other nodes have
        # yet to store
        cursor.time = min(newest, now_ms - CLOCK_MARGIN_MS)
        cursor.seen = {k: t for k, t in seen.items() if t >= cursor.time - overlap_ms}
        cursor.polled = now_ms
        cursor.save()
        return acted

    def reconcile(self, force: bool = False) -> int:
        """Retire Tokenserver users whose Keycloak user is gone; return how many.

        Retirement can't be undone, so nothing is retired unless Keycloak
        answers as expected for a user that certainly exists, and, without
        `force`, not more than REVOKER_RECONCILE_MAX users or 10 % of the
        active ones (rounded down, but at least 1).
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
        logger.info(
            "reconcile: %d of %d active Tokenserver users have the "
            "SYNC_TOKENSERVER__FXA_EMAIL_DOMAIN suffix",
            len(user_ids),
            len(emails),
        )
        if not user_ids:
            logger.warning(
                "reconcile: no active Tokenserver user has the "
                "SYNC_TOKENSERVER__FXA_EMAIL_DOMAIN suffix; check that it is "
                "the same as Tokenserver's"
            )
        gone = [
            user_id for user_id in user_ids if not self.keycloak.user_exists(user_id)
        ]
        # At least 1, or with fewer than 10 active users a single missed
        # deletion would need --force
        allowed = min(
            self.config.reconcile_max,
            max(1, len(user_ids) * RECONCILE_MAX_PERCENT // 100),
        )
        if len(gone) > allowed and not force:
            raise RevokerError(
                f"reconcile would retire {len(gone)} of {len(user_ids)} active "
                f"users, more than {allowed}: REVOKER_RECONCILE_MAX "
                f"({self.config.reconcile_max}) or 10 % (at least 1); retired "
                "none. If Keycloak really lost these users, rerun with --force"
            )
        for user_id in gone:
            self.retire(user_id)
            logger.info("reconcile: retired keycloak user %s", user_id)
        if gone:
            # The cap is per run: a stale Keycloak retires users run after run
            logger.warning("reconcile: retired %d users in total", len(gone))
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
        "--init-cursor",
        action="store_true",
        help="start a new cursor at the current time: for the first deployment, "
        "or after the steps under 'Lost events'; fails if the cursor file exists",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="with --reconcile: retire however many users are gone",
    )
    args = parser.parse_args(argv)
    if args.force and not args.reconcile:
        parser.error("--force needs --reconcile")
    if args.init_cursor and args.reconcile:
        parser.error("--init-cursor can't be used with --reconcile")
    logging.basicConfig(
        level=os.environ.get("REVOKER_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    def run(step: Callable[[], int]) -> bool:
        try:
            count = step()
        except FatalRevokerError:
            raise
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
    if args.init_cursor:
        config.init_cursor = True
    revoker = Revoker(config)

    def reconcile() -> int:
        return revoker.reconcile(force=args.force)

    try:
        if args.reconcile:
            return 0 if run(reconcile) else 1
        revoker.check()
        if args.once:
            return 0 if run(revoker.poll_once) else 1
        # Exit rather than log errors for ever, so that whatever runs the
        # revoker sees it fail: a role taken away, Keycloak gone for good
        failures = 0
        while True:
            failures = 0 if run(revoker.poll_once) else failures + 1
            if failures >= config.max_failures:
                logger.error("%d polls in a row failed; exiting", failures)
                return 1
            time.sleep(config.interval)
    except RevokerError as e:
        logger.error("%s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
