# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Unit tests for revoker.py, against a fake Keycloak and a fake Tokenserver db."""

import base64
import json
import logging
import re
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
from requests.adapters import BaseAdapter

import revoker
from revoker import (
    RETIRE,
    REVOKE_ALL,
    REVOKE_OFFLINE,
    Action,
    Config,
    FatalRevokerError,
    Keycloak,
    Revoker,
    RevokerError,
    admin_event_action,
    user_event_action,
)

KEYCLOAK_URL = "http://keycloak.test"
REALM = "sync"
CLIENT_ID = "keycloak-revoker"
SECRET = "test-revoker-secret-value"
THUNDERBIRD_CLIENTS = ["thunderbird", "thunderbird-beta"]
EMAIL_DOMAIN = "sync.example.com"
ADMIN = f"/admin/realms/{REALM}"
NOW_MS = 1_800_000_000_000
# The revoker client's service-account user, the sub of its tokens
SERVICE_ACCOUNT = "service-account-id"
NOT_FOUND = object()


class FakeKeycloak(BaseAdapter):
    """A requests transport that stands in for the Keycloak endpoints used."""

    def __init__(self):
        super().__init__()
        self.users = {"alice", "bob", "carol"}
        self.clients = set(THUNDERBIRD_CLIENTS)
        # As in keycloak/realm-export.json
        self.events_config = {
            "eventsEnabled": True,
            "eventsExpiration": 604800,
            "eventsListeners": ["jboss-logging"],
            "enabledEventTypes": [
                "UPDATE_CREDENTIAL",
                "UPDATE_PASSWORD",
                "DELETE_ACCOUNT",
                "LOGOUT",
            ],
            "adminEventsEnabled": True,
            "adminEventsDetailsEnabled": False,
        }
        # (user, client): offline sessions / consent
        self.consents = {(u, c) for u in self.users for c in THUNDERBIRD_CLIENTS}
        self.user_events = []
        self.admin_events = []
        self.requests = []
        # [method, path regex, status or exception, times left, body]
        self.failures = []
        self.token = None
        self.tokens_issued = 0

    def fail(self, method, pattern, error=503, times=1, body=NOT_FOUND):
        """Make the next `times` matching requests fail with `error` and `body`."""
        if body is NOT_FOUND:
            body = {"error": "unavailable"}
        self.failures.append([method, re.compile(pattern), error, times, body])

    def calls(self, method=None):
        """Return the (method, path) of the requests that changed state."""
        return [
            (m, p)
            for m, p, _ in self.requests
            if m != "GET" and not p.endswith("/token") and m == (method or m)
        ]

    def send(self, request, **kwargs):
        url = urlsplit(request.url)
        path, query = url.path, parse_qs(url.query)
        self.requests.append((request.method, path, query))
        for failure in self.failures:
            method, pattern, error, times, body = failure
            if times and method == request.method and pattern.search(path):
                failure[3] -= 1
                if isinstance(error, Exception):
                    raise error
                return self._response(request, error, body)

        if path == f"/realms/{REALM}/protocol/openid-connect/token":
            form = parse_qs(request.body)
            if form != {
                "grant_type": ["client_credentials"],
                "client_id": [CLIENT_ID],
                "client_secret": [SECRET],
            }:
                return self._response(request, 401, {"error": "unauthorized_client"})
            self.tokens_issued += 1
            claims = {"sub": SERVICE_ACCOUNT, "n": self.tokens_issued}
            payload = base64.urlsafe_b64encode(json.dumps(claims).encode())
            self.token = f"header.{payload.decode().rstrip('=')}.signature"
            return self._response(
                request, 200, {"access_token": self.token, "expires_in": 300}
            )
        if request.headers.get("Authorization") != f"Bearer {self.token}":
            return self._response(request, 401, {"error": "HTTP 401 Unauthorized"})

        route = path.removeprefix(ADMIN)
        if request.method == "GET" and route in ("/events", "/admin-events"):
            events = self.user_events if route == "/events" else self.admin_events
            since = int(query["dateFrom"][0])
            assert query["direction"] == ["asc"]
            matching = sorted(
                (e for e in events if e["time"] >= since), key=lambda e: e["time"]
            )
            first, size = int(query["first"][0]), int(query["max"][0])
            return self._response(request, 200, matching[first : first + size])
        if request.method == "GET" and route == "/events/config":
            return self._response(request, 200, self.events_config)
        if request.method == "GET" and route == "/users/count":
            return self._response(request, 200, len(self.users))
        match = re.fullmatch(r"/users/([^/]+)(/.*)?", route)
        if not match or match.group(1) not in self.users | {SERVICE_ACCOUNT}:
            return self._response(request, 404, {"error": "User not found"})
        user, rest = match.group(1), match.group(2)
        if request.method == "GET" and rest is None:
            return self._response(request, 200, {"id": user})
        if request.method == "POST" and rest == "/logout":
            return self._response(request, 204)
        consent = re.fullmatch(r"/consents/([^/]+)", rest or "")
        if request.method == "DELETE" and consent:
            if consent.group(1) not in self.clients:
                return self._response(request, 404, {"error": "Client not found"})
            if (user, consent.group(1)) not in self.consents:
                return self._response(
                    request, 404, {"error": "Consent nor offline token not found"}
                )
            self.consents.discard((user, consent.group(1)))
            return self._response(request, 204)
        return self._response(request, 400, {"error": "unexpected request"})

    def close(self):
        pass

    @staticmethod
    def _response(request, status, body=None):
        res = requests.Response()
        res.status_code = status
        res.request = request
        res.url = request.url
        res._content = b"" if body is None else json.dumps(body).encode()
        res.headers["Content-Type"] = "application/json"
        return res


class FakeResult(list):
    def close(self):
        pass


class FakeDb:
    """Stands in for tools/tokenserver's Database."""

    def __init__(self, emails=()):
        self.active = list(emails)
        self.retired = []

    def retire_user(self, email):
        self.retired.append(email)
        self.active = [e for e in self.active if e != email]

    def _execute_sql(self, query):
        return FakeResult((email,) for email in self.active)


class Clock:
    def __init__(self, now_ms=NOW_MS):
        self.now_ms = now_ms

    def __call__(self):
        return self.now_ms / 1000


def make_env(tmp_path, **overrides):
    env = {
        "REVOKER_KEYCLOAK_URL": KEYCLOAK_URL,
        "REVOKER_REALM": REALM,
        "REVOKER_CLIENT_ID": CLIENT_ID,
        "REVOKER_CLIENT_SECRET": SECRET,
        "REVOKER_OFFLINE_CLIENTS": ",".join(THUNDERBIRD_CLIENTS),
        "SYNC_TOKENSERVER__FXA_EMAIL_DOMAIN": EMAIL_DOMAIN,
        "SYNC_TOKENSERVER__DATABASE_URL": "mysql://user:pw@localhost/tokenserver",
        "REVOKER_CURSOR_FILE": str(tmp_path / "cursor.json"),
    }
    env.update(overrides)
    return {k: v for k, v in env.items() if v is not None}


class Harness:
    def __init__(self, tmp_path, db=None):
        self.config = Config.from_env(make_env(tmp_path))
        self.keycloak = FakeKeycloak()
        self.db = db or FakeDb()
        self.clock = Clock()
        self.sleeps = []
        session = requests.Session()
        session.mount(KEYCLOAK_URL, self.keycloak)
        self.revoker = Revoker(
            self.config,
            Keycloak(self.config, session=session, sleep=self.sleeps.append),
            db_factory=lambda: self.db,
            clock=self.clock,
        )
        self.next_id = 0

    def cursor(self):
        with open(self.config.cursor_file) as f:
            return json.load(f)

    def _event(self, offset_ms):
        self.next_id += 1
        return {"id": f"ev-{self.next_id}", "time": NOW_MS + offset_ms, "realmId": "r"}

    def user_event(self, type_, user, offset_ms=1000, **extra):
        event = {**self._event(offset_ms), "type": type_, "userId": user, **extra}
        self.keycloak.user_events.append(event)
        return event

    def admin_event(self, operation, path, offset_ms=1000, resource_type="USER"):
        event = {
            **self._event(offset_ms),
            "operationType": operation,
            "resourceType": resource_type,
            "resourcePath": path,
            "authDetails": {"realmId": "master", "userId": "admin-id"},
        }
        self.keycloak.admin_events.append(event)
        return event

    def start(self):
        """First poll: starts the cursor at the current time minus the overlap.

        Then moves the clock on an hour, so that the events the test adds next
        (at NOW_MS plus a few seconds) are in the past at the next poll.
        """
        assert self.revoker.poll_once() == 0
        self.keycloak.requests.clear()
        self.clock.now_ms = NOW_MS + 3_600_000


def revoke_all(user):
    return [("POST", f"{ADMIN}/users/{user}/logout")] + revoke_offline(user)


def revoke_offline(user):
    return [
        ("DELETE", f"{ADMIN}/users/{user}/consents/{c}") for c in THUNDERBIRD_CLIENTS
    ]


def client_checks():
    """The startup check of the offline clients, on the revoker's own user."""
    return revoke_offline(SERVICE_ACCOUNT)


# ── event → action mapping ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    "event,expected",
    [
        (
            {
                "type": "UPDATE_CREDENTIAL",
                "userId": "u1",
                "details": {"credential_type": "password"},
            },
            Action(REVOKE_ALL, "u1"),
        ),
        # Setting up OTP or WebAuthn emits UPDATE_CREDENTIAL too: not a password
        # change, so the user's sessions are left alone
        (
            {
                "type": "UPDATE_CREDENTIAL",
                "userId": "u1",
                "details": {"credential_type": "otp"},
            },
            None,
        ),
        (
            {
                "type": "UPDATE_CREDENTIAL",
                "userId": "u1",
                "details": {"credential_type": "webauthn"},
            },
            None,
        ),
        ({"type": "UPDATE_CREDENTIAL", "userId": "u1"}, None),
        ({"type": "UPDATE_CREDENTIAL", "userId": "u1", "details": None}, None),
        ({"type": "UPDATE_PASSWORD", "userId": "u1"}, Action(REVOKE_ALL, "u1")),
        # Revoked whether or not the user ticked "Sign out from other devices"
        (
            {
                "type": "UPDATE_PASSWORD",
                "userId": "u1",
                "details": {"logout_sessions": "false"},
            },
            Action(REVOKE_ALL, "u1"),
        ),
        ({"type": "DELETE_ACCOUNT", "userId": "u1"}, Action(RETIRE, "u1")),
        ({"type": "LOGOUT", "userId": "u1"}, None),
        ({"type": "LOGIN", "userId": "u1"}, None),
        ({"type": "SOME_FUTURE_EVENT", "userId": "u1"}, None),
        ({"type": "UPDATE_PASSWORD"}, None),
        ({"type": "UPDATE_PASSWORD", "userId": "u1", "error": "invalid_user"}, None),
    ],
)
def test_user_event_action(event, expected):
    assert user_event_action(event) == expected


@pytest.mark.parametrize(
    "operation,path,resource_type,expected",
    [
        ("ACTION", "users/u1/reset-password", "USER", Action(REVOKE_ALL, "u1")),
        ("ACTION", "users/u1/logout", "USER", Action(REVOKE_OFFLINE, "u1")),
        ("DELETE", "users/u1", "USER", Action(RETIRE, "u1")),
        # PUT users/<id> may have set a password; disabling is an UPDATE too
        ("UPDATE", "users/u1", "USER", Action(REVOKE_ALL, "u1")),
        ("UPDATE", "users/u1/groups/g1", "USER", None),
        ("CREATE", "users/u1", "USER", None),
        ("ACTION", "users/u1/reset-password-email", "USER", None),
        ("ACTION", "users/u1/execute-actions-email", "USER", None),
        ("ACTION", "users/u1/consents/thunderbird", "USER", None),
        ("DELETE", "users/u1/groups/g1", "USER", None),
        ("DELETE", "users/u1/consents/thunderbird", "USER", None),
        ("ACTION", "users/u1/logout/extra", "USER", None),
        ("DELETE", "clients/u1", "CLIENT", None),
        ("DELETE", "users/u1", "CLIENT", None),
        ("ACTION", "users/u1/reset-password", None, None),
    ],
)
def test_admin_event_action(operation, path, resource_type, expected):
    event = {
        "operationType": operation,
        "resourcePath": path,
        "resourceType": resource_type,
    }
    assert admin_event_action(event) == expected


def test_admin_event_with_error_is_ignored():
    event = {
        "operationType": "DELETE",
        "resourcePath": "users/u1",
        "resourceType": "USER",
        "error": "unknown_error",
    }
    assert admin_event_action(event) is None


# ── what each event does, end to end ─────────────────────────────────────────


@pytest.mark.parametrize(
    "type_,details",
    [
        ("UPDATE_CREDENTIAL", {"credential_type": "password"}),
        ("UPDATE_PASSWORD", {"credential_type": "password"}),
        ("UPDATE_PASSWORD", None),
    ],
)
def test_user_password_change_revokes_all_sessions(tmp_path, type_, details):
    h = Harness(tmp_path)
    h.start()
    h.user_event(type_, "alice", details=details)
    assert h.revoker.poll_once() == 1
    assert h.keycloak.calls() == revoke_all("alice")
    assert not {c for c in h.keycloak.consents if c[0] == "alice"}
    assert h.db.retired == []


def test_otp_setup_leaves_sessions_alone(tmp_path):
    h = Harness(tmp_path)
    h.start()
    h.user_event("UPDATE_CREDENTIAL", "alice", details={"credential_type": "otp"})
    assert h.revoker.poll_once() == 0
    assert h.keycloak.calls() == []
    assert len([c for c in h.keycloak.consents if c[0] == "alice"]) == 2


def test_admin_reset_password_revokes_all_sessions(tmp_path):
    h = Harness(tmp_path)
    h.start()
    h.admin_event("ACTION", "users/bob/reset-password")
    assert h.revoker.poll_once() == 1
    assert h.keycloak.calls() == revoke_all("bob")
    assert h.db.retired == []


def test_admin_sign_out_revokes_offline_sessions(tmp_path):
    h = Harness(tmp_path)
    h.start()
    h.admin_event("ACTION", "users/bob/logout")
    assert h.revoker.poll_once() == 1
    # Keycloak's sign-out already ended the online sessions
    assert h.keycloak.calls() == revoke_offline("bob")
    assert ("bob", "thunderbird") not in h.keycloak.consents


def test_admin_update_revokes_all_sessions(tmp_path):
    # A password set through PUT users/<id>, a disable or a profile edit: the
    # event looks the same
    h = Harness(tmp_path)
    h.start()
    h.admin_event("UPDATE", "users/carol")
    assert h.revoker.poll_once() == 1
    assert h.keycloak.calls() == revoke_all("carol")
    assert h.db.retired == []


def test_admin_delete_retires_tokenserver_user(tmp_path):
    h = Harness(tmp_path)
    h.start()
    h.keycloak.users.discard("carol")
    h.admin_event("DELETE", "users/carol")
    assert h.revoker.poll_once() == 1
    assert h.db.retired == [f"carol@{EMAIL_DOMAIN}"]
    assert h.keycloak.calls() == []


def test_user_delete_account_retires_tokenserver_user(tmp_path):
    h = Harness(tmp_path)
    h.start()
    h.user_event("DELETE_ACCOUNT", "carol")
    assert h.revoker.poll_once() == 1
    assert h.db.retired == [f"carol@{EMAIL_DOMAIN}"]


def test_nothing_left_to_revoke_is_not_an_error(tmp_path):
    h = Harness(tmp_path)
    h.start()
    # No offline sessions for bob; dave no longer exists at all
    h.keycloak.consents = {c for c in h.keycloak.consents if c[0] != "bob"}
    h.user_event("UPDATE_PASSWORD", "bob", offset_ms=1000)
    h.admin_event("ACTION", "users/dave/reset-password", offset_ms=2000)
    assert h.revoker.poll_once() == 2
    assert h.keycloak.calls() == revoke_all("bob") + revoke_all("dave")
    assert h.cursor()["time"] == NOW_MS + 2000


def test_unknown_events_are_ignored(tmp_path):
    h = Harness(tmp_path)
    h.start()
    h.user_event("LOGIN", "alice", offset_ms=1000)
    h.user_event("SOMETHING_NEW", "alice", offset_ms=2000)
    h.admin_event("ACTION", "users/alice/execute-actions-email", offset_ms=3000)
    h.admin_event("DELETE", "users/alice/groups/g1", offset_ms=4000)
    h.admin_event("DELETE", "clients/c1", offset_ms=5000, resource_type="CLIENT")
    assert h.revoker.poll_once() == 0
    assert h.keycloak.calls() == []
    assert h.db.retired == []
    # ...and the cursor moves past them
    assert h.cursor()["time"] == NOW_MS + 5000


def test_events_are_handled_in_time_order(tmp_path):
    h = Harness(tmp_path)
    h.start()
    h.admin_event("ACTION", "users/bob/logout", offset_ms=3000)
    h.user_event("UPDATE_PASSWORD", "alice", offset_ms=1000)
    h.admin_event("ACTION", "users/carol/reset-password", offset_ms=2000)
    assert h.revoker.poll_once() == 3
    assert h.keycloak.calls() == (
        revoke_all("alice") + revoke_all("carol") + revoke_offline("bob")
    )


def test_event_queries(tmp_path):
    h = Harness(tmp_path)
    h.start()
    h.revoker.poll_once()
    queries = {
        p.removeprefix(ADMIN): q for m, p, q in h.keycloak.requests if m == "GET"
    }
    # The cursor's floor is the first start minus the overlap, so nothing older
    # is asked for
    floor = str(NOW_MS - h.config.overlap * 1000)
    assert queries["/events"] == {
        "type": ["UPDATE_CREDENTIAL", "UPDATE_PASSWORD", "DELETE_ACCOUNT"],
        "dateFrom": [floor],
        "direction": ["asc"],
        "first": ["0"],
        "max": ["100"],
    }
    assert queries["/admin-events"] == {
        "resourceTypes": ["USER"],
        "operationTypes": ["ACTION", "DELETE", "UPDATE"],
        "dateFrom": [floor],
        "direction": ["asc"],
        "first": ["0"],
        "max": ["100"],
    }
    # Once the cursor has moved on, polls look back by the overlap
    h.clock.now_ms += 3_600_000
    h.user_event("LOGIN", "alice", offset_ms=3_600_000)
    h.revoker.poll_once()
    h.keycloak.requests.clear()
    h.revoker.poll_once()
    queries = {
        p.removeprefix(ADMIN): q for m, p, q in h.keycloak.requests if m == "GET"
    }
    since = str(NOW_MS + 3_600_000 - h.config.overlap * 1000)
    assert queries["/events"]["dateFrom"] == [since]
    assert queries["/admin-events"]["dateFrom"] == [since]


def test_events_are_paged(tmp_path):
    h = Harness(tmp_path)
    h.start()
    for i in range(250):
        h.user_event("UPDATE_PASSWORD", "alice", offset_ms=1000 + i)
    assert h.revoker.poll_once() == 250
    pages = [q["first"] for m, p, q in h.keycloak.requests if p.endswith("/events")]
    assert pages == [["0"], ["100"], ["200"]]


# ── cursor and idempotency ───────────────────────────────────────────────────


def test_first_run_starts_from_now_minus_the_overlap(tmp_path):
    h = Harness(tmp_path)
    # Events older than the overlap, from before the revoker ever ran, are not
    # acted on
    h.user_event("UPDATE_PASSWORD", "alice", offset_ms=-61_000)
    h.admin_event("DELETE", "users/carol", offset_ms=-60_001)
    # Events within it are: Keycloak's clock may run behind the revoker's
    h.user_event("UPDATE_PASSWORD", "bob", offset_ms=-30_000)
    h.admin_event("DELETE", "users/dave", offset_ms=-1)
    assert h.revoker.poll_once() == 2
    assert h.keycloak.calls() == client_checks() + revoke_all("bob")
    assert h.db.retired == [f"dave@{EMAIL_DOMAIN}"]
    floor = NOW_MS - 60_000
    assert h.cursor()["floor"] == floor
    # Not past the revoker's clock minus the margin
    assert h.cursor()["time"] == NOW_MS - 1000


def test_cursor_is_persisted_and_events_are_handled_once(tmp_path):
    h = Harness(tmp_path)
    h.start()
    first = h.user_event("UPDATE_PASSWORD", "alice", offset_ms=1000)
    assert h.revoker.poll_once() == 1
    assert h.cursor()["time"] == NOW_MS + 1000
    assert h.cursor()["seen"] == {f"user:{first['id']}": NOW_MS + 1000}

    # Polling again does nothing new
    h.keycloak.requests.clear()
    assert h.revoker.poll_once() == 0
    assert h.keycloak.calls() == []

    # A new Revoker (a restart) carries on from the file
    h2 = Harness(tmp_path)
    h2.keycloak.user_events = list(h.keycloak.user_events)
    h2.next_id = h.next_id
    h2.admin_event("ACTION", "users/bob/logout", offset_ms=2000)
    assert h2.revoker.poll_once() == 1
    assert h2.keycloak.calls() == client_checks() + revoke_offline("bob")


def test_events_with_the_same_time_are_each_handled_once(tmp_path):
    h = Harness(tmp_path)
    h.start()
    h.user_event("UPDATE_PASSWORD", "alice", offset_ms=1000)
    assert h.revoker.poll_once() == 1
    # Stored in the same millisecond, but visible only after the last poll
    h.admin_event("ACTION", "users/bob/logout", offset_ms=1000)
    h.keycloak.requests.clear()
    assert h.revoker.poll_once() == 1
    assert h.keycloak.calls() == revoke_offline("bob")


def test_cursor_never_passes_the_revoker_clock(tmp_path):
    h = Harness(tmp_path)
    h.start()
    now = h.clock.now_ms
    # From a Keycloak node whose clock runs 5 minutes ahead
    ahead = h.user_event("UPDATE_PASSWORD", "alice", offset_ms=now - NOW_MS + 300_000)
    assert h.revoker.poll_once() == 1
    assert h.cursor()["time"] == now - 1000
    assert f"user:{ahead['id']}" in h.cursor()["seen"]
    # A correctly timed node stores an event a second after that poll; the
    # next poll, 15 s later, still finds it
    h.admin_event("ACTION", "users/bob/reset-password", offset_ms=now - NOW_MS + 1000)
    h.clock.now_ms += 15_000
    h.keycloak.requests.clear()
    assert h.revoker.poll_once() == 1
    # ...and doesn't handle the node's early event again
    assert h.keycloak.calls() == revoke_all("bob")
    assert h.cursor()["time"] == now + 1000


def test_late_events_within_the_overlap_are_handled(tmp_path):
    h = Harness(tmp_path)
    h.start()
    h.user_event("UPDATE_PASSWORD", "alice", offset_ms=10_000)
    assert h.revoker.poll_once() == 1
    # An event stored late, with a time before the cursor's
    h.admin_event("ACTION", "users/bob/reset-password", offset_ms=5_000)
    h.keycloak.requests.clear()
    assert h.revoker.poll_once() == 1
    assert h.keycloak.calls() == revoke_all("bob")
    assert h.cursor()["time"] == NOW_MS + 10_000
    assert h.revoker.poll_once() == 0


def test_seen_keys_are_pruned(tmp_path):
    h = Harness(tmp_path)
    h.start()
    old = h.user_event("UPDATE_PASSWORD", "alice", offset_ms=1000)
    new = h.user_event("UPDATE_PASSWORD", "bob", offset_ms=1000 + 61_000)
    assert h.revoker.poll_once() == 2
    assert set(h.cursor()["seen"]) == {f"user:{new['id']}"}
    assert f"user:{old['id']}" not in h.cursor()["seen"]


def test_events_without_an_id_are_deduplicated(tmp_path):
    h = Harness(tmp_path)
    h.start()
    event = h.user_event("UPDATE_PASSWORD", "alice")
    del event["id"]
    assert h.revoker.poll_once() == 1
    assert h.revoker.poll_once() == 0
    assert len(h.keycloak.calls()) == len(revoke_all("alice"))


# ── Keycloak failures ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "error",
    [500, 502, 503, requests.ConnectionError("refused"), requests.Timeout("slow")],
    ids=["500", "502", "503", "connection-error", "timeout"],
)
def test_transient_failure_is_retried(tmp_path, error):
    h = Harness(tmp_path)
    h.start()
    h.user_event("UPDATE_PASSWORD", "alice")
    h.keycloak.fail("GET", r"/events$", error, times=2)
    h.keycloak.fail("POST", r"/logout$", error, times=1)
    assert h.revoker.poll_once() == 1
    assert h.keycloak.calls() == [("POST", f"{ADMIN}/users/alice/logout")] + revoke_all(
        "alice"
    )
    assert h.sleeps == [1, 2, 1]


def test_keycloak_down_does_not_advance_the_cursor(tmp_path):
    h = Harness(tmp_path)
    h.start()
    before = h.cursor()
    h.admin_event("DELETE", "users/carol")
    h.keycloak.fail("GET", r"/admin-events$", 503, times=h.config.attempts)
    with pytest.raises(RevokerError, match="Keycloak unavailable"):
        h.revoker.poll_once()
    assert h.cursor() == before
    assert h.db.retired == []
    assert h.sleeps == [1, 2, 4]
    # Once Keycloak is back, the event is handled
    assert h.revoker.poll_once() == 1
    assert h.db.retired == [f"carol@{EMAIL_DOMAIN}"]


def test_failed_action_does_not_advance_the_cursor(tmp_path):
    h = Harness(tmp_path)
    h.start()
    before = h.cursor()
    h.user_event("UPDATE_PASSWORD", "alice", offset_ms=1000)
    h.admin_event("ACTION", "users/bob/reset-password", offset_ms=2000)
    h.keycloak.fail(
        "DELETE", r"/users/bob/consents/", requests.ConnectionError(), times=99
    )
    with pytest.raises(RevokerError):
        h.revoker.poll_once()
    assert h.cursor() == before

    # The next poll redoes both events (the actions are idempotent) and moves on
    h.keycloak.failures.clear()
    h.keycloak.requests.clear()
    assert h.revoker.poll_once() == 2
    assert h.keycloak.calls() == revoke_all("alice") + revoke_all("bob")
    assert ("bob", "thunderbird") not in h.keycloak.consents
    assert h.cursor()["time"] == NOW_MS + 2000


def test_permission_error_is_not_retried(tmp_path):
    h = Harness(tmp_path)
    h.start()
    before = h.cursor()
    h.user_event("UPDATE_PASSWORD", "alice")
    h.keycloak.fail("POST", r"/logout$", 403, times=1)
    with pytest.raises(RevokerError, match="HTTP 403"):
        h.revoker.poll_once()
    assert h.sleeps == []
    assert h.cursor() == before


def test_expired_token_is_renewed(tmp_path):
    h = Harness(tmp_path)
    h.start()
    h.user_event("UPDATE_PASSWORD", "alice")
    # Keycloak no longer accepts the cached token
    h.keycloak.token = "revoked"
    assert h.revoker.poll_once() == 1
    assert h.keycloak.tokens_issued == 2


def test_bad_client_secret(tmp_path):
    h = Harness(tmp_path)
    h.revoker.keycloak.config.client_secret = "wrong"
    with pytest.raises(RevokerError, match="can't get a token"):
        h.revoker.poll_once()


# ── event loss ───────────────────────────────────────────────────────────────

DAY_MS = 86_400_000


@pytest.mark.parametrize(
    "change,message",
    [
        ({"eventsEnabled": False}, "doesn't store user events"),
        ({"eventsEnabled": None}, "doesn't store user events"),
        ({"adminEventsEnabled": False}, "doesn't store admin events"),
        (
            {"enabledEventTypes": ["UPDATE_PASSWORD", "LOGOUT"]},
            "UPDATE_CREDENTIAL, DELETE_ACCOUNT",
        ),
        (
            {"enabledEventTypes": []},
            "UPDATE_CREDENTIAL, UPDATE_PASSWORD, DELETE_ACCOUNT",
        ),
    ],
    ids=["events-off", "events-unset", "admin-events-off", "types-missing", "no-types"],
)
def test_realm_must_store_the_events(tmp_path, change, message):
    h = Harness(tmp_path)
    h.keycloak.events_config.update(change)
    h.user_event("UPDATE_PASSWORD", "alice", offset_ms=-1)
    with pytest.raises(RevokerError, match=message):
        h.revoker.poll_once()
    assert h.keycloak.calls() == []
    assert not (tmp_path / "cursor.json").exists()


def test_logout_events_are_not_required(tmp_path):
    h = Harness(tmp_path)
    h.keycloak.events_config["enabledEventTypes"].remove("LOGOUT")
    assert h.revoker.poll_once() == 0


@pytest.mark.parametrize("status", [403, 404])
def test_events_config_must_be_readable(tmp_path, status):
    # For example view-events taken away
    h = Harness(tmp_path)
    h.keycloak.fail("GET", r"/events/config$", status, times=99)
    with pytest.raises(RevokerError, match="events/config: HTTP"):
        h.revoker.poll_once()


def test_gap_longer_than_event_retention_is_fatal(tmp_path):
    h = Harness(tmp_path)
    h.start()
    polled = h.cursor()["polled"]
    before = h.cursor()
    h.user_event("UPDATE_PASSWORD", "alice")
    # Down for longer than the realm's 7 days
    h.clock.now_ms = polled + 7 * DAY_MS + 1
    with pytest.raises(FatalRevokerError, match="events may have been lost"):
        h.revoker.poll_once()
    assert h.cursor() == before
    assert h.keycloak.calls() == []


def test_gap_within_event_retention_is_fine(tmp_path):
    h = Harness(tmp_path)
    h.start()
    h.user_event("UPDATE_PASSWORD", "alice")
    h.clock.now_ms = h.cursor()["polled"] + 7 * DAY_MS
    assert h.revoker.poll_once() == 1
    assert h.cursor()["polled"] == h.clock.now_ms


def test_quiet_realm_is_no_gap(tmp_path):
    # No event for longer than the retention, but every poll succeeded
    h = Harness(tmp_path)
    h.start()
    for _ in range(10):
        h.clock.now_ms += DAY_MS
        assert h.revoker.poll_once() == 0
    assert h.cursor()["polled"] == h.clock.now_ms


def test_failed_polls_count_towards_the_gap(tmp_path):
    h = Harness(tmp_path)
    h.start()
    polled = h.cursor()["polled"]
    h.keycloak.fail("GET", r"/admin-events$", 503, times=99)
    h.clock.now_ms = polled + 3 * DAY_MS
    with pytest.raises(RevokerError, match="Keycloak unavailable"):
        h.revoker.poll_once()
    assert h.cursor()["polled"] == polled
    h.keycloak.failures.clear()
    h.clock.now_ms = polled + 8 * DAY_MS
    with pytest.raises(FatalRevokerError):
        h.revoker.poll_once()


def test_no_expiration_means_no_gap(tmp_path):
    h = Harness(tmp_path)
    del h.keycloak.events_config["eventsExpiration"]
    h.start()
    h.clock.now_ms += 365 * DAY_MS
    assert h.revoker.poll_once() == 0


def test_cursor_file_without_polled(tmp_path):
    # Written before `polled` existed: `time` stands in for it
    h = Harness(tmp_path)
    cursor = {"time": NOW_MS, "floor": NOW_MS - 60_000, "seen": {}}
    (tmp_path / "cursor.json").write_text(json.dumps(cursor))
    h.clock.now_ms = NOW_MS + 8 * DAY_MS
    with pytest.raises(FatalRevokerError):
        h.revoker.poll_once()
    h.clock.now_ms = NOW_MS + DAY_MS
    assert h.revoker.poll_once() == 0
    assert h.cursor()["polled"] == NOW_MS + DAY_MS


class LoopHarness:
    """Runs main()'s forever loop against a Harness, counting polls."""

    def __init__(self, tmp_path, monkeypatch, **env):
        self.h = Harness(tmp_path)
        self.sleeps = []
        monkeypatch.setattr(revoker, "Revoker", lambda config: self.h.revoker)
        monkeypatch.setattr(revoker.time, "sleep", self.sleeps.append)
        for name, value in make_env(tmp_path, **env).items():
            monkeypatch.setenv(name, value)

    def polls(self):
        return len([p for m, p, q in self.h.keycloak.requests if p.endswith("/events")])


def test_loop_exits_after_consecutive_failed_polls(tmp_path, monkeypatch, caplog):
    loop = LoopHarness(tmp_path, monkeypatch)
    loop.h.config.attempts = 1
    loop.h.keycloak.fail("GET", r"/events$", 503, times=999)
    assert revoker.main([]) == 1
    assert loop.polls() == 5
    assert "5 polls in a row failed; exiting" in caplog.text


def test_loop_failure_count_resets_after_a_good_poll(tmp_path, monkeypatch):
    loop = LoopHarness(tmp_path, monkeypatch, REVOKER_MAX_FAILURES="3")
    loop.h.config.attempts = 1
    keycloak = loop.h.keycloak

    def sleep(seconds):
        loop.sleeps.append(seconds)
        # After the third poll, Keycloak goes away for good
        if len(loop.sleeps) == 3:
            keycloak.fail("GET", r"/events$", 503, times=999)

    monkeypatch.setattr(revoker.time, "sleep", sleep)
    # Polls 1 and 2 fail, 3 succeeds, 4, 5 and 6 fail
    keycloak.fail("GET", r"/events$", 503, times=2)
    assert revoker.main([]) == 1
    assert loop.polls() == 6
    assert loop.sleeps == [loop.h.config.interval] * 5


def test_loop_exits_at_once_on_an_event_gap(tmp_path, monkeypatch, caplog):
    loop = LoopHarness(tmp_path, monkeypatch)
    loop.h.start()
    loop.h.clock.now_ms += 8 * DAY_MS
    assert revoker.main([]) == 1
    assert loop.sleeps == []
    assert "events may have been lost" in caplog.text


def test_max_failures_setting(tmp_path):
    assert Config.from_env(make_env(tmp_path)).max_failures == 5
    config = Config.from_env(make_env(tmp_path, REVOKER_MAX_FAILURES="2"))
    assert config.max_failures == 2
    with pytest.raises(RevokerError, match="REVOKER_MAX_FAILURES"):
        Config.from_env(make_env(tmp_path, REVOKER_MAX_FAILURES="0"))


# ── offline clients ──────────────────────────────────────────────────────────


def test_offline_clients_are_checked_before_the_first_poll(tmp_path):
    h = Harness(tmp_path)
    consents = set(h.keycloak.consents)
    h.revoker.poll_once()
    # With the revoker's own user, which has nothing to revoke, rather than
    # GET /clients, which needs view-clients (the fake has no such route)
    assert h.keycloak.calls() == client_checks()
    assert h.keycloak.consents == consents
    # Only once
    h.keycloak.requests.clear()
    h.revoker.poll_once()
    assert h.keycloak.calls() == []


def test_offline_client_check_accepts_a_revoked_consent(tmp_path):
    # Should the revoker's own user have a consent, Keycloak answers 204
    h = Harness(tmp_path)
    h.keycloak.consents.add((SERVICE_ACCOUNT, "thunderbird"))
    h.revoker.poll_once()
    assert h.keycloak.calls() == client_checks()


@pytest.mark.parametrize("missing", ["thunderbird", "thunderbird-beta"])
def test_unknown_offline_client_fails_before_any_event(tmp_path, missing):
    h = Harness(tmp_path)
    h.keycloak.clients.discard(missing)
    h.user_event("UPDATE_PASSWORD", "alice", offset_ms=-1)
    with pytest.raises(RevokerError, match=f"offline client {missing} not found"):
        h.revoker.poll_once()
    # Nothing but the check, which stops at the missing client
    checked = client_checks()[: THUNDERBIRD_CLIENTS.index(missing) + 1]
    assert h.keycloak.calls() == checked
    assert not (tmp_path / "cursor.json").exists()


@pytest.mark.parametrize(
    "body",
    [
        None,
        {"error": "User not found"},
        {"error": "HTTP 404 Not Found"},
        "<html>Not Found</html>",
    ],
    ids=["empty", "own-user-not-found", "other-error", "html"],
)
def test_offline_client_check_fails_on_other_404s(tmp_path, body):
    # They say nothing about whether the client exists
    h = Harness(tmp_path)
    h.keycloak.fail(
        "DELETE", rf"/users/{SERVICE_ACCOUNT}/consents/", 404, times=99, body=body
    )
    with pytest.raises(RevokerError, match="checking offline client thunderbird"):
        h.revoker.poll_once()
    assert not (tmp_path / "cursor.json").exists()


def test_offline_client_check_fails_without_manage_users(tmp_path):
    h = Harness(tmp_path)
    h.keycloak.fail("DELETE", r"/consents/", 403, times=99)
    with pytest.raises(RevokerError, match="HTTP 403"):
        h.revoker.poll_once()
    assert not (tmp_path / "cursor.json").exists()


def test_consent_delete_of_a_missing_client_fails(tmp_path):
    h = Harness(tmp_path)
    h.start()
    before = h.cursor()
    # The client was deleted or renamed after the revoker started
    h.keycloak.clients.discard("thunderbird-beta")
    h.user_event("UPDATE_PASSWORD", "alice")
    with pytest.raises(RevokerError, match="offline client thunderbird-beta not found"):
        h.revoker.poll_once()
    assert h.cursor() == before


@pytest.mark.parametrize(
    "method,pattern",
    [("DELETE", r"/consents/thunderbird$"), ("POST", r"/logout$")],
    ids=["consent", "logout"],
)
@pytest.mark.parametrize(
    "body",
    [None, {"error": "HTTP 404 Not Found"}, "<html>Not Found</html>"],
    ids=["empty", "other-error", "html"],
)
def test_other_404s_of_a_revocation_fail(tmp_path, method, pattern, body):
    h = Harness(tmp_path)
    h.start()
    before = h.cursor()
    h.user_event("UPDATE_PASSWORD", "alice")
    h.keycloak.fail(method, pattern, 404, times=99, body=body)
    with pytest.raises(RevokerError, match="unexpected HTTP 404"):
        h.revoker.poll_once()
    assert h.cursor() == before


def test_main_exits_when_an_offline_client_is_missing(tmp_path, monkeypatch):
    h = Harness(tmp_path)
    h.keycloak.clients.discard("thunderbird")
    monkeypatch.setattr(revoker, "Revoker", lambda config: h.revoker)
    for name, value in make_env(tmp_path).items():
        monkeypatch.setenv(name, value)
    # The forever loop too fails at startup
    assert revoker.main([]) == 1
    assert revoker.main(["--once"]) == 1


# ── reconcile ────────────────────────────────────────────────────────────────


def test_reconcile_retires_users_gone_from_keycloak(tmp_path):
    db = FakeDb(
        [
            f"alice@{EMAIL_DOMAIN}",
            f"dave@{EMAIL_DOMAIN}",
            f"erin@{EMAIL_DOMAIN}",
            # Not this deployment's users: left alone
            "frank@other.example.com",
            f"frank@{EMAIL_DOMAIN}.evil.example",
        ]
    )
    h = Harness(tmp_path, db=db)
    # 2 of 3 is over the cap (1); test_reconcile_cap covers that
    assert h.revoker.reconcile(force=True) == 2
    assert db.retired == [f"dave@{EMAIL_DOMAIN}", f"erin@{EMAIL_DOMAIN}"]
    looked_up = [p for m, p, _ in h.keycloak.requests if "/users/" in p]
    assert looked_up == [
        f"{ADMIN}/users/{u}"
        for u in ("count", SERVICE_ACCOUNT, "alice", "dave", "erin")
    ]
    # Running it again finds nothing more
    assert h.revoker.reconcile() == 0


def test_reconcile_logs_how_many_users_match_the_domain(tmp_path, caplog):
    caplog.set_level(logging.INFO)
    db = FakeDb(
        [f"alice@{EMAIL_DOMAIN}", "frank@other.example.com", "gina@other.example"]
    )
    h = Harness(tmp_path, db=db)
    assert h.revoker.reconcile() == 0
    assert "1 of 3 active Tokenserver users have the" in caplog.text
    assert "WARNING" not in caplog.text


def test_reconcile_warns_when_no_user_matches_the_domain(tmp_path, caplog):
    # SYNC_TOKENSERVER__FXA_EMAIL_DOMAIN differs from Tokenserver's
    caplog.set_level(logging.INFO)
    db = FakeDb(["alice@other.example.com", "bob@other.example.com"])
    h = Harness(tmp_path, db=db)
    assert h.revoker.reconcile() == 0
    assert "0 of 2 active Tokenserver users have the" in caplog.text
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "no active Tokenserver user has the" in warnings[0].getMessage()
    assert db.retired == []


def test_reconcile_refuses_an_empty_realm(tmp_path):
    db = FakeDb([f"alice@{EMAIL_DOMAIN}"])
    h = Harness(tmp_path, db=db)
    h.keycloak.users.clear()
    with pytest.raises(RevokerError, match="no users"):
        h.revoker.reconcile()
    assert db.retired == []


def active_users(count, gone):
    """Return a FakeDb with `count` active users, the first `gone` not in Keycloak."""
    return FakeDb(
        [f"gone-{i}@{EMAIL_DOMAIN}" for i in range(gone)]
        + [f"alice@{EMAIL_DOMAIN}"] * (count - gone)
    )


@pytest.mark.parametrize(
    "body",
    [None, {"error": "HTTP 404 Not Found"}, "<html>Not Found</html>"],
    ids=["empty", "other-error", "html"],
)
def test_reconcile_refuses_when_every_admin_path_404s(tmp_path, body):
    # A proxy that hides /admin/, or a wrong path prefix
    db = active_users(3, gone=0)
    h = Harness(tmp_path, db=db)
    h.keycloak.fail("GET", r"^/admin/", 404, times=99, body=body)
    with pytest.raises(RevokerError, match="users/count"):
        h.revoker.reconcile()
    assert db.retired == []


@pytest.mark.parametrize(
    "body",
    [None, {"error": "HTTP 404 Not Found"}, "<html>Not Found</html>"],
    ids=["empty", "other-error", "html"],
)
def test_reconcile_refuses_when_user_lookups_404_without_keycloak_body(tmp_path, body):
    db = FakeDb([f"alice@{EMAIL_DOMAIN}", f"dave@{EMAIL_DOMAIN}"])
    h = Harness(tmp_path, db=db)
    h.keycloak.fail("GET", r"/users/(?!count$)[^/]+$", 404, times=99, body=body)
    with pytest.raises(RevokerError, match="unexpected HTTP 404"):
        h.revoker.reconcile(force=True)
    assert db.retired == []


def test_reconcile_refuses_when_its_own_user_is_reported_missing(tmp_path):
    # Every user lookup gets Keycloak's own "User not found": the revoker's
    # service-account user too, which certainly exists
    db = FakeDb([f"alice@{EMAIL_DOMAIN}", f"dave@{EMAIL_DOMAIN}"])
    h = Harness(tmp_path, db=db)
    h.keycloak.fail(
        "GET",
        r"/users/(?!count$)[^/]+$",
        404,
        times=99,
        body={"error": "User not found"},
    )
    with pytest.raises(RevokerError, match="own service-account user"):
        h.revoker.reconcile(force=True)
    assert db.retired == []


@pytest.mark.parametrize(
    "status,body",
    [
        (200, {"error": "unknown"}),
        (200, "3"),
        (200, True),
        (200, None),
        (404, {"error": "HTTP 404 Not Found"}),
        (204, None),
    ],
    ids=["dict", "string", "bool", "empty", "404", "204"],
)
def test_reconcile_refuses_when_the_count_is_not_an_int(tmp_path, status, body):
    db = FakeDb([f"dave@{EMAIL_DOMAIN}"])
    h = Harness(tmp_path, db=db)
    h.keycloak.fail("GET", r"/users/count$", status, times=99, body=body)
    with pytest.raises(RevokerError, match="without a user count"):
        h.revoker.reconcile(force=True)
    assert db.retired == []


@pytest.mark.parametrize(
    "count,gone,refused",
    [
        (200, 10, False),  # REVOKER_RECONCILE_MAX, 5 %
        (200, 11, True),  # more than REVOKER_RECONCILE_MAX
        (200, 15, True),  # more than REVOKER_RECONCILE_MAX, under 10 %
        (20, 2, False),  # 10 %
        (20, 3, True),  # more than 10 %
        (29, 2, False),  # 10 %, rounded down
        (29, 3, True),
        (5, 1, False),  # at least 1
        (3, 1, False),  # at least 1
        (3, 2, True),  # more than 1
        (1, 1, False),  # at least 1
    ],
)
def test_reconcile_cap(tmp_path, count, gone, refused):
    db = active_users(count, gone)
    h = Harness(tmp_path, db=db)
    if refused:
        with pytest.raises(RevokerError, match=f"retire {gone} of {count} active"):
            h.revoker.reconcile()
        # All or nothing: none was retired
        assert db.retired == []
        assert h.revoker.reconcile(force=True) == gone
    else:
        assert h.revoker.reconcile() == gone
    assert sorted(db.retired) == sorted(f"gone-{i}@{EMAIL_DOMAIN}" for i in range(gone))


def test_reconcile_max_setting(tmp_path):
    db = active_users(1000, gone=3)
    h = Harness(tmp_path, db=db)
    h.config.reconcile_max = 2
    with pytest.raises(RevokerError, match="REVOKER_RECONCILE_MAX \\(2\\)"):
        h.revoker.reconcile()
    assert db.retired == []
    assert Config.from_env(make_env(tmp_path)).reconcile_max == 10
    config = Config.from_env(make_env(tmp_path, REVOKER_RECONCILE_MAX="50"))
    assert config.reconcile_max == 50


def test_main_force_needs_reconcile(tmp_path, monkeypatch):
    for name, value in make_env(tmp_path).items():
        monkeypatch.setenv(name, value)
    with pytest.raises(SystemExit) as exc:
        revoker.main(["--once", "--force"])
    assert exc.value.code == 2


def test_reconcile_stops_when_keycloak_is_down(tmp_path):
    db = FakeDb([f"alice@{EMAIL_DOMAIN}", f"dave@{EMAIL_DOMAIN}"])
    h = Harness(tmp_path, db=db)
    h.keycloak.fail("GET", r"/users/alice$", 503, times=99)
    with pytest.raises(RevokerError):
        h.revoker.reconcile()
    assert db.retired == []


# ── configuration and logging ────────────────────────────────────────────────


def test_secret_from_file(tmp_path):
    secret_file = tmp_path / "secret"
    secret_file.write_text("from-a-file\n")
    config = Config.from_env(
        make_env(
            tmp_path,
            REVOKER_CLIENT_SECRET=None,
            REVOKER_CLIENT_SECRET_FILE=str(secret_file),
        )
    )
    assert config.client_secret == "from-a-file"
    assert "from-a-file" not in repr(config)


def test_defaults(tmp_path):
    config = Config.from_env(
        make_env(
            tmp_path,
            REVOKER_CLIENT_ID=None,
            REVOKER_OFFLINE_CLIENTS=None,
            SYNC_TOKENSERVER__OIDC_ALLOWED_CLIENTS="tb1, tb2",
        )
    )
    assert config.client_id == "keycloak-revoker"
    assert config.offline_clients == ["tb1", "tb2"]
    assert config.interval == 15


@pytest.mark.parametrize(
    "overrides,message",
    [
        ({"REVOKER_KEYCLOAK_URL": None}, "REVOKER_KEYCLOAK_URL"),
        ({"REVOKER_REALM": ""}, "REVOKER_REALM"),
        ({"REVOKER_CLIENT_SECRET": None}, "REVOKER_CLIENT_SECRET"),
        ({"REVOKER_CLIENT_SECRET_FILE": "/nonexistent/secret"}, "can't read"),
        ({"REVOKER_OFFLINE_CLIENTS": None}, "REVOKER_OFFLINE_CLIENTS"),
        ({"SYNC_TOKENSERVER__FXA_EMAIL_DOMAIN": None}, "FXA_EMAIL_DOMAIN"),
        ({"SYNC_TOKENSERVER__DATABASE_URL": None}, "DATABASE_URL"),
        ({"REVOKER_CURSOR_FILE": None}, "REVOKER_CURSOR_FILE"),
        ({"REVOKER_INTERVAL": "soon"}, "REVOKER_INTERVAL"),
    ],
)
def test_bad_config(tmp_path, overrides, message):
    with pytest.raises(RevokerError, match=message):
        Config.from_env(make_env(tmp_path, **overrides))


def test_logs_have_no_secrets_or_emails(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    db = FakeDb([f"dave@{EMAIL_DOMAIN}"])
    h = Harness(tmp_path, db=db)
    h.start()
    h.user_event("UPDATE_PASSWORD", "alice", offset_ms=1000)
    h.admin_event("DELETE", "users/carol", offset_ms=2000)
    h.keycloak.fail("POST", r"/logout$", 503, times=1)
    h.revoker.poll_once()
    h.revoker.reconcile(force=True)
    assert (
        "revoke-all-sessions: keycloak user alice, for user event UPDATE_PASSWORD"
        in caplog.text
    )
    assert (
        "retire-tokenserver-user: keycloak user carol, for admin event DELETE "
        "users/carol" in caplog.text
    )
    assert "keycloak user dave" in caplog.text
    assert EMAIL_DOMAIN not in caplog.text
    assert SECRET not in caplog.text
    assert "@" not in caplog.text


def test_main_once_exit_status(tmp_path, monkeypatch, caplog):
    for name, value in make_env(tmp_path).items():
        monkeypatch.setenv(name, value)
    for name in ("http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("REVOKER_ATTEMPTS", "1")
    # Nothing listens on this port, so the poll fails
    monkeypatch.setenv("REVOKER_KEYCLOAK_URL", "http://127.0.0.1:9")
    assert revoker.main(["--once"]) == 1
    assert "Keycloak unavailable" in caplog.text
    assert SECRET not in caplog.text
    monkeypatch.delenv("REVOKER_REALM")
    assert revoker.main(["--once"]) == 2
