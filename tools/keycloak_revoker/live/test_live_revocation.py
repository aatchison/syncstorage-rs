# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Live revocation tests: Keycloak, the revoker and Tokenserver together.

For each way of cutting a user off, with an online and an offline_access
session: after the Keycloak admin action and one revoker run, the session's
refresh token no longer works and Keycloak reports its tokens inactive. For a
deleted user, the Tokenserver record is retired and the user's unexpired access
token is refused.
"""

import secrets

import pytest

from .helpers import (
    MAX_GENERATION,
    create_user,
    exchange,
    introspect,
    login,
    refresh,
    run_revoker,
    user_rows,
)


def reset_password(admin, user_id):
    value = secrets.token_urlsafe(24)
    body = {"type": "password", "value": value, "temporary": False}
    return admin("PUT", f"/users/{user_id}/reset-password", json=body)


def sign_out(admin, user_id):
    return admin("POST", f"/users/{user_id}/logout")


def disable(admin, user_id):
    rep = admin("GET", f"/users/{user_id}").json()
    rep["enabled"] = False
    return admin("PUT", f"/users/{user_id}", json=rep)


def delete(admin, user_id):
    return admin("DELETE", f"/users/{user_id}")


ACTIONS = {
    "reset-password": reset_password,
    "sign-out": sign_out,
    "disable": disable,
    "delete": delete,
}
# Where Keycloak on its own leaves the session usable (what the revoker is for)
KEYCLOAK_LEAVES_ALIVE = {
    ("reset-password", False),
    ("reset-password", True),
    ("sign-out", True),
}


def new_user(admin, label):
    name = f"revoker-live-{label}-{secrets.token_hex(4)}"
    password = secrets.token_urlsafe(24)
    return name, password, create_user(admin, name, password)


def assert_active_record(db, user_id):
    rows = user_rows(db, user_id)
    assert rows
    assert all(gen < MAX_GENERATION and replaced is None for gen, replaced in rows)


def assert_retired(db, user_id, access_token):
    rows = user_rows(db, user_id)
    assert rows
    assert all(gen == MAX_GENERATION and replaced is not None for gen, replaced in rows)
    # The deleted user's access token hasn't expired, but is refused
    res = exchange(access_token)
    assert res.status_code == 401, res.text
    assert res.json()["status"] == "invalid-generation"


@pytest.mark.parametrize("offline", [False, True], ids=["online", "offline"])
@pytest.mark.parametrize("action", list(ACTIONS))
def test_revocation(admin, db, revoker, action, offline):
    """After the action and one revoker run, the session is dead."""
    name, password, user_id = new_user(admin, action)
    tokens = login(admin, name, password, offline)
    access_token, refresh_token = tokens["access_token"], tokens["refresh_token"]
    res = exchange(access_token)
    assert res.status_code == 200, res.text
    assert introspect(admin, access_token)
    assert_active_record(db, user_id)

    res = ACTIONS[action](admin, user_id)
    assert res.status_code == 204, res.text
    if (action, offline) in KEYCLOAK_LEAVES_ALIVE:
        assert refresh(admin, refresh_token).status_code == 200
    if action == "delete":
        # Not retired yet, so Tokenserver still takes the token
        assert exchange(access_token).status_code == 200

    revoker("--once")

    res = refresh(admin, refresh_token)
    assert res.status_code == 400, res.text
    assert res.json()["error"] == "invalid_grant"
    assert not introspect(admin, access_token)
    assert not introspect(admin, refresh_token)
    if action == "delete":
        assert_retired(db, user_id, access_token)
    else:
        assert_active_record(db, user_id)


def test_reconcile_retires_user_deleted_while_revoker_was_down(
    admin, db, revoker, revoker_env, tmp_path
):
    """--reconcile retires a user whose deletion event the revoker never saw."""
    name, password, user_id = new_user(admin, "reconcile")
    access_token = login(admin, name, password, offline=False)["access_token"]
    assert exchange(access_token).status_code == 200
    assert delete(admin, user_id).status_code == 204

    # A revoker that starts after the deletion (a new cursor) never sees it
    env = {**revoker_env, "REVOKER_CURSOR_FILE": str(tmp_path / "cursor")}
    run_revoker(env, "--once")
    run_revoker(env, "--once")
    assert_active_record(db, user_id)
    assert exchange(access_token).status_code == 200

    output = run_revoker(env, "--reconcile")
    assert f"reconcile: retired keycloak user {user_id}" in output
    assert_retired(db, user_id, access_token)
