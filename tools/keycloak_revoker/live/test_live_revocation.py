# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Live revocation tests: Keycloak, the revoker and Tokenserver together.

For each way of cutting a user off, with an online and an offline_access
session: after the Keycloak admin action and one revoker run, the session's
refresh token no longer works, Keycloak reports its tokens inactive and no
offline session is left. For a deleted user, the Tokenserver record is retired
and the user's unexpired access token is refused.
"""

import secrets
import time

import pytest

from .helpers import (
    MAX_GENERATION,
    Secret,
    admin_events_on,
    change_password_as_user,
    client_uuid,
    create_user,
    exchange,
    introspect,
    login,
    offline_sessions,
    refresh,
    run_revoker,
    user_events,
    user_rows,
    why,
)


def new_password():
    return Secret(secrets.token_urlsafe(24))


def reset_password(admin, user_id):
    body = {"type": "password", "value": new_password(), "temporary": False}
    return admin("PUT", f"/users/{user_id}/reset-password", json=body)


def update_password(admin, user_id):
    # PUT users/<id> with a credentials array: an admin UPDATE users/<id> event
    rep = admin("GET", f"/users/{user_id}").json()
    rep["credentials"] = [
        {"type": "password", "value": new_password(), "temporary": False}
    ]
    return admin("PUT", f"/users/{user_id}", json=rep)


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
    "update-password": update_password,
    "sign-out": sign_out,
    "disable": disable,
    "delete": delete,
}
# Where Keycloak on its own leaves the session usable (what the revoker is for).
# Not sign-out with an offline session: the sign-out sets the user's notBefore
# (whole seconds), so Keycloak refuses an offline token issued in an earlier
# second as stale, and accepts one issued in the same second. Which of the two
# happens depends on timing; the offline session itself stays either way, and
# the test checks that the revoker removes it.
KEYCLOAK_LEAVES_ALIVE = {
    ("reset-password", False),
    ("reset-password", True),
    ("update-password", False),
    ("update-password", True),
}


def new_user(admin, label):
    name = f"revoker-live-{label}-{secrets.token_hex(4)}"
    password = new_password()
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
    assert res.status_code == 401, why(res)
    assert res.json()["status"] == "invalid-generation", why(res)


@pytest.mark.parametrize("offline", [False, True], ids=["online", "offline"])
@pytest.mark.parametrize("action", list(ACTIONS))
def test_revocation(admin, db, revoker, live_client, action, offline):
    """After the action and one revoker run, the session is dead."""
    name, password, user_id = new_user(admin, action)
    tokens = login(admin, name, password, offline)
    access_token, refresh_token = tokens["access_token"], tokens["refresh_token"]
    res = exchange(access_token)
    assert res.status_code == 200, why(res)
    assert introspect(admin, access_token)
    assert_active_record(db, user_id)
    if offline:
        assert len(offline_sessions(admin, user_id, live_client)) == 1

    res = ACTIONS[action](admin, user_id)
    assert res.status_code == 204, why(res)
    if (action, offline) in KEYCLOAK_LEAVES_ALIVE:
        assert refresh(admin, refresh_token).status_code == 200
    if offline and action != "delete":
        # Keycloak leaves the offline session in place
        assert len(offline_sessions(admin, user_id, live_client)) == 1
    if action == "delete":
        # Not retired yet, so Tokenserver still takes the token
        assert exchange(access_token).status_code == 200

    revoker("--once")

    res = refresh(admin, refresh_token)
    assert res.status_code == 400, why(res)
    assert res.json()["error"] == "invalid_grant", why(res)
    assert not introspect(admin, access_token)
    assert not introspect(admin, refresh_token)
    if action == "delete":
        assert_retired(db, user_id, access_token)
    else:
        assert_active_record(db, user_id)
        assert offline_sessions(admin, user_id, live_client) == []


def test_password_change_by_the_user(admin, db, revoker, live_client):
    """The user changes their password: both sessions die after one run."""
    name, password, user_id = new_user(admin, "self-service")
    online = login(admin, name, password, offline=False)
    offline = login(admin, name, password, offline=True)
    assert exchange(online["access_token"]).status_code == 200
    assert len(offline_sessions(admin, user_id, live_client)) == 1

    change_password_as_user(admin, name, password, new_password())
    # Keycloak on its own leaves both sessions working ("Sign out from other
    # devices" wasn't ticked)
    assert refresh(admin, online["refresh_token"]).status_code == 200
    assert refresh(admin, offline["refresh_token"]).status_code == 200
    # It was a user event, and no admin touched the user since creating them
    assert {"UPDATE_PASSWORD", "UPDATE_CREDENTIAL"} <= set(user_events(admin, user_id))
    assert admin_events_on(admin, user_id) == ["CREATE"]

    output = revoker("--once")
    assert (
        f"revoke-all-sessions: keycloak user {user_id}, for user event UPDATE_PASSWORD"
        in output
    )

    for tokens in (online, offline):
        res = refresh(admin, tokens["refresh_token"])
        assert res.status_code == 400, why(res)
        assert res.json()["error"] == "invalid_grant", why(res)
        assert not introspect(admin, tokens["access_token"])
    assert offline_sessions(admin, user_id, live_client) == []
    assert_active_record(db, user_id)


def test_reconcile_retires_user_deleted_while_revoker_was_down(
    admin, db, revoker, revoker_env, tmp_path
):
    """--reconcile retires a user whose deletion event the revoker never saw."""
    name, password, user_id = new_user(admin, "reconcile")
    access_token = login(admin, name, password, offline=False)["access_token"]
    assert exchange(access_token).status_code == 200
    assert delete(admin, user_id).status_code == 204

    # A revoker that starts after the deletion (a new cursor) never sees it, if
    # it starts more than its overlap later: a first start looks back by it
    time.sleep(2)
    env = revoker_env.but(
        REVOKER_CURSOR_FILE=str(tmp_path / "cursor"), REVOKER_OVERLAP="1"
    )
    run_revoker(env, "--once", "--init-cursor")
    run_revoker(env, "--once")
    assert_active_record(db, user_id)
    assert exchange(access_token).status_code == 200

    # No --force: however few active users this database holds, the cap lets
    # one run retire 1 (and, with fewer than 20, no more, so a second user
    # wrongly counted as gone fails the run)
    output = run_revoker(env, "--reconcile")
    assert f"reconcile: retired keycloak user {user_id}" in output
    assert_retired(db, user_id, access_token)


@pytest.mark.parametrize("offline", [False, True], ids=["online", "offline"])
def test_admin_profile_edit_leaves_sessions_alone(
    admin, revoker_env, live_client, tmp_path, offline
):
    """An admin PUT users/<id> that sets no password signs nobody out.

    The revoker looks at the password credential's createdDate, which only a
    PUT with a credentials array changes. With REVOKER_OVERLAP 1 s (its own
    cursor), a password set 2 s before the edit counts as old.
    """
    env = revoker_env.but(
        REVOKER_CURSOR_FILE=str(tmp_path / "cursor"), REVOKER_OVERLAP="1"
    )
    run_revoker(env, "--once", "--init-cursor")
    name, password, user_id = new_user(admin, "profile-edit")
    tokens = login(admin, name, password, offline)
    res = admin("GET", f"/users/{user_id}/credentials")
    assert res.status_code == 200, why(res)
    (created,) = [c["createdDate"] for c in res.json() if c["type"] == "password"]
    time.sleep(2)

    rep = admin("GET", f"/users/{user_id}").json()
    rep["firstName"] = "Edited"
    rep["attributes"] = {"department": ["sync"]}
    res = admin("PUT", f"/users/{user_id}", json=rep)
    assert res.status_code == 204, why(res)
    assert admin_events_on(admin, user_id)[0] == "UPDATE"
    res = admin("GET", f"/users/{user_id}/credentials")
    assert [c["createdDate"] for c in res.json() if c["type"] == "password"] == [
        created
    ]

    output = run_revoker(env, "--once")
    assert f"no new password: keycloak user {user_id}" in output
    assert f"revoke-all-sessions: keycloak user {user_id}" not in output
    res = refresh(admin, tokens["refresh_token"])
    assert res.status_code == 200, why(res)
    assert introspect(admin, tokens["access_token"])
    if offline:
        assert len(offline_sessions(admin, user_id, live_client)) == 1


def test_admin_disable_is_left_to_keycloak(admin, revoker_env, live_client, tmp_path):
    """Disabling sets no password: Keycloak alone refuses the refresh."""
    env = revoker_env.but(
        REVOKER_CURSOR_FILE=str(tmp_path / "cursor"), REVOKER_OVERLAP="1"
    )
    run_revoker(env, "--once", "--init-cursor")
    name, password, user_id = new_user(admin, "disable-old-pw")
    tokens = login(admin, name, password, offline=True)
    time.sleep(2)
    assert disable(admin, user_id).status_code == 204

    output = run_revoker(env, "--once")
    assert f"no new password: keycloak user {user_id}" in output
    res = refresh(admin, tokens["refresh_token"])
    assert res.status_code == 400, why(res)
    assert res.json()["error"] == "invalid_grant", why(res)
    # The revoker removed nothing
    assert len(offline_sessions(admin, user_id, live_client)) == 1


def test_missing_cursor_file_stops_the_revoker(revoker_env, tmp_path):
    """Without a cursor file the revoker refuses to start, unless asked to."""
    env = revoker_env.but(REVOKER_CURSOR_FILE=str(tmp_path / "cursor"))
    output = run_revoker(env, "--once", status=1)
    assert "no cursor file: first deployment? Run with --init-cursor" in output
    assert not (tmp_path / "cursor").exists()
    run_revoker(env.but(REVOKER_INIT_CURSOR="1"), "--once")
    assert (tmp_path / "cursor").exists()
    run_revoker(env, "--once")


def test_unknown_offline_client_stops_the_revoker(admin, revoker_env, tmp_path):
    """A typo in REVOKER_OFFLINE_CLIENTS fails at startup, before any event.

    The revoker's service account has no view-clients, so the check can't
    depend on reading clients.
    """
    revoker = client_uuid(admin, revoker_env["REVOKER_CLIENT_ID"])
    res = admin("GET", f"/clients/{revoker}/service-account-user")
    assert res.status_code == 200, why(res)
    account = res.json()["id"]
    realm_management = client_uuid(admin, "realm-management")
    res = admin(
        "GET",
        f"/users/{account}/role-mappings/clients/{realm_management}/composite",
    )
    assert res.status_code == 200, why(res)
    assert "view-clients" not in {role["name"] for role in res.json()}

    env = revoker_env.but(
        REVOKER_CURSOR_FILE=str(tmp_path / "cursor"),
        REVOKER_OFFLINE_CLIENTS="revoker-live-thunderbird,revoker-live-typo",
    )
    output = run_revoker(env, "--once", status=1)
    assert "offline client revoker-live-typo not found in the realm" in output
    assert "revoker-live-thunderbird not found" not in output
    assert not (tmp_path / "cursor").exists()
